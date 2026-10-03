"""NetFlow/sFlow UDP collector (4-3). Two always-on listening sockets, each
on its own daemon thread -- this is the first use of raw threading.Thread in
this codebase (everywhere else uses APScheduler's thread pool for periodic
polls). That's deliberate: a flow exporter pushes data to us on its own
schedule, so the only way to receive it is a socket blocked in recvfrom()
forever, which is exactly the kind of permanently-occupied worker
APScheduler's pool is not meant to hold.

Flow records arrive at a rate proportional to real network traffic, not a
fixed poll interval, so they're aggregated into 1-minute buckets *in memory*
here and flushed to storage.py once a minute (see flush(), wired into
collector/scheduler.py as an interval job) rather than writing one row per
flow record -- see storage.py's flow_bandwidth_1m comment for why there's no
raw flow table.
"""
import threading
import time
from collections import defaultdict

import storage
from applog import app_logger
from collector import netflow_parser, sflow_parser

# Per-bucket safety valve: a pathological burst (e.g. a port scan) could
# otherwise create unbounded distinct (src,dst) pairs in memory before the
# next flush. Once a bucket hits this many distinct pairs, already-tracked
# pairs keep accumulating but new ones are dropped for the rest of that
# bucket -- the top-by-bytes pairs (what the UI actually shows) are
# overwhelmingly likely to already be among the first ones seen anyway.
MAX_PAIRS_PER_BUCKET = 2000

_lock = threading.Lock()
# {(device_id, bucket_ts): [bytes, packets]}
_bandwidth = defaultdict(lambda: [0, 0])
# {(device_id, bucket_ts, protocol): [bytes, packets]}
_protocols = defaultdict(lambda: [0, 0])
# {(device_id, bucket_ts): {(src_ip, dst_ip): [bytes, packets]}}
_pairs = defaultdict(dict)
# {exporter_ip: [protocol, last_seen_ms, count]}
_exporters = {}

_device_ip_cache = {}
_sockets = []
_started = False


def _refresh_device_cache():
    try:
        _device_ip_cache.clear()
        for d in storage.load_devices():
            if d.get('ip'):
                _device_ip_cache[d['ip']] = d['id']
    except Exception:
        app_logger.exception('flow_listener: device cache refresh failed')


def _device_id_for(exporter_ip):
    # 'unknown:<ip>' for an exporter that isn't (yet) a registered device --
    # surfaced as-is in /api/flow/status so an unregistered-but-exporting
    # device is actually discoverable, not silently dropped.
    return _device_ip_cache.get(exporter_ip) or f'unknown:{exporter_ip}'


def _record_flow(flow, protocol_label):
    device_id = _device_id_for(flow['exporter_ip'])
    bucket_ts = (flow['ts'] // storage.FLOW_BUCKET_MS) * storage.FLOW_BUCKET_MS
    b = flow['bytes']
    p = flow['packets']
    with _lock:
        bw = _bandwidth[(device_id, bucket_ts)]
        bw[0] += b
        bw[1] += p
        pr = _protocols[(device_id, bucket_ts, flow['protocol'])]
        pr[0] += b
        pr[1] += p
        pair_bucket = _pairs[(device_id, bucket_ts)]
        pair_key = (flow['src_ip'], flow['dst_ip'])
        if pair_key in pair_bucket or len(pair_bucket) < MAX_PAIRS_PER_BUCKET:
            entry = pair_bucket.setdefault(pair_key, [0, 0])
            entry[0] += b
            entry[1] += p
        exp = _exporters.setdefault(flow['exporter_ip'], [protocol_label, flow['ts'], 0])
        exp[0] = protocol_label
        exp[1] = flow['ts']
        exp[2] += 1


def _listen_loop(sock, parser_module, protocol_label):
    while True:
        try:
            data, (addr, _port) = sock.recvfrom(65535)
        except OSError:
            return  # socket closed (shutdown) -- exit the thread cleanly
        recv_ts = int(time.time() * 1000)
        try:
            flows = parser_module.parse(data, addr, recv_ts)
        except ValueError as e:
            app_logger.warning('flow_listener: malformed %s packet from %s: %s', protocol_label, addr, e)
            continue
        except Exception:
            app_logger.exception('flow_listener: unexpected error parsing %s packet from %s', protocol_label, addr)
            continue
        for flow in flows:
            _record_flow(flow, protocol_label)


def _bind(port):
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    return sock


def start():
    """Starts both listeners. Safe to call once at process startup (see
    server.py main(), right after scheduler.start()); binding failure (e.g.
    the port's already in use) is logged, not fatal -- the rest of
    InfraSight has nothing to do with these sockets and shouldn't fail to
    start because of them."""
    global _started
    if _started:
        return
    _started = True
    _refresh_device_cache()
    for port, parser_module, label in (
        (storage.NETFLOW_PORT, netflow_parser, 'netflow'),
        (storage.SFLOW_PORT, sflow_parser, 'sflow'),
    ):
        try:
            sock = _bind(port)
        except OSError as e:
            app_logger.error('flow_listener: could not bind %s UDP port %d: %s', label, port, e)
            continue
        _sockets.append(sock)
        t = threading.Thread(target=_listen_loop, args=(sock, parser_module, label), daemon=True,
                              name=f'flow-{label}')
        t.start()
    app_logger.info('flow_listener: listening (netflow udp/%d, sflow udp/%d)',
                     storage.NETFLOW_PORT, storage.SFLOW_PORT)


def flush():
    """Writes the last minute's in-memory aggregates to storage.py and
    clears them. Called every 60s from collector/scheduler.py -- see that
    module's start(). Swaps each buffer out under the lock and does the
    (slower) DB writes after releasing it, so a UDP thread never blocks on
    SQLite."""
    global _bandwidth, _protocols, _pairs, _exporters
    with _lock:
        bandwidth, protocols, pairs, exporters = _bandwidth, _protocols, _pairs, _exporters
        _bandwidth = defaultdict(lambda: [0, 0])
        _protocols = defaultdict(lambda: [0, 0])
        _pairs = defaultdict(dict)
        _exporters = {}

    if bandwidth:
        storage.record_flow_bandwidth([(did, bts, v[0], v[1]) for (did, bts), v in bandwidth.items()])
    if protocols:
        storage.record_flow_protocols([(did, bts, proto, v[0], v[1]) for (did, bts, proto), v in protocols.items()])
    if pairs:
        rows = []
        for (did, bts), pair_map in pairs.items():
            for (src, dst), v in pair_map.items():
                rows.append((did, bts, src, dst, v[0], v[1]))
        storage.record_flow_top_pairs(rows)
    if exporters:
        storage.record_flow_exporters([(ip, proto, ts, cnt) for ip, (proto, ts, cnt) in exporters.items()])

    # Pick up newly-registered devices (or IP changes) for the next minute's
    # exporter->device_id matching -- cheap enough to just do every cycle.
    _refresh_device_cache()
