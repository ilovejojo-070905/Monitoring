"""NetFlow v5 datagram parser (4-3). Deliberately v5 only, not v9/IPFIX --
v9/IPFIX are template-based (the exporter defines its own field layout in a
separate template record, which has to be cached per-exporter before the
data records that reference it can even be parsed), which is a meaningfully
bigger undertaking than this fixed-format version. See the 4-3 plan notes
for that as a documented follow-up, not an oversight.

No external dependency: NetFlow v5's wire format is fixed and small enough
that struct.unpack is simpler and more auditable than pulling in a flow-
parsing library for one format.
"""
import struct

VERSION = 5
HEADER_FMT = '!HHIIIIBBH'
HEADER_LEN = struct.calcsize(HEADER_FMT)
RECORD_FMT = '!IIIHHIIIIHHBBBBHHBBH'
RECORD_LEN = struct.calcsize(RECORD_FMT)
assert HEADER_LEN == 24 and RECORD_LEN == 48, (HEADER_LEN, RECORD_LEN)

_PROTO_NAMES = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}


def _ip_str(n):
    return '%d.%d.%d.%d' % ((n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF)


def parse(data, exporter_ip, recv_ts_ms):
    """Returns a list of normalized flow dicts:
    {exporter_ip, src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, ts}
    -- the same shape collector/sflow_parser.py produces, so flow_listener.py
    doesn't need to know which protocol a given packet came from. Raises
    ValueError on anything that isn't a well-formed v5 packet (flow_listener
    catches this per-packet so one malformed/misconfigured sender's packets
    don't take down the listener thread)."""
    if len(data) < HEADER_LEN:
        raise ValueError('packet shorter than NetFlow v5 header')
    version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, engine_type, engine_id, sampling = \
        struct.unpack_from(HEADER_FMT, data, 0)
    if version != VERSION:
        raise ValueError(f'not NetFlow v5 (version={version})')
    needed = HEADER_LEN + count * RECORD_LEN
    if len(data) < needed:
        raise ValueError(f'packet too short for {count} records ({len(data)} < {needed})')
    out = []
    off = HEADER_LEN
    for _ in range(count):
        (srcaddr, dstaddr, nexthop, in_if, out_if, d_pkts, d_octets, first, last,
         srcport, dstport, pad1, tcp_flags, prot, tos, src_as, dst_as,
         src_mask, dst_mask, pad2) = struct.unpack_from(RECORD_FMT, data, off)
        off += RECORD_LEN
        out.append({
            'exporter_ip': exporter_ip,
            'src_ip': _ip_str(srcaddr), 'dst_ip': _ip_str(dstaddr),
            'src_port': srcport, 'dst_port': dstport,
            'protocol': _PROTO_NAMES.get(prot, 'OTHER'),
            'bytes': d_octets, 'packets': d_pkts,
            'ts': recv_ts_ms,
        })
    return out
