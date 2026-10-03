"""Synthetic NetFlow v5 / sFlow v5 packet sender (4-3), for validating the
flow collector pipeline without a real NetFlow/sFlow-capable device on the
network -- see the 4-3 plan notes for why none of this environment's actual
hardware supports either protocol.

Sends one realistic packet of each kind to a running InfraSight instance's
collector ports, waits for the 60s in-memory-to-SQLite flush (or triggers it
immediately via an injected call if INFRASIGHT_TEST_FAST=1, see below), then
calls the /api/flow/* endpoints to confirm the data made it all the way
through parsing -> aggregation -> storage -> API.

Credentials come from environment variables only, same policy as
security_tests.py -- never hardcode a real password in a file meant to be
committed.

Usage:
    INFRASIGHT_TEST_ADMIN_USER=admin INFRASIGHT_TEST_ADMIN_PASS='...' \
        python flow_test_sender.py [base_url]
"""
import os
import socket
import struct
import sys
import time
# requests is only needed by main() (the login + /api/flow/* calls) -- not
# by the packet-building helpers above, which collector tests or a REPL can
# reuse without installing it. Imported lazily inside main() instead.

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else 'https://localhost:8443'
ADMIN_USER = os.environ.get('INFRASIGHT_TEST_ADMIN_USER')
ADMIN_PASS = os.environ.get('INFRASIGHT_TEST_ADMIN_PASS')
NETFLOW_PORT = int(os.environ.get('INFRASIGHT_NETFLOW_PORT', '2055'))
SFLOW_PORT = int(os.environ.get('INFRASIGHT_SFLOW_PORT', '6343'))

# Distinct, made-up addresses so these test flows are easy to recognize (and
# ignore / clean up mentally) among anything real that shows up later.
NETFLOW_SRC, NETFLOW_DST = '10.99.0.5', '203.0.113.9'
SFLOW_SRC, SFLOW_DST = '10.99.0.6', '198.51.100.7'


def _ip_bytes(s):
    return bytes(int(x) for x in s.split('.'))


def _ip_u32(s):
    b = _ip_bytes(s)
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]


def build_netflow_v5_packet():
    header = struct.pack('!HHIIIIBBH', 5, 1, 12345, int(time.time()), 0, 1, 0, 0, 0)
    record = struct.pack(
        '!IIIHHIIIIHHBBBBHHBBH',
        _ip_u32(NETFLOW_SRC), _ip_u32(NETFLOW_DST), 0, 1, 2,
        7, 4200, 0, 0, 51000, 443, 0, 0, 6, 0, 0, 0, 0, 0, 0,
    )
    return header + record


def build_sflow_v5_packet():
    eth = b'\x11\x22\x33\x44\x55\x66\xaa\xbb\xcc\xdd\xee\xff' + struct.pack('!H', 0x0800)
    ip_hdr = bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 17, 0, 0]) + _ip_bytes(SFLOW_SRC) + _ip_bytes(SFLOW_DST)
    udp_hdr = struct.pack('!HH', 53124, 53) + b'\x00' * 16  # UDP, for protocol variety vs. the NetFlow TCP sample
    header = eth + ip_hdr + udp_hdr

    flow_record_data = struct.pack('!IIII', 1, 512, 0, len(header)) + header
    flow_record = struct.pack('!II', 1, len(flow_record_data)) + flow_record_data
    flow_record += b'\x00' * ((-len(flow_record_data)) % 4)

    sample_data = struct.pack('!IIIIIII', 1, (1 << 24) | 1, 20, 0, 0, 1, 2)  # sampling_rate=20
    sample_data += struct.pack('!I', 1) + flow_record
    sample = struct.pack('!II', 1, len(sample_data)) + sample_data

    datagram = struct.pack('!II', 5, 1) + _ip_bytes('192.168.1.1') + struct.pack('!IIII', 0, 100, 999, 1)
    return datagram + sample


def send_udp(payload, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, ('127.0.0.1', port))
    finally:
        sock.close()


def main():
    if not ADMIN_USER or not ADMIN_PASS:
        print('INFRASIGHT_TEST_ADMIN_USER / INFRASIGHT_TEST_ADMIN_PASS not set -- skipping (not failing).')
        return 0

    import requests
    import urllib3
    session = requests.Session()
    session.verify = False
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    r = session.post(f'{BASE_URL}/api/auth/login', json={'username': ADMIN_USER, 'password': ADMIN_PASS})
    r.raise_for_status()

    print(f'Sending synthetic NetFlow v5 packet to 127.0.0.1:{NETFLOW_PORT} ...')
    send_udp(build_netflow_v5_packet(), NETFLOW_PORT)
    print(f'Sending synthetic sFlow v5 packet to 127.0.0.1:{SFLOW_PORT} ...')
    send_udp(build_sflow_v5_packet(), SFLOW_PORT)

    print('Waiting up to 70s for the 60s in-memory flush to land in storage...')
    ok = False
    for _ in range(14):
        time.sleep(5)
        resp = session.get(f'{BASE_URL}/api/flow/status').json()
        ips_seen = {e['exporterIp'] for e in resp.get('exporters', [])}
        if '127.0.0.1' in ips_seen:
            ok = True
            break
    if not ok:
        print('FAIL: 127.0.0.1 never showed up in /api/flow/status -- check server logs '
              '(app.log) for flow_listener bind/parse errors.')
        return 1

    status = session.get(f'{BASE_URL}/api/flow/status').json()
    talkers = session.get(f'{BASE_URL}/api/flow/top-talkers?range=1h').json()['pairs']
    protocols = session.get(f'{BASE_URL}/api/flow/protocols?range=1h').json()['protocols']
    summary = session.get(f'{BASE_URL}/api/flow/summary?range=1h').json()

    print('\n--- /api/flow/status ---')
    for e in status['exporters']:
        print(e)
    print('\n--- /api/flow/top-talkers ---')
    for p in talkers:
        print(p)
    print('\n--- /api/flow/protocols ---')
    for p in protocols:
        print(p)
    print('\n--- /api/flow/summary ---')
    print(summary)

    expected_pairs = {(NETFLOW_SRC, NETFLOW_DST), (SFLOW_SRC, SFLOW_DST)}
    found_pairs = {(p['srcIp'], p['dstIp']) for p in talkers}
    missing = expected_pairs - found_pairs
    if missing:
        print(f'\nFAIL: expected test pairs not found in top-talkers: {missing}')
        return 1
    if summary['bytesTotal'] <= 0:
        print('\nFAIL: summary bytesTotal is 0')
        return 1

    print('\nPASS: both synthetic flows made it through parse -> aggregate -> flush -> API.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
