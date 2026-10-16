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
            # 신규 필드(2026-10-16, "지원 버전을 명확히 표시") -- 지금은 v5만
            # 받으므로(다른 버전은 parse() 맨 위에서 이미 ValueError) 항상
            # 5지만, 필드 자체를 데이터에 박아두면 나중에 v9/IPFIX를 추가해도
            # 소비하는 쪽(저장/화면)이 "어떤 버전에서 왔는지"를 추측 없이
            # 바로 구분할 수 있다.
            'version': VERSION,
            # ingress/egress ifIndex -- 집계에는 안 쓰지만(방향 구분은 이
            # 프로젝트가 의도적으로 안 하는 단순화, index.html에 명시돼
            # 있음) 패킷에서 실제로 뽑히는 값 자체를 버리지 않고 남겨서,
            # 나중에 방향별 분석이 필요해지면 "데이터 자체가 없어서 처음부터
            # 다시 파싱해야" 하는 상황을 피한다.
            'in_if': in_if, 'out_if': out_if,
        })
    return out
