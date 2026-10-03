"""sFlow v5 datagram parser (4-3). sFlow is structurally different from
NetFlow: instead of exporting a summary record per completed flow, the
exporter statistically samples 1-in-N raw packets and sends the first bytes
of each one (its captured Ethernet/IP/TCP|UDP headers) verbatim, plus the
sampling rate -- the actual packet/byte counts are *extrapolated* from that
rate, not measured exactly, which is the fundamental accuracy difference
from NetFlow worth knowing about when reading the numbers this produces.

Scope deliberately narrow: only "flow samples" carrying a raw packet header
(sample format 1, flow record format 1 -- the common case for this kind of
analysis) are decoded into a 5-tuple. Counter samples (interface/CPU/memory
stats periodically piggybacked on the same stream) and anything else are
skipped using each record's own declared length, which is how a TLV-style
format like this is supposed to be walked -- an unrecognized record never
breaks parsing of the ones after it.
"""
import struct

VERSION = 5
_PROTO_NAMES = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

SAMPLE_FLOW = 1
SAMPLE_FLOW_EXPANDED = 3
FLOW_RAW_PACKET_HEADER = 1

HDR_ETHERNET = 1


def _u32(data, off):
    return struct.unpack_from('!I', data, off)[0], off + 4


def _ip_str(b):
    return '%d.%d.%d.%d' % (b[0], b[1], b[2], b[3])


def _parse_raw_packet(header, frame_length, sampling_rate):
    """header: the captured bytes starting at the Ethernet frame. Walks
    Ethernet -> (optional 802.1Q) -> IPv4 -> TCP/UDP just far enough to pull
    a 5-tuple. Returns None (not raised) for anything not recognized --
    non-IPv4 traffic (IPv6, ARP, ...) is simply not counted by this pass,
    documented as a known gap rather than a bug to track down."""
    if len(header) < 14:
        return None
    eth_type = struct.unpack_from('!H', header, 12)[0]
    off = 14
    if eth_type == 0x8100:  # 802.1Q VLAN tag -- 4 more bytes, real ethertype after it
        if len(header) < off + 4:
            return None
        eth_type = struct.unpack_from('!H', header, off + 2)[0]
        off += 4
    if eth_type != 0x0800:  # IPv4 only
        return None
    if len(header) < off + 20:
        return None
    ver_ihl = header[off]
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(header) < off + ihl:
        return None
    protocol_num = header[off + 9]
    src_ip = _ip_str(header[off + 12:off + 16])
    dst_ip = _ip_str(header[off + 16:off + 20])
    src_port = dst_port = 0
    l4_off = off + ihl
    if protocol_num in (6, 17) and len(header) >= l4_off + 4:  # TCP/UDP ports are in the same spot
        src_port, dst_port = struct.unpack_from('!HH', header, l4_off)
    return {
        'src_ip': src_ip, 'dst_ip': dst_ip, 'src_port': src_port, 'dst_port': dst_port,
        'protocol': _PROTO_NAMES.get(protocol_num, 'OTHER'),
        # sFlow is sampled, not exhaustive -- these are extrapolated from the
        # one captured packet standing in for `sampling_rate` real ones, not
        # an exact measurement the way NetFlow's d_octets/d_pkts are.
        'bytes': frame_length * max(sampling_rate, 1),
        'packets': max(sampling_rate, 1),
    }


def parse(data, exporter_ip, recv_ts_ms):
    """Returns a list of normalized flow dicts (same shape as
    netflow_parser.parse). Raises ValueError on a malformed/unrecognized
    datagram header; skips individual samples/records it doesn't understand
    rather than raising, since one unfamiliar sample type from a device that
    also sends ones we do understand shouldn't discard the whole datagram."""
    if len(data) < 8:
        raise ValueError('packet shorter than sFlow header start')
    version, ip_version = struct.unpack_from('!II', data, 0)
    if version != VERSION:
        raise ValueError(f'not sFlow v5 (version={version})')
    off = 8
    addr_len = 4 if ip_version == 1 else 16 if ip_version == 2 else None
    if addr_len is None or len(data) < off + addr_len + 16:
        raise ValueError('malformed sFlow agent address / header')
    off += addr_len  # agent address, unused -- exporter_ip (UDP source) is what we key on
    off += 4  # sub_agent_id
    off += 4  # sequence_number
    off += 4  # uptime
    num_samples, off = _u32(data, off)

    out = []
    for _ in range(num_samples):
        if off + 8 > len(data):
            break  # truncated datagram -- stop, keep whatever we already parsed
        sample_type, off = _u32(data, off)
        sample_len, off = _u32(data, off)
        sample_end = off + sample_len
        if sample_end > len(data):
            break
        fmt = sample_type & 0xFFF  # low 12 bits; high bits are an enterprise id we don't use
        try:
            if fmt in (SAMPLE_FLOW, SAMPLE_FLOW_EXPANDED):
                out.extend(_parse_flow_sample(data, off, sample_end, fmt, exporter_ip, recv_ts_ms))
        except (struct.error, IndexError):
            pass  # one malformed sample doesn't invalidate the rest of the datagram
        off = sample_end  # always resync on the declared length, understood or not
    return out


def _parse_flow_sample(data, off, end, fmt, exporter_ip, recv_ts_ms):
    off += 4  # sequence_number
    if fmt == SAMPLE_FLOW_EXPANDED:
        off += 8  # source_id_type + source_id_index (split, vs. packed in the classic format)
    else:
        off += 4  # source_id (type+index packed into one word)
    sampling_rate, off = _u32(data, off)
    off += 4  # sample_pool
    off += 4  # drops
    off += 8 if fmt == SAMPLE_FLOW_EXPANDED else 4 * 2  # input+output ifIndex (expanded ones are wider)
    num_records, off = _u32(data, off)
    out = []
    for _ in range(num_records):
        if off + 8 > end:
            break
        flow_format, off = _u32(data, off)
        flow_len, off = _u32(data, off)
        flow_end = off + flow_len
        if flow_end > end:
            break
        if (flow_format & 0xFFF) == FLOW_RAW_PACKET_HEADER:
            rec = _parse_raw_packet_record(data, off, flow_end, sampling_rate)
            if rec:
                rec['exporter_ip'] = exporter_ip
                rec['ts'] = recv_ts_ms
                out.append(rec)
        # padded to a 4-byte boundary, same as the outer sample length
        off = flow_end + (-flow_len % 4)
    return out


def _parse_raw_packet_record(data, off, end, sampling_rate):
    if off + 16 > end:
        return None
    header_protocol, frame_length, stripped, header_length = struct.unpack_from('!IIII', data, off)
    off += 16
    if header_protocol != HDR_ETHERNET:
        return None
    header_length = min(header_length, end - off)
    header = data[off:off + header_length]
    return _parse_raw_packet(header, frame_length, sampling_rate)
