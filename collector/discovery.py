"""Network auto-discovery: scan an IP range/CIDR for live hosts so they can
be offered as registration candidates instead of typing each one in by hand.

Reuses ping_collector.ping_host (the exact same reachability check the
ongoing ping monitor uses) rather than a separate implementation, run
concurrently across a thread pool since ping_host shells out to the system
ping command and blocks -- asyncio wouldn't buy anything here without
rewriting that call, and a thread per in-flight probe is plenty fast for a
LAN-sized range.
"""
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from collector.ping_collector import ping_host
from collector import snmp_collector

# A typo'd /8 (16M addresses) would otherwise happily queue 16M pings.
MAX_HOSTS = 1024
CONCURRENCY = 64
DEFAULT_TIMEOUT_SEC = 0.6

# 2-6: best-effort device-type guess for whatever answered the ping --
# TCP connect-scan against a small, fixed set of common ports (never
# UDP: a raw connect() on a UDP socket can't actually tell you anything
# about the remote end, so there's no equivalent cheap probe for those).
# Only run against hosts that already answered the ping (see scan() below),
# never the whole requested range, so this doesn't multiply the traffic a
# typo'd-huge range would already have reduced to just MAX_HOSTS pings.
_TYPE_PORT_TIMEOUT_SEC = 0.3
_TYPE_PORTS = [3389, 22, 9100, 443, 80]
_PORT_TYPE_LABEL = {3389: 'Windows PC/서버 (RDP)', 22: 'Linux 서버 (SSH)', 9100: '프린터 (포트 9100)'}


def _port_open(ip, port, timeout_s):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def guess_device_type(ip):
    """Checked in priority order: RDP/SSH/printer ports identify a specific
    device type directly, so the first match wins. SNMP responding (even
    with no open management port) usually means purpose-built network gear,
    so it's checked next. Bare 80/443 with none of the above is downgraded
    to a generic "web service" guess rather than anything specific -- lots
    of unrelated things speak HTTP. Returns None (not a 400/error) when
    nothing matched; this is always a guess, never a claim."""
    for port in (3389, 22, 9100):
        if _port_open(ip, port, _TYPE_PORT_TIMEOUT_SEC):
            return _PORT_TYPE_LABEL[port]
    if snmp_collector.SNMP_AVAILABLE:
        try:
            auth = snmp_collector.build_auth_data_raw('v2c', 'public')
            if snmp_collector.check_reachable(ip, auth, 161, timeout=_TYPE_PORT_TIMEOUT_SEC):
                return '네트워크 장비 (SNMP 응답)'
        except Exception:
            pass
    if _port_open(ip, 80, _TYPE_PORT_TIMEOUT_SEC) or _port_open(ip, 443, _TYPE_PORT_TIMEOUT_SEC):
        return '웹 서비스 장비 (추정)'
    return None


def parse_range(text):
    """Accepts a CIDR ('192.168.30.0/24'), a full dashed range
    ('192.168.30.1-192.168.30.254'), a short dashed range with just the last
    octet changing ('192.168.30.1-254'), or a single address. Returns a list
    of address strings in order. Raises ValueError with a Korean message on
    anything it can't make sense of -- that message goes straight back to
    the caller as the API error.
    """
    s = (text or '').strip()
    if not s:
        raise ValueError('스캔할 IP 대역을 입력해주세요')
    bad_format = ValueError('IP 대역 형식을 확인해주세요 (예: 192.168.0.0/24 또는 192.168.0.1-254)')

    def parse_ip(value):
        # ipaddress.ip_address raises its own ValueError on bad input (a
        # plain English message like "'x' does not appear to be an IPv4 or
        # IPv6 address") -- converted to the friendly Korean one right here,
        # at the only place raw user input actually reaches the library, so
        # it can't leak past this function un-translated.
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            raise bad_format

    if '/' in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            raise bad_format
        ips = [str(ip) for ip in net.hosts()]
    elif '-' in s:
        start_s, end_s = (p.strip() for p in s.split('-', 1))
        start = parse_ip(start_s)
        if '.' in end_s or ':' in end_s:
            end = parse_ip(end_s)
        else:
            parts = start_s.split('.')
            parts[-1] = end_s
            end = parse_ip('.'.join(parts))
        if int(end) < int(start):
            raise ValueError('범위의 끝 주소가 시작 주소보다 작습니다')
        ips = [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
    else:
        ips = [str(parse_ip(s))]
    if len(ips) > MAX_HOSTS:
        raise ValueError(f'한 번에 스캔할 수 있는 주소는 {MAX_HOSTS}개까지입니다 (지정하신 범위: {len(ips)}개)')
    return ips


def _hostname_for(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def scan(range_text, timeout_s=DEFAULT_TIMEOUT_SEC, guess_types=True):
    """Pings every address in range_text concurrently and returns the
    reachable ones as [{ip, latencyMs, hostname, guessedType}], sorted by
    IP. hostname is best-effort reverse DNS -- None on any failure (most
    LANs don't have it configured, which is fine, it's just a label
    suggestion for the form). guessedType (also best-effort, also often
    None) only runs a second, separate probe pass against hosts that
    already answered the ping -- see guess_device_type()'s own docstring
    for why that keeps the extra traffic bounded by live-host count, not
    range size."""
    ips = parse_range(range_text)

    def probe(ip):
        reachable, latency = ping_host(ip, timeout_s)
        if not reachable:
            return None
        return {'ip': ip, 'latencyMs': latency, 'hostname': _hostname_for(ip)}

    found = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        for fut in as_completed([pool.submit(probe, ip) for ip in ips]):
            r = fut.result()
            if r:
                found.append(r)
    found.sort(key=lambda r: tuple(int(p) for p in r['ip'].split('.')))
    if guess_types and found:
        with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            guesses = dict(zip((r['ip'] for r in found),
                                pool.map(guess_device_type, (r['ip'] for r in found))))
        for r in found:
            r['guessedType'] = guesses.get(r['ip'])
    else:
        for r in found:
            r['guessedType'] = None
    return found
