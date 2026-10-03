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

# A typo'd /8 (16M addresses) would otherwise happily queue 16M pings.
MAX_HOSTS = 1024
CONCURRENCY = 64
DEFAULT_TIMEOUT_SEC = 0.6


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


def scan(range_text, timeout_s=DEFAULT_TIMEOUT_SEC):
    """Pings every address in range_text concurrently and returns the
    reachable ones as [{ip, latencyMs, hostname}], sorted by IP. hostname is
    best-effort reverse DNS -- None on any failure (most LANs don't have it
    configured, which is fine, it's just a label suggestion for the form)."""
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
    return found
