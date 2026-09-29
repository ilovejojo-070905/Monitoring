"""Input validation (directive sections 12/13, and the command-injection
fixes in 12/18 that only a validated *input* -- not output escaping -- can
actually prevent). Every function here is a pure predicate/normalizer; none
of them touch the DB or the network, so they're safe to call from anywhere
without import-cycle concerns.
"""
import re

# RFC 1123 hostname: labels of alnum/hyphen (not starting/ending with '-'),
# joined by dots. Deliberately excludes '_', spaces, and shell/batch
# metacharacters -- this is also what keeps a device name or IP from being
# usable as a ping-argument-injection vector (collector/ping_collector.py
# passes ip straight into a subprocess arg list; a value starting with '-'
# would otherwise be read as a ping flag) or a cmd.exe injection vector (the
# installer .bat embeds the device name directly).
_HOSTNAME_RE = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$')
_IPV4_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
# A conservative allow-list for free-text names that end up embedded in a
# generated .bat and rendered in the UI: Hangul, CJK-adjacent scripts aren't
# needed since Python's \w with the Unicode flag already covers Korean
# characters, plus space/dot/hyphen/underscore/parentheses. Explicitly no
# &|<>^%"'`$;\ or control/newline characters.
_SAFE_NAME_RE = re.compile(r'^[\w .()\-]{1,80}$', re.UNICODE)
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def is_valid_ipv4(s):
    m = _IPV4_RE.match(s or '')
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def is_valid_hostname(s):
    return bool(_HOSTNAME_RE.match(s or ''))


def is_valid_host(s):
    """IPv4 or hostname -- what 'ip' actually means for ping/SNMP targets."""
    if not s:
        return False
    return is_valid_ipv4(s) or is_valid_hostname(s)


def is_valid_port(v):
    try:
        return 1 <= int(v) <= 65535
    except (TypeError, ValueError):
        return False


def is_safe_name(s):
    return bool(_SAFE_NAME_RE.match(s or ''))


def is_valid_email(s):
    return bool(_EMAIL_RE.match(s or ''))


def clamp_int(v, lo, hi, default=None):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def clamp_float(v, lo, hi, default=None):
    try:
        n = float(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))
