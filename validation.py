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


MAX_TAGS_PER_DEVICE = 10
MAX_TAG_LEN = 30


def validate_tags(tags):
    """tags: whatever the client sent for fields.tags -- not guaranteed to
    even be a list (it's a JSON body field like any other). Returns a
    cleaned list of unique, trimmed strings, or raises ValueError with a
    Korean message. Reuses the same safe-name charset as a device name
    (tags render in the UI the same way)."""
    if not isinstance(tags, list):
        raise ValueError('tags는 문자열 목록이어야 합니다')
    cleaned = []
    seen = set()
    for t in tags:
        if not isinstance(t, str):
            raise ValueError('태그는 문자열이어야 합니다')
        t = t.strip()
        if not t:
            continue
        if len(t) > MAX_TAG_LEN:
            raise ValueError(f'태그는 {MAX_TAG_LEN}자 이하여야 합니다 ("{t[:MAX_TAG_LEN]}...")')
        if not is_safe_name(t):
            raise ValueError(f'태그에 사용할 수 없는 문자가 포함되어 있습니다: "{t}"')
        if t not in seen:
            seen.add(t)
            cleaned.append(t)
    if len(cleaned) > MAX_TAGS_PER_DEVICE:
        raise ValueError(f'태그는 장비당 최대 {MAX_TAGS_PER_DEVICE}개까지입니다')
    return cleaned


_SNMPV3_AUTH_PROTOCOLS = {'MD5', 'SHA'}
_SNMPV3_PRIV_PROTOCOLS = {'DES', 'AES'}


def validate_snmpv3_params(username, auth_protocol, auth_password, priv_protocol, priv_password,
                            require_username=True, partial=False):
    """Pure validation of an SNMPv3 USM credential set -- shared by the
    device-registration/update endpoints and the standalone connection-test
    endpoint so the same rules apply everywhere a user can submit these
    fields. Returns a Korean error message, or None if the combination is
    valid. require_username is False for device *updates*, where a blank
    username legitimately means "keep the existing one" (it's never sent
    back to the client to prefill) rather than "no username".

    partial=True relaxes the cross-field dependency checks (priv needs auth,
    a password needs its protocol): a device *update* can legitimately submit
    just one changed field (e.g. only a new priv password) while an already-
    stored auth protocol/password from registration time stays in place --
    this function has no DB access, so it cannot tell "missing" apart from
    "unchanged, already set". Registration and the connection-test endpoint
    always submit the full set in one shot, so they keep partial=False.
    """
    username = (username or '').strip()
    if require_username and not username:
        return 'SNMPv3 사용자명을 입력해주세요'
    if len(username) > 64:
        return 'SNMPv3 사용자명은 64자 이하여야 합니다'
    if auth_protocol and auth_protocol not in _SNMPV3_AUTH_PROTOCOLS:
        return f'인증 프로토콜은 {", ".join(sorted(_SNMPV3_AUTH_PROTOCOLS))} 중 하나여야 합니다'
    if priv_protocol and priv_protocol not in _SNMPV3_PRIV_PROTOCOLS:
        return f'개인정보 보호 프로토콜은 {", ".join(sorted(_SNMPV3_PRIV_PROTOCOLS))} 중 하나여야 합니다'
    # USM's own minimum (RFC 3414) -- pysnmp raises an opaque error below this
    # length, so this is just surfacing that same floor with a clear message.
    if auth_password and not (8 <= len(auth_password) <= 200):
        return '인증 비밀번호는 8~200자 사이여야 합니다 (SNMPv3 USM 규격)'
    if priv_password and not (8 <= len(priv_password) <= 200):
        return '개인정보 보호 비밀번호는 8~200자 사이여야 합니다 (SNMPv3 USM 규격)'
    if not partial:
        if priv_password and not auth_password:
            return '개인정보 보호(Priv) 비밀번호를 사용하려면 인증(Auth) 비밀번호도 함께 설정해야 합니다'
        if auth_password and not auth_protocol:
            return '인증 비밀번호를 사용하려면 인증 프로토콜을 선택해주세요'
        if priv_password and not priv_protocol:
            return '개인정보 보호 비밀번호를 사용하려면 개인정보 보호 프로토콜을 선택해주세요'
    return None


_THRESHOLD_METRICS = ('cpu', 'mem', 'disk')
MAX_SUSTAINED_SEC = 4 * 3600  # 4 hours -- past this it's not really an "alert", it's a report


def validate_thresholds(data):
    """data: whatever the client sent for a threshold override (global,
    group, or device-level) -- a dict that may contain any subset of
    cpu/mem/disk (each {warn, crit}, 0-100, warn < crit) and sustainedSec
    (0-MAX_SUSTAINED_SEC). Partial is fine at every scope: a device can
    override just `cpu` and still inherit mem/disk from its group or the
    global default -- see collector/thresholds.py's resolve_thresholds().
    Returns a cleaned dict with only the recognized keys, or raises
    ValueError with a Korean message. An empty/None input is valid (means
    "no override at all") and returns {}."""
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError('임계치 설정 형식이 올바르지 않습니다')
    out = {}
    for metric in _THRESHOLD_METRICS:
        if metric not in data or data[metric] is None:
            continue
        m = data[metric]
        if not isinstance(m, dict) or 'warn' not in m or 'crit' not in m:
            raise ValueError(f'{metric} 임계치는 경고(warn)/심각(crit) 값이 모두 필요합니다')
        try:
            warn_v = float(m['warn'])
            crit_v = float(m['crit'])
        except (TypeError, ValueError):
            raise ValueError(f'{metric} 임계치는 숫자여야 합니다')
        if not (0 <= warn_v <= 100 and 0 <= crit_v <= 100):
            raise ValueError(f'{metric} 임계치는 0~100 사이여야 합니다')
        if warn_v >= crit_v:
            raise ValueError(f'{metric}의 경고 임계치는 심각 임계치보다 작아야 합니다')
        out[metric] = {'warn': warn_v, 'crit': crit_v}
    if 'sustainedSec' in data and data['sustainedSec'] is not None:
        try:
            sustained = int(data['sustainedSec'])
        except (TypeError, ValueError):
            raise ValueError('지속 시간은 숫자(초)여야 합니다')
        if not (0 <= sustained <= MAX_SUSTAINED_SEC):
            raise ValueError(f'지속 시간은 0~{MAX_SUSTAINED_SEC}초 사이여야 합니다')
        out['sustainedSec'] = sustained
    return out


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
