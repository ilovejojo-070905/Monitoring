"""Juniper(Junos) 로그인/로그아웃 syslog 메시지 파서. collector/
cisco_syslog_parser.py의 형제 모듈 -- 사용자 요청("cisco 장비 말고 다른
장비들도 접속 했을 때 접속 이력 보이게 해줘")으로 추가.

Junos의 sshd는 OpenSSH 기반이라(Cisco IOS의 %SEC_LOGIN류 독자 포맷과
다름) 그냥 표준 OpenSSH sshd 로그 문구("Accepted password for ...",
"Failed password for ...") 그대로 나온다 -- 이건 모든 OpenSSH 버전/배포판에
걸쳐 수십 년째 고정된, 아주 널리 문서화된 형식이라 Cisco의 %SEC_LOGIN보다
오히려 더 신뢰도가 높다.

주의: 그래도 이 프로젝트의 다른 벤더 프로필과 달리 실제 장비(192.168.30.253,
root 계정, SSH)의 live syslog로 검증하지 못했다 -- 로그인 시점에만
나오는 메시지라 이 세션에서 재현할 방법이 없었음. 형식이 다르면(예:
publickey 대신 다른 인증 방식, 또는 Junos 자체의 UI_LOGIN_EVENT 메시지를
쓰는 경우) 조정 필요.
"""
import re

_SSH_SUCCESS_RE = re.compile(
    r'sshd\[\d+\]:\s*Accepted (?P<method>password|publickey|keyboard-interactive) for '
    r'(?P<user>\S+) from (?P<src>\S+) port (?P<port>\d+)'
)
_SSH_FAILED_RE = re.compile(
    r'sshd\[\d+\]:\s*Failed (?P<method>password|publickey|none) for '
    r'(?P<user>\S+) from (?P<src>\S+) port (?P<port>\d+)'
)


def parse(data, exporter_ip, recv_ts_ms):
    """collector/cisco_syslog_parser.py의 parse()와 같은 반환 형식.
    로그인/로그아웃이 아닌 메시지는 빈 리스트."""
    try:
        text = data.decode('utf-8', errors='replace')
    except Exception:
        return []

    m = _SSH_SUCCESS_RE.search(text)
    if m:
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'LOGIN_SUCCESS',
            'username': m.group('user'),
            'details': f"{m.group('src')}에서 접속 (SSH {m.group('method')}, 포트 {m.group('port')})",
            'raw_message': text.strip(),
        }]

    m = _SSH_FAILED_RE.search(text)
    if m:
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'LOGIN_FAILED',
            'username': m.group('user'),
            'details': f"{m.group('src')}에서 접속 실패 (SSH {m.group('method')}, 포트 {m.group('port')})",
            'raw_message': text.strip(),
        }]

    return []
