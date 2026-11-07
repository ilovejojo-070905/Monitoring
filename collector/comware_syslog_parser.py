"""HP Comware(H3C OEM) 접속/설정 syslog 메시지 파서. 사용자 요청("cisco
장비 말고 다른 장비들도 접속 했을 때 접속 이력 보이게 해줘")으로 추가.

cisco_syslog_parser.py/junos_syslog_parser.py와 달리, 이건 Comware
포맷을 문서/추측으로 먼저 짜지 않고, 실제 등록된 장비(192.168.30.251,
HPE 5500)가 보낸 live syslog 원문을 syslog_listener.py의 진단 로그로
직접 캡처해서 그 원문 그대로 맞춰 만들었다 -- 실측 기반.

실측으로 확인된 세 가지 메시지:
  %%10SHELL/4/LOGINAUTHFAIL(t):   Trap 1.3.6.1.4.1.25506.2.2.1.1.3.0.3:
      failed to login from VTY, reason is 3
  %%10SHELL/4/LOGOUT(t):   Trap 1.3.6.1.4.1.25506.2.2.1.1.3.0.2:
      logout from VTY
  %%10SHELL/6/SHELL_CMD(l):  -Task=vt0-IPAddr=192.168.30.36-User=admin;
      Command is info-center loghost 192.168.30.36

주의 두 가지:
  1) LOGINAUTHFAIL/LOGOUT 메시지 자체는 접속자의 IP나 사용자명을 전혀
     담지 않는다(이 장비의 이 트랩 종류 자체의 한계로 보임 -- 추측이
     아니라 실제로 받은 원문에 없음). "VTY에서"라는 라인 정보만 있다.
  2) 로그인 "성공" 메시지는 아직 캡처하지 못했다 -- 이 세션 중 처음
     로그인(syslog 전송을 켜려고 콘솔/VTY로 들어간 순간)은 전송 설정이
     켜지기 전에 일어나서 애초에 전송될 수 없었던 것으로 보이고, 그 뒤
     재접속은 전부 실패(LOGINAUTHFAIL)만 캡처됐다. 성공 이벤트 지원은
     실제 성공 사례를 한 번 더 캡처하기 전까지 보류.
"""
import re

_LOGIN_FAILED_RE = re.compile(
    r'%%10SHELL/4/LOGINAUTHFAIL\(\w*\):\s*Trap \S+:\s*failed to login from\s*'
    r'(?P<line>[^,\s]+),\s*reason is\s*(?P<reason>\d+)'
)
_LOGOUT_RE = re.compile(
    r'%%10SHELL/4/LOGOUT\(\w*\):\s*Trap \S+:\s*logout from\s*(?P<line>[^,\s]+)'
)
_CONFIG_CHANGED_RE = re.compile(
    r'%%10SHELL/6/SHELL_CMD\(\w*\):\s*-Task=(?P<task>[^-]+)-IPAddr=(?P<src>[^-]+)-User=(?P<user>[^;]+);'
    r'\s*Command is\s*(?P<cmd>.+)'
)


def parse(data, exporter_ip, recv_ts_ms):
    """collector/cisco_syslog_parser.py의 parse()와 같은 반환 형식."""
    try:
        text = data.decode('utf-8', errors='replace')
    except Exception:
        return []

    m = _LOGIN_FAILED_RE.search(text)
    if m:
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'LOGIN_FAILED',
            'username': None,
            'details': f"{m.group('line')}에서 로그인 실패 (reason {m.group('reason')})",
            'raw_message': text.strip(),
        }]

    m = _LOGOUT_RE.search(text)
    if m:
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'LOGOUT',
            'username': None,
            'details': f"{m.group('line')}에서 로그아웃",
            'raw_message': text.strip(),
        }]

    m = _CONFIG_CHANGED_RE.search(text)
    if m:
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'CONFIG_CHANGED',
            'username': m.group('user').strip(),
            'details': f"{m.group('src').strip()}에서 설정 변경 ({m.group('cmd').strip()})",
            'raw_message': text.strip(),
        }]

    return []
