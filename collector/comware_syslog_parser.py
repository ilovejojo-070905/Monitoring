"""HP Comware(H3C OEM) 접속/설정 syslog 메시지 파서. 사용자 요청("cisco
장비 말고 다른 장비들도 접속 했을 때 접속 이력 보이게 해줘")으로 추가.

cisco_syslog_parser.py/junos_syslog_parser.py와 달리, 이건 Comware
포맷을 문서/추측으로 먼저 짜지 않고, 실제 등록된 장비(192.168.30.251,
HPE 5500)가 보낸 live syslog 원문을 syslog_listener.py의 진단 로그로
직접 캡처해서 그 원문 그대로 맞춰 만들었다 -- 실측 기반.

실측으로 확인된 메시지들:
  %%10SHELL/4/LOGINAUTHFAIL(t):   Trap 1.3.6.1.4.1.25506.2.2.1.1.3.0.3:
      failed to login from VTY, reason is 3
  %%10SHELL/4/LOGOUT(t):   Trap 1.3.6.1.4.1.25506.2.2.1.1.3.0.2:
      logout from VTY
  %%10SHELL/6/SHELL_CMD(l):  -Task=vt0-IPAddr=192.168.30.36-User=admin;
      Command is info-center loghost 192.168.30.36
  %%10SHELL/5/SHELL_LOGIN(l): admin logged in from 192.168.30.36.
  %%10SHELL/5/SHELL_LOGOUT(l): admin logged out from 192.168.30.36.

주의 두 가지:
  1) LOGINAUTHFAIL/LOGOUT 메시지 자체는 접속자의 IP나 사용자명을 전혀
     담지 않는다(이 장비의 이 트랩 종류 자체의 한계로 보임 -- 추측이
     아니라 실제로 받은 원문에 없음). "VTY에서"라는 라인 정보만 있다.
  2) 로그인 "성공" 메시지는 처음엔(2026-11-07) 캡처하지 못했었는데(최초
     로그인이 syslog 전송 켜기 전에 일어나 전송 자체가 안 됨), 2026-11-08
     에 실제 성공 로그인을 다시 캡처해서 확인함:
       %%10SHELL/4/LOGIN(t):   Trap ...:admin login from VTY
       %%10SHELL/5/SHELL_LOGIN(l): admin logged in from 192.168.30.36.
     같은 성공 이벤트 하나에 대해 두 트랩이 같이 온다 -- /4/LOGIN은
     사용자명은 있지만 접속 IP가 없고, /5/SHELL_LOGIN은 사용자명과 IP가
     둘 다 있어 정보가 더 많다. 로그아웃도 같은 구조(/4/LOGOUT에 사용자명
     붙은 변형 + /5/SHELL_LOGOUT)로 둘 다 온다. 두 줄이 같은 이벤트를
     중복으로 알리는 것이므로, 정보가 더 많은 /5/ 쪽만 매치해서 기록하고
     /4/ 쪽의 "사용자명 있는" 변형은 의도적으로 매치하지 않는다(그래야
     이벤트가 두 번 쌓이지 않음) -- 실패 로그인 뒤 자동 끊김으로 오는,
     사용자명 없는 기존 /4/LOGOUT 변형(아래 _LOGOUT_RE)만 그대로 유지.
"""
import re

_LOGIN_FAILED_RE = re.compile(
    r'%%10SHELL/4/LOGINAUTHFAIL\(\w*\):\s*Trap \S+:\s*failed to login from\s*'
    r'(?P<line>[^,\s]+),\s*reason is\s*(?P<reason>\d+)'
)
_LOGIN_SUCCESS_RE = re.compile(
    r'%%10SHELL/5/SHELL_LOGIN\(\w*\):\s*(?P<user>\S+)\s*logged in from\s*(?P<ip>\d+\.\d+\.\d+\.\d+)'
)
_LOGOUT_RE = re.compile(
    r'%%10SHELL/4/LOGOUT\(\w*\):\s*Trap \S+:\s*logout from\s*(?P<line>[^,\s]+)'
)
_LOGOUT_RICH_RE = re.compile(
    r'%%10SHELL/5/SHELL_LOGOUT\(\w*\):\s*(?P<user>\S+)\s*logged out from\s*(?P<ip>\d+\.\d+\.\d+\.\d+)'
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

    m = _LOGIN_SUCCESS_RE.search(text)
    if m:
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'LOGIN_SUCCESS',
            'username': m.group('user').strip(), 'source_ip': m.group('ip'),
            'details': f"{m.group('ip')}에서 접속",
            'raw_message': text.strip(),
        }]

    m = _LOGOUT_RICH_RE.search(text)
    if m:
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'LOGOUT',
            'username': m.group('user').strip(), 'source_ip': m.group('ip'),
            'details': f"{m.group('ip')}에서 로그아웃",
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
            'username': m.group('user').strip(), 'source_ip': m.group('src').strip(),
            'details': f"{m.group('src').strip()}에서 설정 변경 ({m.group('cmd').strip()})",
            'raw_message': text.strip(),
        }]

    return []
