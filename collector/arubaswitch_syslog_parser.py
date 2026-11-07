"""ArubaOS-Switch(클래식, ProCurve 계열 -- ArubaOS-CX와는 다른 OS) 접속
syslog 메시지 파서. 사용자 요청("cisco 장비 말고 다른 장비들도 접속
했을 때 접속 이력 보이게 해줘")으로 추가.

cisco_syslog_parser.py/junos_syslog_parser.py와 달리, 이건 포맷을
문서/추측으로 먼저 짜지 않고, 실제 등록된 장비(192.168.30.252, Arbua,
HP-2530-24G)가 보낸 live syslog 원문을 syslog_listener.py의 진단 로그로
직접 캡처해서 그 원문 그대로 맞춰 만들었다 -- 실측 기반.

실측으로 확인된 메시지:
  <14>Jan  2 14:36:04 192.168.30.252 00179 mgr:  SME TELNET from
      192.168.30.36 - MANAGER Mode

주의: 이 장비는 사용자 계정별 로그인이 아니라 공유 매니저 비밀번호 하나로
로그인하는 구성이라(이 세션에서 바꾸지 않음, device_control.py 주석의
실측 장비 설명과 동일) 메시지 자체에 사용자명이 없다 -- 추측이 아니라
실제로 받은 원문에 없다. 로그인 "실패"/로그아웃 메시지는 아직 캡처하지
못했다(이번 테스트가 전부 성공이었던 것으로 보임) -- 지원은 보류.
TELNET 외에 SSH/CONSOLE로 접속하면 "SME SSH ..."/"SME CONSOLE ..."
형태일 것으로 추정(같은 서브시스템의 같은 문구 틀을 그대로 쓸 것이라는
합리적 추정이지만 실측은 TELNET만 했다)해서 프로토콜 이름만 와일드카드로
둔다.
"""
import re

_LOGIN_SUCCESS_RE = re.compile(
    r'SME (?P<proto>TELNET|SSH|CONSOLE) from (?P<src>\S+) - (?P<mode>MANAGER|OPERATOR) Mode'
)


def parse(data, exporter_ip, recv_ts_ms):
    """collector/cisco_syslog_parser.py의 parse()와 같은 반환 형식."""
    try:
        text = data.decode('utf-8', errors='replace')
    except Exception:
        return []

    m = _LOGIN_SUCCESS_RE.search(text)
    if m:
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'LOGIN_SUCCESS',
            'username': None,
            'details': f"{m.group('src')}에서 접속 ({m.group('proto')}, {m.group('mode')} 모드)",
            'raw_message': text.strip(),
        }]

    return []
