"""Cisco IOS 로그인/로그아웃 syslog 메시지 파서(사용자 요청: "PuTTY로
Cisco 장비에 직접 접속했는데 접속이력이 보이질 않아" -- InfraSight를 거치지
않고 SSH/Telnet으로 직접 접속하면 audit_log에는 애초에 기록될 방법이
없어서, 장비가 스스로 내보내는 syslog를 받아서 보여주는 쪽으로 해결).

주의(이 프로젝트의 다른 벤더 프로필과의 차이점): snmp_profiles.py의 OID나
device_control.py의 CLI 명령은 전부 실제 장비로 직접 검증했지만, 아래
정규식은 그렇게 하지 못했다 -- 장비가 로그인 "시점"에만 내보내는
메시지라 이 세션 안에서 재현해 테스트할 방법이 없었음(실제 장비에 로그인
이벤트를 강제로 발생시켜야 하는데, SNMP 조회처럼 아무 때나 값을 읽어올
수 있는 게 아님). 아래 메시지 형식은 Cisco IOS의 표준 문서화된 %SEC_LOGIN
메시지 그대로(여러 IOS 버전에 걸쳐 안정적으로 알려진 형식)이지만, 실제
운영 장비에서 로그인해보고 형식이 다르면(IOS 버전/옵션에 따라 미묘하게
다를 수 있음) 이 파일의 정규식을 조정해야 한다.

RFC3164 syslog 헤더(<PRI>타임스탬프 호스트명 ...)는 장비 설정(service
timestamps, logging origin-id 등)에 따라 형태가 들쭉날쭉해서 헤더를
엄격하게 파싱하지 않고, 받은 바이트 전체에서 %SEC_LOGIN-* 패턴을
검색(search, 앵커 없음)하는 방식으로 그 들쭉날쭉함을 피한다.
"""
import re

_LOGIN_SUCCESS_RE = re.compile(
    r'%SEC_LOGIN-5-LOGIN_SUCCESS:\s*Login Success\s*\[user:\s*(?P<user>\S+?)\]\s*'
    r'\[Source:\s*(?P<src>\S+?)\]\s*\[localport:\s*(?P<port>\d+)\]'
)
_LOGIN_FAILED_RE = re.compile(
    r'%SEC_LOGIN-4-LOGIN_FAILED:\s*Login failed\s*\[user:\s*(?P<user>\S+?)\]\s*'
    r'\[Source:\s*(?P<src>\S+?)\]\s*\[localport:\s*(?P<port>\d+)\]\s*'
    r'\[Reason:\s*(?P<reason>[^\]]+)\]'
)
_LOGOUT_RE = re.compile(
    r'%SEC_LOGIN-5-LOGOUT:\s*Exec session is terminated for user\s*(?P<user>\S+?)\s*,'
    r'\s*reason is\s*(?P<reason>[^,]+?)\s*,\s*on line\s*(?P<line>\S+)\s*'
    r'\(\s*(?P<src>[^)]*?)\s*\)'
)


def parse(data, exporter_ip, recv_ts_ms):
    """Returns a list of normalized access-event dicts:
    {exporter_ip, ts, event_type, username, details, raw_message}
    -- collector/syslog_listener.py가 그대로 storage.record_device_access()
    에 넘긴다. 로그인/로그아웃이 아닌 메시지(인터페이스 up/down, NTP,
    설정 변경 등)는 매치되는 게 없으면 그냥 빈 리스트를 돌려준다 -- 이건
    netflow_parser.parse()처럼 "잘못된 패킷"이 아니라 "이 파서가 관심
    없는 정상적인 메시지"라서 ValueError를 던지지 않는다(syslog 트래픽의
    대부분이 여기 해당하는 게 정상)."""
    try:
        text = data.decode('utf-8', errors='replace')
    except Exception:
        return []

    m = _LOGIN_SUCCESS_RE.search(text)
    if m:
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'LOGIN_SUCCESS',
            'username': m.group('user'),
            'details': f"{m.group('src')}에서 접속 (포트 {m.group('port')})",
            'raw_message': text.strip(),
        }]

    m = _LOGIN_FAILED_RE.search(text)
    if m:
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'LOGIN_FAILED',
            'username': m.group('user'),
            'details': f"{m.group('src')}에서 접속 실패 - {m.group('reason').strip()} (포트 {m.group('port')})",
            'raw_message': text.strip(),
        }]

    m = _LOGOUT_RE.search(text)
    if m:
        src = m.group('src').strip() or '-'
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'LOGOUT',
            'username': m.group('user'),
            'details': f"{src}에서 접속 종료 - {m.group('reason').strip()} ({m.group('line')})",
            'raw_message': text.strip(),
        }]

    return []
