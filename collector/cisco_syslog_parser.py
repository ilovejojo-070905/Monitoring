"""Cisco IOS 로그인/로그아웃/설정변경 syslog 메시지 파서(사용자 요청:
"PuTTY로 Cisco 장비에 직접 접속했는데 접속이력이 보이질 않아" -- InfraSight
를 거치지 않고 SSH/Telnet으로 직접 접속하면 audit_log에는 애초에 기록될
방법이 없어서, 장비가 스스로 내보내는 syslog를 받아서 보여주는 쪽으로 해결).

LOGIN_SUCCESS/LOGIN_FAILED/LOGOUT: 처음엔 Cisco IOS의 표준 문서화된
%SEC_LOGIN 메시지 형식을 그대로 구현(실제 장비 검증 전)했는데, 2026-11-07
실제 등록된 장비(192.168.30.250)로 실측 검증 완료 -- login local 전환
후 실제 PuTTY(Telnet) 접속에서 "%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success
[user: admin] [Source: 192.168.30.36] [localport: 23] at ..." 그대로
수신/파싱됨을 확인.

CONFIG_CHANGED: 사용자 요청("cisco 장비 말고 다른 장비들도...")에 이어
실제 로그에서 "%SYS-5-CONFIG_I: Configured from console by admin on vty0
(192.168.30.36)" 형태가 그대로 캡처된 것을 보고 추가 -- 이것도 실측
기반. "by X"만 있고 "on 라인" 부분이 없는 변형(아직 username 계정이 없던
시절의 세션, 실제로 캡처됨: "Configured from console by vty0
(192.168.30.36)")도 같이 처리한다.

위 CONFIG_I는 "누가/어디서 설정을 바꿨다"는 사실만 담고, 바꾼 명령어
내용 자체는 담지 않는다(IOS 메시지 자체의 한계). 사용자가 "설정한
내용이 이력에서 보이질 않아"라고 보고해서, Cisco의 "archive log
config" 기능(사용자가 장비에 추가로 켬: archive / log config /
logging enable / notify syslog contenttype plaintext / hidekeys)을
켜면 입력한 명령어 한 줄마다 별도 syslog가 온다는 걸 안내하고, 실제로
2026-11-08 켠 뒤 캡처된 원문 그대로 추가:
  %PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:interface
      GigabitEthernet1/0/1
CONFIG_I(세션당 한 번, 명령어 없음)와 CFGLOG_LOGGEDCMD(명령어당 한 번,
실제 명령어 포함)는 서로 다른 메시지라 둘 다 올 수 있고 중복이 아니다
-- CFGLOG_LOGGEDCMD가 더 상세한 하위 기록을 추가로 남기는 것뿐이다.

RFC3164 syslog 헤더(<PRI>타임스탬프 호스트명 ...)는 장비 설정(service
timestamps, logging origin-id 등)에 따라 형태가 들쭉날쭉해서 헤더를
엄격하게 파싱하지 않고, 받은 바이트 전체에서 %SEC_LOGIN-*/%SYS-5-CONFIG_I
패턴을 검색(search, 앵커 없음)하는 방식으로 그 들쭉날쭉함을 피한다.
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
_CONFIG_CHANGED_RE = re.compile(
    r'%SYS-5-CONFIG_I:\s*Configured from \S+ by\s*(?P<who>\S+)(?:\s+on\s+(?P<line>\S+))?\s*'
    r'\(\s*(?P<src>[^)]*?)\s*\)'
)
_CFGLOG_CMD_RE = re.compile(
    r'%PARSER-5-CFGLOG_LOGGEDCMD:\s*User:(?P<user>\S+)\s+logged command:(?P<cmd>.+)'
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
            'username': m.group('user'), 'source_ip': m.group('src'),
            'details': f"{m.group('src')}에서 접속 (포트 {m.group('port')})",
            'raw_message': text.strip(),
        }]

    m = _LOGIN_FAILED_RE.search(text)
    if m:
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'LOGIN_FAILED',
            'username': m.group('user'), 'source_ip': m.group('src'),
            'details': f"{m.group('src')}에서 접속 실패 - {m.group('reason').strip()} (포트 {m.group('port')})",
            'raw_message': text.strip(),
        }]

    m = _LOGOUT_RE.search(text)
    if m:
        src = m.group('src').strip() or '-'
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'LOGOUT',
            'username': m.group('user'), 'source_ip': src if src != '-' else None,
            'details': f"{src}에서 접속 종료 - {m.group('reason').strip()} ({m.group('line')})",
            'raw_message': text.strip(),
        }]

    m = _CONFIG_CHANGED_RE.search(text)
    if m:
        src = (m.group('src') or '').strip() or '-'
        # "on 라인" 부분이 없으면 "by X"의 X 자체가 사용자명이 아니라
        # 라인/세션 식별자다(실측으로 확인한 두 변형 -- 모듈 docstring
        # 참고). username은 전자에서만 신뢰할 수 있는 값이라 그때만 채운다.
        if m.group('line'):
            username, line = m.group('who'), m.group('line')
        else:
            username, line = None, m.group('who')
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'CONFIG_CHANGED',
            'username': username, 'source_ip': src if src != '-' else None,
            'details': f"{src}에서 설정 변경 ({line})",
            'raw_message': text.strip(),
        }]

    m = _CFGLOG_CMD_RE.search(text)
    if m:
        return [{
            'exporter_ip': exporter_ip, 'ts': recv_ts_ms, 'event_type': 'CONFIG_CHANGED',
            'username': m.group('user').strip(),
            'details': m.group('cmd').strip(),
            'raw_message': text.strip(),
        }]

    return []
