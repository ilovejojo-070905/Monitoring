"""장비 syslog UDP 수신기(사용자 요청: "PuTTY로 직접 접속했는데 접속이력이
보이질 않아", 이어서 "cisco 장비 말고 다른 장비들도 접속했을 때 접속
이력 보이게 해줘"). collector/flow_listener.py와 같은 구조(상시
recvfrom() 소켓을 daemon thread에서 돌림)를 그대로 따르되, 로그인/
로그아웃은 트래픽 바이트 수처럼 집계할 값이 아니라 발생한 사건 하나하나가
그대로 의미있는 기록이라, flow_listener.flush()처럼 메모리에 모았다가
1분마다 플러시하지 않고 파싱되는 즉시 바로 DB에 쓴다(이벤트 발생 빈도
자체가 NetFlow/sFlow 패킷보다 훨씬 낮아 매번 바로 써도 부담이 되지 않음).

벤더마다 메시지 포맷이 완전히 다른데(Cisco는 %SEC_LOGIN류 독자 포맷,
Junos는 OpenSSH 표준 문구) NetFlow/sFlow처럼 포트로 구분할 수 없다 --
syslog는 모든 벤더가 같은 UDP/514 하나로 들어온다. 그래서 한 패킷을
_PARSERS에 등록된 벤더별 파서 모듈에 순서대로 넘겨 첫 번째로 매치되는
파서를 쓴다(각 벤더 포맷이 서로 겹칠 여지가 거의 없어 순서 민감도가
낮음). 아직 파서가 없는 벤더(HP Comware/ArubaOS-Switch 등)는 전부
매치에 실패해 _listen_loop의 "no known pattern matched" 진단 로그로
원문이 그대로 남으므로, 그 로그를 보고 다음 벤더 파서를 추가하면 된다."""
import socket
import threading
import time

import storage
from applog import app_logger, safe_log_value
from collector import cisco_syslog_parser, junos_syslog_parser

_PARSERS = (cisco_syslog_parser, junos_syslog_parser)

_device_ip_cache = {}
_sock = None
_started = False


def _refresh_device_cache():
    try:
        _device_ip_cache.clear()
        for d in storage.load_devices():
            if d.get('ip'):
                _device_ip_cache[d['ip']] = d['id']
    except Exception:
        app_logger.exception('syslog_listener: device cache refresh failed')


def refresh_device_cache():
    """scheduler에서 주기적으로 호출(collector/scheduler.py) -- 새로 등록된
    장비나 IP 변경을 반영한다. flow_listener.flush()가 매 플러시 주기마다
    _refresh_device_cache()를 다시 부르는 것과 같은 이유."""
    _refresh_device_cache()


def _listen_loop(sock):
    while True:
        try:
            data, (addr, _port) = sock.recvfrom(65535)
        except OSError:
            return  # socket closed (shutdown) -- exit the thread cleanly
        recv_ts = int(time.time() * 1000)
        # 진단용(2026-11-08, "허용규칙 하고 cisco에서 설정도 넣었는데
        # 보이질 않아"): 매치가 안 되는 패킷은 cisco_syslog_parser.parse()가
        # 조용히 빈 리스트를 돌려주는 게 정상 동작(위 docstring)이라, 지금까지
        # 는 "패킷이 아예 안 왔다"와 "왔는데 형식이 안 맞았다"를 구분할
        # 방법이 로그에 전혀 없었다. 받은 원문을 매치 여부와 무관하게 항상
        # 한 줄 남겨서(안전하게 safe_log_value로 개행 무력화, 길이도 잘라
        # 로그 비대화 방지) 이 둘을 구분할 수 있게 한다 -- NetFlow/sFlow
        # 쪽이 파싱 실패만 기록하는 것과 달리, syslog는 "매치 안 됨"이
        # 대부분이라 실패 로그만으로는 수신 자체를 확인할 수 없어서 의도적으로
        # 더 상세히 남김.
        try:
            raw_text = data.decode('utf-8', errors='replace')
        except Exception:
            raw_text = repr(data)
        app_logger.info('syslog_listener: received from %s: %s', addr, safe_log_value(raw_text[:400]))
        events = []
        for parser_module in _PARSERS:
            try:
                events = parser_module.parse(data, addr, recv_ts)
            except Exception:
                app_logger.exception('syslog_listener: unexpected error in %s parsing packet from %s',
                                      parser_module.__name__, addr)
                continue
            if events:
                break
        if not events:
            app_logger.info('syslog_listener: no known pattern matched (not a login/logout message, or format differs)')
        for ev in events:
            device_id = _device_ip_cache.get(ev['exporter_ip'])
            try:
                storage.record_device_access(
                    device_id=device_id, device_ip=ev['exporter_ip'], ts=ev['ts'],
                    event_type=ev['event_type'], username=ev.get('username'),
                    details=ev.get('details'), raw_message=ev['raw_message'])
            except Exception:
                app_logger.exception('syslog_listener: failed to record event from %s', addr)


def start():
    """Safe to call once at process startup (see server.py main(), right
    after flow_listener.start()); binding failure (e.g. the port's already
    in use) is logged, not fatal -- the same reasoning as flow_listener."""
    global _sock, _started
    if _started:
        return
    _started = True
    _refresh_device_cache()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', storage.SYSLOG_PORT))
    except OSError as e:
        app_logger.error('syslog_listener: could not bind UDP port %d: %s', storage.SYSLOG_PORT, e)
        return
    _sock = sock
    t = threading.Thread(target=_listen_loop, args=(sock,), daemon=True, name='syslog-listener')
    t.start()
    app_logger.info('syslog_listener: listening (udp/%d)', storage.SYSLOG_PORT)
