"""Cisco syslog UDP 수신기(사용자 요청: "PuTTY로 직접 접속했는데 접속이력이
보이질 않아"). collector/flow_listener.py와 같은 구조(상시 recvfrom()
소켓을 daemon thread에서 돌림)를 그대로 따르되, 로그인/로그아웃은
트래픽 바이트 수처럼 집계할 값이 아니라 발생한 사건 하나하나가 그대로
의미있는 기록이라, flow_listener.flush()처럼 메모리에 모았다가 1분마다
플러시하지 않고 파싱되는 즉시 바로 DB에 쓴다(이벤트 발생 빈도 자체가
NetFlow/sFlow 패킷보다 훨씬 낮아 매번 바로 써도 부담이 되지 않음).
"""
import socket
import threading
import time

import storage
from applog import app_logger
from collector import cisco_syslog_parser

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
        try:
            events = cisco_syslog_parser.parse(data, addr, recv_ts)
        except Exception:
            app_logger.exception('syslog_listener: unexpected error parsing packet from %s', addr)
            continue
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
