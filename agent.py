"""
InfraSight agent — run this on any other Windows/Linux/Mac PC you want to
monitor for real. It reports this machine's real CPU/memory/disk/network
metrics back to your InfraSight server every few seconds.

First run (either is fine):
    InfraSightAgent.exe --server http://<InfraSight PC IP>:5057 --token <token>
    (or just double-click it and type the server/token when asked)

The server + token are saved locally after the first run, so every run after
that needs no arguments at all — just double-click the exe.

Auto-start at Windows login (no admin rights needed):
    InfraSightAgent.exe --install-startup
Remove auto-start:
    InfraSightAgent.exe --uninstall-startup

Requirements when run as a .py script (not needed for the packaged .exe):
    pip install psutil
"""
import argparse
import json
import os
import sys
import time
import urllib.request

import psutil

IS_WINDOWS = os.name == 'nt'


def config_path():
    if IS_WINDOWS:
        base = os.environ.get('LOCALAPPDATA') or os.path.expanduser('~')
    else:
        base = os.path.expanduser('~/.config')
    d = os.path.join(base, 'InfraSightAgent')
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, 'config.json')


def load_config():
    try:
        with open(config_path(), 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg):
    try:
        with open(config_path(), 'w', encoding='utf-8') as f:
            json.dump(cfg, f)
        print(f"[agent] 설정 저장됨: {config_path()}")
    except Exception as e:
        print('[agent] 설정 저장 실패:', e)


def this_executable_command():
    """Command to relaunch this program, whether running as a script or a frozen exe."""
    if getattr(sys, 'frozen', False):
        return [sys.executable]
    return [sys.executable, os.path.abspath(__file__)]


def startup_folder():
    appdata = os.environ.get('APPDATA') or os.path.expanduser('~')
    return os.path.join(appdata, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')


def startup_bat_path():
    return os.path.join(startup_folder(), 'InfraSightAgent.bat')


def install_startup():
    # Uses the per-user Startup folder rather than Task Scheduler: it needs no
    # admin rights and works under locked-down / managed Windows accounts too.
    if not IS_WINDOWS:
        print('[agent] 자동 시작 등록은 현재 Windows에서만 지원됩니다.')
        return
    cmd = this_executable_command()
    cmd_str = ' '.join(f'"{c}"' for c in cmd)
    try:
        os.makedirs(startup_folder(), exist_ok=True)
        with open(startup_bat_path(), 'w', encoding='utf-8') as f:
            f.write('@echo off\r\nstart "" /min ' + cmd_str + '\r\n')
        print(f"[agent] Windows 로그인 시 자동 시작 등록 완료: {startup_bat_path()}")
    except Exception as e:
        print('[agent] 자동 시작 등록 실패:', e)


def uninstall_startup():
    if not IS_WINDOWS:
        return
    try:
        if os.path.exists(startup_bat_path()):
            os.remove(startup_bat_path())
            print('[agent] 자동 시작 등록 해제 완료')
        else:
            print('[agent] 등록된 자동 시작이 없습니다.')
    except Exception as e:
        print('[agent] 자동 시작 해제 실패:', e)


def prompt_for_config():
    print('=' * 60)
    print(' InfraSight 에이전트 최초 설정')
    print(' (InfraSight 대시보드의 "장비 등록" 화면에서 안내된 값을 입력하세요)')
    print('=' * 60)
    server = input('서버 주소 (예: http://192.168.0.10:5057): ').strip()
    token = input('토큰: ').strip()
    return {'server': server, 'token': token}


def sample(last_net, last_net_t):
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent
    try:
        disk = psutil.disk_usage('C:\\' if IS_WINDOWS else '/').percent
    except Exception:
        disk = 0.0
    now = time.time()
    net = psutil.net_io_counters()
    dt = max(now - last_net_t, 0.5)
    net_in = max((net.bytes_recv - last_net.bytes_recv) * 8 / dt / 1_000_000, 0)
    net_out = max((net.bytes_sent - last_net.bytes_sent) * 8 / dt / 1_000_000, 0)
    try:
        load = os.getloadavg()[0]
    except Exception:
        load = round(cpu / 25, 2)
    uptime_days = round((time.time() - psutil.boot_time()) / 86400, 1)
    ncpu = psutil.cpu_count() or 1
    procs = []
    for p in psutil.process_iter(['name', 'cpu_percent']):
        try:
            info = p.info
            procs.append({'name': info.get('name') or '-', 'pct': round((info.get('cpu_percent') or 0.0) / ncpu, 1)})
        except Exception:
            pass
    procs.sort(key=lambda x: x['pct'], reverse=True)
    payload = {
        'cpu': round(cpu, 1), 'mem': round(mem, 1), 'disk': round(disk, 1),
        'netIn': round(net_in, 2), 'netOut': round(net_out, 2),
        'load': round(load, 2), 'uptime': uptime_days, 'procs': procs[:6],
    }
    return payload, net, now


def run(server, token, interval):
    url = server.rstrip('/') + '/api/agent/report'
    print(f"InfraSight agent reporting to {url} every {interval}s. 이 창을 닫으면 보고가 멈춥니다. (Ctrl+C 종료)")

    psutil.cpu_percent(interval=None)
    for p in psutil.process_iter(['name']):
        try:
            p.cpu_percent(None)
        except Exception:
            pass
    last_net = psutil.net_io_counters()
    last_net_t = time.time()
    time.sleep(1)

    while True:
        try:
            payload, last_net, last_net_t = sample(last_net, last_net_t)
            payload['token'] = token
            req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'),
                                          headers={'Content-Type': 'application/json'}, method='POST')
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
        except Exception as e:
            print('[agent] report failed:', e)
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description='InfraSight monitoring agent')
    ap.add_argument('--server', help='InfraSight server base URL, e.g. http://192.168.0.10:5057')
    ap.add_argument('--token', help='device token shown when you registered this device')
    ap.add_argument('--interval', type=float, default=3.0, help='report interval in seconds (default 3)')
    ap.add_argument('--install-startup', action='store_true', help='Windows 로그온 시 자동 실행 등록')
    ap.add_argument('--uninstall-startup', action='store_true', help='자동 실행 등록 해제')
    ap.add_argument('--setup-only', action='store_true', help='설정 저장(+자동시작 등록)만 하고 즉시 종료 (모니터링 루프 실행 안 함)')
    args = ap.parse_args()

    if args.uninstall_startup:
        uninstall_startup()
        return

    existing_cfg = load_config()
    server = args.server or existing_cfg.get('server')
    token = args.token or existing_cfg.get('token')
    from_prompt = False

    if not server or not token:
        prompted = prompt_for_config()
        server, token = prompted['server'], prompted['token']
        from_prompt = True

    if not server or not token:
        print('[agent] 서버 주소와 토큰이 필요합니다.')
        sys.exit(1)

    if args.server or args.token or from_prompt:
        save_config({'server': server, 'token': token})

    if args.install_startup:
        install_startup()

    if args.setup_only:
        print('[agent] 설정 완료. 모니터링은 백그라운드에서 시작됩니다.')
        return

    run(server, token, args.interval)


if __name__ == '__main__':
    main()
