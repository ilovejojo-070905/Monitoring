"""
InfraSight agent — run this on any other Windows/Linux/Mac PC you want to
monitor for real. It reports this machine's real CPU/memory/disk/network
metrics back to your InfraSight server every few seconds.

First run (any of these):
    InfraSightAgent.exe --server http://<InfraSight PC IP>:5057 --token <token>
    (or just double-click it and type the server/token when asked)
    (or drop a small InfraSightAgent.cfg -- {"server":...,"token":...} --
     downloaded from the dashboard into the same folder as the exe, then
     just double-click it: no typing, and the exe itself never needs
     re-downloading for the next device, only that small file does)

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
import platform
import shutil
import subprocess
import sys
import time
import urllib.request

import psutil

IS_WINDOWS = os.name == 'nt'

# Agent management pass: bump this on every change to agent.py, then rebuild
# dist/InfraSightAgent.exe -- keep server.py's AGENT_VERSION (near the top of
# api_agent_info) in sync so the dashboard can tell a device "this agent is
# older than what the server has available". This version is the whole
# foundation an eventual auto-update feature would compare against; nothing
# here downloads or applies updates yet, by design (see the directive this
# was built from).
AGENT_VERSION = '1.2.0'

_START_TIME = time.time()
_LAST_ERROR = None  # most recent local exception message, if any (sample() or the report request itself)

# Marker + JSON payload the server appends after the compiled exe's own bytes
# when it hands out a per-device "InfraSight-Install.exe" from the dashboard's
# device-registration screen (see server.py's /download/installer route).
# Appending data past a PE file's real image doesn't corrupt it -- the OS
# loader only reads up to where the executable's own sections end -- so the
# exe still runs completely normally; this file just also knows how to look
# for its own trailing config when frozen.
EMBEDDED_CONFIG_MARKER = b'\n===INFRASIGHT_CONFIG===\n'


def read_embedded_config():
    if not getattr(sys, 'frozen', False):
        return None
    try:
        with open(sys.executable, 'rb') as f:
            data = f.read()
        idx = data.rfind(EMBEDDED_CONFIG_MARKER)
        if idx == -1:
            return None
        return json.loads(data[idx + len(EMBEDDED_CONFIG_MARKER):].decode('utf-8'))
    except Exception:
        return None


# A tiny per-device {server, token} file placed next to this exe (not baked
# into its own bytes, unlike EMBEDDED_CONFIG_MARKER above) -- lets the SAME
# already-downloaded, reusable InfraSightAgent.exe configure itself for a
# NEW device with zero typing and zero command line: download just this
# small file (server.py's /download/config/<token>) into the same folder as
# the exe and double-click the exe, nothing else. Without this, a user who
# grabbed the plain reusable exe (rather than the per-device one-click
# installer) hits the interactive "서버 주소 / 토큰" prompt every single time,
# exactly the friction reusability was supposed to remove.
SIDECAR_CONFIG_FILENAME = 'InfraSightAgent.cfg'


def read_sidecar_config():
    try:
        base_dir = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))
        path = os.path.join(base_dir, SIDECAR_CONFIG_FILENAME)
        if not os.path.exists(path):
            return None
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def _stop_other_running_instances():
    """A stale copy already running from a previous install (old token)
    holds the target exe file locked on Windows, which silently breaks the
    copy below -- this process then falls back to running from wherever it
    was downloaded instead of the stable path, and the *old* process just
    keeps running on its *old* (by now revoked) token forever. This used to
    require manually ending InfraSightAgent.exe in Task Manager before
    reinstalling; now a fresh install (a genuinely different embedded
    token -- see is_fresh_embedded in main()) does it automatically.
    Best-effort: any failure here just means the copy below may fail too,
    same as before this existed."""
    my_pid = os.getpid()
    for p in psutil.process_iter(['pid', 'name']):
        try:
            if p.info['pid'] == my_pid or (p.info['name'] or '').lower() != 'infrasightagent.exe':
                continue
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            pass


def relocate_and_relaunch_if_needed(server, token):
    """A one-click installer exe downloaded straight from the dashboard often
    sits in Downloads/Desktop -- fine to run once, but install_startup()
    below points the Windows auto-start entry at *this exact file path*, so
    if the user later deletes or moves it, monitoring silently stops. Copy
    ourselves into the same stable per-user folder the old install script
    used, and hand off to that copy, so auto-start keeps working regardless
    of what happens to the originally-downloaded file. Best-effort: any
    failure here just falls back to running in place.

    server/token are passed explicitly as --server/--token to the relaunched
    copy rather than relying on it to rediscover them on its own: that
    rediscovery works for embedded config (the bytes travel with the file
    copy below) but NOT for a sidecar InfraSightAgent.cfg sitting next to the
    *original* exe -- that file never gets copied alongside, so the
    relaunched copy at the new location would otherwise find no config at
    all and fall back to the interactive prompt, silently defeating the
    whole point of the sidecar file."""
    if not IS_WINDOWS or not getattr(sys, 'frozen', False):
        return False
    target_dir = os.path.join(os.environ.get('LOCALAPPDATA') or os.path.expanduser('~'), 'InfraSightAgent')
    target = os.path.join(target_dir, 'InfraSightAgent.exe')
    current = os.path.abspath(sys.executable)
    if os.path.normcase(current) == os.path.normcase(target):
        return False
    _stop_other_running_instances()
    try:
        os.makedirs(target_dir, exist_ok=True)
        shutil.copy2(current, target)
        extra_args = ['--server', server, '--token', token] if (server and token) else []
        subprocess.Popen([target] + extra_args, creationflags=subprocess.CREATE_NO_WINDOW)
        return True
    except Exception as e:
        print('[agent] 파일을 표준 위치로 복사하지 못해 현재 위치에서 계속 실행합니다:', e)
        return False


def hide_console_window():
    """Hides this process's own console window immediately -- a direct,
    unconditional fallback for any non-interactive run (one-click installer
    with embedded config, or a plain re-run off an already-saved config)
    regardless of whether relocate_and_relaunch_if_needed() above already
    handed off to a separately-hidden copy or fell back to running in place
    (e.g. antivirus blocking the copy, a read-only Desktop/Downloads
    folder, ...). Without this, that fallback path is exactly the visible
    "InfraSight agent reporting to..." window a user hit after double-
    clicking a freshly-downloaded InfraSight-Install.exe -- relocation
    failing silently left the *original* process (the one Explorer already
    gave a console to just by launching it) running the reporting loop
    in full view instead of handing off to a hidden copy.
    GetConsoleWindow() returns NULL if this process has no console at all
    (already detached/hidden, or non-Windows) -- ShowWindow on a NULL
    handle is a documented no-op, not an error."""
    if not IS_WINDOWS:
        return
    try:
        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
    except Exception:
        pass


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
    # Superseded by startup_vbs_path() below -- kept only so uninstall_startup()
    # can still find and remove a .bat left behind by an older agent version.
    return os.path.join(startup_folder(), 'InfraSightAgent.bat')


def startup_vbs_path():
    return os.path.join(startup_folder(), 'InfraSightAgent.vbs')


def install_startup():
    # Uses the per-user Startup folder rather than Task Scheduler: it needs no
    # admin rights and works under locked-down / managed Windows accounts too.
    #
    # A .vbs launcher via WScript.Shell.Run(..., 0, False), not a .bat with
    # `start /min` (the old approach): `/min` only ever asks the shell to
    # *minimize* the newly-created window after the fact -- the console
    # window still gets allocated and can flash or stay visible depending on
    # the exe's build (console- vs GUI-subsystem) and Windows version/timing,
    # exactly the black "InfraSight agent reporting to..." window a user hit
    # after a reboot. WScript.Shell.Run's windowStyle=0 tells Windows never
    # to create the window visible in the first place, which is reliable
    # regardless of how the target exe was built.
    if not IS_WINDOWS:
        print('[agent] 자동 시작 등록은 현재 Windows에서만 지원됩니다.')
        return
    cmd = this_executable_command()
    cmd_str = ' '.join(f'"{c}"' for c in cmd)
    vbs_cmd = cmd_str.replace('"', '""')  # escape for embedding inside a VBScript string literal
    try:
        os.makedirs(startup_folder(), exist_ok=True)
        with open(startup_vbs_path(), 'w', encoding='utf-8') as f:
            f.write(f'CreateObject("WScript.Shell").Run "{vbs_cmd}", 0, False\r\n')
        # Migration cleanup: remove a leftover .bat from an older agent
        # version registered on this same machine, so there's only ever one
        # active Startup entry (and the old visible-window one stops firing).
        if os.path.exists(startup_bat_path()):
            try:
                os.remove(startup_bat_path())
            except Exception:
                pass
        print(f"[agent] Windows 로그인 시 자동 시작 등록 완료 (창 없이 백그라운드 실행): {startup_vbs_path()}")
    except Exception as e:
        print('[agent] 자동 시작 등록 실패:', e)


def uninstall_startup():
    if not IS_WINDOWS:
        return
    try:
        removed = False
        for p in (startup_vbs_path(), startup_bat_path()):
            if os.path.exists(p):
                os.remove(p)
                removed = True
        if removed:
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


def sample_disks():
    """Per-partition usage (more detail pass): disk_usage() can raise for
    unready removable drives (empty CD slot, disconnected network share), so
    each partition is sampled independently -- one bad drive shouldn't blank
    out the rest."""
    out = []
    try:
        parts = psutil.disk_partitions(all=False)
    except Exception:
        parts = []
    for p in parts:
        try:
            u = psutil.disk_usage(p.mountpoint)
        except Exception:
            continue
        out.append({
            'mount': p.mountpoint, 'total': round(u.total / 1_073_741_824, 1),
            'used': round(u.used / 1_073_741_824, 1), 'pct': round(u.percent, 1),
        })
    return out[:12]


def sample_nics(last_nics, dt):
    """Per-interface in/out (more detail pass): mirrors the existing
    aggregate net_in/net_out math, just keyed by interface name instead of
    summed across all of them. Interfaces that only just appeared (no prior
    sample) report 0 for this cycle rather than a misleading spike."""
    out = []
    try:
        current = psutil.net_io_counters(pernic=True)
    except Exception:
        current = {}
    for name, c in current.items():
        prev = last_nics.get(name)
        if prev is None:
            in_mbps = out_mbps = 0.0
        else:
            in_mbps = max((c.bytes_recv - prev.bytes_recv) * 8 / dt / 1_000_000, 0)
            out_mbps = max((c.bytes_sent - prev.bytes_sent) * 8 / dt / 1_000_000, 0)
        if c.bytes_recv or c.bytes_sent:
            out.append({'name': name, 'inMbps': round(in_mbps, 2), 'outMbps': round(out_mbps, 2)})
    out.sort(key=lambda x: x['inMbps'] + x['outMbps'], reverse=True)
    return out[:10], current


def sample_services():
    """Windows auto-start services that aren't running (service/daemon-status
    pass): reporting all ~200 services every cycle would be noise -- a
    service set to start automatically but not currently running is the
    actionable anomaly worth surfacing, so only that subset (plus a running/
    total count for context) goes in the payload. Windows-only: psutil has
    no win_service_iter() equivalent on Linux/Mac."""
    if not IS_WINDOWS:
        return {'running': 0, 'total': 0, 'stoppedAutoStart': []}
    running = 0
    total = 0
    anomalies = []
    try:
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
            except Exception:
                continue
            total += 1
            if info.get('status') == 'running':
                running += 1
            elif info.get('start_type') == 'automatic':
                anomalies.append({'name': info.get('display_name') or info.get('name'), 'status': info.get('status')})
    except Exception:
        pass
    return {'running': running, 'total': total, 'stoppedAutoStart': anomalies[:30]}


def sample(last_net, last_net_t, last_nics):
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
    nics, current_nics = sample_nics(last_nics, dt)
    try:
        load = os.getloadavg()[0]
    except Exception:
        load = round(cpu / 25, 2)
    uptime_days = round((time.time() - psutil.boot_time()) / 86400, 1)
    ncpu = psutil.cpu_count() or 1
    procs = []
    for p in psutil.process_iter(['name', 'cpu_percent', 'memory_percent']):
        try:
            info = p.info
            procs.append({
                'name': info.get('name') or '-',
                'pct': round((info.get('cpu_percent') or 0.0) / ncpu, 1),
                'memPct': round(info.get('memory_percent') or 0.0, 1),
            })
        except Exception:
            pass
    procs.sort(key=lambda x: x['pct'], reverse=True)
    payload = {
        'cpu': round(cpu, 1), 'mem': round(mem, 1), 'disk': round(disk, 1),
        'netIn': round(net_in, 2), 'netOut': round(net_out, 2),
        'load': round(load, 2), 'uptime': uptime_days, 'procs': procs[:12],
        'disks': sample_disks(), 'nics': nics, 'services': sample_services(),
        # Agent management pass: version/OS/start time are static per-process
        # (constant every report -- the server only needs the latest one),
        # lastError carries forward whatever the most recent local exception
        # was until a newer one replaces it, so it's visible even on a report
        # cycle that itself succeeded.
        'version': AGENT_VERSION, 'os': platform.platform(), 'startedAt': int(_START_TIME * 1000),
        'lastError': _LAST_ERROR,
    }
    return payload, net, now, current_nics


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
    try:
        last_nics = psutil.net_io_counters(pernic=True)
    except Exception:
        last_nics = {}
    time.sleep(1)

    global _LAST_ERROR
    while True:
        try:
            payload, last_net, last_net_t, last_nics = sample(last_net, last_net_t, last_nics)
            payload['token'] = token
            req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'),
                                          headers={'Content-Type': 'application/json'}, method='POST')
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
        except Exception as e:
            print('[agent] report failed:', e)
            _LAST_ERROR = str(e)[:300]
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
    # Either config source counts equally: bytes appended to the exe itself
    # (the per-device one-click installer) or a small InfraSightAgent.cfg
    # sitting next to a reused, already-downloaded exe (see
    # read_sidecar_config's docstring). Embedded wins if somehow both are
    # present -- that only happens with the one-click installer, which is
    # already fully self-contained.
    embedded_cfg = read_embedded_config() or read_sidecar_config()
    # A *different* embedded token than whatever's already saved means this
    # exe was just downloaded for a fresh (re)registration -- re-installing
    # on a machine that already has an old config.json from a previous
    # install (delete + re-register the same PC, for example) is exactly
    # this case, and it used to lose silently: the old check only looked at
    # embedded_cfg when there was *no* existing config at all, so a stale
    # saved token always won and the new one was never even read.
    is_fresh_embedded = bool(embedded_cfg) and embedded_cfg.get('token') and embedded_cfg.get('token') != existing_cfg.get('token')

    # Computed before the relocate call (not after, as before) so the
    # resolved server/token can be handed to the relaunched copy explicitly
    # -- see relocate_and_relaunch_if_needed's docstring for why that matters
    # for a sidecar-file config specifically.
    server = args.server or (embedded_cfg.get('server') if is_fresh_embedded else None) or existing_cfg.get('server')
    token = args.token or (embedded_cfg.get('token') if is_fresh_embedded else None) or existing_cfg.get('token')

    if is_fresh_embedded and relocate_and_relaunch_if_needed(server, token):
        return  # the relocated copy takes over from here; this process is done

    from_prompt = False

    if not server or not token:
        prompted = prompt_for_config()
        server, token = prompted['server'], prompted['token']
        from_prompt = True

    if not server or not token:
        print('[agent] 서버 주소와 토큰이 필요합니다.')
        sys.exit(1)

    if args.server or args.token or from_prompt or is_fresh_embedded:
        save_config({'server': server, 'token': token})

    if args.install_startup or is_fresh_embedded:
        install_startup()

    if args.setup_only:
        print('[agent] 설정 완료. 모니터링은 백그라운드에서 시작됩니다.')
        return

    # Only an interactive prompt() exchange earns a visible window -- the
    # user just typed into it, so leave it up so they can see it actually
    # started. Every other path (embedded-config installer, saved config,
    # explicit --server/--token) has nothing left for a human to read here;
    # hide before the loop runs forever, as the guaranteed-to-work fallback
    # for whatever relocate_and_relaunch_if_needed() above could not do.
    if not from_prompt:
        hide_console_window()
    run(server, token, args.interval)


if __name__ == '__main__':
    main()
