"""
InfraSight one-click installer / supervisor.

This single frozen exe (built via build_installer.ps1 into InfraSight.exe)
replaces the whole "install Python, pip install, install Caddy, install
mkcert, generate a cert, create an admin account, register autostart, open
the firewall" manual sequence (see the install guide) with one double-click.
It bundles the backend itself (server.py and everything it imports) plus
caddy.exe, mkcert.exe, index.html, agent.py and the prebuilt agent installer
as data files -- see build_installer.ps1 for the exact --add-data list.

Modes (chosen automatically on first run; the scheduled task set up by the
wizard always launches with --supervise):
  (no flag, not yet installed) -> elevate via UAC if needed, then first-run
                                    setup wizard, then --supervise
  (no flag, already installed) -> straight to --supervise (manual re-run,
                                    runs as whatever user double-clicked it --
                                    no elevation, matching the scheduled task)
  --serve                       -> runs the Flask/waitress backend in this
                                    process (what used to be `python server.py`)
  --supervise                   -> keeps --serve and caddy.exe alive,
                                    restarting whichever dies; mirrors
                                    ops/supervisor.ps1's crash-loop backoff,
                                    just with nothing to resolve on PATH --
                                    everything it launches lives next to it
  --stop                        -> asks a running --supervise instance to
                                    shut down cleanly (mirrors ops/stop.ps1)
  --status                      -> prints whether backend/Caddy are alive
"""
import argparse
import ctypes
import getpass
import json
import os
import shutil
import subprocess
import sys
import time
import webbrowser

IS_WINDOWS = os.name == 'nt'
INSTALLED_MARKER = 'installed.marker'
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

POLL_SECONDS = 5
CRASH_WINDOW_SECONDS = 120
CRASH_LIMIT = 5
BACKOFF_SECONDS = 300


def install_dir():
    base = os.environ.get('LOCALAPPDATA') or os.path.expanduser('~')
    d = os.path.join(base, 'InfraSight')
    os.makedirs(d, exist_ok=True)
    return d


def bundle_root():
    """Where PyInstaller's --add-data payloads land at runtime: an ephemeral
    per-run temp folder when frozen, this script's own folder otherwise (lets
    installer.py also be run unfrozen, straight from the project folder, for
    testing)."""
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def this_executable_command():
    if getattr(sys, 'frozen', False):
        return [sys.executable]
    return [sys.executable, os.path.abspath(__file__)]


def is_elevated():
    if not IS_WINDOWS:
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_elevated():
    """Re-invokes this same exe, with the same arguments, through a UAC
    prompt (ShellExecuteW 'runas'). Without this, a non-admin double-click
    (the common case) would silently fail to register the firewall rules
    in setup_firewall() later, defeating the whole point of a "one-click"
    installer -- the user would still have to find and run a PowerShell
    command by hand. A child process normally inherits its parent's
    elevation, so doing this once here, before relocate_and_relaunch_if_needed()
    spawns the copy at the stable path, covers the entire setup wizard with
    a single approval. Returns True if the elevated relaunch was *started*
    (not whether the user actually clicked Yes -- Windows gives no way to
    tell the difference from here)."""
    try:
        params = ' '.join(f'"{a}"' for a in sys.argv[1:])
        ret = ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, params, None, 1)
        return ret > 32
    except Exception:
        return False


def _stop_other_running_instances():
    """Mirrors agent.py's _stop_other_running_instances: a stale InfraSight.exe
    left running from a previous install holds files locked (or two
    supervisors would both try to bind :5057/:8443), so a fresh relocation
    kills any sibling first. Best-effort -- psutil is already a transitive
    dependency via collector.local_collector."""
    import psutil
    my_pid = os.getpid()
    for p in psutil.process_iter(['pid', 'name']):
        try:
            if p.info['pid'] == my_pid or (p.info['name'] or '').lower() != 'infrasight.exe':
                continue
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            pass


def relocate_and_relaunch_if_needed():
    """A freshly downloaded installer often sits in Downloads -- fine to run
    once, but the scheduled task registered in the setup wizard points at a
    *stable* path, so this copies itself there first (same pattern as
    agent.py's relocate_and_relaunch_if_needed)."""
    if not IS_WINDOWS or not getattr(sys, 'frozen', False):
        return False
    d = install_dir()
    target = os.path.join(d, 'InfraSight.exe')
    current = os.path.abspath(sys.executable)
    if os.path.normcase(current) == os.path.normcase(target):
        return False
    _stop_other_running_instances()
    try:
        shutil.copy2(current, target)
        # Only --supervise/--serve/--stop/--status are non-interactive -- the
        # no-flag first run continues into run_setup_wizard(), which prompts
        # on the console for the admin username/password. Relaunching THAT
        # hidden (CREATE_NO_WINDOW) would leave the user staring at a window
        # that silently did nothing forever, waiting on a console input() no
        # one can see or type into. Only hide the window for the modes that
        # never read stdin.
        hide = bool(set(sys.argv[1:]) & {'--supervise', '--serve', '--stop', '--status'})
        subprocess.Popen([target] + sys.argv[1:], cwd=d,
                          creationflags=CREATE_NO_WINDOW if hide else subprocess.CREATE_NEW_CONSOLE)
        return True
    except Exception as e:
        print(f"[installer] 표준 위치({target})로 복사하지 못해 현재 위치에서 계속합니다: {e}")
        return False


def extract_bundled_files(dest_dir):
    src_root = bundle_root()
    for name in ('index.html', 'agent.py', 'Caddyfile', 'caddy.exe', 'mkcert.exe'):
        s = os.path.join(src_root, name)
        if os.path.exists(s):
            shutil.copy2(s, os.path.join(dest_dir, name))
        else:
            print(f"  (경고) 번들 파일을 찾을 수 없습니다: {name}")
    dist_src = os.path.join(src_root, 'dist', 'InfraSightAgent.exe')
    if os.path.exists(dist_src):
        os.makedirs(os.path.join(dest_dir, 'dist'), exist_ok=True)
        shutil.copy2(dist_src, os.path.join(dest_dir, 'dist', 'InfraSightAgent.exe'))


def setup_certs(d):
    import storage
    mkcert_exe = os.path.join(d, 'mkcert.exe')
    try:
        subprocess.run([mkcert_exe, '-install'], cwd=d)
    except Exception as e:
        print(f"  mkcert -install 실행 중 문제: {e}")
    lan_ip = storage.get_lan_ip()
    cert_path = os.path.join(d, 'certs', 'infrasight.crt')
    key_path = os.path.join(d, 'certs', 'infrasight.key')
    try:
        subprocess.run(
            [mkcert_exe, '-cert-file', cert_path, '-key-file', key_path, lan_ip, 'localhost', 'infrasight.local'],
            check=True, cwd=d)
        print(f"  인증서 발급 완료 (이 PC의 LAN IP: {lan_ip})")
    except Exception as e:
        print(f"  인증서 발급 실패: {e}")
        print("  나중에 설치 폴더에서 아래 명령을 직접 실행해주세요:")
        print(f'    mkcert.exe -cert-file certs\\infrasight.crt -key-file certs\\infrasight.key {lan_ip} localhost infrasight.local')


def create_admin_account():
    import storage
    print("  로그인에 사용할 관리자 계정을 만듭니다.")
    while True:
        username = input("  아이디: ").strip()
        if username:
            break
        print("  아이디를 입력해주세요.")
    while True:
        pw = getpass.getpass("  비밀번호 (8자 이상, 화면에 보이지 않습니다): ")
        if len(pw) < 8:
            print("  8자 이상 입력해주세요.")
            continue
        pw2 = getpass.getpass("  비밀번호 확인: ")
        if pw != pw2:
            print("  비밀번호가 일치하지 않습니다. 다시 입력하세요.")
            continue
        break
    storage.create_admin_if_missing(username, pw)
    print(f"  관리자 계정 '{username}' 생성 완료")


def register_autostart(d):
    exe_path = os.path.join(d, 'InfraSight.exe')
    ps_script = (
        f'$action = New-ScheduledTaskAction -Execute "{exe_path}" -Argument "--supervise" -WorkingDirectory "{d}"; '
        f'$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME; '
        f'$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries '
        f'-StartWhenAvailable -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 '
        f'-RestartInterval (New-TimeSpan -Minutes 1); '
        f'Register-ScheduledTask -TaskName "InfraSight Supervisor" -Action $action -Trigger $trigger '
        f'-Settings $settings -RunLevel Limited -Force | Out-Null'
    )
    try:
        subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                        check=True, capture_output=True, text=True)
        print("  로그온 시 자동 시작 등록 완료")
    except Exception as e:
        print(f"  자동 시작 등록 실패: {e}")
        print("  나중에 PowerShell에서 직접 실행해 등록할 수 있습니다 (설치 폴더에서 InfraSight.exe --supervise 를 가리키도록).")


def setup_firewall():
    rules = [('InfraSight HTTPS (Caddy)', 8443), ('InfraSight HTTP (legacy direct, agents)', 5057)]
    for name, port in rules:
        ps = (f'New-NetFirewallRule -DisplayName "{name}" -Direction Inbound -Protocol TCP '
              f'-LocalPort {port} -Action Allow -ErrorAction Stop | Out-Null')
        try:
            subprocess.run(['powershell', '-NoProfile', '-Command', ps], check=True, capture_output=True, text=True)
            print(f"  방화벽 규칙 추가됨: {name}")
        except Exception:
            print(f"  방화벽 규칙을 자동으로 추가하지 못했습니다 ({name}).")
            print(f"  다른 PC/장비에서 접속이 안 되면, 관리자 권한 PowerShell에서 아래 명령을 실행해주세요:")
            print(f'    New-NetFirewallRule -DisplayName "{name}" -Direction Inbound -Protocol TCP -LocalPort {port} -Action Allow')


def run_setup_wizard(d):
    print('=' * 60)
    print(' InfraSight 설치를 시작합니다')
    print(f' 설치 위치: {d}')
    print('=' * 60)
    for sub in ('certs', 'logs', 'run', 'backups'):
        os.makedirs(os.path.join(d, sub), exist_ok=True)

    print('\n[1/6] 필요한 파일을 설치 위치로 복사합니다...')
    extract_bundled_files(d)

    print('\n[2/6] HTTPS 인증서를 준비합니다 (Windows가 동의 창을 띄울 수 있습니다)...')
    setup_certs(d)

    print('\n[3/6] 데이터베이스를 초기화합니다...')
    import storage
    storage.init_db()

    print('\n[4/6] 관리자 계정을 만듭니다.')
    create_admin_account()

    print('\n[5/6] 로그온 시 자동 시작을 등록합니다...')
    register_autostart(d)

    print('\n[6/6] 방화벽 인바운드 규칙을 추가합니다 (관리자 권한이 필요할 수 있습니다)...')
    setup_firewall()

    with open(os.path.join(d, INSTALLED_MARKER), 'w', encoding='utf-8') as f:
        f.write(str(int(time.time())))

    lan_ip = storage.get_lan_ip()
    print('\n' + '=' * 60)
    print(' 설치가 완료되었습니다!')
    print(f'   이 PC:        https://localhost:8443')
    print(f'   다른 기기에서: https://{lan_ip}:8443')
    print('=' * 60)
    print('\n잠시 후 브라우저가 열립니다. 이 창은 자동으로 백그라운드로 전환됩니다.')
    run_supervise(open_browser=True)


def _hide_console():
    if not IS_WINDOWS:
        return
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass


def run_serve():
    import server
    server.main()


def run_supervise(open_browser=False):
    d = install_dir()
    run_dir = os.path.join(d, 'run')
    log_dir = os.path.join(d, 'logs')
    os.makedirs(run_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    lock_file = os.path.join(run_dir, 'supervisor.lock')
    stop_marker = os.path.join(run_dir, 'stop.marker')
    log_file = os.path.join(log_dir, 'supervisor.log')
    status_file = os.path.join(run_dir, 'status.json')

    def log(level, msg):
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {msg}\n")

    # See ops/supervisor.ps1's matching comment: this lock file can belong to
    # either implementation (this one, or the git-clone deployment's ps1
    # supervisor) if both ever point at the same install folder. Liveness
    # alone is what matters for not double-binding 5057/8443 -- the second
    # line is only for clearer logging.
    if os.path.exists(lock_file):
        try:
            import psutil
            lines = open(lock_file, encoding='utf-8').read().splitlines()
            old_pid = int(lines[0].strip())
            old_kind = lines[1].strip() if len(lines) > 1 else 'unknown'
            if psutil.pid_exists(old_pid):
                log('INFO', f"이미 실행 중인 supervisor(PID {old_pid}, {old_kind})를 발견해 이번 실행은 종료합니다.")
                return
        except Exception:
            pass
        log('WARN', "이전 lock 파일이 남아있었지만 더 이상 실행 중이 아닙니다. 새로 시작합니다.")

    try:
        os.remove(stop_marker)
    except FileNotFoundError:
        pass
    with open(lock_file, 'w', encoding='utf-8') as f:
        f.write(f"{os.getpid()}\npy")

    log('INFO', f"===== supervisor 시작 (PID {os.getpid()}) =====")

    crash_times = {'backend': [], 'caddy': []}
    backoff_until = {'backend': None, 'caddy': None}

    def start_backend():
        # A launch failure (missing/quarantined file, bad permissions) used to
        # raise straight out of this function -- uncaught, it tore down the
        # whole try block below including an already-started Caddy, crashing
        # the entire supervisor instead of just this one piece. Returning
        # None instead lets the existing alive()/register_crash() retry loop
        # handle "never started" exactly like "started then died".
        try:
            p = subprocess.Popen(this_executable_command() + ['--serve'], cwd=d, creationflags=CREATE_NO_WINDOW)
            log('INFO', f"Backend 시작됨 (PID {p.pid})")
            return p
        except Exception as e:
            log('ERROR', f"Backend 시작 실패: {e}")
            return None

    def start_caddy():
        try:
            p = subprocess.Popen([os.path.join(d, 'caddy.exe'), 'run', '--config', 'Caddyfile'],
                                  cwd=d, creationflags=CREATE_NO_WINDOW)
            log('INFO', f"Caddy 시작됨 (PID {p.pid})")
            return p
        except Exception as e:
            log('ERROR', f"Caddy 시작 실패: {e}")
            return None

    def alive(p):
        return p is not None and p.poll() is None

    def should_restart(name):
        now = time.time()
        if backoff_until[name]:
            if now < backoff_until[name]:
                return False
            backoff_until[name] = None
            crash_times[name] = []
        return True

    def register_crash(name):
        now = time.time()
        crash_times[name] = [t for t in crash_times[name] if now - t <= CRASH_WINDOW_SECONDS] + [now]
        if len(crash_times[name]) >= CRASH_LIMIT and not backoff_until[name]:
            backoff_until[name] = now + BACKOFF_SECONDS
            log('ERROR', f"{name} 이(가) 최근 {CRASH_WINDOW_SECONDS}초 동안 {CRASH_LIMIT}회 이상 종료되었습니다. "
                          f"{BACKOFF_SECONDS}초 동안 재시작을 멈춥니다.")

    def write_status(backend, caddy):
        status = {
            'supervisorPid': os.getpid(),
            'updatedAt': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'backend': {'pid': backend.pid if backend else None, 'alive': alive(backend)},
            'caddy': {'pid': caddy.pid if caddy else None, 'alive': alive(caddy)},
        }
        with open(status_file, 'w', encoding='utf-8') as f:
            json.dump(status, f)

    try:
        backend = start_backend()
        caddy = start_caddy()
        write_status(backend, caddy)

        if open_browser:
            time.sleep(3)
            try:
                webbrowser.open('https://localhost:8443')
            except Exception:
                pass
            _hide_console()

        while True:
            time.sleep(POLL_SECONDS)

            if os.path.exists(stop_marker):
                log('INFO', "정상 종료 요청 감지 (stop.marker). Backend/Caddy를 종료합니다.")
                for p in (backend, caddy):
                    if alive(p):
                        p.terminate()
                try:
                    os.remove(stop_marker)
                except FileNotFoundError:
                    pass
                log('INFO', "정상 종료 완료. ===== supervisor 종료 =====")
                break

            if not alive(backend):
                log('WARN', f"Backend가 비정상 종료된 것을 감지했습니다 (이전 PID {backend.pid}).")
                register_crash('backend')
                if should_restart('backend'):
                    backend = start_backend()

            if not alive(caddy):
                log('WARN', f"Caddy가 비정상 종료된 것을 감지했습니다 (이전 PID {caddy.pid}).")
                register_crash('caddy')
                if should_restart('caddy'):
                    caddy = start_caddy()

            write_status(backend, caddy)
    finally:
        try:
            os.remove(lock_file)
        except FileNotFoundError:
            pass
        try:
            os.remove(status_file)
        except FileNotFoundError:
            pass


def request_stop():
    d = install_dir()
    run_dir = os.path.join(d, 'run')
    os.makedirs(run_dir, exist_ok=True)
    lock_file = os.path.join(run_dir, 'supervisor.lock')
    if not os.path.exists(lock_file):
        print('실행 중이 아닙니다.')
        return
    with open(os.path.join(run_dir, 'stop.marker'), 'w', encoding='utf-8') as f:
        f.write(str(int(time.time())))
    print('종료 요청을 보냈습니다. 정리될 때까지 기다립니다...')
    deadline = time.time() + 30
    while os.path.exists(lock_file) and time.time() < deadline:
        time.sleep(1)
    print('InfraSight를 종료했습니다.' if not os.path.exists(lock_file) else '30초 안에 종료되지 않았습니다.')


def show_status():
    d = install_dir()
    status_file = os.path.join(d, 'run', 'status.json')
    if not os.path.exists(status_file):
        print('실행 중이 아닙니다.')
        return
    with open(status_file, encoding='utf-8') as f:
        s = json.load(f)
    print(f"Backend: {'실행 중' if s['backend']['alive'] else '중지됨'} (PID {s['backend']['pid']})")
    print(f"Caddy:   {'실행 중' if s['caddy']['alive'] else '중지됨'} (PID {s['caddy']['pid']})")
    print(f"업데이트: {s['updatedAt']}")


def main():
    ap = argparse.ArgumentParser(description='InfraSight installer/supervisor')
    ap.add_argument('--serve', action='store_true')
    ap.add_argument('--supervise', action='store_true')
    ap.add_argument('--stop', action='store_true')
    ap.add_argument('--status', action='store_true')
    args = ap.parse_args()

    if args.serve:
        run_serve()
        return
    if args.stop:
        request_stop()
        return
    if args.status:
        show_status()
        return
    if args.supervise:
        if relocate_and_relaunch_if_needed():
            return
        run_supervise()
        return

    d = install_dir()
    if os.path.exists(os.path.join(d, INSTALLED_MARKER)):
        if relocate_and_relaunch_if_needed():
            return
        run_supervise(open_browser=True)
        return

    # Fresh install: elevate once, up front -- mkcert -install doesn't need
    # it (CurrentUser cert store), but the firewall rules later in the
    # wizard do, and relocate_and_relaunch_if_needed()'s spawned copy below
    # inherits whatever elevation this process already has. One UAC prompt
    # here, instead of a silent "방화벽 규칙을 자동으로 추가하지 못했습니다"
    # at the very end that would have sent the user to find and run a
    # PowerShell command themselves.
    if IS_WINDOWS and not is_elevated():
        print('관리자 권한이 필요합니다 (인증서 등록 · 방화벽 설정).')
        print('잠시 후 "사용자 계정 컨트롤" 승인 창이 뜨면 "예"를 눌러주세요.')
        ok = relaunch_elevated()
        if not ok:
            print('관리자 권한 요청에 실패했습니다. 이 파일을 마우스 오른쪽 버튼으로 누른 뒤 "관리자 권한으로 실행"을 선택해 다시 시도해주세요.')
        # This window is about to close either way (the real work continues
        # in the elevated relaunch, or the user needs to read the error
        # above) -- without this pause it would vanish mid-UAC-prompt,
        # which looks like a crash rather than the expected hand-off.
        time.sleep(4)
        return

    if relocate_and_relaunch_if_needed():
        return
    run_setup_wizard(d)


if __name__ == '__main__':
    main()
