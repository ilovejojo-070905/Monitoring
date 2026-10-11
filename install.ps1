<#
InfraSight installer (PowerShell)
=================================
One script to set up InfraSight on a fresh Windows PC: installs Git/Python/
Caddy/mkcert if missing, clones the project from GitHub, installs the Python
dependencies, issues an HTTPS certificate for THIS machine's LAN IP, creates
the admin login, registers autostart at logon, opens the firewall, and starts
it immediately.

Usage (run as the user who will normally be logged in when this PC is used --
the scheduled task it registers starts at THIS user's logon):
    powershell -ExecutionPolicy Bypass -File install.ps1
    powershell -ExecutionPolicy Bypass -File install.ps1 -InstallDir "D:\InfraSight"

Safe to re-run: existing files are left alone where it matters (an existing
database/admin account is never touched or recreated), everything else is
just redone.
#>

param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'InfraSight'),
    [string]$RepoUrl = 'https://github.com/ilovejojo-070905/Monitoring.git'
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg" -ForegroundColor Yellow }

# git/winget/mkcert/pip all routinely write normal progress or status text
# to STDERR (e.g. git fetch's own "From https://..." line) -- with
# $ErrorActionPreference='Stop' in effect, PowerShell can treat that stderr
# output as a terminating error and abort the whole script even though the
# command actually succeeded (exit code 0). Confirmed live: a Patch.exe run
# died right after printing git fetch's completely normal "From
# https://github.com/..." status line, with no real failure at all -- this
# turned out to be the real cause behind several "installed/patched but
# nothing happened" reports this session, not just coincidence. Every native
# exe call below goes through this so stderr chatter can't be mistaken for
# a real failure; callers still check $LASTEXITCODE themselves afterward to
# catch an ACTUAL failure. SilentlyContinue (not just Continue) also hides
# the resulting "ERROR: From https://..." lines from the console entirely --
# confirmed live that even non-terminating, these still print in red and
# look exactly like a real failure to someone just trying to double-click
# their way through an install.
function Invoke-Native([scriptblock]$Command) {
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try { & $Command } finally { $ErrorActionPreference = $prevEAP }
}

# ---------------------------------------------------------------- elevation --
# Needed for New-NetFirewallRule later; everything else here works fine
# without it. One prompt up front beats a silent firewall-rule failure at
# the very end that would send the user hunting for a PowerShell command.
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-Admin)) {
    Write-Host "관리자 권한이 필요합니다 (인증서 신뢰 등록 · 방화벽 설정). UAC 승인 창을 확인해주세요..." -ForegroundColor Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath,
                 '-InstallDir', $InstallDir, '-RepoUrl', $RepoUrl)
    try {
        Start-Process powershell -Verb RunAs -ArgumentList $argList -Wait
    } catch {
        # UAC 승인을 취소하면 Start-Process 자체가 예외를 던진다 -- 이걸 못
        # 잡으면 이 창(관리자 권한 없는 원래 창)이 아무 메시지 없이 그냥
        # 닫혀버려서, 더블클릭한 사람 입장에서는 "실행했는데 아무 일도 안
        # 일어남"으로만 보인다 (실제로 겪은 문제: 설치/패치가 조용히 실패
        # 해도 창이 바로 닫혀 원인을 알 길이 없었음).
        Write-Host "`n관리자 권한 승인이 취소되었거나 실패했습니다." -ForegroundColor Red
        Write-Host "이 파일을 다시 실행한 뒤, UAC 창에서 '예'를 눌러주세요." -ForegroundColor Yellow
        Write-Host "`n아무 키나 누르면 창이 닫힙니다..." -ForegroundColor DarkGray
        try { [void][System.Console]::ReadKey($true) } catch { Start-Sleep -Seconds 3 }
    }
    exit
}

# 아래 설치 단계 전체를 try/finally로 감싸는 이유: 어디서든 오류(throw)가
# 나면 $ErrorActionPreference='Stop' 때문에 스크립트가 그 즉시 종료되는데,
# 끝에 있는 "아무 키나 누르면 창이 닫힙니다" 일시정지는 성공 경로에만
# 있었어서 실패 시엔 거치지도 못하고 창이 바로 닫혔다 -- 실제로 다른 PC에
# 설치하다 이 증상(오류 메시지를 읽을 틈도 없이 창이 사라짐)을 겪었다.
# finally에 일시정지를 두면 성공/실패 어느 쪽이든 창이 안 닫히고 남는다.
try {

Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' InfraSight 설치' -ForegroundColor Cyan
Write-Host " 설치 위치: $InstallDir"
Write-Host '============================================================' -ForegroundColor Cyan

# --------------------------------------------------------- [1] 필수 도구 --
Write-Step '[1/9] 필수 도구 확인 (Git / Python / Caddy / mkcert)'

function Install-IfMissing([string]$cmd, [string]$wingetId, [string]$label) {
    # Same WindowsApps-stub trap Resolve-ExeAndAddToPath guards against below
    # (see its own comment for the full story) -- without this check here
    # too, this function sees the fake python.exe alias on PATH, concludes
    # Python is "already installed", and skips the winget install entirely.
    # Resolve-ExeAndAddToPath then correctly rejects that same stub and finds
    # nothing real to fall back on, throwing "python 를 설치 후에도 찾을 수
    # 없습니다" -- confirmed live on a fresh PC with the Store alias enabled
    # (Windows 11's default) and no real Python ever installed.
    $existing = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($existing -and $existing.Source -notmatch '\\WindowsApps\\') {
        Write-Ok "$label 이미 설치됨"
        return
    }
    Write-Host "    $label 설치 중 (winget install $wingetId)..."
    Invoke-Native { winget install --id $wingetId -e --source winget --accept-package-agreements --accept-source-agreements | Out-Null }
}

Install-IfMissing 'git' 'Git.Git' 'Git'
Install-IfMissing 'python' 'Python.Python.3.12' 'Python'
Install-IfMissing 'caddy' 'CaddyServer.Caddy' 'Caddy'
Install-IfMissing 'mkcert' 'FiloSottile.mkcert' 'mkcert'
# 네트워크 장비 목록의 SSH/Telnet 버튼(ops\setup-remote-access.ps1이 뒤에서
# 설정하는 Native Messaging Host)이 실제로 띄우는 프로그램 -- 이 PC에선
# 미리 수동 설치돼 있었지만, 새 PC는 이 installer가 직접 깔아줘야 "버튼
# 눌렀는데 PuTTY를 찾을 수 없다"는 일이 안 생긴다.
Install-IfMissing 'putty' 'PuTTY.PuTTY' 'PuTTY'

# Freshly-installed tools update the registry PATH, but THIS already-running
# process doesn't pick that up automatically -- resolve each exe's actual
# location once here (no hardcoded machine-specific paths: searched, not
# assumed) and prepend to this process's own PATH so the rest of this script
# can just call git/python/caddy/mkcert directly. A normal new shell (e.g.
# the scheduled task at next logon) sees the registry PATH update on its own
# and needs none of this.
function Resolve-ExeAndAddToPath([string]$cmd, [string[]]$searchGlobs) {
    # Get-Command alone is NOT trustworthy for 'python': Windows ships a
    # WindowsApps\python.exe "app execution alias" stub on PATH by default on
    # most PCs (to upsell the Store listing) that LOOKS like a valid command
    # but does nothing real -- Get-Command happily returns it, and every
    # python call after that silently no-ops or errors. Confirmed by actually
    # running this function end-to-end: it picked the stub over the real,
    # just-installed interpreter and broke every step after it. Rejecting any
    # match under WindowsApps forces the search-glob fallback (the actual
    # known winget install location) instead.
    $existing = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($existing -and $existing.Source -notmatch '\\WindowsApps\\') { return $existing.Source }
    foreach ($glob in $searchGlobs) {
        # No -Recurse: it doesn't combine with a wildcard in the middle of
        # the path on PowerShell 5.1 (silently matches nothing) -- the glob
        # itself already covers the one variable path segment (version
        # number / winget's hash-named folder), so it isn't needed anyway.
        $found = Get-ChildItem $glob -ErrorAction SilentlyContinue -File | Select-Object -First 1
        if ($found) {
            $dir = Split-Path $found.FullName -Parent
            $env:Path = "$dir;$env:Path"
            return $found.FullName
        }
    }
    throw "$cmd 를 설치 후에도 찾을 수 없습니다. 설치가 실패했을 수 있습니다."
}

$gitExe    = Resolve-ExeAndAddToPath 'git'    @("$env:ProgramFiles\Git\cmd\git.exe")
$pythonExe = Resolve-ExeAndAddToPath 'python' @("$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe")
$caddyExe  = Resolve-ExeAndAddToPath 'caddy'  @("$env:LOCALAPPDATA\Microsoft\WinGet\Packages\CaddyServer.Caddy_*\caddy.exe")
$mkcertExe = Resolve-ExeAndAddToPath 'mkcert' @("$env:LOCALAPPDATA\Microsoft\WinGet\Packages\FiloSottile.mkcert_*\mkcert*.exe")
Write-Ok "git:    $gitExe"
Write-Ok "python: $pythonExe"
Write-Ok "caddy:  $caddyExe"
Write-Ok "mkcert: $mkcertExe"

# --------------------------------------------------------- [2] 프로젝트 받기 --
Write-Step "[2/9] 프로젝트 받기 ($InstallDir)"
if (Test-Path (Join-Path $InstallDir '.git')) {
    Write-Ok '이미 받아져 있어 최신 상태로 갱신합니다 (git fetch + reset --hard)'
    Push-Location $InstallDir
    # `git pull`이 아니라 fetch + reset --hard인 이유: pull은 머지를 시도하다
    # 실패하면(로컬에 추적되는 수정 사항이 남아있거나, 이전에 누가 특정
    # 커밋으로 직접 checkout해 detached HEAD가 됐거나, 다른 PC의
    # core.autocrlf 설정 차이로 줄바꿈만 다르게 보여도) git.exe는 0이 아닌
    # 종료 코드로 끝나는데, PowerShell의 $ErrorActionPreference='Stop'은
    # 외부 exe의 종료 코드에는 적용되지 않는다 -- 실패해도 이 스크립트는
    # 그냥 다음 단계로 넘어갔고, 그 결과 "최신 Setup.exe로 설치했는데 예전
    # 코드가 그대로 떠 있다"는 증상으로 나타났다 (git pull이 콘솔에 에러를
    # 찍긴 했지만 아무도 안 보고 있었을 뿐). 이 설치 폴더는 사람이 직접
    # 수정할 일이 없는 배포 전용 디렉터리이므로, 머지를 시도할 이유 없이
    # 매번 origin/main과 완전히 똑같은 상태로 강제로 맞추는 게 더 맞고,
    # 실패하면 바로 알 수 있게 명시적으로 중단한다.
    Invoke-Native { & $gitExe fetch origin main }
    if ($LASTEXITCODE -ne 0) { throw "git fetch 실패 (종료 코드 $LASTEXITCODE). 네트워크 연결을 확인해주세요." }
    Invoke-Native { & $gitExe reset --hard origin/main }
    if ($LASTEXITCODE -ne 0) { throw "git reset --hard 실패 (종료 코드 $LASTEXITCODE)." }
    Pop-Location
} else {
    if ((Test-Path $InstallDir) -and (Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue)) {
        throw "설치 위치($InstallDir)가 이미 있고 비어있지 않은데 git 저장소도 아닙니다. 다른 -InstallDir 경로를 지정해주세요."
    }
    # 설치 위치가 드라이브 바로 아래(예: D:\InfraSight)면 Split-Path -Parent가
    # "D:\" 하나만 돌려주는데, New-Item -ItemType Directory에 드라이브 루트를
    # 그대로 넘기면 "만들 디렉터리 이름이 없다"는 이유로 .NET이 거부한다
    # (System.ArgumentException: 경로의 형식이 잘못되었습니다 -- 실측 확인:
    # New-Item -ItemType Directory -Force -Path "D:\" 단독 실행만으로도 재현됨).
    # 그 부모가 이미 존재하면(드라이브 루트는 항상 존재) 애초에 만들 필요도
    # 없으므로, 없을 때만 만든다.
    $parentDir = Split-Path $InstallDir -Parent
    if ($parentDir -and -not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Force -Path $parentDir | Out-Null
    }
    Invoke-Native { & $gitExe clone $RepoUrl $InstallDir }
    if ($LASTEXITCODE -ne 0) { throw "git clone 실패 (종료 코드 $LASTEXITCODE). 네트워크 연결을 확인해주세요." }
    Write-Ok '클론 완료'
}

# ------------------------------------------------------- [3] 파이썬 패키지 --
Write-Step '[3/9] 파이썬 패키지 설치 (requirements.txt)'
Invoke-Native { & $pythonExe -m pip install --quiet --disable-pip-version-check -r (Join-Path $InstallDir 'requirements.txt') }
Write-Ok '설치 완료'

# ------------------------------------------------------------- [4] 인증서 --
Write-Step '[4/9] HTTPS 인증서 발급 (이 PC의 LAN IP 기준)'
Push-Location $InstallDir
Invoke-Native { & $mkcertExe -install }
$lanIp = (& $pythonExe -c "import storage; print(storage.get_lan_ip())").Trim()
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir 'certs') | Out-Null
Invoke-Native { & $mkcertExe -cert-file 'certs\infrasight.crt' -key-file 'certs\infrasight.key' $lanIp localhost infrasight.local }
Write-Ok "인증서 발급 완료 (LAN IP: $lanIp)"
Pop-Location

# --------------------------------------------------------- [5] DB 초기화 --
Write-Step '[5/9] 데이터베이스 초기화'
Push-Location $InstallDir
& $pythonExe -c "import storage; storage.init_db()"
Pop-Location
Write-Ok '완료'

# ------------------------------------------------------- [6] 관리자 계정 --
Write-Step '[6/9] 관리자 계정'
Push-Location $InstallDir
$hasAdmin = (& $pythonExe -c "import storage; c=storage.get_db(); r=c.execute('SELECT 1 FROM users LIMIT 1').fetchone(); c.close(); print(1 if r else 0)").Trim()
if ($hasAdmin -eq '1') {
    Write-Ok '이미 계정이 있어 건너뜁니다 (기존 계정 유지)'
} else {
    # No prompts: always admin/admin, flagged must_change_password so the
    # web UI refuses to let anyone past login with it still set (see
    # index.html's promptForcedPasswordChange / server.py's mustChangePassword)
    # -- the security boundary is "can't use the app with the default
    # password", not "was asked to pick one during install".
    & $pythonExe -c "import storage; storage.create_admin_if_missing('admin', 'admin', must_change_password=True)"
    Write-Ok "관리자 계정 'admin' / 'admin' 생성 완료 (최초 웹 로그인 시 비밀번호 변경 필수)"
}
Pop-Location

# --------------------------------------------------------- [7] 자동 시작 --
Write-Step '[7/9] 로그온 시 자동 시작 등록'
& (Join-Path $InstallDir 'ops\register-task.ps1')

# ----------------------------------------------------------- [8] 방화벽 --
Write-Step '[8/9] 방화벽 인바운드 규칙'
$rules = @(
    @{ Name = 'InfraSight HTTPS (Caddy)'; Port = 8443; Protocol = 'TCP' },
    @{ Name = 'InfraSight HTTP (agents)';  Port = 5057; Protocol = 'TCP' },
    # 4-3: NetFlow/sFlow are push-based -- a device exports to these UDP
    # ports on its own, so without an inbound allow rule here its export
    # traffic just gets silently dropped before it ever reaches
    # collector/flow_listener.py, regardless of how correctly the device
    # itself is configured.
    @{ Name = 'InfraSight NetFlow (UDP)'; Port = 2055; Protocol = 'UDP' },
    @{ Name = 'InfraSight sFlow (UDP)';   Port = 6343; Protocol = 'UDP' }
)
foreach ($r in $rules) {
    try {
        if (-not (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Protocol $r.Protocol -LocalPort $r.Port -Action Allow | Out-Null
        }
        Write-Ok "방화벽 규칙 확인/추가됨: $($r.Name) (포트 $($r.Port)/$($r.Protocol))"
    } catch {
        Write-Warn2 "방화벽 규칙 추가 실패 ($($r.Name)): $_"
    }
}

# ----------------------------------------------------- [9] 원격 접속 구성 --
Write-Step '[9/9] 네트워크 장비 원격 접속(SSH/Telnet) 구성'
try {
    & (Join-Path $InstallDir 'ops\setup-remote-access.ps1') -InstallDir $InstallDir -PythonExe $pythonExe
} catch {
    Write-Warn2 "원격 접속 구성 중 문제가 있었습니다 (무시하고 계속합니다): $_"
}

# ------------------------------------------------------------ 지금 시작 --
Write-Step '지금 바로 시작'
# This may be an update to an already-running install (step [2] did
# `git pull` rather than a fresh clone): the pulled code doesn't take effect
# in an already-running python.exe on its own, and if a supervisor.ps1 is
# still alive, launching a new one below just hits its own duplicate-run
# guard and exits immediately instead of upgrading anything -- silently
# leaving the OLD code running. Stop this install's own previously-tracked
# processes (read from its own run\status.json, so this never touches any
# unrelated python/caddy process elsewhere on the machine) before starting
# fresh, so the just-pulled code actually takes effect either way.
$statusFile = Join-Path $InstallDir 'run\status.json'
if (Test-Path $statusFile) {
    try {
        $prevStatus = Get-Content $statusFile -Raw | ConvertFrom-Json
        foreach ($p in @($prevStatus.supervisorPid, $prevStatus.backend.pid, $prevStatus.caddy.pid)) {
            if ($p) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }
        }
        Remove-Item (Join-Path $InstallDir 'run\supervisor.lock') -ErrorAction SilentlyContinue
        Write-Ok '기존에 실행 중이던 프로세스를 종료해 방금 받은 최신 코드가 적용되도록 했습니다'
        Start-Sleep -Seconds 2
    } catch {
        Write-Warn2 "기존 프로세스 종료 중 문제가 있었습니다 (무시하고 계속합니다): $_"
    }
}
# `Start-Process powershell -WindowStyle Hidden` looks right but isn't
# reliable -- register-task.ps1 hit this exact problem (see its own long
# comment on the same thing) and a Patch.exe run surfaced it again live: a
# blank "Windows PowerShell" window popped up and just sat there after
# patching, because -WindowStyle Hidden only ever *asks* for a hidden
# window and Windows doesn't always honor it, especially this soon after
# the parent process itself was just elevated/launched. WScript.Shell's
# .Run(cmd, 0, False) -- windowStyle 0 -- is the same reliable mechanism
# register-task.ps1 already uses via a .vbs file; done here directly
# through the COM object instead, since there's no reason to drop a .vbs
# file to disk just for this one relaunch.
$supervisorCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'ops\supervisor.ps1')`""
(New-Object -ComObject WScript.Shell).Run($supervisorCmd, 0, $false) | Out-Null
Start-Sleep -Seconds 4

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host ' 설치가 완료되었습니다!' -ForegroundColor Green
Write-Host "   이 PC:        https://localhost:8443"
Write-Host "   같은 네트워크의 다른 기기: https://${lanIp}:8443"
Write-Host '============================================================' -ForegroundColor Green
Write-Host "`n로그인 계정: admin / admin (처음 로그인하면 비밀번호 변경 화면이 바로 뜹니다)" -ForegroundColor Yellow
Write-Host "`n참고: 접속하는 다른 기기의 브라우저에는 인증서 경고가 뜰 수 있습니다"
Write-Host "(이 PC에서 발급한 '로컬 CA' 방식 인증서라서 그렇습니다 -- 무시하고 진행하거나,"
Write-Host "%LOCALAPPDATA%\mkcert\rootCA.pem 을 그 기기에 설치하면 경고 없이 접속할 수 있습니다)."

Start-Process "https://localhost:8443"

} catch {
    # This window is the elevated one (Start-Process -Verb RunAs) where every
    # message above actually printed -- without a pause here it closes the
    # instant the script ends, taking the only copy of the error message
    # with it before anyone can read it. The success path below has no such
    # pause: nothing left to read there once the success banner and browser
    # launch are done, so it just closes on its own.
    Write-Host "`n============================================================" -ForegroundColor Red
    Write-Host ' 설치 중 오류가 발생했습니다' -ForegroundColor Red
    Write-Host " $_" -ForegroundColor Red
    # "$_"만으로는 메시지 텍스트만 보이고 정확히 어느 줄에서 터졌는지 안 보여서,
    # 애매한 .NET 예외 메시지(예: "경로의 형식이 잘못되었습니다")만으론 원인을
    # 못 짚는 경우가 실제로 있었다 -- 줄 번호/코드까지 같이 찍는다.
    if ($_.InvocationInfo) { Write-Host " 위치: $($_.InvocationInfo.PositionMessage)" -ForegroundColor Red }
    Write-Host '============================================================' -ForegroundColor Red
    Write-Host "`n아무 키나 누르면 창이 닫힙니다..." -ForegroundColor DarkGray
    # ReadKey는 실제 콘솔에서 더블클릭으로 직접 실행했을 때나 통하는 방식이다
    # -- GUI 설치 프로그램(ops\installer.nsi)이 nsExec::ExecToLog로 이 스크립트를
    # 돌릴 때는 표준 입출력이 로그 캡처용으로 리디렉션되어 있어서 ReadKey 자체가
    # 예외를 던진다. 그 예외가 catch 블록 안에서 또 잡히지 않은 채로 전파되면
    # 정작 위에서 막 출력한 진짜 에러 메시지($_)가 뒤따라오는 이 2차 예외에
    # 가려져 버린다 (실측: GUI 설치 중 실패했을 때 로그에 ReadKey 예외만 보이고
    # 진짜 원인은 스크롤해야 보이는 위쪽에 있었음). 패치적용.ps1의 같은 자리와
    # 동일하게 try/catch로 감싼다.
    try { [void][System.Console]::ReadKey($true) } catch { Start-Sleep -Seconds 3 }
    # exit 코드를 명시적으로 지정하지 않으면 catch에 들어왔어도(= 설치가
    # 실제로는 실패했어도) 스크립트 자체는 그냥 끝까지 실행된 것으로 쳐서
    # 종료 코드 0(성공)을 돌려준다 -- 더블클릭 직접 실행할 땐 위의 에러
    # 메시지를 사람이 직접 보니 상관없었지만, ops\installer.nsi가
    # nsExec::ExecToLog로 이 스크립트를 실행하고 그 종료 코드만으로
    # 성공/실패를 판단할 때는 치명적이다 -- 실측: 설치 중 실제로 이 catch에
    # 들어갔는데(로그에 "설치 중 오류가 발생했습니다"가 찍혔는데도) GUI
    # 설치 프로그램은 종료 코드 0을 받아 "설치가 완료되었습니다" 화면을
    # 그대로 보여줬음.
    exit 1
}
