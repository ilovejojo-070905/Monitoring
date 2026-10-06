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
    Start-Process powershell -Verb RunAs -ArgumentList $argList -Wait
    exit
}

Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' InfraSight 설치' -ForegroundColor Cyan
Write-Host " 설치 위치: $InstallDir"
Write-Host '============================================================' -ForegroundColor Cyan

# --------------------------------------------------------- [1] 필수 도구 --
Write-Step '[1/8] 필수 도구 확인 (Git / Python / Caddy / mkcert)'

function Install-IfMissing([string]$cmd, [string]$wingetId, [string]$label) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        Write-Ok "$label 이미 설치됨"
        return
    }
    Write-Host "    $label 설치 중 (winget install $wingetId)..."
    winget install --id $wingetId -e --source winget --accept-package-agreements --accept-source-agreements | Out-Null
}

Install-IfMissing 'git' 'Git.Git' 'Git'
Install-IfMissing 'python' 'Python.Python.3.12' 'Python'
Install-IfMissing 'caddy' 'CaddyServer.Caddy' 'Caddy'
Install-IfMissing 'mkcert' 'FiloSottile.mkcert' 'mkcert'

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
Write-Step "[2/8] 프로젝트 받기 ($InstallDir)"
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
    & $gitExe fetch origin main
    if ($LASTEXITCODE -ne 0) { throw "git fetch 실패 (종료 코드 $LASTEXITCODE). 네트워크 연결을 확인해주세요." }
    & $gitExe reset --hard origin/main
    if ($LASTEXITCODE -ne 0) { throw "git reset --hard 실패 (종료 코드 $LASTEXITCODE)." }
    Pop-Location
} else {
    if ((Test-Path $InstallDir) -and (Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue)) {
        throw "설치 위치($InstallDir)가 이미 있고 비어있지 않은데 git 저장소도 아닙니다. 다른 -InstallDir 경로를 지정해주세요."
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $InstallDir -Parent) | Out-Null
    & $gitExe clone $RepoUrl $InstallDir
    if ($LASTEXITCODE -ne 0) { throw "git clone 실패 (종료 코드 $LASTEXITCODE). 네트워크 연결을 확인해주세요." }
    Write-Ok '클론 완료'
}

# ------------------------------------------------------- [3] 파이썬 패키지 --
Write-Step '[3/8] 파이썬 패키지 설치 (requirements.txt)'
& $pythonExe -m pip install --quiet --disable-pip-version-check -r (Join-Path $InstallDir 'requirements.txt')
Write-Ok '설치 완료'

# ------------------------------------------------------------- [4] 인증서 --
Write-Step '[4/8] HTTPS 인증서 발급 (이 PC의 LAN IP 기준)'
Push-Location $InstallDir
& $mkcertExe -install
$lanIp = (& $pythonExe -c "import storage; print(storage.get_lan_ip())").Trim()
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir 'certs') | Out-Null
& $mkcertExe -cert-file 'certs\infrasight.crt' -key-file 'certs\infrasight.key' $lanIp localhost infrasight.local
Write-Ok "인증서 발급 완료 (LAN IP: $lanIp)"
Pop-Location

# --------------------------------------------------------- [5] DB 초기화 --
Write-Step '[5/8] 데이터베이스 초기화'
Push-Location $InstallDir
& $pythonExe -c "import storage; storage.init_db()"
Pop-Location
Write-Ok '완료'

# ------------------------------------------------------- [6] 관리자 계정 --
Write-Step '[6/8] 관리자 계정'
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
Write-Step '[7/8] 로그온 시 자동 시작 등록'
& (Join-Path $InstallDir 'ops\register-task.ps1')

# ----------------------------------------------------------- [8] 방화벽 --
Write-Step '[8/8] 방화벽 인바운드 규칙'
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
Start-Process powershell -ArgumentList @(
    '-NoProfile', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $InstallDir 'ops\supervisor.ps1')
) -WorkingDirectory $InstallDir
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

# This window is the elevated one (Start-Process -Verb RunAs) where every
# message above actually printed -- without a pause here it closes the
# instant this script ends, so the success message (and the LAN URL to give
# out) flashes by and is gone before anyone can read it.
Write-Host "`n아무 키나 누르면 창이 닫힙니다..." -ForegroundColor DarkGray
[void][System.Console]::ReadKey($true)
