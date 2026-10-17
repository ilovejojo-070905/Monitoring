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
    [string]$RepoUrl = 'https://github.com/ilovejojo-070905/Monitoring.git',
    # ops\installer.nsi(GUI 마법사)가 이 스크립트를 감싸 돌릴 때 켠다 -- 이
    # 스크립트 혼자 돌 때는(콘솔용 Setup.exe) 끝에서 바로 브라우저를 여는 게
    # 자연스럽지만, GUI 마법사 안에서는 그게 "설치 중" 진행 화면 단계에서
    # 실행되어 사용자가 "마침" 버튼을 누르기도 전에 사이트가 먼저 열려버리는
    # 문제가 실측으로 확인됐다 -- GUI 쪽은 마침 화면 자체의 "지금 바로 열기"
    # 체크박스가 이미 같은 일을 하므로, 이 스위치가 켜져 있으면 여기서는
    # 열지 않는다.
    [switch]$SkipBrowserLaunch
)

# 빌드(ps2exe 컴파일) 시 build-release.ps1이 dist\InfraSightAgent.exe(에이전트
# 실행 파일)를 base64로 치환해 넣는다 -- 에이전트 다운로드 기능(장비 등록 시
# "InfraSightAgent.exe 다운로드")이 git에는 안 올라가는(용량 때문에
# .gitignore 처리된) 이 파일에 의존하는데, git clone만으로 설치하면 이 파일이
# 아예 없어서 다운로드가 500 에러로 실패하는 문제가 실측으로 확인됐음 --
# 설치 과정 자체에 끼워 넣어 해결한다. 패치적용.ps1의 $EMBEDDED_PATCH_B64와
# 완전히 같은 패턴(치환 전이면 플레이스홀더 그대로 남아있어 건너뜀).
$EMBEDDED_AGENT_EXE_B64 = '__EMBEDDED_AGENT_EXE_B64__'

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg" -ForegroundColor Yellow }

# 버그 수정(2026-10-17, 보안감사 Phase A #16/#35): infrasight.db/backups/
# 암호화 키 파일이 전부 "Authenticated Users: 수정" 상속 ACL로 생성돼서,
# 이 PC에 로그인 가능한 다른 어떤 계정도 백업 파일과 암호화 키 파일을
# 같이 복사해 SNMP/SMTP 자격증명을 오프라인으로 풀어볼 수 있었다(필드별
# Fernet 암호화 자체는 멀쩡하지만, 키가 바로 옆에 똑같이 노출돼 있으면
# 그 암호화가 사실상 의미가 없음). 그 길을 막되, 서비스 자체는 계속
# 돌아가야 한다 -- ops\register-task.ps1이 등록하는 작업은 일부러
# -RunLevel Limited로 돈다(그 스크립트 자신의 주석 참고: install.ps1의
# 하위 단계로도 실행되므로 UAC 상승이 필요하면 그 자리에서 멈춰버림).
# Limited 토큰은 이 사용자가 Administrators 그룹에 속해 있어도 그 그룹의
# 권한을 실제로는 못 쓴다(실측으로 확인: Authenticated Users만 빼고
# BUILTIN\Administrators(F)만 남겨놨더니 바로 "attempt to write a
# readonly database"로 서비스가 멈췄음) -- 그래서 이 설치를 실행하는
# 사용자 계정 자신에게 그룹을 거치지 않고 직접 Modify를 줘야 한다.
# 실패해도(예: 이 사용자가 그 파일의 소유자가 아니어서 ACL을 못 바꾸는
# 드문 경우) 설치 자체를 중단시키지 않는다 -- 이건 심화 방어이고, 핵심
# 기능(수집/알림)과는 무관하므로.
function Protect-SensitiveFiles {
    param([string]$InstallDir)
    $targets = @(
        (Join-Path $InstallDir 'backups'),
        (Join-Path $InstallDir 'infrasight.db'),
        (Join-Path $InstallDir '.infrasight_credentials_key')
    )
    foreach ($target in $targets) {
        if (-not (Test-Path $target)) { continue }
        try {
            & icacls $target /inheritance:d | Out-Null
            & icacls $target /remove:g "NT AUTHORITY\Authenticated Users" | Out-Null
            if ((Get-Item $target) -is [System.IO.DirectoryInfo]) {
                & icacls $target /grant "${env:USERNAME}:(OI)(CI)(M)" | Out-Null
            } else {
                & icacls $target /grant "${env:USERNAME}:(M)" | Out-Null
            }
        } catch {
            Write-Warn2 "$target 파일 권한 강화에 실패했습니다(기능에는 영향 없음): $_"
        }
    }
}

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
    if ($SkipBrowserLaunch) { $argList += '-SkipBrowserLaunch' }
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

# ------------------------------------------------ [1] 이전 프로세스 정리 --
# 실측으로 겪은 문제 (2026-10-14): uninstall.ps1을 거치지 않고(예: 설치
# 폴더를 탐색기에서 직접 지움) 재설치하면, 이전 설치의 백엔드/Caddy
# 프로세스가 안 죽은 채로 계속 5057/8443 포트를 쥐고 있다 -- 그 상태에서
# install.ps1이 새 supervisor를 등록/시작하면 새 백엔드가 매 폴링 주기마다
# "포트를 못 열었나?"로 오인되어 계속 재시작을 시도하면서, 죽지도 않은
# 예전 프로세스 위에 새 프로세스가 계속 쌓이는 것까지 실제로 확인됨
# (한 PC에서 30개 넘는 python.exe가 전부 5057에 몰려있었음). uninstall.ps1
# 쪽은 이미 ops\stop.ps1(이름/커맨드라인 기준 머신 전체 정리)을 거치지만,
# "지우고 다시 설치"가 꼭 그 스크립트를 거쳐서 일어나는 게 아니므로,
# 재설치가 실제로 시작되는 이 지점에서 같은 정리를 한 번 더 해야 안전하다.
# stop.ps1이 아직 없는(설치 폴더가 통째로 사라진) 상태에서도 동작해야 하므로
# 그 파일을 찾아 호출하는 대신 같은 로직을 그대로 인라인함.
Write-Step '[1/10] 이전에 남아있을 수 있는 InfraSight 프로세스 정리'
$staleBackend = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*server.py*' }
$staleCaddy = Get-Process caddy -ErrorAction SilentlyContinue
if ($staleBackend -or $staleCaddy) {
    Write-Warn2 "재설치 전 정리 대상 발견: 백엔드 $(@($staleBackend).Count)개, Caddy $(@($staleCaddy).Count)개 -- 종료합니다."
    $staleBackend | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    $staleCaddy | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Ok '정리 완료'
} else {
    Write-Ok '남아있는 프로세스 없음'
}

# --------------------------------------------------------- [2] 필수 도구 --
Write-Step '[2/10] 필수 도구 확인 (Git / Python / Caddy / mkcert)'

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

# --------------------------------------------------------- [3] 프로젝트 받기 --
Write-Step "[3/10] 프로젝트 받기 ($InstallDir)"
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
    if (Test-Path $InstallDir) {
        $existingItems = Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue
        if ($existingItems) {
            # 실패했거나 제거된 이전 설치 시도가 남긴 찌꺼기(빈 DB, logs\ 등)만
            # 있다면 "git 저장소가 아니다"라는 이유로 막을 필요가 없다 --
            # 실측: 드라이브 루트 버그 때문에 실패한 GUI Setup 시도가
            # infrasight.db(0바이트)/logs\를 남겼고, 그걸 고친 뒤 같은 경로로
            # 재시도할 때마다 이 에러로 다시 막히는 상황이 실제로 발생했다.
            # 알려진 InfraSight 산출물 이름만 있으면 자동으로 치우고,
            # 그 외의(사람이 직접 만든 다른 파일 등) 뭔가가 하나라도 섞여
            # 있으면 여전히 안전하게 막고 다른 경로를 요청한다.
            $knownArtifacts = @(
                'infrasight.db', 'infrasight.db-journal', 'infrasight.db-wal', 'infrasight.db-shm',
                'logs', 'run', 'certs',
                '.infrasight_secret_key', '.infrasight_secret_key_backup_*', '.infrasight_credentials_key',
                'server.log', 'caddy.log'
            )
            $unknownItems = $existingItems | Where-Object {
                $itemName = $_.Name
                -not ($knownArtifacts | Where-Object { $itemName -like $_ })
            }
            if ($unknownItems) {
                throw "설치 위치($InstallDir)가 이미 있고 비어있지 않은데 git 저장소도 아닙니다. 다른 -InstallDir 경로를 지정해주세요."
            }
            Write-Warn2 "이전 설치 시도의 찌꺼기($($existingItems.Count)개 항목)를 정리하고 새로 시작합니다."
            $existingItems | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
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

# ------------------------------------------------------- [4] 파이썬 패키지 --
Write-Step '[4/10] 파이썬 패키지 설치 (requirements.txt)'
Invoke-Native { & $pythonExe -m pip install --quiet --disable-pip-version-check -r (Join-Path $InstallDir 'requirements.txt') }
# 버그 수정(2026-10-16): Invoke-Native 자신의 주석이 "호출한 쪽이 $LASTEXITCODE
# 로 실제 실패를 확인해야 한다"고 명시하는데, 이 호출은 그 확인을 안 해서
# pip install이 실패해도(예: requirements.txt의 한 패키지가 PyPI에서
# 사라짐, 디스크 공간 부족) "설치 완료"가 그대로 찍히고 다음 단계로
# 넘어갔음 -- 나중에 서버가 아예 안 뜨는 원인 불명의 실패로만 나타남.
if ($LASTEXITCODE -ne 0) { throw "pip install 실패 (종료 코드 $LASTEXITCODE). 네트워크 연결이나 디스크 공간을 확인해주세요." }
Write-Ok '설치 완료'

# ------------------------------------------------------------- [5] 인증서 --
Write-Step '[5/10] HTTPS 인증서 발급 (이 PC의 LAN IP 기준)'
Push-Location $InstallDir
Invoke-Native { & $mkcertExe -install }
if ($LASTEXITCODE -ne 0) { throw "mkcert -install 실패 (종료 코드 $LASTEXITCODE)" }
$lanIp = (& $pythonExe -c "import storage; print(storage.get_lan_ip())").Trim()
if ($LASTEXITCODE -ne 0) { throw "LAN IP 조회 실패 (종료 코드 $LASTEXITCODE)" }
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir 'certs') | Out-Null
Invoke-Native { & $mkcertExe -cert-file 'certs\infrasight.crt' -key-file 'certs\infrasight.key' $lanIp localhost infrasight.local }
# 버그 수정(2026-10-16): 인증서 발급이 조용히 실패하면(예: LAN IP를 못
# 구함, mkcert 루트 CA가 깨짐) Caddy가 시작할 때 쓸 인증서 파일이
# 없는데도 "발급 완료"가 그대로 찍혔음 -- 실제 증상은 몇 단계 뒤
# Caddy가 못 뜨는 걸로만 보여서 원인 추적이 어려웠음.
if ($LASTEXITCODE -ne 0) { throw "인증서 발급 실패 (종료 코드 $LASTEXITCODE)" }
Write-Ok "인증서 발급 완료 (LAN IP: $lanIp)"
Pop-Location

# --------------------------------------------------------- [6] DB 초기화 --
Write-Step '[6/10] 데이터베이스 초기화'
Push-Location $InstallDir
& $pythonExe -c "import storage; storage.init_db()"
# 버그 수정(2026-10-16): DB 초기화가 실패해도(예: 테이블 생성 중 예외)
# 그대로 "완료"가 찍히고 다음 단계(관리자 계정 생성, DB 접근 필요)로
# 넘어갔음 -- 그 단계가 더 알아보기 어려운 다른 오류로 실패하는 식으로만
# 드러났음.
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "데이터베이스 초기화 실패 (종료 코드 $LASTEXITCODE)" }
Pop-Location
# backups\는 평소엔 첫 백업이 실제로 돌 때(scheduler.py의 일일 작업,
# 또는 수동 "지금 백업") storage.backup_database가 처음 만든다 -- 그때
# 가서야 생기면 이 설치 시점 권한 강화를 못 받고 상위 폴더 기본 ACL을
# 그대로 상속받으므로, 여기서 미리 만들어 바로 강화한다.
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir 'backups') | Out-Null
Protect-SensitiveFiles -InstallDir $InstallDir
Write-Ok '완료'

# ------------------------------------------------------- [7] 관리자 계정 --
Write-Step '[7/10] 관리자 계정'
Push-Location $InstallDir
$hasAdmin = (& $pythonExe -c "import storage; c=storage.get_db(); r=c.execute('SELECT 1 FROM users LIMIT 1').fetchone(); c.close(); print(1 if r else 0)").Trim()
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "계정 존재 확인 실패 (종료 코드 $LASTEXITCODE)" }
if ($hasAdmin -eq '1') {
    Write-Ok '이미 계정이 있어 건너뜁니다 (기존 계정 유지)'
} else {
    # No prompts: always admin/admin, flagged must_change_password so the
    # web UI refuses to let anyone past login with it still set (see
    # index.html's promptForcedPasswordChange / server.py's mustChangePassword)
    # -- the security boundary is "can't use the app with the default
    # password", not "was asked to pick one during install".
    & $pythonExe -c "import storage; storage.create_admin_if_missing('admin', 'admin', must_change_password=True)"
    # 버그 수정(2026-10-16): 계정 생성이 실패해도 "생성 완료" 메시지가
    # 그대로 찍혀서, 처음 설치한 사람이 admin/admin으로 로그인해보기
    # 전까지는 실패한 걸 전혀 알 수 없었음.
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "관리자 계정 생성 실패 (종료 코드 $LASTEXITCODE)" }
    Write-Ok "관리자 계정 'admin' / 'admin' 생성 완료 (최초 웹 로그인 시 비밀번호 변경 필수)"
}
Pop-Location

# --------------------------------------------------------- [8] 자동 시작 --
# powershell.exe -ExecutionPolicy Bypass로 직접 불러야 한다 -- `& 경로\*.ps1`
# 식으로 바로 부르면 그 PC의 PowerShell 실행 정책(기본값이 흔히 Restricted인
# 평범한 사용자 PC)에 그대로 걸려 "이 시스템에서 스크립트를 실행할 수
# 없으므로..." 오류로 죽는다 -- 실측으로 확인됨(이 단계가 try/catch로
# 안 감싸여 있어서 install.ps1 전체가 여기서 중단됨). uninstall.ps1은
# 처음부터 이 방식으로 불러서 같은 문제를 겪은 적이 없었음.
Write-Step '[8/10] 로그온 시 자동 시작 등록'
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $InstallDir 'ops\register-task.ps1')
if ($LASTEXITCODE -ne 0) { throw "register-task.ps1 실행 실패 (종료 코드 $LASTEXITCODE)" }

# ----------------------------------------------------------- [9] 방화벽 --
Write-Step '[9/10] 방화벽 인바운드 규칙'
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

# ---------------------------------------------------- [10] 원격 접속 구성 --
# 위 [8/10]과 같은 이유로 powershell.exe -ExecutionPolicy Bypass로 직접 부른다.
Write-Step '[10/10] 네트워크 장비 원격 접속(SSH/Telnet) 구성'
try {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $InstallDir 'ops\setup-remote-access.ps1') -InstallDir $InstallDir -PythonExe $pythonExe
    if ($LASTEXITCODE -ne 0) { throw "setup-remote-access.ps1 실행 실패 (종료 코드 $LASTEXITCODE)" }
} catch {
    Write-Warn2 "원격 접속 구성 중 문제가 있었습니다 (무시하고 계속합니다): $_"
}

# --------------------------------------------------- [에이전트] 설치 파일 --
Write-Step '서버/PC 모니터링용 에이전트(InfraSightAgent.exe) 배치'
try {
    if ($EMBEDDED_AGENT_EXE_B64 -and $EMBEDDED_AGENT_EXE_B64 -notlike '__*') {
        $distDir = Join-Path $InstallDir 'dist'
        New-Item -ItemType Directory -Force -Path $distDir | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $distDir 'InfraSightAgent.exe'), [Convert]::FromBase64String($EMBEDDED_AGENT_EXE_B64))
        Write-Ok '에이전트 설치 파일을 배치했습니다 (장비 등록 시 다운로드 가능).'
    } else {
        Write-Warn2 '에이전트 실행 파일이 이 설치 프로그램에 포함되어 있지 않습니다 (개발/테스트용 직접 실행 -- 건너뜁니다).'
    }
} catch {
    Write-Warn2 "에이전트 설치 파일 배치 중 문제가 있었습니다 (무시하고 계속합니다): $_"
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

if (-not $SkipBrowserLaunch) { Start-Process "https://localhost:8443" }

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
