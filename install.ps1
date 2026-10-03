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
    $existing = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($existing) { return $existing.Source }
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
    Write-Ok '이미 받아져 있어 최신 상태로 갱신합니다 (git pull)'
    Push-Location $InstallDir
    & $gitExe pull origin main
    Pop-Location
} else {
    if ((Test-Path $InstallDir) -and (Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue)) {
        throw "설치 위치($InstallDir)가 이미 있고 비어있지 않은데 git 저장소도 아닙니다. 다른 -InstallDir 경로를 지정해주세요."
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $InstallDir -Parent) | Out-Null
    & $gitExe clone $RepoUrl $InstallDir
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
    $username = Read-Host '  로그인에 사용할 아이디'
    while (-not $username) { $username = Read-Host '  아이디를 입력해주세요' }
    do {
        $securePw  = Read-Host '  비밀번호 (8자 이상)' -AsSecureString
        $securePw2 = Read-Host '  비밀번호 확인' -AsSecureString
        $pw  = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($securePw))
        $pw2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($securePw2))
        $ok = $true
        if ($pw.Length -lt 8) { Write-Warn2 '8자 이상 입력해주세요.'; $ok = $false }
        elseif ($pw -ne $pw2) { Write-Warn2 '비밀번호가 일치하지 않습니다.'; $ok = $false }
    } while (-not $ok)
    # Piped via stdin rather than a command-line argument so the password
    # never shows up in the process list. No double quotes anywhere in this
    # Python snippet: PowerShell mangles embedded " characters when building
    # the argument list for a native (non-PowerShell) executable, which
    # silently corrupts a -c script passed this way (confirmed -- it turned
    # rstrip("\n") into rstrip(\n), a Python SyntaxError). Single quotes for
    # every Python string literal sidesteps that entirely.
    "$username`n$pw" | & $pythonExe -c @'
import sys, storage
username = sys.stdin.readline().strip()
pw = sys.stdin.readline().rstrip(chr(10))
storage.create_admin_if_missing(username, pw)
'@
    Write-Ok "관리자 계정 '$username' 생성 완료"
}
Pop-Location

# --------------------------------------------------------- [7] 자동 시작 --
Write-Step '[7/8] 로그온 시 자동 시작 등록'
& (Join-Path $InstallDir 'ops\register-task.ps1')

# ----------------------------------------------------------- [8] 방화벽 --
Write-Step '[8/8] 방화벽 인바운드 규칙'
$rules = @(
    @{ Name = 'InfraSight HTTPS (Caddy)'; Port = 8443 },
    @{ Name = 'InfraSight HTTP (agents)';  Port = 5057 }
)
foreach ($r in $rules) {
    try {
        if (-not (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Protocol TCP -LocalPort $r.Port -Action Allow | Out-Null
        }
        Write-Ok "방화벽 규칙 확인/추가됨: $($r.Name) (포트 $($r.Port))"
    } catch {
        Write-Warn2 "방화벽 규칙 추가 실패 ($($r.Name)): $_"
    }
}

# ------------------------------------------------------------ 지금 시작 --
Write-Step '지금 바로 시작'
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
Write-Host "`n참고: 접속하는 다른 기기의 브라우저에는 인증서 경고가 뜰 수 있습니다"
Write-Host "(이 PC에서 발급한 '로컬 CA' 방식 인증서라서 그렇습니다 -- 무시하고 진행하거나,"
Write-Host "%LOCALAPPDATA%\mkcert\rootCA.pem 을 그 기기에 설치하면 경고 없이 접속할 수 있습니다)."

Start-Process "https://localhost:8443"
