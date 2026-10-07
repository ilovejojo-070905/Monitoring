<#
InfraSight patch (PowerShell)
=============================
Lightweight updater for a PC that already has InfraSight installed via
install.ps1 -- unlike re-running the full Setup.exe, this skips the tool
checks, certificate issuance, admin-account creation and firewall rules
(all already done), and just: force-syncs the install folder to the
latest GitHub main (git fetch + reset --hard, not a merge -- see the
comment in install.ps1's own [2/8] step for why), reinstalls Python
dependencies in case any changed, then stops and restarts the running
backend/Caddy so the new code actually takes effect.

No admin rights needed (nothing here touches the firewall or a
machine-wide certificate store).

Usage:
    powershell -ExecutionPolicy Bypass -File patch.ps1
    powershell -ExecutionPolicy Bypass -File patch.ps1 -InstallDir "D:\InfraSight"
#>

param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'InfraSight')
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg" -ForegroundColor Yellow }

# git/pip routinely write normal progress or status text to STDERR (e.g.
# git fetch's own "From https://..." line) -- with $ErrorActionPreference
# ='Stop' in effect, PowerShell can treat that as a terminating error and
# abort the whole script even though the command actually succeeded (exit
# code 0). Confirmed live: a Patch.exe run died right after printing git
# fetch's completely normal "From https://github.com/..." status line, with
# no real failure at all. Every native exe call below goes through this so
# stderr chatter can't be mistaken for a real failure; callers still check
# $LASTEXITCODE themselves afterward to catch an ACTUAL failure.
# SilentlyContinue (not just Continue) also hides the resulting "ERROR:
# From https://..." lines from the console entirely -- confirmed live that
# even non-terminating, these still print in red and look exactly like a
# real failure to someone just trying to double-click their way through a
# patch.
function Invoke-Native([scriptblock]$Command) {
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try { & $Command } finally { $ErrorActionPreference = $prevEAP }
}

Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' InfraSight 패치 적용' -ForegroundColor Cyan
Write-Host " 설치 위치: $InstallDir"
Write-Host '============================================================' -ForegroundColor Cyan

# 아래 전체를 try/finally로 감싸는 이유: 중간에 오류가 나면
# $ErrorActionPreference='Stop' 때문에 즉시 종료되는데, 끝의 "아무 키나
# 누르면 창이 닫힙니다" 일시정지는 성공 경로에만 있어서 실패 시엔 거치지도
# 못하고 오류 메시지를 읽을 틈도 없이 창이 사라졌다 (install.ps1에서
# 실제로 겪은 것과 같은 문제). finally에 일시정지를 두면 성공/실패 어느
# 쪽이든 창이 남는다.
try {

if (-not (Test-Path (Join-Path $InstallDir '.git'))) {
    throw "'$InstallDir' 에 설치된 InfraSight(git 저장소)를 찾을 수 없습니다. 처음 설치라면 install.ps1(Setup.exe)을 사용해주세요."
}

# install.ps1의 [1/8]과 동일한 패턴: 이미 설치돼 있다는 전제이므로 git만
# PATH에서 찾으면 된다 (python/caddy는 아래 단계에서야 필요하고, 이미 설치
# 당시 PATH에 등록됐을 것이므로 보통은 Get-Command만으로 충분하다).
function Resolve-ExeAndAddToPath([string]$cmd, [string[]]$searchGlobs) {
    $existing = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($existing -and $existing.Source -notmatch '\\WindowsApps\\') { return $existing.Source }
    foreach ($glob in $searchGlobs) {
        $found = Get-ChildItem $glob -ErrorAction SilentlyContinue -File | Select-Object -First 1
        if ($found) {
            $dir = Split-Path $found.FullName -Parent
            $env:Path = "$dir;$env:Path"
            return $found.FullName
        }
    }
    throw "$cmd 를 찾을 수 없습니다. InfraSight가 정상 설치된 상태인지 확인해주세요."
}

$gitExe    = Resolve-ExeAndAddToPath 'git'    @("$env:ProgramFiles\Git\cmd\git.exe")
$pythonExe = Resolve-ExeAndAddToPath 'python' @("$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe")

Write-Step '[1/3] 최신 코드 받기 (git fetch + reset --hard)'
Push-Location $InstallDir
Invoke-Native { & $gitExe fetch origin main }
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "git fetch 실패 (종료 코드 $LASTEXITCODE). 네트워크 연결을 확인해주세요." }
Invoke-Native { & $gitExe reset --hard origin/main }
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "git reset --hard 실패 (종료 코드 $LASTEXITCODE)." }
$headNow = (& $gitExe rev-parse --short HEAD).Trim()
Pop-Location
Write-Ok "최신 커밋으로 갱신됨: $headNow"

Write-Step '[2/3] 파이썬 패키지 확인 (requirements.txt)'
Invoke-Native { & $pythonExe -m pip install --quiet --disable-pip-version-check -r (Join-Path $InstallDir 'requirements.txt') }
Write-Ok '확인 완료'

Write-Step '[3/3] 실행 중인 프로세스 재시작'
# install.ps1의 "지금 바로 시작" 단계와 동일한 이유: 방금 받은 새 코드는
# 이미 떠 있는 python.exe/caddy.exe에 저절로 반영되지 않는다. 이 설치
# 폴더가 직접 기록한 run\status.json만 사용하므로(다른 PC나 무관한
# 프로세스는 절대 건드리지 않음) 안전하다.
$statusFile = Join-Path $InstallDir 'run\status.json'
if (Test-Path $statusFile) {
    try {
        $prevStatus = Get-Content $statusFile -Raw | ConvertFrom-Json
        foreach ($p in @($prevStatus.supervisorPid, $prevStatus.backend.pid, $prevStatus.caddy.pid)) {
            if ($p) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }
        }
        Remove-Item (Join-Path $InstallDir 'run\supervisor.lock') -ErrorAction SilentlyContinue
        Write-Ok '기존에 실행 중이던 프로세스를 종료했습니다'
        Start-Sleep -Seconds 2
    } catch {
        Write-Warn2 "기존 프로세스 종료 중 문제가 있었습니다 (무시하고 계속합니다): $_"
    }
} else {
    Write-Warn2 '실행 중인 상태 정보를 찾지 못했습니다 (처음부터 꺼져 있었을 수 있습니다). 계속 진행합니다.'
}
Start-Process powershell -ArgumentList @(
    '-NoProfile', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $InstallDir 'ops\supervisor.ps1')
) -WorkingDirectory $InstallDir
Start-Sleep -Seconds 4
Write-Ok 'InfraSight를 새 코드로 다시 시작했습니다'

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " 패치 완료 (커밋 $headNow)" -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Green

} catch {
    Write-Host "`n============================================================" -ForegroundColor Red
    Write-Host ' 패치 적용 중 오류가 발생했습니다' -ForegroundColor Red
    Write-Host " $_" -ForegroundColor Red
    Write-Host '============================================================' -ForegroundColor Red
} finally {
    Write-Host "`n아무 키나 누르면 창이 닫힙니다..." -ForegroundColor DarkGray
    [void][System.Console]::ReadKey($true)
}
