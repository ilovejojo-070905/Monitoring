<#
InfraSight 제거 스크립트
========================
이 PC에 설치된 InfraSight를 깨끗하게 제거한다:
  - 실행 중인 프로세스(백엔드 + Caddy) 정상 종료
  - 자동 시작 작업(예약 작업) 해제
  - 방화벽 인바운드 규칙 제거 (install.ps1이 연 것과 동일한 4개)
  - 원격 접속(SSH/Telnet) Native Messaging Host 등록 해제 + 관련 파일 삭제
  - (확인 후) 설치 폴더 전체 삭제 -- 데이터베이스(등록 장비/알림 이력/계정)
    포함이라 되돌릴 수 없음. 기본적으로 지우기 전에 DB만 바탕화면에 백업한다.

이 스크립트가 **건드리지 않는** 것 (다른 프로그램이 같이 쓸 수 있어서):
  - winget으로 설치된 Git / Python / Caddy / mkcert / PuTTY 자체
  - mkcert가 이 PC에 등록해둔 로컬 CA 신뢰 (다른 로컬 개발 인증서에도 쓰일 수 있음)
  - Chrome에 직접 "압축해제된 확장 프로그램"으로 로드해둔 확장 프로그램 자체
    (chrome://extensions에서 직접 제거해야 함 -- InfraSight 폴더 밖에 있어서
    이 스크립트가 어디 있는지 알 방법이 없음)

사용법:
    powershell -ExecutionPolicy Bypass -File uninstall.ps1
    powershell -ExecutionPolicy Bypass -File uninstall.ps1 -InstallDir "D:\InfraSight"
    powershell -ExecutionPolicy Bypass -File uninstall.ps1 -NoBackup   # DB 백업 생략
    powershell -ExecutionPolicy Bypass -File uninstall.ps1 -Force      # 확인 문구 입력 없이 바로 삭제 (주의)
#>
param(
    [string]$InstallDir,
    [switch]$NoBackup,
    [switch]$Force
)

$ErrorActionPreference = 'Continue'

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg" -ForegroundColor Yellow }

try {

Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' InfraSight 제거' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan

# ------------------------------------------------------ [1] 설치 폴더 --
Write-Step '[1/7] 설치 폴더 확인'
if (-not $InstallDir) { $InstallDir = Join-Path $env:LOCALAPPDATA 'InfraSight' }
while (-not (Test-Path (Join-Path $InstallDir 'server.py'))) {
    Write-Warn2 "InfraSight 설치 폴더를 찾을 수 없습니다: $InstallDir"
    $InstallDir = Read-Host 'InfraSight가 설치된 폴더 경로를 입력해주세요 (취소하려면 Ctrl+C)'
}
Write-Ok "설치 폴더: $InstallDir"

# --------------------------------------------------- [2] 프로세스 종료 --
Write-Step '[2/7] 실행 중인 프로세스 종료'
$stopScript = Join-Path $InstallDir 'ops\stop.ps1'
if (Test-Path $stopScript) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $stopScript
} else {
    Write-Warn2 'ops\stop.ps1을 찾을 수 없어 건너뜁니다 (이미 실행 중이 아니라면 문제 없음).'
}

# ------------------------------------------------- [3] 자동 시작 해제 --
Write-Step '[3/7] 로그온 자동 시작 해제'
$unregScript = Join-Path $InstallDir 'ops\unregister-task.ps1'
if (Test-Path $unregScript) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $unregScript
} else {
    Write-Warn2 'ops\unregister-task.ps1을 찾을 수 없어 건너뜁니다.'
}

# ----------------------------------------------------- [4] 방화벽 규칙 --
Write-Step '[4/7] 방화벽 인바운드 규칙 제거'
$ruleNames = @(
    'InfraSight HTTPS (Caddy)',
    'InfraSight HTTP (agents)',
    'InfraSight NetFlow (UDP)',
    'InfraSight sFlow (UDP)'
)
foreach ($name in $ruleNames) {
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
        Write-Ok "제거됨: $name"
    }
}

# --------------------------------------------- [5] 원격 접속 구성 해제 --
# ops\setup-remote-access.ps1이 만든 것들 -- InstallDir이 아니라
# %LOCALAPPDATA%\InfraSight라는 고정 위치(이 PC 로그온 계정 기준)에 있다.
Write-Step '[5/7] 원격 접속(SSH/Telnet) 구성 해제'
$regKeyPath = 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.infrasight.remote'
if (Test-Path $regKeyPath) {
    Remove-Item $regKeyPath -Force -ErrorAction SilentlyContinue
    Write-Ok 'Native Messaging Host 레지스트리 등록 해제됨'
}
$remoteBase = Join-Path $env:LOCALAPPDATA 'InfraSight'
foreach ($sub in @('native-host', 'extension')) {
    $p = Join-Path $remoteBase $sub
    if (Test-Path $p) {
        Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "삭제됨: $p"
    }
}
Write-Warn2  'Chrome에 직접 로드해둔 확장 프로그램은 chrome://extensions에서 따로 제거해주세요 (이 스크립트가 어디 있는지 알 수 없음).'

# --------------------------------------------------------- [6] 백업 --
Write-Step '[6/7] 삭제 전 데이터베이스 백업'
$dbPath = Join-Path $InstallDir 'infrasight.db'
if (-not $NoBackup -and (Test-Path $dbPath)) {
    $backupName = "infrasight-db-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').db"
    $backupPath = Join-Path ([Environment]::GetFolderPath('Desktop')) $backupName
    Copy-Item $dbPath $backupPath -ErrorAction SilentlyContinue
    if (Test-Path $backupPath) {
        Write-Ok "바탕화면에 백업됨: $backupName"
    } else {
        Write-Warn2 '백업에 실패했습니다 (그래도 계속 진행합니다).'
    }
} elseif ($NoBackup) {
    Write-Warn2 '-NoBackup 지정됨 -- 백업을 건너뜁니다.'
} else {
    Write-Warn2 '데이터베이스 파일을 찾을 수 없어 백업을 건너뜁니다.'
}

# ----------------------------------------------- [7] 설치 폴더 삭제 --
Write-Step '[7/7] 설치 폴더 삭제'
Write-Host ''
Write-Host "    아래 폴더와 그 안의 모든 내용(데이터베이스, 인증서, 로그 포함)을" -ForegroundColor Yellow
Write-Host "    완전히 삭제합니다. 되돌릴 수 없습니다:" -ForegroundColor Yellow
Write-Host "      $InstallDir" -ForegroundColor Yellow
Write-Host ''

if (-not $Force) {
    $confirm = Read-Host '계속하려면 정확히 "삭제"를 입력하세요 (다른 입력은 모두 취소)'
    if ($confirm -ne '삭제') {
        Write-Warn2 '취소되었습니다. 설치 폴더는 그대로 남아있습니다.'
        Write-Host "`n아무 키나 누르면 창이 닫힙니다..." -ForegroundColor DarkGray
        try { [void][System.Console]::ReadKey($true) } catch { Start-Sleep -Seconds 3 }
        exit 0
    }
}

Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path $InstallDir) {
    Write-Warn2 "일부 파일이 삭제되지 않았습니다 (다른 프로그램이 사용 중일 수 있음): $InstallDir"
    Write-Warn2 '해당 폴더를 직접 확인 후 남은 파일을 지워주세요.'
} else {
    Write-Ok '설치 폴더 삭제 완료'
}

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host ' InfraSight 제거가 완료되었습니다.' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Green
Write-Host "`n참고: Git/Python/Caddy/mkcert/PuTTY 자체와 mkcert의 로컬 CA 신뢰는" -ForegroundColor DarkGray
Write-Host "그대로 남아있습니다 (다른 프로그램이 쓰고 있을 수 있어 건드리지 않습니다)." -ForegroundColor DarkGray

Write-Host "`n아무 키나 누르면 창이 닫힙니다..." -ForegroundColor DarkGray
try { [void][System.Console]::ReadKey($true) } catch { Start-Sleep -Seconds 3 }

} catch {
    Write-Host "`n============================================================" -ForegroundColor Red
    Write-Host ' 제거 중 오류가 발생했습니다' -ForegroundColor Red
    Write-Host " $_" -ForegroundColor Red
    Write-Host '============================================================' -ForegroundColor Red
    Write-Host "`n아무 키나 누르면 창이 닫힙니다..." -ForegroundColor DarkGray
    try { [void][System.Console]::ReadKey($true) } catch { Start-Sleep -Seconds 3 }
}
