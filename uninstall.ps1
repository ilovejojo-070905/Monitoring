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

# ---------------------------------------------------------------- elevation --
# install.ps1과 동일한 이유로 필요하다 -- 예약 작업 해제(Unregister-ScheduledTask)와
# 방화벽 규칙 제거는 관리자 권한이 있어야 한다. 실측 확인: 관리자 권한 없이
# 돌렸더니 Unregister-ScheduledTask가 "액세스가 거부되었습니다"로 조용히
# 실패했는데, 그 뒤에 무조건 찍히던 "해제했습니다" 메시지 때문에 실제로는
# 작업이 그대로 남아있는데도 성공한 것처럼 보였다 (이 메시지 자체도 아래에서
# 같이 고침).
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-Admin)) {
    Write-Host "관리자 권한이 필요합니다 (예약 작업 해제 · 방화벽 규칙 제거). UAC 승인 창을 확인해주세요..." -ForegroundColor Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    if ($InstallDir) { $argList += @('-InstallDir', $InstallDir) }
    if ($NoBackup)   { $argList += '-NoBackup' }
    if ($Force)      { $argList += '-Force' }
    try {
        Start-Process powershell -Verb RunAs -ArgumentList $argList -Wait
    } catch {
        Write-Host "`n관리자 권한 승인이 취소되었거나 실패했습니다." -ForegroundColor Red
        Write-Host "이 파일을 다시 실행한 뒤, UAC 창에서 '예'를 눌러주세요." -ForegroundColor Yellow
        Write-Host "`n아무 키나 누르면 창이 닫힙니다..." -ForegroundColor DarkGray
        try { [void][System.Console]::ReadKey($true) } catch { Start-Sleep -Seconds 3 }
    }
    exit
}

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
        try {
            Remove-NetFirewallRule -DisplayName $name -ErrorAction Stop
            Write-Ok "제거됨: $name"
        } catch {
            Write-Warn2 "제거 실패: $name ($_)"
        }
    }
}

# --------------------------------------------- [5] 원격 접속 구성 해제 --
# ops\setup-remote-access.ps1이 만든 것들 -- InstallDir이 아니라
# %LOCALAPPDATA%\InfraSight라는 고정 위치(이 PC 로그온 계정 기준)에 있다.
Write-Step '[5/7] 원격 접속(SSH/Telnet) 구성 해제'
$regKeyPath = 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.infrasight.remote'
if (Test-Path $regKeyPath) {
    Remove-Item $regKeyPath -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $regKeyPath)) {
        Write-Ok 'Native Messaging Host 레지스트리 등록 해제됨'
    } else {
        Write-Warn2 '레지스트리 등록 해제에 실패했습니다.'
    }
}
$remoteBase = Join-Path $env:LOCALAPPDATA 'InfraSight'
foreach ($sub in @('native-host', 'extension')) {
    $p = Join-Path $remoteBase $sub
    if (Test-Path $p) {
        Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $p)) {
            Write-Ok "삭제됨: $p"
        } else {
            Write-Warn2 "삭제 실패: $p"
        }
    }
}
Write-Warn2  'Chrome에 직접 로드해둔 확장 프로그램은 chrome://extensions에서 따로 제거해주세요 (이 스크립트가 어디 있는지 알 수 없음).'

# --------------------------------------------------------- [6] 백업 --
Write-Step '[6/7] 삭제 전 데이터베이스 + 암호화 키 백업'
# infrasight.db 백업만으로는 부족하다 -- 장비 SSH/SNMP 접속 정보 같은
# credentials 테이블 값은 DB 안에 평문이 아니라, DB와는 별도 파일인
# .infrasight_credentials_key(Fernet 키)로 암호화되어 있다
# (secrets_crypto.py 자신의 주석: "DB 백업만 있고 이 키가 없으면 무용지물").
# 이 키 없이 DB만 복원하면 그 장비 자격증명들은 영구히 복호화할 수 없게
# 된다 -- 새로 설치하면서 새 키가 생성되기 전에 반드시 같이 챙겨야 한다.
# .infrasight_secret_key(Flask 세션 서명 키)는 잃어도 전체 재로그인 정도로
# 끝나는 문제라 치명적이진 않지만, 같이 백업해두면 재설치 후 세션 끊김 없이
# 넘어갈 수 있어 같이 챙긴다.
$backupTargets = @(
    (Join-Path $InstallDir 'infrasight.db'),
    (Join-Path $InstallDir '.infrasight_credentials_key'),
    (Join-Path $InstallDir '.infrasight_secret_key')
)
if (-not $NoBackup) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backupDir = Join-Path ([Environment]::GetFolderPath('Desktop')) "infrasight-backup-$stamp"
    $anyBackedUp = $false
    foreach ($f in $backupTargets) {
        if (Test-Path $f) {
            if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Force -Path $backupDir | Out-Null }
            Copy-Item $f (Join-Path $backupDir (Split-Path $f -Leaf)) -ErrorAction SilentlyContinue
            $anyBackedUp = $true
        }
    }
    if ($anyBackedUp) {
        Write-Ok "바탕화면에 백업됨: infrasight-backup-$stamp\ (DB + 암호화 키)"
        Write-Warn2 '재설치 후 기존 데이터를 그대로 쓰려면, 새로 설치된 폴더에 이 백업 폴더 안의 파일들을 전부 덮어써주세요 (첫 로그인 전에).'
    } else {
        Write-Warn2 '백업할 파일을 찾지 못했습니다 (그래도 계속 진행합니다).'
    }
} else {
    Write-Warn2 '-NoBackup 지정됨 -- 백업을 건너뜁니다.'
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
