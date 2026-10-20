<#
InfraSight 에이전트 제거 스크립트 (Windows)
============================================
이 PC에서 돌아가는 InfraSight 에이전트를 깨끗하게 제거한다:
  - 실행 중인 InfraSightAgent.exe 프로세스 종료
  - 로그온 자동 시작 등록 해제 (시작프로그램 폴더의 .vbs/레거시 .bat)
  - 설치 폴더 삭제 (%LOCALAPPDATA%\InfraSightAgent -- 복사된 실행 파일 +
    설정 파일, agent.py의 relocate_and_relaunch_if_needed/config_path가
    쓰는 바로 그 폴더)

관리자 권한이 필요 없다 -- 에이전트 설치 자체가 처음부터 전부 현재
사용자 범위(%LOCALAPPDATA%, 개인 시작프로그램 폴더) 안에서만 동작하기
때문에(uninstall.ps1의 InfraSight 서버 쪽과 달리 예약 작업/방화벽 규칙이
없음), 이 스크립트도 동일하게 관리자 권한 없이 동작한다.

사용법:
    powershell -ExecutionPolicy Bypass -File uninstall-agent.ps1
    powershell -ExecutionPolicy Bypass -File uninstall-agent.ps1 -Force   # 확인 없이 바로 삭제
#>
param(
    [switch]$Force
)

$ErrorActionPreference = 'Continue'

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg" -ForegroundColor Yellow }

try {

Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' InfraSight 에이전트 제거' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan

$installDir = Join-Path $env:LOCALAPPDATA 'InfraSightAgent'
$startupDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'

if (-not $Force) {
    Write-Host ''
    Write-Host '    이 PC에서 InfraSight 에이전트를 제거합니다:' -ForegroundColor Yellow
    Write-Host '      - 실행 중인 에이전트 프로세스 종료' -ForegroundColor Yellow
    Write-Host '      - 로그온 자동 시작 등록 해제' -ForegroundColor Yellow
    Write-Host "      - 설치 폴더 삭제: $installDir" -ForegroundColor Yellow
    Write-Host ''
    $confirm = Read-Host '계속하려면 정확히 "삭제"를 입력하세요 (다른 입력은 모두 취소)'
    if ($confirm -ne '삭제') {
        Write-Warn2 '취소되었습니다.'
        Write-Host "`n아무 키나 누르면 창이 닫힙니다..." -ForegroundColor DarkGray
        try { [void][System.Console]::ReadKey($true) } catch { Start-Sleep -Seconds 3 }
        exit 0
    }
}

Write-Step '[1/3] 실행 중인 프로세스 종료'
$procs = Get-Process -Name 'InfraSightAgent' -ErrorAction SilentlyContinue
if ($procs) {
    $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Write-Ok "종료됨 ($($procs.Count)개 프로세스)"
} else {
    Write-Ok '실행 중인 프로세스가 없습니다.'
}

Write-Step '[2/3] 로그온 자동 시작 해제'
$removed = $false
foreach ($name in @('InfraSightAgent.vbs', 'InfraSightAgent.bat')) {
    $p = Join-Path $startupDir $name
    if (Test-Path $p) {
        Remove-Item $p -Force -ErrorAction SilentlyContinue
        $removed = $true
    }
}
if ($removed) { Write-Ok '자동 시작 등록 해제됨' } else { Write-Ok '등록된 자동 시작이 없습니다.' }

Write-Step '[3/3] 설치 폴더 삭제'
if (Test-Path $installDir) {
    Remove-Item $installDir -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $installDir)) {
        Write-Ok "삭제 완료: $installDir"
    } else {
        Write-Warn2 "일부 파일이 삭제되지 않았습니다 (에이전트가 아직 실행 중일 수 있습니다): $installDir"
    }
} else {
    Write-Ok '설치 폴더가 이미 없습니다.'
}

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host ' 에이전트 제거가 완료되었습니다.' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Green
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
