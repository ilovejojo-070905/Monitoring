<#
Shows whether InfraSight's supervisor / backend / Caddy are currently
running, and the most recent supervisor log lines.
#>

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$RunDir      = Join-Path $ProjectRoot 'run'
$LogFile     = Join-Path $ProjectRoot 'logs\supervisor.log'
$LockFile    = Join-Path $RunDir 'supervisor.lock'
$StatusFile  = Join-Path $RunDir 'status.json'

Write-Host "=== InfraSight 상태 ===" -ForegroundColor Cyan

$supervisorPid = if (Test-Path $LockFile) { Get-Content $LockFile -ErrorAction SilentlyContinue | Select-Object -First 1 } else { $null }
$supervisorAlive = $supervisorPid -and (Get-Process -Id $supervisorPid -ErrorAction SilentlyContinue)

if ($supervisorAlive) {
    Write-Host "Supervisor: 실행 중 (PID $supervisorPid)" -ForegroundColor Green
} else {
    Write-Host "Supervisor: 실행 중이 아님" -ForegroundColor Red
}

if (Test-Path $StatusFile) {
    try {
        $s = Get-Content $StatusFile -Raw | ConvertFrom-Json
        $age = ((Get-Date) - [datetime]$s.updatedAt).TotalSeconds
        $fresh = $age -lt 30
        $tag = if ($fresh) { '' } else { ' (정보가 오래됨 -- supervisor가 멈췄을 수 있음)' }
        $beOk = $s.backend.alive
        $cdOk = $s.caddy.alive
        Write-Host ("Backend   : {0} (PID {1}){2}" -f $(if($beOk){'실행 중'}else{'중지됨'}), $s.backend.pid, $tag) -ForegroundColor $(if($beOk){'Green'}else{'Red'})
        Write-Host ("Caddy     : {0} (PID {1}){2}" -f $(if($cdOk){'실행 중'}else{'중지됨'}), $s.caddy.pid, $tag) -ForegroundColor $(if($cdOk){'Green'}else{'Red'})
    } catch {
        Write-Host "status.json을 읽는 데 실패했습니다: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "Backend/Caddy: 상태 파일 없음 (supervisor 미실행)" -ForegroundColor Yellow
}

$task = Get-ScheduledTask -TaskName 'InfraSight Supervisor' -ErrorAction SilentlyContinue
if ($task) {
    Write-Host "자동 시작 등록: 되어 있음 (상태: $($task.State))" -ForegroundColor Green
} else {
    Write-Host "자동 시작 등록: 안 되어 있음 -- ops\register-task.ps1 실행 필요" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== 최근 로그 (logs\supervisor.log) ===" -ForegroundColor Cyan
if (Test-Path $LogFile) {
    Get-Content $LogFile -Tail 20
} else {
    Write-Host "(로그 파일이 아직 없습니다)"
}
