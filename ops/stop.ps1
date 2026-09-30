<#
Stops the InfraSight supervisor (and, through it, the backend + Caddy)
cleanly -- this is what makes the shutdown "normal" instead of "crashed" in
supervisor.log. Safe to run even if nothing is currently running.
#>

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$RunDir      = Join-Path $ProjectRoot 'run'
$LockFile    = Join-Path $RunDir 'supervisor.lock'
$StopMarker  = Join-Path $RunDir 'stop.marker'

New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

if (-not (Test-Path $LockFile)) {
    Write-Host "supervisor가 실행 중이 아닙니다 (lock 파일 없음)."
    exit 0
}

"stop requested $(Get-Date -Format 's')" | Out-File -FilePath $StopMarker -Encoding utf8 -Force
Write-Host "종료 요청을 보냈습니다. supervisor가 정리할 때까지 기다립니다..."

$deadline = (Get-Date).AddSeconds(30)
while ((Test-Path $LockFile) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 1
}

if (Test-Path $LockFile) {
    Write-Host "30초 안에 정상 종료되지 않아 강제로 정리합니다."
    $lockPid = Get-Content $LockFile -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($lockPid) { Stop-Process -Id $lockPid -Force -ErrorAction SilentlyContinue }
    Get-Process python  -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*Python314*' } | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-Process caddy   -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item $LockFile -ErrorAction SilentlyContinue
}

Remove-Item $StopMarker -ErrorAction SilentlyContinue
Write-Host "InfraSight를 종료했습니다."
