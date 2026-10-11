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

if (Test-Path $LockFile) {
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
    }
    Remove-Item $LockFile -ErrorAction SilentlyContinue
} else {
    Write-Host "이 설치 자신의 supervisor는 실행 중이 아닙니다 (lock 파일 없음)."
}

# lock 파일 유무와 무관하게 항상 이름/커맨드라인으로 한 번 더 정리한다 --
# 실측으로 겪은 문제: 전혀 다른(또는 훨씬 예전) 설치에서 남겨진 Caddy/백엔드
# 프로세스가 이 설치의 lock 파일과는 아예 무관하게 8443/5057 포트를 계속
# 쥐고 있어서, "lock 파일 없음 = 아무것도 안 돈다"는 가정이 틀렸다 (한 PC에서
# 10월 1일에 시작된 캐디 프로세스가 그 이후 여러 번의 재설치를 전부 무사히
# 통과해 계속 포트를 쥐고 있던 게 실제로 확인됨 -- 매번 이 설치 자신의 lock
# 파일만 보고 "실행 중 아님"으로 판단해 조용히 건너뛰었던 것). InfraSight는
# 머신당 하나만 돌아가게 설계되어 있으므로(포트가 고정) 이름/커맨드라인으로
# 걸리는 건 이 설치 소유든 아니든 전부 정리하는 게 맞다.
Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*server.py*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Get-Process caddy -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Remove-Item $StopMarker -ErrorAction SilentlyContinue
Write-Host "InfraSight를 종료했습니다."
