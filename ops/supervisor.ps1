<#
InfraSight supervisor
=====================
Keeps the Flask backend (server.py) and the Caddy HTTPS reverse proxy running:
starts both, watches them, and restarts whichever one dies unexpectedly. Meant
to be launched once at Windows logon (see register-task.ps1) and left running
in the background for the whole session -- it IS the "run InfraSight" step
from then on; start.bat / start-https.bat still work for manual/debug runs,
they just aren't watched or auto-restarted.

Stopping it on purpose: run stop.ps1 (or the InfraSight-Stop shortcut it
creates). That is the ONLY normal way this should ever end -- anything else
(closed window, killed process, crash) is logged as abnormal.
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path $PSScriptRoot -Parent

# Resolved from PATH rather than hardcoded (portability pass): this file used
# to hardcode this machine's exact python.exe/caddy.exe locations (including
# the WinGet package's hash-named folder for Caddy), which broke silently on
# any other PC -- different Windows username, different WinGet package hash,
# or a Python installed to a different path. `Get-Command` finds whatever
# `python`/`caddy` already resolve to in a normal shell on THIS machine too
# (verified identical), so this is a no-op here and just portable elsewhere.
$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
$CaddyExe  = (Get-Command caddy  -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) { throw "python.exe를 PATH에서 찾을 수 없습니다. Python 설치 후 PATH에 추가되어 있는지 확인하세요." }
if (-not $CaddyExe)  { throw "caddy.exe를 PATH에서 찾을 수 없습니다. Caddy 설치 후 PATH에 추가되어 있는지 확인하세요 (예: winget install CaddyServer.Caddy)." }

$RunDir      = Join-Path $ProjectRoot 'run'
$LogDir      = Join-Path $ProjectRoot 'logs'
$LockFile    = Join-Path $RunDir 'supervisor.lock'
$StopMarker  = Join-Path $RunDir 'stop.marker'
$LogFile     = Join-Path $LogDir 'supervisor.log'
$StatusFile  = Join-Path $RunDir 'status.json'
$RestartHistoryFile = Join-Path $RunDir 'restart-history.json'

$PollSeconds        = 5
$CrashWindowSeconds = 120   # count crashes within this rolling window...
$CrashLimit         = 5     # ...and if this many happen, back off instead of tight-looping
$BackoffSeconds     = 300

New-Item -ItemType Directory -Force -Path $RunDir, $LogDir | Out-Null

function Write-Log([string]$Level, [string]$Message) {
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogFile -Value $line -Encoding utf8
}

# 신규(2026-10-17, "Supervisor의 재시작 횟수와 실패 원인을 기록한다"):
# 이전엔 재시작 "횟수"가 $crashTimes/$backoffUntil라는 변수 두 개뿐이고,
# 그마저 supervisor.ps1 자신이 재시작되면(재부팅 등) 그냥 사라졌다 --
# 누적 횟수가 아니라 "지금 이 supervisor 프로세스가 떠 있는 동안"만
# 유효한 값이었음. 실패 "원인"도 supervisor.log 텍스트 줄로만 남아서,
# 프로그램으로 조회하거나 화면에 보여줄 방법이 없었다. run\
# restart-history.json에 누적 횟수+최근 사유를 영구히(supervisor
# 재시작을 거쳐도) 남기고, status.json을 통해 매번 같이 내보낸다.
function Load-RestartHistory {
    if (Test-Path $RestartHistoryFile) {
        try {
            $loaded = Get-Content $RestartHistoryFile -Raw | ConvertFrom-Json
            if ($loaded.backend -and $loaded.caddy) { return $loaded }
        } catch {}
    }
    return [pscustomobject]@{
        backend = [pscustomobject]@{ totalRestarts = 0; lastReason = $null; lastAt = $null }
        caddy   = [pscustomobject]@{ totalRestarts = 0; lastReason = $null; lastAt = $null }
    }
}
$script:restartHistory = Load-RestartHistory

function Save-RestartHistory {
    try { $script:restartHistory | ConvertTo-Json -Depth 5 | Set-Content -Path $RestartHistoryFile -Encoding utf8 } catch {}
}

function Register-Restart([string]$name, [string]$reason) {
    $script:restartHistory.$name.totalRestarts = [int]$script:restartHistory.$name.totalRestarts + 1
    $script:restartHistory.$name.lastReason = $reason
    $script:restartHistory.$name.lastAt = (Get-Date).ToString('s')
    Save-RestartHistory
}

# ---------- duplicate-run guard ----------
# Two supervisor implementations can exist on the same machine now: this
# script (the git-clone/dev deployment) and installer.py's run_supervise()
# (the one-click InfraSight.exe deployment) -- both point at the same
# run/supervisor.lock when installed to the same folder. This used to only
# recognize a PID whose process path contained "powershell", so a still-alive
# PID belonging to the *other* implementation (python.exe / InfraSight.exe)
# was wrongly treated as stale, and this script would start its own
# Backend+Caddy on top of the other's -- a silent double-bind of 5057/8443.
# Liveness alone (matching installer.py's own guard) is what actually
# matters here; the lock file's second line is only for clearer logging.
# First attempt (CreateNew-only, atomic at the OS level) fixed the common
# case live, but a second bug showed up right after: when the lock WAS
# stale (old PID dead), recovery was "delete it, then CreateNew again" --
# two separate steps, not one. Two processes that both detect the exact
# same stale lock each independently delete-then-recreate, and since
# neither re-checks whether the file it's about to delete is still the
# stale one it inspected (or has since become a DIFFERENT process's
# freshly-won lock), either order lets both win: confirmed live, three
# supervisor.ps1 instances started within 6 seconds of each other, all
# past the guard, two of them presumably deleting a lock a sibling had
# *just* legitimately claimed. FileShare.None on OpenOrCreate is the fix:
# it's a single handle that EXCLUDES every other process (new lock or
# stale-recovery alike) for the entire span from "open it" to "write our
# own PID and close it" -- there's no longer a gap between inspecting the
# old PID and claiming the file for another process to slip into.
function Try-AcquireLock {
    try {
        $fs = [System.IO.File]::Open($LockFile, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    } catch [System.IO.IOException] {
        return $false  # someone else currently holds this exact handle
    }
    try {
        $existingPid = $null
        if ($fs.Length -gt 0) {
            $buf = New-Object byte[] $fs.Length
            [void]$fs.Read($buf, 0, $buf.Length)
            $existingPid = ([System.Text.Encoding]::ASCII.GetString($buf) -split "`n")[0].Trim()
        }
        if ($existingPid -and $existingPid -match '^\d+$') {
            if (Get-Process -Id $existingPid -ErrorAction SilentlyContinue) {
                return $false  # genuinely still running -- not ours to take
            }
            Write-Log 'WARN' "이전 lock 파일이 남아있었지만 해당 PID($existingPid)는 더 이상 실행 중이 아닙니다. 새로 시작합니다."
        }
        $fs.SetLength(0)
        $fs.Position = 0
        $bytes = [System.Text.Encoding]::ASCII.GetBytes("$PID`nps1`n")
        $fs.Write($bytes, 0, $bytes.Length)
        $fs.Flush()
        return $true
    } finally {
        $fs.Dispose()
    }
}

if (-not (Try-AcquireLock)) {
    Write-Log 'INFO' "이미 실행 중인 supervisor를 발견해 이번 실행은 종료합니다 (중복 실행 방지)."
    exit 0
}
Remove-Item $StopMarker -ErrorAction SilentlyContinue

Write-Log 'INFO' "===== supervisor 시작 (PID $PID) ====="

# ---------- process management ----------
$backend = $null
$caddy = $null
$crashTimes   = @{ backend = @();   caddy = @()   }
$backoffUntil = @{ backend = $null; caddy = $null }

# ---------- hang (먹통) detection, 2026-10-16 ----------
# 실제로 겪은 사각지대: Test-Alive는 프로세스가 "완전히 죽었는지"만 보기
# 때문에, 내부 작업(APScheduler job)이 교착되거나 Flask가 응답만 느려지고
# 안 죽어 있으면 이 스크립트는 영원히 "정상"으로 본다. /api/system/
# health-public(server.py, 인증 없이 호출 가능하도록 새로 추가됨)을
# 주기적으로 불러서 web/database/collector가 전부 'up'인지 직접 확인하고,
# 몇 번 연속으로 실패하면 "살아있지만 먹통"으로 판단해 강제로 죽인다 --
# 그다음은 아래 기존 Test-Alive 블록이 "죽은 걸 감지 -> Register-Crash ->
# 재시작"을 그대로 처리하므로, 먹통 감지는 "죽이기"만 하고 재시작 로직은
# 중복으로 안 만듦.
$HealthCheckGraceSec    = 30  # 막 시작한 프로세스는 초기화 중일 수 있어 이 기간은 확인 안 함
$HealthCheckIntervalSec = 30
$HealthFailLimit        = 3   # 연속 실패 횟수 -- 한 번의 일시적 지연으로 재시작하지 않도록
$backendStartedAt = $null
$lastHealthCheckAt = $null
$healthFailCount = 0

function Test-BackendHealthy {
    try {
        $resp = Invoke-RestMethod -Uri 'https://localhost:8443/api/system/health-public' -TimeoutSec 5 -ErrorAction Stop
        # 신규(2026-10-17, "Flask, 스케줄러, 수집기, 알림 엔진... 상태를
        # 구분한다"): scheduler/alerts도 같이 확인 -- 이전엔 collector만
        # 봐서, 장비 polling은 멀쩡한데 알림 엔진(에스컬레이션/재시도 큐)
        # 이나 배치 작업(백업/보존/인증서 확인)만 교착된 경우는 전혀 못
        # 잡았다. 둘 다 같은 Flask 프로세스 안에서 도는 백그라운드
        # 작업이라, collector 먹통과 똑같이 프로세스 재시작으로 풀린다.
        return ($resp.web -eq 'up' -and $resp.database -eq 'up' -and $resp.collector -eq 'up' `
                -and $resp.scheduler -eq 'up' -and $resp.alerts -eq 'up')
    } catch {
        return $false
    }
}

function Start-Backend {
    $p = Start-Process -FilePath $PythonExe -ArgumentList 'server.py' -WorkingDirectory $ProjectRoot `
        -WindowStyle Hidden -PassThru
    Write-Log 'INFO' "Backend 시작됨 (PID $($p.Id))"
    $script:backendStartedAt = Get-Date
    $script:healthFailCount = 0
    return $p
}

function Start-Caddy {
    $p = Start-Process -FilePath $CaddyExe -ArgumentList 'run', '--config', 'Caddyfile' -WorkingDirectory $ProjectRoot `
        -WindowStyle Hidden -PassThru
    Write-Log 'INFO' "Caddy 시작됨 (PID $($p.Id))"
    return $p
}

function Test-Alive($proc) {
    if (-not $proc) { return $false }
    return [bool](Get-Process -Id $proc.Id -ErrorAction SilentlyContinue)
}

# $true if the caller should (re)start the process now, $false if it's
# cooling down after crashing too many times in a row.
function Test-ShouldRestart([string]$name) {
    $now = Get-Date
    if ($backoffUntil[$name]) {
        if ($now -lt $backoffUntil[$name]) { return $false }
        # cooldown elapsed -- clear it and give it a fresh window
        $backoffUntil[$name] = $null
        $crashTimes[$name] = @()
    }
    return $true
}

function Register-Crash([string]$name) {
    $now = Get-Date
    $crashTimes[$name] = @($crashTimes[$name] | Where-Object { ($now - $_).TotalSeconds -le $CrashWindowSeconds }) + $now
    if ($crashTimes[$name].Count -ge $CrashLimit -and -not $backoffUntil[$name]) {
        $backoffUntil[$name] = $now.AddSeconds($BackoffSeconds)
        Write-Log 'ERROR' "$name 이(가) 최근 $CrashWindowSeconds 초 동안 $CrashLimit 회 이상 종료되었습니다. ${BackoffSeconds}초 동안 재시작을 멈추고 지켜봅니다."
    }
}

function Write-Status {
    $status = [ordered]@{
        supervisorPid = $PID
        updatedAt     = (Get-Date).ToString('s')
        backend       = [ordered]@{
            pid = $backend.Id; alive = (Test-Alive $backend)
            totalRestarts = $script:restartHistory.backend.totalRestarts
            lastRestartReason = $script:restartHistory.backend.lastReason
            lastRestartAt = $script:restartHistory.backend.lastAt
        }
        caddy         = [ordered]@{
            pid = $caddy.Id; alive = (Test-Alive $caddy)
            totalRestarts = $script:restartHistory.caddy.totalRestarts
            lastRestartReason = $script:restartHistory.caddy.lastReason
            lastRestartAt = $script:restartHistory.caddy.lastAt
        }
    }
    $status | ConvertTo-Json -Depth 5 | Set-Content -Path $StatusFile -Encoding utf8
}

try {
    $backend = Start-Backend
    $caddy = Start-Caddy
    Write-Status

    while ($true) {
        Start-Sleep -Seconds $PollSeconds

        if (Test-Path $StopMarker) {
            Write-Log 'INFO' "정상 종료 요청 감지 (stop.marker). Backend/Caddy를 종료합니다."
            foreach ($p in @($backend, $caddy)) {
                if (Test-Alive $p) {
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                }
            }
            Remove-Item $StopMarker -ErrorAction SilentlyContinue
            Write-Log 'INFO' "정상 종료 완료. ===== supervisor 종료 ====="
            break
        }

        if (-not (Test-Alive $backend)) {
            Write-Log 'WARN' "Backend가 비정상 종료된 것을 감지했습니다 (이전 PID $($backend.Id))."
            Register-Crash 'backend'
            Register-Restart 'backend' '비정상 종료 감지 (프로세스가 스스로 꺼짐)'
            if (Test-ShouldRestart 'backend') { $backend = Start-Backend }
        } elseif (-not (Test-Path $StopMarker)) {
            $sinceStart = ((Get-Date) - $backendStartedAt).TotalSeconds
            $sinceLastCheck = if ($lastHealthCheckAt) { ((Get-Date) - $lastHealthCheckAt).TotalSeconds } else { [double]::MaxValue }
            if ($sinceStart -ge $HealthCheckGraceSec -and $sinceLastCheck -ge $HealthCheckIntervalSec) {
                $lastHealthCheckAt = Get-Date
                if (Test-BackendHealthy) {
                    $healthFailCount = 0
                } else {
                    $healthFailCount++
                    Write-Log 'WARN' "Backend 상태 확인 실패 ($healthFailCount/$HealthFailLimit) -- 프로세스는 살아있지만 응답이 없거나 비정상입니다."
                    if ($healthFailCount -ge $HealthFailLimit) {
                        Write-Log 'ERROR' "Backend가 먹통 상태로 판단되어 강제로 재시작합니다 (PID $($backend.Id))."
                        Register-Restart 'backend' '먹통(hang) 감지 -- 프로세스는 살아있었지만 health-public 응답 없음/비정상이 반복됨'
                        Stop-Process -Id $backend.Id -Force -ErrorAction SilentlyContinue
                        $healthFailCount = 0
                    }
                }
            }
        }

        if (-not (Test-Alive $caddy)) {
            Write-Log 'WARN' "Caddy가 비정상 종료된 것을 감지했습니다 (이전 PID $($caddy.Id))."
            Register-Crash 'caddy'
            Register-Restart 'caddy' '비정상 종료 감지 (프로세스가 스스로 꺼짐)'
            if (Test-ShouldRestart 'caddy') { $caddy = Start-Caddy }
        }

        Write-Status
    }
} finally {
    Remove-Item $LockFile -ErrorAction SilentlyContinue
    Remove-Item $StatusFile -ErrorAction SilentlyContinue
}
