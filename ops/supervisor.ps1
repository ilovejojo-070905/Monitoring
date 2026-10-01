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

$PollSeconds        = 5
$CrashWindowSeconds = 120   # count crashes within this rolling window...
$CrashLimit         = 5     # ...and if this many happen, back off instead of tight-looping
$BackoffSeconds     = 300

New-Item -ItemType Directory -Force -Path $RunDir, $LogDir | Out-Null

function Write-Log([string]$Level, [string]$Message) {
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogFile -Value $line -Encoding utf8
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
if (Test-Path $LockFile) {
    $lockLines = Get-Content $LockFile -ErrorAction SilentlyContinue
    $oldPid = $lockLines | Select-Object -First 1
    $oldKind = if ($lockLines.Count -ge 2) { $lockLines[1] } else { 'unknown' }
    $existing = if ($oldPid) { Get-Process -Id $oldPid -ErrorAction SilentlyContinue } else { $null }
    if ($existing) {
        Write-Log 'INFO' "이미 실행 중인 supervisor(PID $oldPid, $oldKind)를 발견해 이번 실행은 종료합니다 (중복 실행 방지)."
        exit 0
    } else {
        Write-Log 'WARN' "이전 lock 파일이 남아있었지만 해당 PID($oldPid)는 더 이상 실행 중이 아닙니다. 새로 시작합니다."
    }
}
Remove-Item $StopMarker -ErrorAction SilentlyContinue
"$PID`nps1" | Out-File -FilePath $LockFile -Encoding ascii -Force

Write-Log 'INFO' "===== supervisor 시작 (PID $PID) ====="

# ---------- process management ----------
$backend = $null
$caddy = $null
$crashTimes   = @{ backend = @();   caddy = @()   }
$backoffUntil = @{ backend = $null; caddy = $null }

function Start-Backend {
    $p = Start-Process -FilePath $PythonExe -ArgumentList 'server.py' -WorkingDirectory $ProjectRoot `
        -WindowStyle Hidden -PassThru
    Write-Log 'INFO' "Backend 시작됨 (PID $($p.Id))"
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
        backend       = [ordered]@{ pid = $backend.Id; alive = (Test-Alive $backend) }
        caddy         = [ordered]@{ pid = $caddy.Id; alive = (Test-Alive $caddy) }
    }
    $status | ConvertTo-Json | Set-Content -Path $StatusFile -Encoding utf8
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
            if (Test-ShouldRestart 'backend') { $backend = Start-Backend }
        }

        if (-not (Test-Alive $caddy)) {
            Write-Log 'WARN' "Caddy가 비정상 종료된 것을 감지했습니다 (이전 PID $($caddy.Id))."
            Register-Crash 'caddy'
            if (Test-ShouldRestart 'caddy') { $caddy = Start-Caddy }
        }

        Write-Status
    }
} finally {
    Remove-Item $LockFile -ErrorAction SilentlyContinue
    Remove-Item $StatusFile -ErrorAction SilentlyContinue
}
