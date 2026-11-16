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
# 로그인 없이(S4U, register-task.ps1) 부팅 직후 실행되면 사용자 PATH가 평소와
# 다르게 잡힐 수 있어서, PATH에서 못 찾으면 install.ps1이 설치하는 기본 위치
# (winget/python.org 사용자 설치)도 찾아본다. WindowsApps의 python 스텁은
# 진짜 python이 아니라 제외.
function Resolve-ToolExe([string]$cmd, [string[]]$globs) {
    $found = Get-Command $cmd -ErrorAction SilentlyContinue | Where-Object { $_.Source -notmatch '\\WindowsApps\\' } | Select-Object -First 1
    if ($found) { return $found.Source }
    foreach ($g in $globs) {
        $f = Get-ChildItem $g -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($f) { return $f.FullName }
    }
    return $null
}
$PythonExe = Resolve-ToolExe 'python' @("$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe", "$env:ProgramFiles\Python3*\python.exe")
$CaddyExe  = Resolve-ToolExe 'caddy'  @("$env:LOCALAPPDATA\Microsoft\WinGet\Links\caddy.exe", "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\CaddyServer.Caddy_*\caddy.exe", "$env:ProgramFiles\Caddy\caddy.exe")
$MkcertExe = Resolve-ToolExe 'mkcert' @("$env:LOCALAPPDATA\Microsoft\WinGet\Links\mkcert.exe", "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\FiloSottile.mkcert_*\mkcert*.exe")
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
        # Caddy(8443)를 거치지 않고 백엔드(5057)에 직접 묻는다 -- 로그인 없이
        # 실행(S4U)될 때는 mkcert 로컬 CA 신뢰가 이 세션에 안 잡혀 HTTPS 호출이
        # 인증서 오류로 실패할 수 있고, 그러면 멀쩡한 백엔드를 "먹통"으로 오인해
        # 계속 재시작하게 된다. 확인 대상도 원래 백엔드 자체라 이 편이 정확하다
        # (Caddy는 아래 Test-Alive로 따로 본다).
        $resp = Invoke-RestMethod -Uri 'http://127.0.0.1:5057/api/system/health-public' -TimeoutSec 5 -ErrorAction Stop
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

# ---------- LAN IP 변경 시 HTTPS 인증서 자동 재발급 ----------
# 사용자 요청("다른 장소에 설치 후 오랜만에 접속하니 안 됨"): 인증서는 설치
# 당시 LAN IP로만 발급되는데, DHCP로 IP가 바뀌면 새 IP로 들어가도 인증서
# 오류가 났다(collector/cert_check.py는 하루 한 번 경고만 했음). 1분마다
# 현재 LAN IP가 인증서 주소 목록에 있는지 보고, 없으면 같은 로컬 CA(mkcert)로
# 다시 발급해 Caddy만 재시작한다. PC 이름(COMPUTERNAME)도 같이 넣어서
# https://<PC이름>:8443 으로도 접속할 수 있게 한다 -- IP가 또 바뀌어도
# 같은 주소로 들어갈 수 있는 방법.
$CertFile = Join-Path $ProjectRoot 'certs\infrasight.crt'
$KeyFile  = Join-Path $ProjectRoot 'certs\infrasight.key'
$CertCheckIntervalSec = 60
$CertRetryAfterFailSec = 600
$lastCertCheckAt = $null
$certRetryAt = $null

# storage.get_lan_ip()와 같은 방식(UDP connect -- 실제 패킷은 안 나감).
function Get-LanIp {
    $s = $null
    try {
        $s = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,
            [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
        $s.Connect('8.8.8.8', 80)
        $ip = $s.LocalEndPoint.Address.ToString()
        # 네트워크가 아직 안 잡힌 상태(부팅 직후, 케이블 빠짐)면 재발급하지 않는다.
        if ($ip -match '^(127\.|169\.254\.|0\.)') { return $null }
        return $ip
    } catch {
        return $null
    } finally {
        if ($s) { $s.Close() }
    }
}

# 인증서 SAN 목록. Format() 결과의 "DNS Name=" / "IP Address=" 라벨은 Windows
# 언어에 따라 바뀔 수 있어서 라벨 대신 '=' 뒤 값만 뽑는다.
function Get-CertNames {
    try {
        $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertFile)
        $ext = $c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
        if (-not $ext) { return @() }
        return @([regex]::Matches($ext.Format($false), '=\s*([^,\r\n]+)') | ForEach-Object { $_.Groups[1].Value.Trim() })
    } catch {
        return @()
    }
}

# 재발급이 필요하면 하고 $true, 아니면(또는 할 수 없으면) $false.
function Sync-Certificate {
    $ip = Get-LanIp
    if (-not $ip) { return $false }
    $names = Get-CertNames
    $hostName = $env:COMPUTERNAME
    if ((Test-Path $CertFile) -and ($names -contains $ip) -and (-not $hostName -or ($names -contains $hostName))) { return $false }
    if (-not $MkcertExe) {
        Write-Log 'WARN' "인증서에 현재 IP($ip)가 없지만 mkcert를 찾지 못해 재발급하지 못했습니다."
        return $false
    }
    # 설치 때 만든 로컬 CA가 없으면 mkcert가 새 CA를 만들어버려(다른 PC에서
    # 신뢰하지 않는 인증서) 오히려 나빠지므로 그 경우는 재발급하지 않는다.
    $caRoot = if ($env:CAROOT) { $env:CAROOT } else { Join-Path $env:LOCALAPPDATA 'mkcert' }
    if (-not (Test-Path (Join-Path $caRoot 'rootCA-key.pem'))) {
        Write-Log 'WARN' "인증서에 현재 IP($ip)가 없지만 로컬 CA($caRoot)를 찾지 못해 재발급하지 못했습니다."
        return $false
    }
    $newCrt = "$CertFile.new"; $newKey = "$KeyFile.new"
    $sans = @($ip, 'localhost', 'infrasight.local')
    if ($hostName) { $sans += $hostName }
    try {
        $p = Start-Process -FilePath $MkcertExe -ArgumentList (@('-cert-file', "`"$newCrt`"", '-key-file', "`"$newKey`"") + $sans) `
            -WorkingDirectory $ProjectRoot -WindowStyle Hidden -Wait -PassThru `
            -RedirectStandardOutput (Join-Path $RunDir 'mkcert.out.log') -RedirectStandardError (Join-Path $RunDir 'mkcert.err.log')
        if ($p.ExitCode -ne 0 -or -not (Test-Path $newCrt) -or -not (Test-Path $newKey)) {
            throw "mkcert 종료 코드 $($p.ExitCode) (자세한 내용: run\mkcert.err.log)"
        }
        Move-Item -Force $newKey $KeyFile
        Move-Item -Force $newCrt $CertFile
        $old = if ($names.Count) { $names -join ', ' } else { '(없음)' }
        Write-Log 'INFO' "HTTPS 인증서 재발급 완료: $($sans -join ', ') (이전: $old)"
        return $true
    } catch {
        Remove-Item $newCrt, $newKey -ErrorAction SilentlyContinue
        Write-Log 'ERROR' "HTTPS 인증서 재발급 실패: $_"
        $script:certRetryAt = (Get-Date).AddSeconds($CertRetryAfterFailSec)
        return $false
    }
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
    # Caddy를 띄우기 전에 한 번 맞춰 둔다(부팅 사이 IP가 바뀐 경우 바로 반영).
    try { [void](Sync-Certificate) } catch { Write-Log 'WARN' "인증서 확인 중 오류: $_" }
    $lastCertCheckAt = Get-Date
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

        if (((Get-Date) - $lastCertCheckAt).TotalSeconds -ge $CertCheckIntervalSec -and
            (-not $certRetryAt -or (Get-Date) -ge $certRetryAt)) {
            $lastCertCheckAt = Get-Date
            $reissued = $false
            try { $reissued = Sync-Certificate } catch { Write-Log 'WARN' "인증서 확인 중 오류: $_" }
            if ($reissued) {
                $certRetryAt = $null
                # Caddy는 인증서 파일을 시작할 때만 읽으므로 재시작해야 반영된다.
                if (Test-Alive $caddy) { Stop-Process -Id $caddy.Id -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1 }
                Register-Restart 'caddy' 'LAN IP 변경으로 HTTPS 인증서 재발급'
                $caddy = Start-Caddy
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
