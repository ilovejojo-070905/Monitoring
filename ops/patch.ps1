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
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'InfraSight'),
    # 기본값은 실제 운영 경로 그대로 -- 일반 사용자는 이 값을 몰라도 되고,
    # 동작도 전혀 안 바뀐다. 회귀 테스트(ops\patch_full_rollback_test.ps1)가
    # 격리된 디스포저블 Caddy 포트를 가리키도록 오버라이드할 수 있게 하기
    # 위한 용도로만 추가 -- 전에는 Test-PatchedHealthy에 포트가 그대로
    # 하드코딩돼 있어서, 패치 전체 흐름(특히 헬스체크 실패->자동 롤백 분기)을
    # 실제 운영 포트가 아닌 별도 디스포저블 설치로 끝까지 재현할 방법이
    # 전혀 없었다.
    [string]$HealthCheckUrl = 'https://localhost:8443/api/system/health-public'
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

# install.ps1의 Protect-SensitiveFiles와 동일(그 함수 쪽 주석에 전체 배경).
# 여기 다시 두는 이유: 이 설치가 그 보안 강화(2026-10-17)보다 먼저
# 설치됐다면 infrasight.db/backups/암호화 키가 여전히 느슨한 상속 ACL
# (Authenticated Users: 수정)을 가진 채로 남아있을 수 있어서, 패치 때도
# 같은 강화를 다시 적용해야 한다 -- 이미 적용돼 있으면(Authenticated
# Users가 이미 없음) icacls가 그냥 조용히 아무 변화 없이 끝나므로 매번
# 패치마다 돌려도 안전(멱등).
function Protect-SensitiveFiles {
    param([string]$InstallDir)
    $targets = @(
        (Join-Path $InstallDir 'backups'),
        (Join-Path $InstallDir 'infrasight.db'),
        (Join-Path $InstallDir '.infrasight_credentials_key')
    )
    foreach ($target in $targets) {
        if (-not (Test-Path $target)) { continue }
        # 버그 수정(2026-10-17, 운영 서버에 실제 패치 적용 중 실측 발견):
        # 이미 강화되어 있는(Authenticated Users가 이미 없는) 파일에도
        # 매번 icacls /inheritance:d 등을 그냥 시도했음 -- ACL을
        # "바꾸는" 명령 자체는(설령 결과적으로 아무것도 안 바뀌는
        # no-op이라도) WRITE_DAC 권한이 있어야 호출할 수 있는데, 이
        # 스크립트는 일부러 관리자 권한 없이 돈다(파일 맨 위 주석).
        # 그래서 "이미 끝난 상태에 또 손대려다 거부당함" -> icacls
        # 자신이 콘솔에 바로 "Access is denied"를 찍는(이건 .NET 예외가
        # 아니라 icacls 자체의 출력이라 try/catch로도 못 잡힘) 소음이
        # 매 패치마다 반복됐다 -- 기능상 문제는 없었지만(이미 올바른
        # 상태였으니) Patch.exe를 돌리는 사람 입장에서는 뭔가 깨진 것
        # 처럼 보였음. 이미 강화돼 있으면(Authenticated Users 부재)
        # 아예 시도조차 안 하도록 먼저 확인.
        $currentAcl = & icacls $target 2>$null
        if ($currentAcl -match 'Authenticated Users') {
            try {
                & icacls $target /inheritance:d | Out-Null
                & icacls $target /remove:g "NT AUTHORITY\Authenticated Users" | Out-Null
                if ((Get-Item $target) -is [System.IO.DirectoryInfo]) {
                    & icacls $target /grant "${env:USERNAME}:(OI)(CI)(M)" | Out-Null
                } else {
                    & icacls $target /grant "${env:USERNAME}:(M)" | Out-Null
                }
            } catch {
                Write-Warn2 "$target 파일 권한 강화에 실패했습니다(관리자 권한으로 다시 실행하면 적용됩니다; 기능에는 영향 없음): $_"
            }
        }
    }
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

# 재사용 헬퍼: 패치 적용 후와 실패 시 롤백 후 둘 다 똑같이 "기존 프로세스
# 종료 -> supervisor 재시작"을 해야 해서 분리.
function Restart-InfraSightProcesses {
    $statusFile = Join-Path $InstallDir 'run\status.json'
    if (Test-Path $statusFile) {
        try {
            $prevStatus = Get-Content $statusFile -Raw | ConvertFrom-Json
            foreach ($p in @($prevStatus.supervisorPid, $prevStatus.backend.pid, $prevStatus.caddy.pid)) {
                if ($p) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }
            }
            Remove-Item (Join-Path $InstallDir 'run\supervisor.lock') -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        } catch {
            Write-Warn2 "기존 프로세스 종료 중 문제가 있었습니다 (무시하고 계속합니다): $_"
        }
    }
    # `Start-Process powershell -WindowStyle Hidden` looks right but isn't
    # reliable -- confirmed live: a blank "Windows PowerShell" window popped up
    # and just sat there after patching, because -WindowStyle Hidden only ever
    # *asks* for a hidden window and Windows doesn't always honor it this soon
    # after the parent process itself was elevated/launched (same root cause
    # register-task.ps1's own long comment already documents). WScript.Shell's
    # .Run(cmd, 0, False) -- windowStyle 0 -- is the same reliable mechanism
    # register-task.ps1 uses via a .vbs file; done here directly through the
    # COM object instead, since there's no reason to drop a .vbs file to disk
    # just for this one relaunch.
    $supervisorCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'ops\supervisor.ps1')`""
    (New-Object -ComObject WScript.Shell).Run($supervisorCmd, 0, $false) | Out-Null
    Start-Sleep -Seconds 4
}

# 신규(2026-10-17, "패치 후 핵심 기능 헬스체크를 수행한다"): supervisor.ps1
# 의 먹통 감지가 이미 쓰는 것과 같은 /api/system/health-public을 재시작
# 직후 몇 번 폴링한다 -- 그 즉시가 아니라 여유를 두는 이유: 막 재시작된
# 백엔드는 DB 연결/스케줄러 초기화에 몇 초 걸릴 수 있어서, 1회만 확인하면
# "아직 뜨는 중"을 "패치 실패"로 오판할 수 있다.
function Test-PatchedHealthy {
    param([int]$MaxAttempts = 10, [int]$DelaySeconds = 3)
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try {
            $resp = Invoke-RestMethod -Uri $HealthCheckUrl -TimeoutSec 5 -ErrorAction Stop
            if ($resp.web -eq 'up' -and $resp.database -eq 'up' -and $resp.collector -eq 'up' `
                -and $resp.scheduler -eq 'up' -and $resp.alerts -eq 'up') {
                return $true
            }
        } catch {}
        Start-Sleep -Seconds $DelaySeconds
    }
    return $false
}

Write-Step '[1/5] 패치 전 버전 확인 + 백업'
Push-Location $InstallDir
$prevCommit = (& $gitExe rev-parse HEAD).Trim()
Invoke-Native { & $gitExe fetch origin main }
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "git fetch 실패 (종료 코드 $LASTEXITCODE). 네트워크 연결을 확인해주세요." }
$remoteCommit = (& $gitExe rev-parse origin/main).Trim()
Pop-Location
# 버전 검증: 이미 최신이면 코드 교체/서비스 재시작 없이 바로 끝낸다 --
# 불필요한 다운타임을 피하기 위함(재시작 자체가 몇 초간의 서비스 공백).
if ($prevCommit -eq $remoteCommit) {
    Write-Ok "이미 최신 버전입니다 (커밋 $($prevCommit.Substring(0,7))) -- 패치할 내용이 없어 종료합니다."
    # 코드가 안 바뀌어도 ACL 강화는 멱등하니 그냥 같이 적용해둔다(이
    # 패치 자체가 처음으로 그 강화를 들고 온 경우라도 놓치지 않도록).
    Protect-SensitiveFiles -InstallDir $InstallDir
    Write-Host "`n============================================================" -ForegroundColor Green
    Write-Host ' 패치 확인 완료 (변경 사항 없음)' -ForegroundColor Green
    Write-Host '============================================================' -ForegroundColor Green
    exit 0
}
Write-Ok "현재 커밋 $($prevCommit.Substring(0,7)) -> 새 커밋 $($remoteCommit.Substring(0,7))"
# 패치 전 DB 백업 -- 패치가 실패해서 롤백해야 할 경우 코드만 되돌리는 것과
# DB까지 그 시점으로 되돌리는 것 둘 다 필요할 수 있다(새 코드가 스키마를
# 바꿨다면 구 코드는 그 바뀐 스키마를 모를 수 있으므로). storage.
# backup_database()를 그대로 호출(제자리 integrity_check 포함, 이미
# storage.py에 있는 로직 재사용 -- 별도로 다시 구현 안 함).
$prePatchBackupPath = (Invoke-Native { & $pythonExe -c "import sys; sys.path.insert(0, r'$InstallDir'); import storage, os; print(storage.backup_database(os.path.join(storage.BASE_DIR, 'backups'), keep_days=storage.BACKUP_RETENTION_DAYS))" } | Select-Object -Last 1).Trim()
if ($LASTEXITCODE -ne 0 -or -not $prePatchBackupPath -or -not (Test-Path $prePatchBackupPath)) {
    throw "패치 전 DB 백업에 실패했습니다 -- 안전을 위해 패치를 중단합니다. (디스크 공간/권한을 확인해주세요)"
}
Write-Ok "패치 전 DB 백업 완료: $prePatchBackupPath"

Write-Step '[2/5] 최신 코드 받기 (git reset --hard)'
Push-Location $InstallDir
Invoke-Native { & $gitExe reset --hard origin/main }
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "git reset --hard 실패 (종료 코드 $LASTEXITCODE)." }
$headNow = (& $gitExe rev-parse --short HEAD).Trim()
Pop-Location
Write-Ok "최신 커밋으로 갱신됨: $headNow"

Write-Step '[3/5] 파이썬 패키지 확인 (requirements.txt)'
Invoke-Native { & $pythonExe -m pip install --quiet --disable-pip-version-check -r (Join-Path $InstallDir 'requirements.txt') }
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir 'backups') | Out-Null
Protect-SensitiveFiles -InstallDir $InstallDir
Write-Ok '확인 완료'

Write-Step '[4/5] 실행 중인 프로세스 재시작'
# install.ps1의 "지금 바로 시작" 단계와 동일한 이유: 방금 받은 새 코드는
# 이미 떠 있는 python.exe/caddy.exe에 저절로 반영되지 않는다. 이 설치
# 폴더가 직접 기록한 run\status.json만 사용하므로(다른 PC나 무관한
# 프로세스는 절대 건드리지 않음) 안전하다.
Restart-InfraSightProcesses
Write-Ok 'InfraSight를 새 코드로 다시 시작했습니다'

Write-Step '[5/5] 패치 후 헬스체크'
if (Test-PatchedHealthy) {
    Write-Ok '헬스체크 통과 (web/database/collector/scheduler/alerts 전부 정상)'
    Write-Host "`n============================================================" -ForegroundColor Green
    Write-Host " 패치 완료 (커밋 $headNow)" -ForegroundColor Green
    Write-Host '============================================================' -ForegroundColor Green
} else {
    # 신규(2026-10-17, "패치 실패 시 코드와 DB 호환성을 고려한 복구 절차를
    # 마련한다"): 새 코드로 재시작했는데 핵심 기능이 정상으로 안 올라오면,
    # 코드를 패치 전 커밋으로 되돌리고 DB도 패치 전 백업으로 복원한 뒤
    # 다시 재시작한다 -- 코드만 되돌리고 DB는 그대로 두면, 새 코드가 이미
    # 적용한 스키마 변경과 구 코드가 안 맞을 수 있어서 둘 다 같이 되돌려야
    # 진짜 안전하다. storage.restore_database()가 복원 직전 또 한 번
    # 안전 백업을 만들어주므로(이미 있는 로직 재사용) 이 롤백 자체도
    # 되돌릴 수 없는 손실은 아니다.
    Write-Warn2 "헬스체크 실패 -- 패치 전 상태(커밋 $($prevCommit.Substring(0,7)))로 자동 롤백합니다."
    Push-Location $InstallDir
    Invoke-Native { & $gitExe reset --hard $prevCommit }
    $gitRollbackOk = ($LASTEXITCODE -eq 0)
    Pop-Location
    if (-not $gitRollbackOk) {
        throw "코드 롤백(git reset --hard)에 실패했습니다 -- 설치 폴더가 불안정한 상태일 수 있습니다. 수동으로 확인해주세요: cd $InstallDir; git reset --hard $prevCommit"
    }
    Invoke-Native { & $pythonExe -m pip install --quiet --disable-pip-version-check -r (Join-Path $InstallDir 'requirements.txt') }
    $backupDirForRestore = Split-Path $prePatchBackupPath -Parent
    $backupFileForRestore = Split-Path $prePatchBackupPath -Leaf
    $restoreOutput = Invoke-Native { & $pythonExe -c "import sys; sys.path.insert(0, r'$InstallDir'); import storage; r=storage.restore_database(r'$backupDirForRestore', r'$backupFileForRestore'); print('OK')" }
    $dbRollbackOk = ($LASTEXITCODE -eq 0) -and ($restoreOutput -match 'OK')
    if (-not $dbRollbackOk) {
        Write-Warn2 "DB 롤백에 실패했습니다: $restoreOutput -- 코드는 되돌렸지만 DB는 새 코드가 만든 상태 그대로입니다. 수동 확인이 필요합니다."
    } else {
        Write-Ok "DB를 패치 전 백업으로 복원했습니다: $prePatchBackupPath"
    }
    Restart-InfraSightProcesses
    $rollbackHealthy = Test-PatchedHealthy
    Write-Host "`n============================================================" -ForegroundColor Red
    Write-Host ' 패치 실패 -- 패치 전 상태로 롤백되었습니다' -ForegroundColor Red
    Write-Host " 되돌린 커밋: $($prevCommit.Substring(0,7))" -ForegroundColor Red
    Write-Host " DB 복원: $(if($dbRollbackOk){'성공'}else{'실패 (수동 확인 필요)'})" -ForegroundColor Red
    Write-Host " 롤백 후 헬스체크: $(if($rollbackHealthy){'정상'}else{'여전히 비정상 -- 수동 확인 필요'})" -ForegroundColor Red
    Write-Host '============================================================' -ForegroundColor Red
    if (-not $rollbackHealthy) {
        throw "롤백 후에도 헬스체크가 통과하지 않습니다. InfraSight 상태를 직접 확인해주세요 (ops\status.ps1)."
    }
}

} catch {
    # 성공 경로엔 일부러 일시정지를 안 둔다 -- 다 끝나고 더 읽을 내용이
    # 없으면 그냥 창이 알아서 닫히는 게 맞다. 실패했을 때만, 메시지를 읽을
    # 틈도 없이 창이 사라지지 않도록 여기서 멈춘다.
    Write-Host "`n============================================================" -ForegroundColor Red
    Write-Host ' 패치 적용 중 오류가 발생했습니다' -ForegroundColor Red
    Write-Host " $_" -ForegroundColor Red
    Write-Host '============================================================' -ForegroundColor Red
    Write-Host "`n아무 키나 누르면 창이 닫힙니다..." -ForegroundColor DarkGray
    [void][System.Console]::ReadKey($true)
}
