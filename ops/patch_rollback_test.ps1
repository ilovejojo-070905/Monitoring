<#
patch.ps1의 DB 백업/복원 롤백 경로 회귀 테스트
=================================================
patch.ps1의 [1/5]/[5/5]가 쓰는 두 PowerShell->Python 한줄 호출(backup_database
/ restore_database)은, 패치가 실제로 실패해서 자동 롤백이 발동할 때만 실행되는
코드다. 이 세션에서 실제 운영 서버에 patch.ps1을 두 번 돌려봤지만 둘 다
"이미 최신" 또는 "패치 성공" 경로였고, 롤백 분기(코드+DB를 패치 전 상태로
되돌리는 부분)는 한 번도 실제로 실행된 적이 없다 -- 정작 필요한 순간(패치가
망가졌을 때)에만 돌아가는 코드라 지금 검증해두지 않으면 가장 위험한 상태로
방치된다.

patch.ps1 전체(venv/인증서/Caddy/supervisor까지 포함한 실제 설치)를 통째로
복제해서 돌리는 건 이 변경 단위에 비해 과하므로, 실제로 위험한 지점 --
PowerShell이 Python 한줄 호출의 종료 코드/출력으로 "성공/실패"를 올바르게
판단하는지 -- 만 patch.ps1에 있는 것과 동일한 패턴으로 직접 재현해서 검증한다.
가장 걱정되는 실패 양상은 "복원이 실제로는 실패했는데 patch.ps1이 성공으로
오판"하는 것 -- 이번 세션에 이미 두 번(stderr를 오류로 착각, icacls 멱등성
문제) PowerShell<->외부 프로세스 경계에서 바로 이런 종류의 버그를 실제로
찾았기 때문에, 같은 경계를 가진 이 코드도 같은 종류의 결함이 있을 수 있다.

운영 DB는 전혀 건드리지 않는다 -- storage.py/secrets_crypto.py를 복사해 넣은
임시 폴더에서 storage.DB_PATH 자체가 그 임시 폴더를 가리키도록(실제 설치
경로를 모방) 완전히 분리된 디스포저블 DB로만 검증한다.

Usage:
    powershell -ExecutionPolicy Bypass -File ops\patch_rollback_test.ps1
#>

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$pythonExe = (Get-Command python).Source

# patch.ps1 자신의 Invoke-Native와 동일한 이유로 필요: 실패를 의도적으로
# 일으키는 [3]단계의 python 호출은 stderr에 traceback을 찍는데, 이를 2>&1로
# 리다이렉션하면 PowerShell이 그걸 터미네이팅 NativeCommandError로 감싸서
# $ErrorActionPreference='Stop' 때문에 스크립트 전체가 죽어버린다(실제로
# 이 테스트를 작성하며 직접 겪음 -- patch.ps1이 이미 아는 바로 그 함정).
function Invoke-Native([scriptblock]$Command) {
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try { & $Command } finally { $ErrorActionPreference = $prevEAP }
}

$failCount = 0
function Test-Assert([bool]$cond, [string]$label) {
    if ($cond) {
        Write-Host "[PASS] $label" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $label" -ForegroundColor Red
        $script:failCount++
    }
}

$testDir = Join-Path $env:TEMP ("infrasight_patch_rollback_test_" + [Guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path $testDir | Out-Null
Write-Host "임시 테스트 설치 폴더: $testDir"

try {
    # patch.ps1이 'sys.path.insert(0, $InstallDir)'로 storage를 불러오는 것과
    # 동일하게, 이 임시 폴더 자체가 "설치 폴더"인 것처럼 storage.py/
    # secrets_crypto.py만 복사해 넣는다 (venv/인증서/Caddy는 이 테스트의
    # 대상이 아니므로 불필요).
    Copy-Item (Join-Path $repoRoot 'storage.py') $testDir
    Copy-Item (Join-Path $repoRoot 'secrets_crypto.py') $testDir
    New-Item -ItemType Directory -Force -Path (Join-Path $testDir 'backups') | Out-Null

    Write-Host "`n[1] 디스포저블 DB 초기화"
    & $pythonExe -c "import sys; sys.path.insert(0, r'$testDir'); import storage; storage.init_db()"
    Test-Assert ($LASTEXITCODE -eq 0) "storage.init_db() 성공"
    Test-Assert (Test-Path (Join-Path $testDir 'infrasight.db')) "디스포저블 infrasight.db 생성됨"

    Write-Host "`n[2] 백업 한줄 호출 (patch.ps1 [1/5]와 동일 패턴)"
    $backupPath = (& $pythonExe -c "import sys; sys.path.insert(0, r'$testDir'); import storage, os; print(storage.backup_database(os.path.join(storage.BASE_DIR, 'backups'), keep_days=storage.BACKUP_RETENTION_DAYS))" | Select-Object -Last 1).Trim()
    Test-Assert ($LASTEXITCODE -eq 0) "backup_database() 호출 종료 코드 0"
    Test-Assert (Test-Path $backupPath) "백업 파일이 실제로 생성됨: $backupPath"

    Write-Host "`n[3] 복원 실패 케이스 (patch.ps1이 실패를 올바르게 감지하는지 -- 가장 위험한 '거짓 성공' 방지)"
    $backupDirForRestore = Split-Path $backupPath -Parent
    $backupFileForRestore = Split-Path $backupPath -Leaf

    # 복잡한 다중 문장 파이썬 코드는 PowerShell의 -c 인라인 인용부호 이스케이프가
    # 깨지기 쉬워서(실제로 겪음: \" 는 PowerShell에서 Python과 다르게 해석됨)
    # 임시 .py 파일로 적어서 실행한다 -- patch.ps1 자체는 여전히 한줄 -c 호출만
    # 쓰므로 그 호출 패턴은 위 [2]/아래 [4]에서 그대로 검증한다.
    $bogusRestoreScript = Join-Path $testDir '_bogus_restore.py'
    @"
import sys
sys.path.insert(0, r'$testDir')
import storage
storage.restore_database(r'$backupDirForRestore', 'infrasight_does_not_exist.db')
print('OK')
"@ | Set-Content -Path $bogusRestoreScript -Encoding utf8

    $bogusRestoreOutput = Invoke-Native { & $pythonExe $bogusRestoreScript }
    $bogusExit = $LASTEXITCODE
    # patch.ps1의 실제 판정식 그대로: ($LASTEXITCODE -eq 0) -and (출력에 'OK' 포함)
    $bogusWouldReportSuccess = ($bogusExit -eq 0) -and ($bogusRestoreOutput -match 'OK')
    Test-Assert (-not $bogusWouldReportSuccess) "존재하지 않는 백업으로 복원 시도 -> patch.ps1 판정식이 실패로 올바르게 인식함 (거짓 성공 아님)"

    Write-Host "`n[4] 복원 성공 케이스 (patch.ps1 [5/5] 롤백 분기와 동일 패턴)"
    # 복원 전/후를 구분하기 위해 DB를 한 번 더 건드려서(가짜 변경) 복원이
    # 실제로 그 변경을 되돌리는지까지 확인한다.
    $tamperScript = Join-Path $testDir '_tamper.py'
    @"
import sys
sys.path.insert(0, r'$testDir')
import storage
conn = storage.get_db()
conn.execute("DELETE FROM settings WHERE key='_rollback_test_marker'")
conn.execute("INSERT INTO settings(key, value) VALUES ('_rollback_test_marker', 'TAMPERED')")
conn.commit()
conn.close()
"@ | Set-Content -Path $tamperScript -Encoding utf8
    & $pythonExe $tamperScript | Out-Null
    Test-Assert ($LASTEXITCODE -eq 0) "복원 전 비교용 변조(tamper) 적용 성공"

    # patch.ps1 [5/5]가 실제로 실행하는 한줄 호출과 동일한 패턴 (restore 성공 시)
    $restoreOutput = & $pythonExe -c "import sys; sys.path.insert(0, r'$testDir'); import storage; r=storage.restore_database(r'$backupDirForRestore', r'$backupFileForRestore'); print('OK')"
    $restoreExit = $LASTEXITCODE
    $wouldReportSuccess = ($restoreExit -eq 0) -and ($restoreOutput -match 'OK')
    Test-Assert $wouldReportSuccess "유효한 백업으로 복원 -> patch.ps1 판정식이 성공으로 올바르게 인식함"

    $checkScript = Join-Path $testDir '_check.py'
    @"
import sys
sys.path.insert(0, r'$testDir')
import storage
conn = storage.get_db()
row = conn.execute("SELECT value FROM settings WHERE key='_rollback_test_marker'").fetchone()
print(row['value'] if row else 'MISSING')
conn.close()
"@ | Set-Content -Path $checkScript -Encoding utf8
    $restoredValue = (& $pythonExe $checkScript | Select-Object -Last 1).Trim()
    Test-Assert ($restoredValue -ne 'TAMPERED') "복원 후 DB 내용이 백업 시점(변조 이전)으로 실제로 되돌아감"

} finally {
    Remove-Item -Recurse -Force $testDir -ErrorAction SilentlyContinue
    Write-Host "`n임시 테스트 설치 폴더 정리 완료"
}

Write-Host "`n============================================================"
if ($failCount -eq 0) {
    Write-Host " 전부 통과 -- patch.ps1의 백업/복원 롤백 판정 로직은 올바르게 동작함" -ForegroundColor Green
    exit 0
} else {
    Write-Host " $failCount 개 실패 -- patch.ps1의 백업/복원 롤백 판정 로직을 다시 확인해야 함" -ForegroundColor Red
    exit 1
}
