<#
InfraSight 패치 적용 스크립트
=============================
이 스크립트와 같은 폴더에 있는 .patch 파일을, 이 PC에 설치된 InfraSight
저장소에 적용합니다. (오프라인 PC용 - git pull이 안 되는 환경에서
USB 등으로 패치 파일을 옮겨와 적용할 때 사용)

사용법: 이 스크립트와 .patch 파일을 같은 폴더에 두고 패치적용.bat을
더블클릭하거나, 직접 실행:
    powershell -ExecutionPolicy Bypass -File 패치적용.ps1
    powershell -ExecutionPolicy Bypass -File 패치적용.ps1 -InstallDir "D:\InfraSight"
#>

param(
    [string]$InstallDir
)

# 'Stop'으로 두면 ps2exe로 컴파일된 실행 파일 안에서는 git(네이티브 exe)이
# stderr에 한 줄만 써도(리다이렉션 여부와 무관하게) 스크립트 전체가 죽어버린다
# -- 특히 "이미 적용됐는지" 확인 단계처럼 실패가 정상적으로 예상되는 곳에서
# 치명적이다. 그래서 기본값(Continue)으로 두고, 진짜 실패는 $LASTEXITCODE
# 확인과 명시적 throw로만 처리한다.
$ErrorActionPreference = 'Continue'

function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg" -ForegroundColor Yellow }

Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' InfraSight 패치 적용' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan

# ------------------------------------------------------------- [1] git --
# install.ps1과 동일한 이유로 WindowsApps 스텁은 걸러낸다 (진짜 git이 아님).
function Resolve-Git {
    $existing = Get-Command git -ErrorAction SilentlyContinue
    if ($existing -and $existing.Source -notmatch '\\WindowsApps\\') { return $existing.Source }
    $fallback = "$env:ProgramFiles\Git\cmd\git.exe"
    if (Test-Path $fallback) { return $fallback }
    throw 'git을 찾을 수 없습니다. InfraSight 설치 시 함께 설치되었어야 합니다.'
}
$gitExe = Resolve-Git
Write-Ok "git: $gitExe"

# ------------------------------------------------------ [2] 설치 폴더 --
if (-not $InstallDir) { $InstallDir = Join-Path $env:LOCALAPPDATA 'InfraSight' }
while (-not (Test-Path (Join-Path $InstallDir '.git'))) {
    Write-Warn2 "InfraSight 설치 폴더를 찾을 수 없습니다: $InstallDir"
    $InstallDir = Read-Host 'InfraSight가 설치된 폴더 경로를 입력해주세요'
}
Write-Ok "설치 폴더: $InstallDir"

# ------------------------------------------------------ [3] 패치 파일 --
# ps2exe로 컴파일된 실행 파일은 $PSScriptRoot가 exe 자신의 실제 폴더를
# 가리키지 못할 수 있다(비어있거나 작업 디렉터리에 따라 달라짐) -- 실측 확인:
# 바탕화면에서 더블클릭하면 우연히 맞았지만, 다른 폴더(예: PowerShell 창의
# 현재 위치가 System32)에서 전체 경로로 실행하면 $PSScriptRoot가 빈 값이 되어
# Get-ChildItem이 그 현재 위치에서 찾다가 못 찾는 걸로 실측됨. 컴파일된 실행
# 파일 자신의 실제 경로(어디서 실행하든 변하지 않음)를 대신 사용한다.
$scriptDir = $PSScriptRoot
if (-not $scriptDir) {
    try { $scriptDir = Split-Path -Parent ([System.Reflection.Assembly]::GetEntryAssembly().Location) } catch {}
}
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
$patchFile = Get-ChildItem $scriptDir -Filter '*.patch' | Select-Object -First 1
if (-not $patchFile) { throw "$scriptDir 폴더에 .patch 파일이 없습니다." }
Write-Ok "패치 파일: $($patchFile.Name)"

# ------------------------------------------------------ [4] 패치 적용 --
# git 명령의 stderr를 PowerShell에서 리다이렉트하면(2>$null 포함) 5.1에서
# NativeCommandError로 감싸져 $ErrorActionPreference='Stop'과 만나 스크립트가
# 죽어버린다 (실패가 예상되는 "이미 적용됐는지 확인" 단계에서도) -- 그래서
# 리다이렉트하지 않고 그대로 출력되게 둔 뒤 $LASTEXITCODE로만 분기한다.
Push-Location $InstallDir
try {
    Write-Host '    (적용 여부 확인 중 -- 아래 git 메시지가 보여도 정상입니다)' -ForegroundColor DarkGray
    & $gitExe apply --check -R $patchFile.FullName
    $alreadyApplied = ($LASTEXITCODE -eq 0)

    if ($alreadyApplied) {
        Write-Ok '이미 이 패치가 적용되어 있습니다. 할 일이 없습니다.'
    } else {
        & $gitExe am $patchFile.FullName
        if ($LASTEXITCODE -ne 0) {
            & $gitExe am --abort
            & $gitExe apply $patchFile.FullName
            if ($LASTEXITCODE -ne 0) {
                throw '패치 적용에 실패했습니다. 설치된 버전이 패치와 맞지 않을 수 있습니다 (예전 버전이거나 이미 다르게 수정됨). InfraSight 폴더에서 git pull로 최신 버전을 받은 뒤 다시 시도해주세요.'
            }
        }
        Write-Ok '패치 적용 완료'
    }
} finally {
    Pop-Location
}

# --------------------------------------------------- [5] 원격 접속 구성 --
# install.ps1으로 이미 설치된 PC에는 보통 python도 이미 있다 -- 못 찾으면
# (설치가 아주 오래돼 PATH가 갱신되기 전이거나 특이 케이스) 이 단계만
# 건너뛰고 나머지 패치 적용 결과는 그대로 둔다.
try {
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue |
        Where-Object { $_.Source -notmatch '\\WindowsApps\\' } | Select-Object -First 1).Source
    if (-not $pythonExe) {
        $pythonExe = (Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue -File | Select-Object -First 1).FullName
    }
    if ($pythonExe) {
        & (Join-Path $InstallDir 'ops\setup-remote-access.ps1') -InstallDir $InstallDir -PythonExe $pythonExe
    } else {
        Write-Warn2 'python을 찾을 수 없어 원격 접속(SSH/Telnet) 구성을 건너뜁니다.'
    }
} catch {
    Write-Warn2 "원격 접속 구성 중 문제가 있었습니다 (무시하고 계속합니다): $_"
}

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host ' 완료되었습니다!' -ForegroundColor Green
Write-Host ' 브라우저에서 강력 새로고침(Ctrl+F5) 해주세요.' -ForegroundColor Yellow
Write-Host ' 화면이 그대로면 InfraSight를 재시작해주세요 (로그아웃 후 재로그인하면 자동으로 다시 시작됩니다).'
Write-Host '============================================================' -ForegroundColor Green

Write-Host "`n아무 키나 누르면 창이 닫힙니다..." -ForegroundColor DarkGray
try { [void][System.Console]::ReadKey($true) } catch { Start-Sleep -Seconds 3 }
