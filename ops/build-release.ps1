<#
InfraSight 릴리스 빌드 (Setup.exe + Setup-GUI.exe + 자체 내장형 Patch.exe + Uninstall.exe)
=============================================================================
현재 HEAD 기준으로 이 저장소의 setup\ 폴더에 새로 만든다:
  - InfraSight-Setup-*.exe       : install.ps1(에이전트 exe가 base64로
                                    치환된 임시 복사본)을 ps2exe로 감싼 콘솔
                                    설치 프로그램 (자동화/무인 설치에 적합)
  - InfraSight-Setup-GUI-*.exe   : 같은 install.ps1을 NSIS 마법사(환영 ->
                                    설치 위치 선택 -> 설치 진행 -> 완료)로
                                    감싼 그래픽 설치 프로그램 -- 설치 로직
                                    자체는 install.ps1 하나뿐이고(둘로
                                    나뉘어 있지 않음), ops\installer.nsi가
                                    그 바깥 UI만 제공한다.
  - InfraSight-Patch-*.exe       : main 브랜치 전체를 담은 git bundle을 exe
                                    안에 통째로 내장한 패치 (패치적용.ps1의
                                    $EMBEDDED_PATCH_B64 참고) -- 별도 파일
                                    없이 exe 하나만 전달하면 된다. 특정
                                    기준 커밋과의 diff가 아니라 번들이라서,
                                    대상 PC가 지금 어느 커밋에 있든(심지어
                                    한참 예전 버전이든) git merge --ff-only로
                                    항상 최신으로 올라간다 -- 예전엔 고정된
                                    -BaseCommit과의 diff 방식이었는데,
                                    대상 PC가 그 기준 커밋이 아니면 거의
                                    모든 파일에서 "patch does not apply"로
                                    실패하는 문제가 실제로 발생해서
                                    (기준 커밋을 매 빌드마다 갱신해줘야
                                    하는데 깜빡하기 쉬운 구조였음) 폐기함.
  - InfraSight-Uninstall-*.exe   : uninstall.ps1을 ps2exe로 감싼 제거 프로그램
  - InfraSight-Patch-GUI-*.exe   : 같은 패치적용.ps1을 NSIS 마법사(환영 ->
                                    설치 폴더 확인 -> 진행 -> 완료)로 감싼
                                    그래픽 패치 프로그램. ops\patch-gui.nsi 참고.
  - InfraSight-Uninstall-GUI-*.exe : 같은 uninstall.ps1을 NSIS 마법사로 감싼
                                    그래픽 제거 프로그램. ops\uninstall-gui.nsi
                                    참고.
  - InfraSightAgent-Uninstall-*.exe / InfraSightAgent-Uninstall-GUI-*.exe :
                                    모니터링 대상 PC(InfraSight 서버가 아닌
                                    다른 PC)에 설치된 에이전트만 따로 깔끔하게
                                    제거하는 콘솔/그래픽 제거 프로그램.
                                    uninstall-agent.ps1 / ops\uninstall-agent-
                                    gui.nsi 참고 -- 관리자 권한도 설치 경로
                                    선택도 필요 없다(에이전트는 항상
                                    %LOCALAPPDATA%\InfraSightAgent 고정).

Setup/Patch 둘 다 dist\InfraSightAgent.exe(장비 등록 시 다운로드하는 에이전트
실행 파일)도 base64로 함께 내장한다 -- 이 파일은 용량 때문에 .gitignore
대상이라 git bundle에는 안 담기는데, 그렇다고 아예 안 실으면 설치/패치를
받은 PC에서 "에이전트 다운로드"가 500 에러로 실패하는 문제가 실제로
있었음(이 파일 자체가 아예 없어서). PyInstaller가 있으면 agent.py에서
매번 새로 빌드해 최신으로 유지하고, 없으면 이미 dist\에 있는 걸 그대로
쓰고, 그것도 없으면 건너뛴다(install.ps1/패치적용.ps1 쪽도 그 경우 조용히
건너뛰게 되어 있음).

사용법 (저장소 루트에서):
    powershell -ExecutionPolicy Bypass -File ops\build-release.ps1
#>
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $repoRoot 'setup'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

Push-Location $repoRoot
try {
    $date = Get-Date -Format 'yyyyMMdd'
    $sha = (git log -1 --format=%h)

    # 이전 빌드가 폴더에 계속 쌓이지 않도록 정리
    Get-ChildItem $outDir -File | Remove-Item -Force -ErrorAction SilentlyContinue

    # git bundle: main 브랜치가 지금까지 가진 커밋 전체(그 조상 포함)를 담은
    # 바이너리 파일 하나. 대상 PC에서 `git fetch <이 파일> main` +
    # `git merge --ff-only FETCH_HEAD`를 돌리면, 그 PC가 지금 이 히스토리
    # 선상의 어느 커밋에 있든(한참 예전 버전이든 바로 전 패치 상태든)
    # 항상 올바르게 최신으로 올라간다 -- 고정된 기준 커밋과의 diff가
    # 아니라서 "기준 커밋을 안 갱신해서 거의 다 충돌" 같은 문제가 구조적으로
    # 없어진다. base64로 담는 이유는 패치적용.ps1 쪽 $EMBEDDED_PATCH_B64
    # 주석 참고 (여기-문자열에 바이너리를 그대로 박을 수 없어서이기도 함).
    $bundlePath = Join-Path $env:TEMP "infrasight-bundle-$([guid]::NewGuid().ToString('N')).bundle"
    & git bundle create $bundlePath main
    if ($LASTEXITCODE -ne 0) { throw 'git bundle 생성에 실패했습니다.' }
    $diffB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($bundlePath))
    Remove-Item $bundlePath -Force -ErrorAction SilentlyContinue

    # 에이전트 실행 파일: PyInstaller가 있으면 agent.py에서 매번 새로 빌드해
    # dist\InfraSightAgent.exe가 항상 최신(지금 빌드하는 코드 버전과 일치)이
    # 되게 한다 -- 없으면 이미 dist\에 있는 걸 그대로 쓴다(없을 수도 있음).
    $agentExePath = Join-Path $repoRoot 'dist\InfraSightAgent.exe'
    $pyinstaller = Get-Command pyinstaller -ErrorAction SilentlyContinue
    if ($pyinstaller) {
        & pyinstaller --noconfirm (Join-Path $repoRoot 'InfraSightAgent.spec')
        if ($LASTEXITCODE -ne 0) { Write-Warning "에이전트(PyInstaller) 빌드 실패 (종료 코드 $LASTEXITCODE) -- 기존 dist\InfraSightAgent.exe가 있으면 그걸 그대로 씁니다." }
    } else {
        Write-Warning 'PyInstaller를 찾을 수 없어 에이전트를 새로 빌드하지 못합니다 (pip install pyinstaller) -- 기존 dist\InfraSightAgent.exe가 있으면 그걸 그대로 씁니다.'
    }
    $agentExeB64 = $null
    if (Test-Path $agentExePath) {
        $agentExeB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($agentExePath))
    } else {
        Write-Warning 'dist\InfraSightAgent.exe가 없어 에이전트 다운로드 기능 없이 빌드합니다.'
    }

    $patchSrc = Get-Content (Join-Path $repoRoot '패치적용.ps1') -Raw -Encoding UTF8
    $patchSrc = $patchSrc.Replace('__EMBEDDED_PATCH_B64__', $diffB64)
    if ($agentExeB64) { $patchSrc = $patchSrc.Replace('__EMBEDDED_AGENT_EXE_B64__', $agentExeB64) }
    $tempPatchPs1 = Join-Path $env:TEMP "infrasight-patch-embedded-$([guid]::NewGuid().ToString('N')).ps1"

    $installSrc = Get-Content (Join-Path $repoRoot 'install.ps1') -Raw -Encoding UTF8
    if ($agentExeB64) { $installSrc = $installSrc.Replace('__EMBEDDED_AGENT_EXE_B64__', $agentExeB64) }
    $tempInstallPs1 = Join-Path $env:TEMP "infrasight-install-embedded-$([guid]::NewGuid().ToString('N')).ps1"

    # ps2exe가 소스를 한글 주석까지 포함해 정확히 읽으려면 BOM이 있어야 한다
    # (이번 세션에 실제로 BOM 없는 .ps1이 $PSParser에서 깨진 전례가 있었음).
    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($tempPatchPs1, $patchSrc, $utf8Bom)
    [System.IO.File]::WriteAllText($tempInstallPs1, $installSrc, $utf8Bom)

    $iconFile = Join-Path $repoRoot 'ops\assets\installer.ico'

    Import-Module ps2exe
    Invoke-ps2exe -inputFile $tempInstallPs1 -outputFile (Join-Path $outDir "InfraSight-Setup-$date-$sha.exe") -title 'InfraSight Setup' -iconFile $iconFile -noConsole:$false -requireAdmin:$false
    Invoke-ps2exe -inputFile $tempPatchPs1 -outputFile (Join-Path $outDir "InfraSight-Patch-$date-$sha.exe") -title 'InfraSight Patch' -iconFile $iconFile -noConsole:$false -requireAdmin:$false
    Invoke-ps2exe -inputFile (Join-Path $repoRoot 'uninstall.ps1') -outputFile (Join-Path $outDir "InfraSight-Uninstall-$date-$sha.exe") -title 'InfraSight Uninstall' -iconFile $iconFile -noConsole:$false -requireAdmin:$false
    Invoke-ps2exe -inputFile (Join-Path $repoRoot 'uninstall-agent.ps1') -outputFile (Join-Path $outDir "InfraSightAgent-Uninstall-$date-$sha.exe") -title 'InfraSight Agent Uninstall' -iconFile $iconFile -noConsole:$false -requireAdmin:$false

    $makensis = "${env:ProgramFiles(x86)}\NSIS\makensis.exe"
    if (-not (Test-Path $makensis)) { $makensis = "$env:ProgramFiles\NSIS\makensis.exe" }
    $buildFailures = @()
    if (Test-Path $makensis) {
        Push-Location (Join-Path $repoRoot 'ops')
        try {
            & $makensis "/DVERSION=$date-$sha" "/DINSTALL_PS1_PATH=$tempInstallPs1" installer.nsi
            if ($LASTEXITCODE -ne 0) {
                $buildFailures += 'GUI 설치 프로그램'
                Write-Warning "GUI 설치 프로그램(makensis) 빌드 실패 (종료 코드 $LASTEXITCODE) -- 나머지 빌드는 계속합니다."
            }

            & $makensis "/DVERSION=$date-$sha" "/DPATCH_PS1_PATH=$tempPatchPs1" patch-gui.nsi
            if ($LASTEXITCODE -ne 0) {
                $buildFailures += 'GUI 패치 프로그램'
                Write-Warning "GUI 패치 프로그램(makensis) 빌드 실패 (종료 코드 $LASTEXITCODE) -- 나머지 빌드는 계속합니다."
            }

            & $makensis "/DVERSION=$date-$sha" uninstall-gui.nsi
            if ($LASTEXITCODE -ne 0) {
                $buildFailures += 'GUI 제거 프로그램'
                Write-Warning "GUI 제거 프로그램(makensis) 빌드 실패 (종료 코드 $LASTEXITCODE) -- 나머지 빌드는 계속합니다."
            }

            & $makensis "/DVERSION=$date-$sha" uninstall-agent-gui.nsi
            if ($LASTEXITCODE -ne 0) {
                $buildFailures += 'GUI 에이전트 제거 프로그램'
                Write-Warning "GUI 에이전트 제거 프로그램(makensis) 빌드 실패 (종료 코드 $LASTEXITCODE) -- 나머지 빌드는 계속합니다."
            }
        } finally {
            Pop-Location
        }
    } else {
        Write-Warning 'NSIS(makensis.exe)를 찾을 수 없어 GUI 설치/패치/제거 프로그램 빌드를 건너뜁니다 (winget install NSIS.NSIS로 설치해주세요).'
    }

    Remove-Item $tempPatchPs1, $tempInstallPs1 -Force -ErrorAction SilentlyContinue
    # 버그 수정(2026-10-16): makensis 실패는 이미 위에서 Write-Warning으로
    # 찍혔지만, 그 바로 뒤에 "빌드 완료" 녹색 배너가 무조건 또 떠서 스크롤된
    # 터미널에서는 경고를 놓치고 "완료"만 보기 쉬웠음 -- 실패가 하나라도
    # 있으면 배너 자체를 다르게 보여줌 (exe 파일 일부가 안 만들어졌다는 걸
    # 바로 알 수 있게).
    if ($buildFailures.Count -gt 0) {
        Write-Host "`n빌드 일부 실패: $outDir (실패: $($buildFailures -join ', '))" -ForegroundColor Yellow
    } else {
        Write-Host "`n빌드 완료: $outDir" -ForegroundColor Green
    }
    Get-ChildItem $outDir
} finally {
    Pop-Location
}
