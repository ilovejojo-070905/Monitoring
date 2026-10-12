<#
InfraSight 릴리스 빌드 (Setup.exe + Setup-GUI.exe + 자체 내장형 Patch.exe + Uninstall.exe)
=============================================================================
현재 HEAD 기준으로 이 저장소의 setup\ 폴더에 새로 만든다:
  - InfraSight-Setup-*.exe       : install.ps1을 그대로 ps2exe로 감싼 콘솔
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

    $patchSrc = Get-Content (Join-Path $repoRoot '패치적용.ps1') -Raw -Encoding UTF8
    $patchSrc = $patchSrc.Replace('__EMBEDDED_PATCH_B64__', $diffB64)
    $tempPs1 = Join-Path $env:TEMP "infrasight-patch-embedded-$([guid]::NewGuid().ToString('N')).ps1"
    # ps2exe가 소스를 한글 주석까지 포함해 정확히 읽으려면 BOM이 있어야 한다
    # (이번 세션에 실제로 BOM 없는 .ps1이 $PSParser에서 깨진 전례가 있었음).
    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($tempPs1, $patchSrc, $utf8Bom)

    $iconFile = Join-Path $repoRoot 'ops\assets\installer.ico'

    Import-Module ps2exe
    Invoke-ps2exe -inputFile (Join-Path $repoRoot 'install.ps1') -outputFile (Join-Path $outDir "InfraSight-Setup-$date-$sha.exe") -title 'InfraSight Setup' -iconFile $iconFile -noConsole:$false -requireAdmin:$false
    Invoke-ps2exe -inputFile $tempPs1 -outputFile (Join-Path $outDir "InfraSight-Patch-$date-$sha.exe") -title 'InfraSight Patch' -iconFile $iconFile -noConsole:$false -requireAdmin:$false
    Invoke-ps2exe -inputFile (Join-Path $repoRoot 'uninstall.ps1') -outputFile (Join-Path $outDir "InfraSight-Uninstall-$date-$sha.exe") -title 'InfraSight Uninstall' -iconFile $iconFile -noConsole:$false -requireAdmin:$false

    $makensis = "${env:ProgramFiles(x86)}\NSIS\makensis.exe"
    if (-not (Test-Path $makensis)) { $makensis = "$env:ProgramFiles\NSIS\makensis.exe" }
    if (Test-Path $makensis) {
        Push-Location (Join-Path $repoRoot 'ops')
        try {
            & $makensis "/DVERSION=$date-$sha" installer.nsi
            if ($LASTEXITCODE -ne 0) { Write-Warning "GUI 설치 프로그램(makensis) 빌드 실패 (종료 코드 $LASTEXITCODE) -- 나머지 빌드는 계속합니다." }
        } finally {
            Pop-Location
        }
    } else {
        Write-Warning 'NSIS(makensis.exe)를 찾을 수 없어 GUI 설치 프로그램 빌드를 건너뜁니다 (winget install NSIS.NSIS로 설치해주세요).'
    }

    Remove-Item $tempPs1 -Force -ErrorAction SilentlyContinue
    Write-Host "`n빌드 완료: $outDir" -ForegroundColor Green
    Get-ChildItem $outDir
} finally {
    Pop-Location
}
