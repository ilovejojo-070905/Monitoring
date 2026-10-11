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
  - InfraSight-Patch-*.exe       : -BaseCommit부터 HEAD까지의 git diff를
                                    exe 안에 통째로 내장한 패치 (패치적용.ps1의
                                    $EMBEDDED_PATCH_B64 참고) -- 별도 .patch
                                    파일 없이 exe 하나만 전달하면 된다.
  - InfraSight-Uninstall-*.exe   : uninstall.ps1을 ps2exe로 감싼 제거 프로그램

사용법 (저장소 루트에서):
    powershell -ExecutionPolicy Bypass -File ops\build-release.ps1
    powershell -ExecutionPolicy Bypass -File ops\build-release.ps1 -BaseCommit abcd123
#>
param(
    [string]$BaseCommit = '72e4fbd'
)

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

    # base64로 담는 이유는 패치적용.ps1 쪽 $EMBEDDED_PATCH_B64 주석 참고 --
    # diff 텍스트를 여기-문자열에 그대로 박으면 우연히 줄 맨 앞에 오는 '@
    # 같은 패턴에 깨질 수 있어서, 그런 걱정이 없는 base64로 옮긴다.
    $diffText = (& git format-patch "$BaseCommit..HEAD" --stdout) -join "`n"
    $diffB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($diffText))

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
