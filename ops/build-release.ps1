<#
InfraSight 릴리스 빌드 (Setup.exe + 자체 내장형 Patch.exe)
===========================================================
현재 HEAD 기준으로 InfraSight-Setup-*.exe / InfraSight-Patch-*.exe를
이 저장소의 setup\ 폴더에 새로 만든다. Patch.exe는 -BaseCommit부터 HEAD까지의
git diff를 exe 안에 통째로 내장하므로(패치적용.ps1의 $EMBEDDED_PATCH_B64
참고), 별도 .patch 파일을 같이 보낼 필요가 없다 -- exe 하나만 전달하면 된다.

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

    Remove-Item $tempPs1 -Force -ErrorAction SilentlyContinue
    Write-Host "`n빌드 완료: $outDir" -ForegroundColor Green
    Get-ChildItem $outDir
} finally {
    Pop-Location
}
