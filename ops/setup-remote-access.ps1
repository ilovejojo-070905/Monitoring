<#
InfraSight 원격 접속(SSH/Telnet) 로컬 구성 요소 설치/갱신
=========================================================
네트워크 장비 목록의 SSH/Telnet 버튼이 동작하려면 이 PC에 두 가지가 필요하다:
  1. Native Messaging Host -- Chrome 확장 프로그램의 메시지를 받아 PuTTY를
     실행하는 PowerShell 스크립트 + 그걸 가리키는 레지스트리 키. 전부 이
     스크립트가 자동으로 만든다 (사용자가 직접 host.bat/host.ps1 파일을 만들
     필요가 없다).
  2. Chrome 확장 프로그램 "InfraSight 원격 접속" 소스 파일 -- 파일 자체는 이
     스크립트가 배치하지만, Chrome이 "압축해제된 확장 프로그램을 로드"하는
     건 브라우저 보안 정책상 스크립트로 자동화할 수 없어서(개발자 모드에서
     사람이 폴더를 직접 선택해야 함) 그 한 단계만 안내 메시지로 남긴다.

install.ps1(최초 설치)과 패치적용.ps1(기존 설치 갱신) 양쪽에서 공통으로
호출한다. 매번 다시 실행해도 안전함 -- 파일을 덮어쓰고 레지스트리 키를
다시 쓸 뿐, 뭔가를 지우거나 되돌리는 동작은 없다.
#>
param(
    [Parameter(Mandatory)]
    [string]$InstallDir,
    [Parameter(Mandatory)]
    [string]$PythonExe
)

function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg" -ForegroundColor Yellow }

$repoRemoteDir = Join-Path $InstallDir 'remote-access'
if (-not (Test-Path $repoRemoteDir)) {
    Write-Warn2 '원격 접속 구성 파일(remote-access\)이 이 설치 버전에 없어 건너뜁니다.'
    return
}

$baseDir = Join-Path $env:LOCALAPPDATA 'InfraSight'
$hostDir = Join-Path $baseDir 'native-host'
$extDir  = Join-Path $baseDir 'extension'
$extDirExisted = Test-Path $extDir
New-Item -ItemType Directory -Force -Path $hostDir | Out-Null
New-Item -ItemType Directory -Force -Path $extDir  | Out-Null

Copy-Item (Join-Path $repoRemoteDir 'native-host\host.ps1') (Join-Path $hostDir 'host.ps1') -Force
Copy-Item (Join-Path $repoRemoteDir 'native-host\host.bat') (Join-Path $hostDir 'host.bat') -Force
Copy-Item (Join-Path $repoRemoteDir 'extension\background.js') (Join-Path $extDir 'background.js') -Force

# host.json의 "path"는 이 PC에서 host.bat가 실제로 있는 절대 경로라 머신마다
# 달라진다(계정명이 다르면 %LOCALAPPDATA% 전체 경로가 달라짐) -- 그래서
# 레포에 고정 파일로 두지 않고 설치/패치 시점마다 이 경로를 넣어 새로 만든다.
$hostBatPath = Join-Path $hostDir 'host.bat'
$extensionId = 'ogpngpbjjcgifjaodhhnejonanmhhdhd'  # extension\manifest.json.template의 "key"에서 고정 유도된 값 -- 경로가 달라도 항상 동일
$hostJsonObj = [ordered]@{
    name = 'com.infrasight.remote'
    description = 'InfraSight remote access launcher'
    path = $hostBatPath
    type = 'stdio'
    allowed_origins = @("chrome-extension://$extensionId/")
}
($hostJsonObj | ConvertTo-Json) | Set-Content -Path (Join-Path $hostDir 'host.json') -Encoding utf8

# manifest.json의 externally_connectable.matches도 머신마다 다른 LAN IP가
# 필요하다 (install.ps1의 인증서 발급과 같은 이유 -- storage.get_lan_ip()를
# 그대로 재사용해 두 곳의 "이 PC의 LAN IP" 판단이 항상 일치하게 한다).
$lanIp = (& $PythonExe -c "import storage; print(storage.get_lan_ip())").Trim()
$manifestTemplate = Get-Content (Join-Path $repoRemoteDir 'extension\manifest.json.template') -Raw
$manifestTemplate.Replace('__LAN_IP__', $lanIp) | Set-Content -Path (Join-Path $extDir 'manifest.json') -Encoding utf8 -NoNewline

# Chrome Native Messaging Host 등록 (HKCU -- 관리자 권한 불필요, 이 로그인
# 계정에서 Chrome이 조회하는 바로 그 위치).
$regKeyPath = 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.infrasight.remote'
New-Item -Path $regKeyPath -Force | Out-Null
Set-ItemProperty -Path $regKeyPath -Name '(default)' -Value (Join-Path $hostDir 'host.json')
Write-Ok "원격 접속 Native Messaging Host 등록 완료 (LAN IP: $lanIp)"

if (-not (Test-Path 'C:\Program Files\PuTTY\putty.exe')) {
    Write-Warn2 'PuTTY가 설치되어 있지 않습니다 -- SSH/Telnet 버튼을 쓰려면 PuTTY를 설치해주세요 (winget install PuTTY.PuTTY).'
}

if (-not $extDirExisted) {
    Write-Host ''
    Write-Host '    [최초 1회 수동 설정] 네트워크 장비 목록의 SSH/Telnet 버튼을 쓰려면' -ForegroundColor Yellow
    Write-Host '    Chrome 확장 프로그램을 한 번만 등록해야 합니다 (브라우저 보안 정책상' -ForegroundColor Yellow
    Write-Host '    이 단계만큼은 자동화가 불가능합니다):' -ForegroundColor Yellow
    Write-Host "      1. Chrome에서 chrome://extensions 열기"
    Write-Host "      2. 우측 상단 '개발자 모드' 켜기"
    Write-Host "      3. '압축해제된 확장 프로그램을 로드합니다' 클릭 -> 아래 폴더 선택:"
    Write-Host "         $extDir" -ForegroundColor Cyan
    Write-Host ''
    try { Start-Process 'explorer.exe' $extDir } catch {}
} else {
    Write-Ok '확장 프로그램 파일 갱신 완료 (이미 등록되어 있다면 다시 로드할 필요 없음)'
}
