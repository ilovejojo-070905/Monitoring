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

# 자동 설치(GUI installer -> nsExec::ExecToLog) 경로에서 이 스크립트가 일부만
# 실행되고 조용히 멈추는 현상이 실측으로 반복 확인됐는데(수동으로 같은 환경을
# 똑같이 재현해 돌리면 매번 성공함), 그 설치 창은 끝나면 로그가 같이 사라져서
# 사후에 원인을 짚을 방법이 없었다 -- host.ps1의 host-debug.log와 같은 이유로,
# 매 실행마다 어디까지 도달했는지 파일에 남긴다.
$diagLog = Join-Path $env:LOCALAPPDATA 'InfraSight\setup-remote-access.log'
function Write-Diag($msg) {
    try {
        New-Item -ItemType Directory -Force -Path (Split-Path $diagLog -Parent) -ErrorAction SilentlyContinue | Out-Null
        Add-Content -Path $diagLog -Value "$(Get-Date -Format o)  $msg" -Encoding utf8
    } catch {}
}
Write-Diag "시작 (InstallDir=$InstallDir, PythonExe=$PythonExe)"

try {

$repoRemoteDir = Join-Path $InstallDir 'remote-access'
if (-not (Test-Path $repoRemoteDir)) {
    Write-Warn2 '원격 접속 구성 파일(remote-access\)이 이 설치 버전에 없어 건너뜁니다.'
    Write-Diag 'remote-access 폴더 없음 -- 건너뜀'
    return
}

$baseDir = Join-Path $env:LOCALAPPDATA 'InfraSight'
$hostDir = Join-Path $baseDir 'native-host'
$extDir  = Join-Path $baseDir 'extension'
$extDirExisted = Test-Path $extDir
New-Item -ItemType Directory -Force -Path $hostDir | Out-Null
New-Item -ItemType Directory -Force -Path $extDir  | Out-Null
Write-Diag '디렉터리 준비 완료'

Copy-Item (Join-Path $repoRemoteDir 'native-host\host.ps1') (Join-Path $hostDir 'host.ps1') -Force
Copy-Item (Join-Path $repoRemoteDir 'native-host\host.bat') (Join-Path $hostDir 'host.bat') -Force
Copy-Item (Join-Path $repoRemoteDir 'extension\background.js') (Join-Path $extDir 'background.js') -Force
Write-Diag 'host.ps1/host.bat/background.js 복사 완료'

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
# 실제 원인 발견: Windows PowerShell 5.1의 -Encoding utf8은 Set-Content/Out-File
# 어느 쪽으로 써도 항상 파일 맨 앞에 UTF-8 BOM(EF BB BF)을 붙인다 -- Chrome의
# Native Messaging 매니페스트 파서는 이 BOM을 허용하지 않아서, 레지스트리/
# host.bat 경로가 전부 올바른데도 "Specified native messaging host not found"로
# 실패한다 (host-debug.log에 아예 실행 시도 흔적조차 없는 것으로 실측 확인 --
# Chrome이 매니페스트 파싱 단계에서부터 이 호스트를 "없는 것"으로 취급했다는
# 뜻). BOM 없이 쓰려면 .NET의 UTF8Encoding(false)를 직접 써야 한다.
$hostJsonText = $hostJsonObj | ConvertTo-Json
[System.IO.File]::WriteAllText((Join-Path $hostDir 'host.json'), $hostJsonText, (New-Object System.Text.UTF8Encoding $false))
Write-Diag 'host.json 생성 완료'

# manifest.json의 externally_connectable.matches도 머신마다 다른 LAN IP가
# 필요하다 (install.ps1의 인증서 발급과 같은 이유 -- storage.get_lan_ip()를
# 그대로 재사용해 두 곳의 "이 PC의 LAN IP" 판단이 항상 일치하게 한다).
Write-Diag 'LAN IP 조회 시작'
# 실제 원인 발견: `python -c "..."`는 스크립트 파일이 아니라 코드 문자열이라
# sys.path에 아무 폴더도 자동으로 안 끼워준다 -- import storage가 되려면
# "현재 작업 디렉터리"가 storage.py가 있는 $InstallDir이어야 하는데, 이
# 스크립트는(install.ps1의 앞선 단계들과 달리) 그 디렉터리로 미리 옮겨두지
# 않았다. 사람이 손으로 테스트할 때는 항상 먼저 cd D:\InfraSight 하고
# 돌렸으니 매번 우연히 성공했고, GUI 설치 자동 실행(ops\installer.nsi ->
# install.ps1 -> 이 스크립트) 중에는 그 디렉터리가 아닌 전혀 다른 곳(NSIS가
# 이 프로세스를 띄운 그 위치)이라 import storage가 실패해 $lanIp가 $null이
# 되고, 그 뒤 .Trim() 호출에서 "null 값 식에서 메서드를 호출할 수 없습니다"로
# 터졌다 -- host-debug.log에 오늘 날짜 기록이 전혀 없던 이유(= host.json/
# manifest.json이 끝까지 안 만들어져 레지스트리는 예전 값 그대로였던 것)가
# 바로 이거였다.
Push-Location $InstallDir
try {
    $lanIp = (& $PythonExe -c "import storage; print(storage.get_lan_ip())").Trim()
} finally {
    Pop-Location
}
Write-Diag "LAN IP 조회 완료: [$lanIp]"
# -Encoding를 안 주면 BOM 없는 UTF-8 파일을 PowerShell 5.1이 시스템 ANSI
# 코드페이지(CP949)로 잘못 읽어서 한글이 깨진다 -- 실측 확인: manifest.json의
# "name"/"description" 필드가 "InfraSight ?먭꺽 ?묒냽" 처럼 깨져서 생성됐음
# (JSON 형식 자체는 유효해서 Chrome이 로드는 하지만 표시 이름이 깨짐).
$manifestTemplate = Get-Content (Join-Path $repoRemoteDir 'extension\manifest.json.template') -Raw -Encoding UTF8
# host.json과 같은 이유로 -Encoding utf8(BOM 붙음) 대신 BOM 없는 .NET
# UTF8Encoding을 직접 쓴다 -- Chrome의 확장 프로그램 매니페스트 파서도 BOM이
# 있으면 "압축해제된 확장 프로그램을 로드"할 때 파싱에 실패할 수 있다.
$manifestText = $manifestTemplate.Replace('__LAN_IP__', $lanIp)
[System.IO.File]::WriteAllText((Join-Path $extDir 'manifest.json'), $manifestText, (New-Object System.Text.UTF8Encoding $false))
Write-Diag 'manifest.json 생성 완료'

# Chrome Native Messaging Host 등록 (HKCU -- 관리자 권한 불필요, 이 로그인
# 계정에서 Chrome이 조회하는 바로 그 위치).
$regKeyPath = 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.infrasight.remote'
New-Item -Path $regKeyPath -Force | Out-Null
Set-ItemProperty -Path $regKeyPath -Name '(default)' -Value (Join-Path $hostDir 'host.json')
Write-Ok "원격 접속 Native Messaging Host 등록 완료 (LAN IP: $lanIp)"
Write-Diag '레지스트리 등록 완료 -- 정상 종료'

# host.ps1의 Resolve-Putty와 같은 위치들을 확인한다 (install.ps1 쪽에서
# winget으로 이미 설치했으면 보통 바로 찾아지지만, 그 전에 수동으로 PuTTY를
# 이미 깔아둔 PC는 다른 위치일 수 있다).
$puttyFound = $false
foreach ($p in @((Join-Path $env:ProgramFiles 'PuTTY\putty.exe'), (Join-Path ${env:ProgramFiles(x86)} 'PuTTY\putty.exe'))) {
    if ($p -and (Test-Path $p)) { $puttyFound = $true; break }
}
if (-not $puttyFound) {
    if (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\PuTTY.PuTTY_*\putty.exe" -ErrorAction SilentlyContinue -File | Select-Object -First 1) { $puttyFound = $true }
}
if (-not $puttyFound -and (Get-Command putty -ErrorAction SilentlyContinue)) { $puttyFound = $true }
if (-not $puttyFound) {
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
    # 이 폴더를 탐색기로 자동으로 여는 건 여기(설치 진행 중)가 아니라
    # ops\installer.nsi의 마침 버튼 콜백(OnFinishLeave)에서 한다 -- 여기서
    # 열면 GUI 설치 마법사가 "설치 중" 화면일 때 탐색기 창이 불쑥 끼어들어서
    # 사용자가 아직 마침 버튼도 안 눌렀는데 다른 창이 앞에 뜨는 흐름이 됐었다.
} else {
    Write-Ok '확장 프로그램 파일 갱신 완료 (이미 등록되어 있다면 다시 로드할 필요 없음)'
}

} catch {
    # 마지막으로 성공한 Write-Diag 체크포인트 다음 줄 어딘가에서 터졌다는
    # 뜻이다 -- 여기서 실제 예외 내용까지 로그에 남긴 뒤 그대로 다시 던져서,
    # install.ps1 쪽의 기존 try/catch(원격 접속 구성 실패를 무시하고 계속
    # 진행하는 처리)는 지금과 똑같이 동작한다.
    Write-Diag "예외 발생: $_ -- 위치: $($_.InvocationInfo.PositionMessage)"
    throw
}
