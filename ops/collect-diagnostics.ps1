<#
InfraSight 진단 정보 수집
=========================
새 환경에 설치/패치하다 문제가 생겼을 때 그 PC에 원격 접속하지 않고도 원인을
찾을 수 있게, 필요한 정보를 zip 하나로 묶어 바탕화면에 만든다(사용자 요청:
"새로운 환경에 셋업 및 패치 시 문제 발생하면 파일이나 로그 같은 거 만들어서
그걸로 확인해서 문제를 해결하는 방법은 없어?").

- 설치(install.ps1)/패치(패치적용.ps1, ops\patch.ps1)가 실패하면 자동으로 호출된다
  (-Reason, -TranscriptPath로 실패 사유와 진행 로그를 같이 넘김).
- 설치는 됐는데 나중에 접속이 안 되는 등은 InfraSight-Diagnostics-*.exe(이
  스크립트를 감싼 것)를 더블클릭하거나 직접 실행:
      powershell -ExecutionPolicy Bypass -File collect-diagnostics.ps1

넣지 않는 것: DB(infrasight.db), 자격증명 암호화 키, 인증서 개인키, 장비 설정
백업(config-backups), 보안 감사 로그(security.log) -- 비밀번호/개인 정보가 들어갈
수 있는 것은 전부 제외. 관리자 권한 없이도 돈다(일부 항목만 "권한 없음"으로 표시).
어떤 항목이 실패해도 나머지는 계속 수집한다.
#>
param(
    [string]$InstallDir,
    [string]$Reason = '사용자가 직접 실행',
    [string[]]$TranscriptPath = @(),
    [string]$OutDir = [Environment]::GetFolderPath('Desktop'),
    [switch]$NoPause
)

$ErrorActionPreference = 'Continue'
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$stage = Join-Path $env:TEMP "InfraSight-diag-$ts-$([guid]::NewGuid().ToString('N').Substring(0,6))"
New-Item -ItemType Directory -Force -Path $stage | Out-Null
$summary = Join-Path $stage 'summary.txt'

function Add-Section([string]$title, [scriptblock]$body) {
    Add-Content -Path $summary -Encoding utf8 -Value "`r`n===== $title ====="
    try {
        $out = & $body 2>&1 | Out-String -Width 220
        Add-Content -Path $summary -Encoding utf8 -Value $out.TrimEnd()
    } catch {
        Add-Content -Path $summary -Encoding utf8 -Value "(수집 실패: $_)"
    }
}

# 실행 파일 위치/버전 -- PATH에서 못 찾으면 install.ps1이 설치하는 기본 위치도 본다.
function Find-Tool([string]$cmd, [string[]]$globs) {
    $c = Get-Command $cmd -ErrorAction SilentlyContinue | Where-Object { $_.Source -notmatch '\\WindowsApps\\' } | Select-Object -First 1
    if ($c) { return $c.Source }
    foreach ($g in $globs) {
        $f = Get-ChildItem $g -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($f) { return "$($f.FullName)  (PATH에는 없음)" }
    }
    return $null
}

function Test-Tcp([string]$hostName, [int]$port, [int]$timeoutMs = 3000) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $c.BeginConnect($hostName, $port, $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne($timeoutMs) -and $c.Connected) { return 'OK' }
        return '연결 안 됨(시간 초과)'
    } catch { return "실패: $($_.Exception.InnerException.Message)" } finally { $c.Close() }
}

function Copy-Tail([string]$src, [string]$destName, [int]$lines = 3000) {
    if (Test-Path $src) {
        try { Get-Content $src -Tail $lines -Encoding utf8 | Set-Content (Join-Path $stage $destName) -Encoding utf8 } catch {}
    }
}

Write-Host '[InfraSight] 진단 정보를 수집하는 중입니다 (1분 정도 걸릴 수 있습니다)...' -ForegroundColor Cyan

# ---------------------------------------------------------------- 설치 위치
if (-not $InstallDir) {
    try {
        $t = Get-ScheduledTask -TaskName 'InfraSight Supervisor' -ErrorAction SilentlyContinue
        if ($t -and $t.Actions[0].WorkingDirectory) { $InstallDir = $t.Actions[0].WorkingDirectory }
    } catch {}
}
if (-not $InstallDir) {
    foreach ($cand in 'C:\InfraSight', (Join-Path $env:LOCALAPPDATA 'InfraSight')) {
        if (Test-Path (Join-Path $cand '.git')) { $InstallDir = $cand; break }
    }
}

Set-Content -Path $summary -Encoding utf8 -Value @"
InfraSight 진단 정보
수집 시각 : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
수집 사유 : $Reason
PC 이름   : $env:COMPUTERNAME
사용자    : $env:USERDOMAIN\$env:USERNAME
설치 위치 : $(if ($InstallDir) { $InstallDir } else { '(찾지 못함 -- 설치 전이거나 설치 초기에 실패)' })
"@

Add-Section '운영체제 / PowerShell / 권한' {
    $os = Get-CimInstance Win32_OperatingSystem
    "OS        : $($os.Caption) $($os.Version) (빌드 $($os.BuildNumber)), $($os.OSArchitecture)"
    "부팅 시각 : $($os.LastBootUpTime)"
    "PowerShell: $($PSVersionTable.PSVersion)  ($($Host.Name))"
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    "관리자 권한으로 실행 중: $((New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
    "언어/지역 : $((Get-Culture).Name) / 시스템 코드페이지 $([Text.Encoding]::Default.CodePage)"
    'ExecutionPolicy:'; Get-ExecutionPolicy -List | Format-Table -AutoSize
}

Add-Section '필수 도구 (경로 / 버전)' {
    $tools = [ordered]@{
        git    = @("$env:ProgramFiles\Git\cmd\git.exe")
        python = @("$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe", "$env:ProgramFiles\Python3*\python.exe")
        caddy  = @("$env:LOCALAPPDATA\Microsoft\WinGet\Links\caddy.exe", "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\CaddyServer.Caddy_*\caddy.exe")
        mkcert = @("$env:LOCALAPPDATA\Microsoft\WinGet\Links\mkcert.exe", "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\FiloSottile.mkcert_*\mkcert*.exe")
        winget = @("$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe")
    }
    foreach ($k in $tools.Keys) {
        $p = Find-Tool $k $tools[$k]
        if (-not $p) { "{0,-7}: 없음" -f $k; continue }
        $exe = ($p -split '  \(')[0]
        $ver = try { (& $exe --version 2>&1 | Select-Object -First 1) } catch { '(버전 확인 실패)' }
        if ($k -eq 'mkcert') { $ver = try { & $exe -version 2>&1 | Select-Object -First 1 } catch { '' } }
        "{0,-7}: {1}  -> {2}" -f $k, $p, $ver
    }
    "`nWindowsApps의 python 스텁(가짜 python): $([bool](Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WindowsApps\python*.exe" -ErrorAction SilentlyContinue))"
    "`nPATH (사용자+시스템, 현재 프로세스):"
    $env:Path -split ';' | Where-Object { $_ } | ForEach-Object { "  $_" }
}

Add-Section '디스크' {
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        "{0} 전체 {1:N1}GB / 남음 {2:N1}GB" -f $_.DeviceID, ($_.Size / 1GB), ($_.FreeSpace / 1GB)
    }
}

Add-Section '네트워크 (IP / 게이트웨이 / DNS / 프록시)' {
    Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4Address } | ForEach-Object {
        "{0}: IP {1}, 게이트웨이 {2}, DNS {3}" -f $_.InterfaceAlias, ($_.IPv4Address.IPAddress -join ','),
            ($_.IPv4DefaultGateway.NextHop -join ','), ($_.DNSServer.ServerAddresses -join ',')
    }
    "`nWinHTTP 프록시:"; (netsh winhttp show proxy) -join "`n"
    $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    "사용자 프록시: 사용=$($ie.ProxyEnable) 서버=$($ie.ProxyServer) 자동구성=$($ie.AutoConfigURL)"
    "환경변수 HTTP(S)_PROXY: $env:HTTP_PROXY / $env:HTTPS_PROXY"
}

Add-Section '인터넷 연결 (설치 시 필요한 사이트)' {
    foreach ($h in 'github.com', 'objects.githubusercontent.com', 'pypi.org', 'files.pythonhosted.org', 'cdn.winget.microsoft.com', 'dl.cloudsmith.io') {
        $dns = try { ([System.Net.Dns]::GetHostAddresses($h) | Select-Object -First 1).IPAddressToString } catch { 'DNS 실패' }
        "{0,-32} DNS={1,-16} 443={2}" -f $h, $dns, (Test-Tcp $h 443)
    }
}

Add-Section '포트 사용 현황 (8443 HTTPS / 5057 백엔드 / 514 syslog / 2055 / 6343)' {
    foreach ($port in 8443, 5057) {
        $l = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)
        if (-not $l.Count) { "TCP $port : 아무도 안 씀"; continue }
        foreach ($c in $l) { "TCP $port : PID $($c.OwningProcess) ($((Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName)) $($c.LocalAddress)" }
    }
    foreach ($port in 514, 2055, 6343) {
        $u = @(Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue)
        "UDP $port : " + $(if ($u.Count) { ($u | ForEach-Object { "PID $($_.OwningProcess) ($((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName))" }) -join ', ' } else { '아무도 안 씀' })
    }
}

Add-Section '방화벽 규칙 (InfraSight)' {
    $rules = Get-NetFirewallRule -DisplayName 'InfraSight*' -ErrorAction SilentlyContinue
    if (-not $rules) { '(InfraSight 규칙 없음)' }
    foreach ($r in $rules) {
        $pf = $r | Get-NetFirewallPortFilter
        "{0}: 사용={1} 방향={2} 동작={3} 프로필={4} {5}/{6}" -f $r.DisplayName, $r.Enabled, $r.Direction, $r.Action, $r.Profile, $pf.Protocol, $pf.LocalPort
    }
    "`n방화벽 프로필:"; Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.Name): 켜짐=$($_.Enabled)" }
}

Add-Section '백신 / 보안 프로그램' {
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
        ForEach-Object { "$($_.displayName) (상태코드 $($_.productState))" }
    try { $mp = Get-MpPreference -ErrorAction Stop; "Defender 제외 경로: $($mp.ExclusionPath -join ', ')" } catch { 'Defender 설정 조회 불가(권한/다른 백신)' }
}

Add-Section '자동 시작 작업 (InfraSight Supervisor)' {
    $t = Get-ScheduledTask -TaskName 'InfraSight Supervisor' -ErrorAction SilentlyContinue
    if (-not $t) { '(등록 안 됨)' } else {
        $i = Get-ScheduledTaskInfo -TaskName 'InfraSight Supervisor'
        "사용자/방식: $($t.Principal.UserId) / $($t.Principal.LogonType) / $($t.Principal.RunLevel)"
        "트리거: $(($t.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task','' }) -join ', ')"
        "동작: $($t.Actions[0].Execute) $($t.Actions[0].Arguments)  (시작 위치 $($t.Actions[0].WorkingDirectory))"
        "마지막 실행: $($i.LastRunTime) 결과코드 $($i.LastTaskResult) / 다음: $($i.NextRunTime)"
    }
}

Add-Section '실행 중인 InfraSight 관련 프로세스' {
    Get-Process powershell, python, caddy -ErrorAction SilentlyContinue |
        Select-Object Id, ProcessName, SessionId, @{n='시작';e={ try { $_.StartTime } catch { '(다른 세션)' } }} |
        Sort-Object SessionId, ProcessName | Format-Table -AutoSize
}

Add-Section '서버 응답 확인' {
    foreach ($u in 'http://127.0.0.1:5057/api/system/health-public', 'https://localhost:8443/api/system/health-public') {
        try { "$u -> " + ((Invoke-RestMethod $u -TimeoutSec 5) | ConvertTo-Json -Compress) } catch { "$u -> 실패: $($_.Exception.Message)" }
    }
}

if ($InstallDir -and (Test-Path $InstallDir)) {
    Add-Section '설치 폴더 / 코드 버전' {
        $git = Find-Tool 'git' @("$env:ProgramFiles\Git\cmd\git.exe")
        if ($git) {
            $g = ($git -split '  \(')[0]
            "커밋: $(& $g -C $InstallDir log --oneline -1 2>&1)"
            "변경된 파일(git status):"; & $g -C $InstallDir status --short 2>&1 | Select-Object -First 40
        }
        "`n폴더 내용:"; Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue | Select-Object Mode, LastWriteTime, Length, Name | Format-Table -AutoSize
    }
    Add-Section 'HTTPS 인증서 (공개 인증서만, 개인키 제외)' {
        $crt = Join-Path $InstallDir 'certs\infrasight.crt'
        if (-not (Test-Path $crt)) { '(인증서 파일 없음)' } else {
            $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($crt)
            "유효기간: $($c.NotBefore) ~ $($c.NotAfter)"
            "주소 목록: $(($c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }).Format($false))"
            "발급자: $($c.Issuer)"
        }
        "mkcert 로컬 CA 키 존재: $(Test-Path (Join-Path $env:LOCALAPPDATA 'mkcert\rootCA-key.pem'))"
    }
    Add-Section '파이썬 패키지' {
        $py = Find-Tool 'python' @("$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe")
        if ($py) { & (($py -split '  \(')[0]) -m pip list --disable-pip-version-check 2>&1 }
    }
    foreach ($f in 'supervisor.log', 'app.log', 'error.log') { Copy-Tail (Join-Path $InstallDir "logs\$f") "logs-$f" }
    foreach ($f in 'status.json', 'restart-history.json', 'mkcert.err.log') {
        $p = Join-Path $InstallDir "run\$f"
        if (Test-Path $p) { Copy-Item $p (Join-Path $stage "run-$f") -ErrorAction SilentlyContinue }
    }
    # 지난 설치/패치 진행 로그(성공했던 것 포함)
    Get-ChildItem (Join-Path $InstallDir 'logs') -Filter 'InfraSight-setup-*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 5 |
        ForEach-Object { Copy-Item $_.FullName (Join-Path $stage "past-$($_.Name)") -ErrorAction SilentlyContinue }
}

# 이번 설치/패치 진행 로그(호출한 쪽이 넘겨줌)
$n = 0
foreach ($tp in $TranscriptPath) {
    if ($tp -and (Test-Path $tp)) { $n++; Copy-Item $tp (Join-Path $stage "this-run-$n-$(Split-Path $tp -Leaf)") -ErrorAction SilentlyContinue }
}
# 최근 InfraSight 설치/패치 로그가 TEMP에 남아 있으면 같이(직접 실행한 경우)
$thisRunNames = @($TranscriptPath | Where-Object { $_ } | ForEach-Object { Split-Path $_ -Leaf })
Get-ChildItem $env:TEMP -Filter 'InfraSight-setup-*.log' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin $thisRunNames } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 3 |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $stage "temp-$($_.Name)") -ErrorAction SilentlyContinue }

Add-Section '최근 Windows 응용 프로그램 오류 (python/caddy/powershell, 3일)' {
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 2; StartTime = (Get-Date).AddDays(-3) } -MaxEvents 300 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'python|caddy|powershell|InfraSight' } | Select-Object -First 15 |
        ForEach-Object { "$($_.TimeCreated) [$($_.ProviderName)] $(($_.Message -split "`n")[0..3] -join ' | ')" }
}

# ---------------------------------------------------------------- 묶기
if (-not (Test-Path $OutDir)) { $OutDir = $env:TEMP }
$zip = Join-Path $OutDir "InfraSight-진단-$env:COMPUTERNAME-$ts.zip"
try {
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Yellow
    Write-Host ' 진단 파일을 만들었습니다:' -ForegroundColor Yellow
    Write-Host "   $zip" -ForegroundColor Yellow
    Write-Host ' 이 파일을 개발 담당 PC로 가져가 주세요 (원격 접속 없이 원인을 확인할 수 있습니다).' -ForegroundColor Yellow
    Write-Host ' (비밀번호/DB/암호화 키/장비 설정 백업은 들어 있지 않습니다)' -ForegroundColor DarkGray
    Write-Host '============================================================' -ForegroundColor Yellow
} catch {
    $zip = $stage
    Write-Host "zip 만들기에 실패해 폴더로 남겼습니다: $stage ($_)" -ForegroundColor Yellow
}
if (-not $NoPause) {
    Write-Host "`n아무 키나 누르면 창이 닫힙니다..." -ForegroundColor DarkGray
    try { [void][System.Console]::ReadKey($true) } catch { Start-Sleep -Seconds 3 }
}
# 호출한 쪽(설치/패치)이 경로를 알 수 있게 마지막 출력으로 남김
Write-Output $zip
