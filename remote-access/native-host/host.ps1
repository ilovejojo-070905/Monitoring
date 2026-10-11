<#
InfraSight Native Messaging Host
================================
Chrome 확장 프로그램(InfraSight 원격 접속)이 Native Messaging으로 보낸 메시지를
받아서 PuTTY를 실행한다. Native Messaging 프로토콜: stdin/stdout 모두
"4바이트 길이(리틀엔디안 uint32) + 그만큼의 UTF-8 JSON" 프레임 하나.

입력 메시지 형식: {"protocol":"ssh"|"telnet", "host":"...", "user":"...", "port":123}
(user/port는 선택)
#>
$ErrorActionPreference = 'SilentlyContinue'
$LogPath = Join-Path $PSScriptRoot 'host-debug.log'

function Write-Log($msg) {
    try { Add-Content -Path $LogPath -Value "$(Get-Date -Format o)  $msg" -Encoding utf8 } catch {}
}

function Send-Response([hashtable]$obj) {
    $json = $obj | ConvertTo-Json -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $stdout = [Console]::OpenStandardOutput()
    $stdout.Write([BitConverter]::GetBytes($bytes.Length), 0, 4)
    $stdout.Write($bytes, 0, $bytes.Length)
    $stdout.Flush()
    Write-Log "OUT=[$json]"
}

try {
    $stdin = [Console]::OpenStandardInput()

    $lenBytes = New-Object byte[] 4
    $readTotal = 0
    while ($readTotal -lt 4) {
        $n = $stdin.Read($lenBytes, $readTotal, 4 - $readTotal)
        if ($n -le 0) { Write-Log 'EOF before length prefix'; exit 0 }
        $readTotal += $n
    }
    $len = [BitConverter]::ToInt32($lenBytes, 0)
    if ($len -le 0 -or $len -gt 1MB) { Write-Log "SUSPICIOUS length=$len"; exit 1 }
    $msgBytes = New-Object byte[] $len
    $readTotal = 0
    while ($readTotal -lt $len) {
        $n = $stdin.Read($msgBytes, $readTotal, $len - $readTotal)
        if ($n -le 0) { break }
        $readTotal += $n
    }
    $json = [System.Text.Encoding]::UTF8.GetString($msgBytes)
    Write-Log "IN=[$json]"
    $msg = $json | ConvertFrom-Json

    # 이 PC(개발 겸 운영 PC)에서는 winget 기본 설치 위치에 있었지만, 다른
    # PC는 32비트 Program Files(x86)이거나, winget이 PATH에만 걸어두고
    # Program Files에 안 둔 경우(Caddy/mkcert와 같은 패턴 -- install.ps1의
    # Resolve-ExeAndAddToPath 주석 참고)이거나, PATH에만 있는 수동/choco
    # 설치일 수 있다 -- 하나로 단정하지 않고 알려진 위치를 순서대로 찾는다.
    function Resolve-Putty {
        $candidates = @(
            (Join-Path $env:ProgramFiles 'PuTTY\putty.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'PuTTY\putty.exe')
        )
        foreach ($p in $candidates) { if ($p -and (Test-Path $p)) { return $p } }
        $glob = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\PuTTY.PuTTY_*\putty.exe" -ErrorAction SilentlyContinue -File | Select-Object -First 1
        if ($glob) { return $glob.FullName }
        $cmd = Get-Command putty -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
        return $null
    }
    $PuttyExe = Resolve-Putty
    if (-not $PuttyExe) {
        Send-Response @{ ok = $false; error = 'PuTTY를 찾을 수 없습니다 (winget install PuTTY.PuTTY로 설치해주세요)' }
        exit 0
    }

    # 장비 IP는 InfraSight 쪽 정규식(is_valid_host)을 거쳐 온 값이지만, 이 호스트는
    # 외부에서 직접 메시지를 보낼 수도 있는 경계이므로 여기서도 다시 한번
    # 영숫자/점/하이픈/콜론(IPv6용)만 허용해 Start-Process 인자 목록에 그대로
    # 들어가더라도(셸 재해석 없음) 터무니없는 값은 걸러낸다.
    $hostVal = [string]$msg.host
    if ($hostVal -notmatch '^[A-Za-z0-9.\-:]{1,255}$') {
        Send-Response @{ ok = $false; error = 'host 형식이 올바르지 않습니다' }
        exit 0
    }
    $userVal = $null
    if ($msg.user) {
        $userVal = [string]$msg.user
        if ($userVal -notmatch '^[A-Za-z0-9._\-]{1,64}$') {
            Send-Response @{ ok = $false; error = 'user 형식이 올바르지 않습니다' }
            exit 0
        }
    }
    $portVal = $null
    if ($msg.port) {
        $portVal = [int]$msg.port
        if ($portVal -lt 1 -or $portVal -gt 65535) {
            Send-Response @{ ok = $false; error = 'port 범위가 올바르지 않습니다' }
            exit 0
        }
    }

    $puttyArgs = New-Object System.Collections.Generic.List[string]
    if ($msg.protocol -eq 'telnet') {
        $puttyArgs.Add('-telnet')
    } else {
        $puttyArgs.Add('-ssh')
    }
    if ($portVal) { $puttyArgs.Add('-P'); $puttyArgs.Add([string]$portVal) }
    $target = if ($userVal) { "$userVal@$hostVal" } else { $hostVal }
    $puttyArgs.Add($target)

    Write-Log "LAUNCH putty $($puttyArgs -join ' ')"
    Start-Process -FilePath $PuttyExe -ArgumentList $puttyArgs.ToArray()
    Send-Response @{ ok = $true }
} catch {
    Write-Log "ERROR=[$_]"
    try { Send-Response @{ ok = $false; error = "$_" } } catch {}
}
