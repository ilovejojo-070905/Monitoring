<#
로컬 개발 서버 앞에 임시 HTTPS Caddy 띄우기 (functional_tests.py/security_tests.py용)
================================================================================
security_tests.py/functional_tests.py는 세션 쿠키가 Secure 플래그(HTTPS 전용)로
설정돼 있어서, 개발 서버의 평문 백엔드 포트에 직접 쏘면 로그인은 성공해도
그 다음 모든 인증 호출이 401로 실패한다(쿠키가 아예 재전송되지 않음). 실제
운영은 Caddy가 그 앞단을 맡지만, 로컬 개발 서버를 그때그때 띄울 때는 보통
Caddy 없이 python server.py만 돌리므로 이 문제를 매번 새로 겪는다.

이 스크립트는 지정한 백엔드 포트 앞에 짧게 쓰고 버릴 HTTPS Caddy를 하나
띄운다 -- 운영 Caddy(8443, Caddyfile)와는 완전히 별도의 포트/설정이라
운영에 전혀 영향 없음. 인증서는 이 저장소의 certs\를 그대로 재사용한다
(mkcert로 이미 발급돼 있다는 전제 -- install.ps1이 처음 설치 시 만들어둔다).

사용법:
    # 1) 평문 포트로 개발 서버를 먼저 띄운다
    $env:INFRASIGHT_PORT = '5099'
    Start-Process python -ArgumentList 'server.py' -WorkingDirectory .

    # 2) 이 스크립트로 그 앞에 임시 HTTPS를 띄운다
    powershell -ExecutionPolicy Bypass -File ops\devtest-https.ps1 -BackendPort 5099 -CaddyPort 8444

    # 3) 테스트를 https://localhost:<CaddyPort> 로 실행
    $env:INFRASIGHT_TEST_ADMIN_USER='...'; $env:INFRASIGHT_TEST_ADMIN_PASS='...'
    python security_tests.py https://localhost:8444
    python functional_tests.py https://localhost:8444

    # 4) 끝나면 반환된 PID를 종료
    Stop-Process -Id <PID>
#>
param(
    [Parameter(Mandatory)]
    [int]$BackendPort,
    [int]$CaddyPort = 8444
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$certPath = Join-Path $ProjectRoot 'certs\infrasight.crt'
$keyPath  = Join-Path $ProjectRoot 'certs\infrasight.key'

if (-not (Test-Path $certPath) -or -not (Test-Path $keyPath)) {
    throw "certs\infrasight.crt/.key 를 찾을 수 없습니다 -- install.ps1을 한 번 실행했는지 확인해주세요 (mkcert 인증서 발급 단계)."
}

$caddyExe = (Get-Command caddy -ErrorAction SilentlyContinue).Source
if (-not $caddyExe) { throw "caddy.exe를 PATH에서 찾을 수 없습니다 (예: winget install CaddyServer.Caddy)." }

$configPath = Join-Path ([System.IO.Path]::GetTempPath()) "infrasight-devtest-https-$CaddyPort.Caddyfile"
@"
{
	admin off
	auto_https off
}

:$CaddyPort {
	tls $certPath $keyPath
	reverse_proxy 127.0.0.1:$BackendPort
}
"@ | Set-Content -Path $configPath -Encoding utf8

$p = Start-Process -FilePath $caddyExe -ArgumentList 'run', '--config', $configPath, '--adapter', 'caddyfile' `
    -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 2

if ($p.HasExited) {
    throw "Caddy가 바로 종료되었습니다 (포트 $CaddyPort 가 이미 사용 중일 수 있습니다)."
}

Write-Host "임시 HTTPS 준비됨: https://localhost:$CaddyPort -> 127.0.0.1:$BackendPort (PID $($p.Id))" -ForegroundColor Green
Write-Host "끝나면: Stop-Process -Id $($p.Id)" -ForegroundColor DarkGray
