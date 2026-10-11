<#
Removes the auto-start registration (does not stop anything already
running -- run stop.ps1 first if you want that too).
#>
$TaskName = 'InfraSight Supervisor'
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    try {
        # -ErrorAction Stop: 기본값(이 스크립트 자체는 $ErrorActionPreference를
        # 따로 안 건드려서 PowerShell 기본값인 'Continue')으로 두면, 실패해도
        # 그냥 다음 줄(성공 메시지)로 넘어가 버린다 -- 실측 확인: 관리자 권한
        # 없이 돌렸을 때 "액세스가 거부되었습니다" 에러가 찍히고도 바로 아래
        # "해제했습니다" 메시지가 뒤따라서, 실제로는 작업이 그대로 남아있는데
        # 성공한 것처럼 보였다.
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        Write-Host "'$TaskName' 자동 시작 등록을 해제했습니다." -ForegroundColor Green
    } catch {
        Write-Host "'$TaskName' 자동 시작 등록 해제에 실패했습니다: $_" -ForegroundColor Red
        Write-Host "(관리자 권한으로 실행했는지 확인해주세요.)" -ForegroundColor Red
    }
} else {
    Write-Host "등록되어 있지 않습니다." -ForegroundColor Yellow
}
