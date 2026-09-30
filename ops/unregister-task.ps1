<#
Removes the auto-start registration (does not stop anything already
running -- run stop.ps1 first if you want that too).
#>
$TaskName = 'InfraSight Supervisor'
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "'$TaskName' 자동 시작 등록을 해제했습니다." -ForegroundColor Green
} else {
    Write-Host "등록되어 있지 않습니다." -ForegroundColor Yellow
}
