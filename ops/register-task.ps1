<#
One-time setup: registers "InfraSight Supervisor" as a Windows Scheduled
Task that starts at logon for the CURRENT user (no admin rights, no stored
password needed -- it only runs while you're logged in). Safe to re-run;
it replaces any existing registration of the same task.

Run this once, then either log off/on or just run start-now.ps1 (or start
supervisor.ps1 directly) to begin without waiting for the next logon.
#>

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ScriptPath  = Join-Path $PSScriptRoot 'supervisor.ps1'
$TaskName    = 'InfraSight Supervisor'

$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`"" `
    -WorkingDirectory $ProjectRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -RunLevel Limited -Force | Out-Null

Write-Host "'$TaskName' 작업을 등록했습니다 -- 다음 로그인부터 자동으로 시작됩니다." -ForegroundColor Green
Write-Host "지금 바로 시작하려면: powershell -File `"$PSScriptRoot\supervisor.ps1`"  (또는 로그오프 후 재로그인)"
