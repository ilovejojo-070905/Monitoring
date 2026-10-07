<#
One-time setup: registers "InfraSight Supervisor" as a Windows Scheduled
Task that starts at logon for the CURRENT user (no stored password needed --
it only runs while you're logged in). Also tries to add an AtStartup trigger
for extra coverage, but that needs an elevated (admin) session to register --
if this script isn't running elevated, it registers the AtLogOn-only version
instead of failing outright, and tells you how to add AtStartup later. Safe
to re-run; it replaces any existing registration of the same task.

Run this once, then either log off/on, reboot, or just run supervisor.ps1
directly to begin without waiting for either trigger.
#>

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ScriptPath  = Join-Path $PSScriptRoot 'supervisor.ps1'
$VbsPath     = Join-Path $PSScriptRoot 'run-supervisor-hidden.vbs'
$TaskName    = 'InfraSight Supervisor'

# `powershell.exe -WindowStyle Hidden` as the task's own action is the
# intuitive way to do this, but it's unreliable specifically for an
# AtStartup-triggered task: that trigger can fire while the session/window
# station is still being set up (before explorer.exe is ready), early enough
# that -WindowStyle Hidden's flag doesn't reliably take -- a black PowerShell
# window briefly (or persistently) shows after a reboot despite it being set.
# This is the exact same class of bug agent.py's install_startup() hit and
# fixed by launching through a .vbs wrapper (WScript.Shell.Run with the
# window-mode argument set to 0) instead of relying on the flag -- that
# approach is what actually guarantees no window, so the task now launches
# this .vbs instead of calling powershell.exe directly.
$vbsContent = @"
CreateObject("WScript.Shell").Run "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ""$ScriptPath""", 0, False
"@
[System.IO.File]::WriteAllText($VbsPath, $vbsContent, (New-Object System.Text.UTF8Encoding $false))

$action  = New-ScheduledTaskAction -Execute 'wscript.exe' `
    -Argument "`"$VbsPath`"" `
    -WorkingDirectory $ProjectRoot
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

# Two (now three) triggers when possible: a real interactive logoff/logon
# reliably fires AtLogOn, but this has been observed going dead with no
# logon ever having happened in between (Get-ScheduledTaskInfo showed
# LastRunTime stuck at the Task Scheduler "never run" sentinel, 1999-11-30)
# -- whatever actually ended the session (sleep/resume, a VM/remote-session
# reset, etc.) didn't go through a logon event at all. AtStartup covers that
# gap by firing on boot regardless of how the prior session ended. But
# registering a task with an AtStartup trigger requires an elevated session
# -- and unlike install.ps1, this script must not just self-elevate and
# block on a UAC prompt, because it's also invoked non-interactively as a
# sub-step of install.ps1 (where a stuck "Yes/No" dialog would hang the
# whole installer with nobody watching to click it). So: try both triggers
# first, and only if that specific registration fails for a permissions
# reason, fall back to the AtLogOn-only version, which never needs elevation.
#
# Recurring trigger (every 5 min, forever) added after a real incident:
# AtStartup/AtLogOn both only fire on an actual boot or logon event, and
# this process tree has been observed dying mid-session with *no* reboot
# and *no* log line about why (confirmed directly: Get-ScheduledTaskInfo's
# LastRunTime matched Win32_OperatingSystem.LastBootUpTime to the second,
# proving no boot/logon had happened since, while supervisor.log's last
# line was from hours earlier with no shutdown entry after it -- the
# process was just gone). Neither trigger covers "still logged in, nothing
# rebooted, but the supervisor process itself vanished" -- only a periodic
# check does. This reuses the exact same action (the .vbs wrapper) rather
# than a separate watchdog script: supervisor.ps1 already has its own
# duplicate-run guard (exits immediately if the lock file's PID is still
# alive), so firing this every 5 minutes is a harmless near-instant no-op
# when supervisor is already running, and a real relaunch within 5 minutes
# when it isn't. It also doesn't collide with the AtLogOn/AtStartup-
# triggered instance in Task Scheduler's own instance tracking: wscript.exe
# (what Task Scheduler actually watches) exits right after detaching
# supervisor.ps1 via WScript.Shell.Run's wait=False, so Task Scheduler
# always sees each trigger's own instance finish in under a second,
# regardless of whether supervisor.ps1 itself keeps running for hours
# afterward. No elevation needed, so this is included in both the
# with-startup and logon-only registrations below.
$recurringTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue)

$bothTriggers = @(
    New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    New-ScheduledTaskTrigger -AtStartup
    $recurringTrigger
)
$logonOnlyTriggers = @(
    New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $recurringTrigger
)

$registeredWithStartup = $false
try {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $bothTriggers -Settings $settings `
        -RunLevel Limited -Force | Out-Null
    $registeredWithStartup = $true
} catch {
    Write-Host "(시스템 시작 트리거는 관리자 권한이 필요해 건너뜁니다 -- 로그인 시 시작 + 5분마다 재확인만 등록합니다)" -ForegroundColor DarkYellow
    try {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $logonOnlyTriggers -Settings $settings `
            -RunLevel Limited -Force | Out-Null
    } catch {
        Write-Host "작업 등록에 실패했습니다: $_" -ForegroundColor Red
        exit 1
    }
}

if ($registeredWithStartup) {
    Write-Host "'$TaskName' 작업을 등록했습니다 -- 다음 로그인 또는 시스템 시작 시 자동으로 시작되고, 실행 중에도 5분마다 살아있는지 재확인해 죽어있으면 다시 띄웁니다." -ForegroundColor Green
} else {
    Write-Host "'$TaskName' 작업을 등록했습니다 (로그인 시 시작 + 5분마다 재확인) -- 다음 로그인부터 자동으로 시작됩니다." -ForegroundColor Green
    if (Test-Admin) {
        Write-Host "참고: 관리자 권한으로 실행했는데도 시스템 시작 트리거 등록에 실패했습니다. 위 오류 메시지를 확인해주세요." -ForegroundColor Yellow
    } else {
        Write-Host "시스템 시작 시에도 자동으로 켜지게 하려면, 이 스크립트를 '관리자 권한으로 실행'으로 한 번 더 실행해주세요." -ForegroundColor Yellow
    }
}
Write-Host "지금 바로 시작하려면: powershell -File `"$PSScriptRoot\supervisor.ps1`"  (또는 로그오프 후 재로그인)"
