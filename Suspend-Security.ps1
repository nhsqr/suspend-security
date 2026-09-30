# Suspend the active protections on this PC for 10 or 60 minutes, then put them back.
# Double-click "Suspend security.cmd" on the desktop, or run this file from an elevated window:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\Suspend-Security.ps1 -Minutes 10
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\Suspend-Security.ps1 -Minutes 60
#
# What it turns off for the timer: Defender real-time, behavior, download, script, and
# archive scanning; every firewall profile; the app SmartScreen check.
# Tamper Protection cannot be switched off by a script. If it is on, the script stops
# and tells you how to turn it off in Windows Security. When the timer ends, the script
# turns Tamper Protection back on.
# What it leaves alone: exclusions, accounts, BitLocker, Secure Boot, Windows Update,
# and LSA protection.
# The scheduled restore keeps the other settings from the moment you started the timer.

param(
    [int]$Minutes = 0,
    [switch]$Restore
)

$TaskName = 'SecuritySuspendRestore'
$StateDir = 'C:\ProgramData\SecuritySuspend'
$StatePath = Join-Path $StateDir 'state.json'
$LogPath = Join-Path $StateDir 'suspend.log'

function Write-Log {
    param([string]$Message)
    if (-not (Test-Path $StateDir)) {
        New-Item -Path $StateDir -ItemType Directory -Force | Out-Null
    }
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
    Write-Host $line
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Admin {
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Restore) { $arg += ' -Restore' }
    if ($Minutes) { $arg += " -Minutes $Minutes" }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arg | Out-Null
}

function Get-Snapshot {
    $pref = Get-MpPreference
    $firewall = @{}
    foreach ($name in @('Domain', 'Private', 'Public')) {
        $firewall[$name] = [bool](Get-NetFirewallProfile -Name $name).Enabled
    }
    $appHostPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost'
    $explorerPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
    $smartScreen = $null
    if (Test-Path $appHostPath) {
        $item = Get-ItemProperty $appHostPath
        if ($null -ne $item.EnableWebContentEvaluation) {
            $smartScreen = [int]$item.EnableWebContentEvaluation
        }
    }
    $explorerSmartScreen = $null
    $explorerSet = $false
    if (Test-Path $explorerPath) {
        $explorer = Get-ItemProperty $explorerPath
        if ($null -ne $explorer.SmartScreenEnabled) {
            $explorerSet = $true
            $explorerSmartScreen = [string]$explorer.SmartScreenEnabled
        }
    }
    return [pscustomobject]@{
        DisableRealtimeMonitoring     = [bool]$pref.DisableRealtimeMonitoring
        DisableBehaviorMonitoring     = [bool]$pref.DisableBehaviorMonitoring
        DisableIOAVProtection         = [bool]$pref.DisableIOAVProtection
        DisableScriptScanning         = [bool]$pref.DisableScriptScanning
        DisableArchiveScanning        = [bool]$pref.DisableArchiveScanning
        DisableEmailScanning          = [bool]$pref.DisableEmailScanning
        DisableRemovableDriveScanning = [bool]$pref.DisableRemovableDriveScanning
        DisableBlockAtFirstSeen       = [bool]$pref.DisableBlockAtFirstSeen
        MAPSReporting                 = [int]$pref.MAPSReporting
        SubmitSamplesConsent          = [int]$pref.SubmitSamplesConsent
        CloudBlockLevel               = [int]$pref.CloudBlockLevel
        EnableControlledFolderAccess  = [int]$pref.EnableControlledFolderAccess
        EnableNetworkProtection       = [int]$pref.EnableNetworkProtection
        PUAProtection                 = [int]$pref.PUAProtection
        FirewallDomain                = [bool]$firewall.Domain
        FirewallPrivate               = [bool]$firewall.Private
        FirewallPublic                = [bool]$firewall.Public
        SmartScreen                   = $smartScreen
        ExplorerSmartScreenSet        = [bool]$explorerSet
        ExplorerSmartScreen           = $explorerSmartScreen
    }
}

function Set-DefenderPreferences {
    param($Values)
    Set-MpPreference `
        -DisableRealtimeMonitoring $Values.DisableRealtimeMonitoring `
        -DisableBehaviorMonitoring $Values.DisableBehaviorMonitoring `
        -DisableIOAVProtection $Values.DisableIOAVProtection `
        -DisableScriptScanning $Values.DisableScriptScanning `
        -DisableArchiveScanning $Values.DisableArchiveScanning `
        -DisableEmailScanning $Values.DisableEmailScanning `
        -DisableRemovableDriveScanning $Values.DisableRemovableDriveScanning `
        -DisableBlockAtFirstSeen $Values.DisableBlockAtFirstSeen `
        -MAPSReporting $Values.MAPSReporting `
        -SubmitSamplesConsent $Values.SubmitSamplesConsent `
        -CloudBlockLevel $Values.CloudBlockLevel `
        -EnableControlledFolderAccess $Values.EnableControlledFolderAccess `
        -EnableNetworkProtection $Values.EnableNetworkProtection `
        -PUAProtection $Values.PUAProtection
}

function Set-SavedProtection {
    param($Values)
    Set-DefenderPreferences $Values
    Set-NetFirewallProfile -Name 'Domain' -Enabled ([bool]$Values.FirewallDomain) | Out-Null
    Set-NetFirewallProfile -Name 'Private' -Enabled ([bool]$Values.FirewallPrivate) | Out-Null
    Set-NetFirewallProfile -Name 'Public' -Enabled ([bool]$Values.FirewallPublic) | Out-Null

    $appHostPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost'
    $explorerPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
    if ($null -eq $Values.SmartScreen) {
        Remove-ItemProperty -Path $appHostPath -Name 'EnableWebContentEvaluation' -ErrorAction SilentlyContinue
    } else {
        if (-not (Test-Path $appHostPath)) { New-Item -Path $appHostPath -Force | Out-Null }
        Set-ItemProperty -Path $appHostPath -Name 'EnableWebContentEvaluation' -Value ([int]$Values.SmartScreen) -Type DWord
    }
    if ($Values.ExplorerSmartScreenSet) {
        Set-ItemProperty -Path $explorerPath -Name 'SmartScreenEnabled' -Value ([string]$Values.ExplorerSmartScreen) -Type String
    } else {
        Remove-ItemProperty -Path $explorerPath -Name 'SmartScreenEnabled' -ErrorAction SilentlyContinue
    }
}

function Test-TamperProtectionOn {
    $status = Get-MpComputerStatus
    if ($status.IsTamperProtected) { return $true }
    $pref = Get-MpPreference
    if ($pref.PSObject.Properties.Name -contains 'DisableTamperProtection') {
        return -not [bool]$pref.DisableTamperProtection
    }
    return $false
}

function Show-TamperProtectionReminder {
    Write-Host ''
    Write-Host 'Tamper Protection is on, so this script stopped without changing anything.'
    Write-Host 'Windows does not let a script turn Tamper Protection off. Turn it off yourself, then run this file again:'
    Write-Host ''
    Write-Host '  1. Windows Security is opening to Virus and threat protection settings.'
    Write-Host '  2. Find Tamper protection and switch it to Off.'
    Write-Host '  3. Run Suspend security.cmd again and choose 10 or 60 minutes.'
    Write-Host ''
    Write-Host 'When the timer ends, this script turns Tamper Protection back on.'
    Start-Process 'windowsdefender://threatsettings'
}

function Enable-TamperProtection {
    try {
        Set-MpPreference -DisableTamperProtection $false
    } catch {
        Write-Log ("Could not turn Tamper Protection on: {0}" -f $_.Exception.Message)
        return
    }
    $status = Get-MpComputerStatus
    if ($status.IsTamperProtected) {
        Write-Log 'Tamper Protection is back on.'
    } else {
        Write-Log 'Tamper Protection was requested on. If the switch is still off, turn it on under Windows Security, Virus and threat protection, Manage settings.'
    }
}

function Disable-ActiveProtection {
    $pref = Get-MpPreference
    Set-MpPreference `
        -DisableRealtimeMonitoring $true `
        -DisableBehaviorMonitoring $true `
        -DisableIOAVProtection $true `
        -DisableScriptScanning $true `
        -DisableArchiveScanning $true `
        -EnableControlledFolderAccess 0 `
        -EnableNetworkProtection 0 `
        -PUAProtection 0
    Set-NetFirewallProfile -Name 'Domain','Private','Public' -Enabled False | Out-Null
    $appHostPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost'
    if (-not (Test-Path $appHostPath)) { New-Item -Path $appHostPath -Force | Out-Null }
    Set-ItemProperty -Path $appHostPath -Name 'EnableWebContentEvaluation' -Value 0 -Type DWord
    $explorerPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
    Set-ItemProperty -Path $explorerPath -Name 'SmartScreenEnabled' -Value 'Off' -Type String
}

function Register-RestoreTask {
    param([datetime]$When)
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Restore"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
    $once = New-ScheduledTaskTrigger -Once -At $When
    $startup = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($once, $startup) -Settings $settings -Principal $principal -Force | Out-Null
}

function Remove-RestoreTask {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

function Read-State {
    if (-not (Test-Path $StatePath)) { return $null }
    return (Get-Content -Path $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Write-State {
    param($Snapshot, [datetime]$RestoreAt)
    if (-not (Test-Path $StateDir)) {
        New-Item -Path $StateDir -ItemType Directory -Force | Out-Null
    }
    $payload = [pscustomobject]@{
        RestoreAt = $RestoreAt.ToString('o')
        Saved     = $Snapshot
    }
    $payload | ConvertTo-Json -Depth 5 | Set-Content -Path $StatePath -Encoding UTF8
}

function Restore-Protection {
    param([switch]$Force)
    $state = Read-State
    if (-not $state) {
        Write-Log 'Nothing to restore.'
        return
    }
    $due = [datetime]$state.RestoreAt
    if (-not $Force -and (Get-Date) -lt $due.AddSeconds(-15)) {
        exit 0
    }
    Write-Log 'Restoring protections saved before the timer.'
    Set-SavedProtection $state.Saved
    Enable-TamperProtection
    Remove-Item -Path $StatePath -Force -ErrorAction SilentlyContinue
    Remove-RestoreTask
    $realtime = (Get-MpComputerStatus).RealTimeProtectionEnabled
    Write-Log ("Restore finished. Real-time protection is {0}." -f $(if ($realtime) { 'on' } else { 'still off' }))
}

function Start-Suspension {
    param([int]$Duration)
    if (Test-TamperProtectionOn) {
        Show-TamperProtectionReminder
        Write-Log 'Stopped because Tamper Protection is on.'
        return
    }

    $existing = Read-State
    if ($existing) {
        $saved = $existing.Saved
        Write-Log 'A timer is already running. The original settings will be restored at the new time.'
    } else {
        $saved = Get-Snapshot
    }

    try {
        Disable-ActiveProtection
    } catch {
        Write-Log ("Could not turn protections off: {0}" -f $_.Exception.Message)
        if (-not $existing) {
            Set-SavedProtection $saved
        }
        throw
    }

    $realtime = (Get-MpComputerStatus).RealTimeProtectionEnabled
    if ($realtime) {
        if (-not $existing) { Set-SavedProtection $saved }
        Show-TamperProtectionReminder
        throw 'Defender real-time protection is still on, so the other changes were put back.'
    }

    $restoreAt = (Get-Date).AddMinutes($Duration)
    Write-State -Snapshot $saved -RestoreAt $restoreAt
    try {
        Register-RestoreTask -When $restoreAt
    } catch {
        Set-SavedProtection $saved
        Remove-Item -Path $StatePath -Force -ErrorAction SilentlyContinue
        Remove-RestoreTask
        throw
    }
    Write-Log ("Protections are off until {0:HH:mm} ({1} minutes)." -f $restoreAt, $Duration)
    Write-Log 'Tamper Protection will be turned back on when the timer ends.'
    Write-Log 'Leave this script on the desktop until the timer ends. The restore task runs this file.'
}

if (-not (Test-IsAdmin)) {
    Request-Admin
    exit
}

if ($Restore) {
    Restore-Protection
    exit
}

if ($Minutes -eq 0) {
    $pending = Read-State
    Write-Host ''
    Write-Host 'Suspend security on this PC'
    if ($pending) {
        Write-Host ("A timer is already set for {0:yyyy-MM-dd HH:mm}." -f [datetime]$pending.RestoreAt)
    }
    Write-Host '  1  10 minutes'
    Write-Host '  2  60 minutes'
    Write-Host '  3  Turn the saved protections back on now'
    Write-Host '  4  Cancel'
    $choice = Read-Host 'Choose'
    switch ($choice) {
        '1' { $Minutes = 10 }
        '2' { $Minutes = 60 }
        '3' { Restore-Protection -Force; Read-Host 'Press Enter to close'; exit }
        default { exit }
    }
}

if ($Minutes -notin 10, 60) {
    throw 'Choose 10 or 60 minutes.'
}

try {
    Start-Suspension -Duration $Minutes
} catch {
    Write-Host ''
    Write-Host $_.Exception.Message
    Write-Log $_.Exception.Message
}

Write-Host ''
Read-Host 'Press Enter to close'
