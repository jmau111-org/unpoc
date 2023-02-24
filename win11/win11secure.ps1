###  For pro/enterprise
#           _       _ _                              
# __      _(_)_ __ / / |___  ___  ___ _   _ _ __ ___ 
# \ \ /\ / / | '_ \| | / __|/ _ \/ __| | | | '__/ _ \
#  \ V  V /| | | | | | \__ \  __/ (__| |_| | | |  __/
#   \_/\_/ |_|_| |_|_|_|___/\___|\___|\__,_|_|  \___|
# 
### J.

# Make non-terminating errors terminate
$ErrorActionPreference = "Stop"

# It's only a test, but it should work.
$osVersion = (Get-CimInstance Win32_OperatingSystem).Version
if ([version]$osVersion -lt [version]'11.0') {
    Write-Host "This script requires Windows 11 or later." -ForegroundColor Red
    return
}

$edition = (Get-WmiObject -Class "Win32_OperatingSystem").Caption
if ($edition -like "*Enterprise*" -or $edition -like "*Pro*") {
    Write-Host "Let's start..."
} else {
    Write-Host "This script requires Windows 11 Pro or Enterprise." -ForegroundColor Red
    return
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as an administrator." -ForegroundColor Red
    return
}

# Backup of the registry
try {
    $backupDir = "C:\Backups"
    $backupFileName = "registry_backup_$(Get-Date -Format 'yyyyMMddHHmmss').reg"

    # Create backup folder if it does not exist
    if (!(Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force
    }

    $backupFilePath = Join-Path $backupPath $backupFileName
    $regBackup = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Export-Clixml -Path $backupFilePath -ErrorAction Stop
    Write-Host "Registry backup created at $backupFilePath"
} catch {
    Write-Host "Error creating registry backup: $($_.Exception.Message)" -ForegroundColor Red
}

# Set useful Registry values
try {
    # UAC
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
    
    # File explorer
    $k = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $k -Name "ShowTaskViewButton" -Type DWord -Value 0
    Set-ItemProperty -Path $k -Name Hidden -Value 1
    Set-ItemProperty -Path $k -Name HideFileExt -Value 0
    Set-ItemProperty -Path $k -Name LaunchTo -Value 1
    Set-ItemProperty -Path $k -Name ShowSuperHidden -Value 1
    
    # Disable RDP
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
} catch {
    Write-Host "Error writing Registry values: $($_.Exception.Message)" -ForegroundColor Red
}

# Disable unnecessary services
try {
    Set-Service -Name RemoteRegistry -Status Stopped
    Set-Service -Name Telnet -Status Stopped
    Set-Service -Name FTPsvc -Status Stopped
    Set-Service -Name SNMP -Status Stopped

    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

    Set-NetBIOS -InterfaceIndex (Get-NetAdapter).InterfaceIndex -NetBiosOption "Disabled"

    Stop-Service -Name Spooler
    Set-Service -Name Spooler -StartupType Disabled

    Set-Service -Name RemoteRegistry -StartupType Disabled
    Set-Service -Name Telnet -StartupType Disabled
    Set-Service -Name FTPsvc -StartupType Disabled
    Set-Service -Name SNMP -StartupType Disabled
} catch {
    Write-Host "Error disabling services: $($_.Exception.Message)" -ForegroundColor Red
}

# Control folder access
try {  
    Set-MpPreference -EnableControlledFolderAccess Enabled
} catch {
    Write-Host "Error setting folder access: $($_.Exception.Message)" -ForegroundColor Red
}

# Enable Windows Guards
try { 
    Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard
    Enable-WindowsOptionalFeature -Online -FeatureName DeviceGuard
} catch {
    Write-Host "Error setting folder access: $($_.Exception.Message)" -ForegroundColor Red
}

try { 
    # Set Windows Firewall
    Get-NetFirewallRule -DisplayGroup 'Core Networking Diagnostics' | Enable-NetFirewallRule
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    
    # Without proper network monitoring, the following rules are risky
    New-NetFirewallRule -DisplayName "Allow ICMPv4" -Protocol ICMPv4 -Action Allow # can be bombed by DDoS but useful for diagostics
    New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow # this can be attacked but legitimate services might use it
    New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow # this can be attacked but legitimate services might use it
    New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow # this can be attacked but legitimate services might use it
} catch {
    Write-Host "Error setting Windows Firewall: $($_.Exception.Message)" -ForegroundColor Red
}

# BitLocker encryption
try { 
    $drive = "C:"
    Enable-BitLocker -MountPoint $drive -EncryptionMethod Aes256 -UsedSpaceOnly

    $key = Get-BitLockerVolume -MountPoint $drive -KeyProtector | Select-Object -ExpandProperty KeyProtector | Select-Object -ExpandProperty RecoveryPassword
    Write-Host "The BitLocker recovery key for $drive is: $key"
} catch [System.Exception] {
    Write-Host "Error setting BitLocker: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "It's done."
