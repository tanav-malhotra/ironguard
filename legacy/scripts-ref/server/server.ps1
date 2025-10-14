######################################################################################
# Authors: Tanav Malhotra (GitHub: https://github.com/tanav-malhotra), Bryan Lochan 
# License: GNU General Public License v3.0
# Copyright (c) 2024 Tanav Malhotra, Bryan Lochan 
#
# This script is licensed under the GNU General Public License v3.0.
# You may obtain a copy of the license at:
#   https://www.gnu.org/licenses/gpl-3.0.html
#
# The script is provided "as-is", without any warranty of any kind,
# express or implied, including but not limited to the implied warranties
# of merchantability and fitness for a particular purpose. See the GPL-3.0
# for full details.
#
# You can also view the license by running this script
# with the '-License' option.
######################################################################################

##### VARIABLES #####
$current_dir = (Get-Location).Path
$LOGFILE = "$current_dir\windows_script.log"

##### REMOVE EXISTING LOG FILE #####
if (Test-Path $LOGFILE) {
    Remove-Item $LOGFILE -Force
}
"" | Out-File $LOGFILE

##### FUNCTIONS #####
function log {
    param (
        [string]$Message
    )
    # Write-Host ($args -join ' ')
    Write-Host $Message
    $Message | Out-File -Append -FilePath $LOGFILE
}
function log_info {
    param (
        [string]$Message
    )
    $Message | Out-File -Append -FilePath $LOGFILE
}

##### ARGS #####
#TODO: -Help, -Version, -License, -Debug

##### CHECK FOR ADMIN #####
log_info "Checking for admininstrative access..."
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    log_info "error: Please run this script as an administrator."
    Write-Error "Please run this script as an administrator."
    exit
}

##### RENAMING ADMIN ACCOUNT #####
log "Renaming 'Administrator' account to 'CyberPatriot' (and updating group memberships)..."
try {
    $adminName = "Administrator"
    $newAdminName = "CyberPatriot"
    # $adminAccount = Get-LocalUser -Name $adminName
    # $newAdminAccount = Get-LocalUser -Name $newAdminName

    wmic useraccount where "name='$adminName'" rename $newAdminName
    net localgroup Administrators /delete $adminName
    net localgroup Administrators /add $newAdminName

    # $adminGroup = Get-LocalGroup -Name "Administrators"
    # $adminGroup.Members.Remove($adminAccount)
    # $adminGroup.Members.Add($newAdminAccount)

    net user $adminName /active:no
} catch {
    log_info "error: Failed to rename 'Administrator' account: $_"
    Write-Error "Failed to rename 'Administrator' account: $_"
}

##### PASSWORD SETTINGS #####
log "Setting password settings and lockout policy..."
$newPassword = "CyberPatr!0t"
$users = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount = 'True' AND Disabled = 'False'"
foreach ($user in $users) {
    if ($user.Name -ne "Administrator" -and $user.Name -ne "DefaultAccount" -and $user.Name -ne "Guest") {
        try {
            net user $user.Name $newPassword
            log "Password for user $($user.Name) changed successfully."
        } catch {
            log_info "error: Failed to change password for user $($user.Name): $_"
            Write-Error "Failed to change password for user $($user.Name): $_"
        }
    }
}
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$registryName = "LimitBlankPasswordUse"
try {
    log "Enabling 'Limit local account use of blank passwords to console logon only'..."
    Set-ItemProperty -Path $registryPath -Name $registryName -Value 1
} catch {
    log_info "error: Failed to enable the setting: $_"
    Write-Error "Failed to enable the setting: $_"
}
net accounts /maxpwage:30
net accounts /minpwage:1
net accounts /minpwlen:12
net accounts /uniquepw:5
net accounts /lockoutthreshold:5 # attempts
net accounts /lockoutduration:30 # minutes
net accounts /lockoutwindow:30 # minutes before failed login attempts threshold counter is reset to 0
# Apply password complexity setting using secedit
log "Applying password complexity setting..."
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | 
    Set-Content C:\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\secpol.cfg /overwrite
Remove-Item C:\secpol.cfg
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
	-Name "PasswordComplexity" -Value 1 -PropertyType DWord -Force
log "Password complexity applied."
# Disable Password Reversible Encryption for passwords (Decryption)
$path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Password"
if (-not (Test-Path $path)) {
    New-Item -Path $path -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Password" -Name "DisableReversibleEncryption" -Value 1 -PropertyType DWord -Force
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisablePasswordReversibleEncryption' -Value 1

#### FIREWALL #####
log "Setting up firewall..."
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
Get-NetFirewallRule | Where-Object {$_.DisplayGroup -eq "Windows Firewall"} | Set-NetFirewallRule -Enabled True
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
# rules
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any

##### DISABLE IPv6 #####
log "Disabling IPv6..."
Set-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -Enabled $false
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Value 0xFFFFFFFF

##### DISBALE GUEST LOGIN #####
log "Disabling guest login..."
net user guest /active:no

##### SOFTWARE MANAGEMENT #####
# log "Managing software..."
# # removing software
# log "Removing prohibited software..."
# $appsToRemove = @(
#     "*xbox*",
#     "*zune*",
#     "*3dbuilder*",
#     "*bingnews*",
#     "*solitaire*",
#     "*skypeapp*",
#     "*getstarted*",
#     "*oneconnect*",
#     "*people*",
#     "*communicationsapps*",
#     "*feedbackhub*",
#     "*officehub*",
#     "*onenote*",
#     "*onedrive*",
#     "*mixedreality*",
#     "*wallet*",
#     "*yourphone*",
#     "*candycrush*",
#     "*twitter*",
#     "*netflix*",
#     "*wireshark*",
#     "*bittorrent*",
#     "*netcat*",
#     "*teamviewer*",
#     "*team-viewer*",
#     "*webcompanion*",
#     "*groove*",
#     "*Paint3D*",
#     "*tftp*", # remove if tftp is needed as a critical service
#     "*telnet*"
# )
# foreach ($app in $appsToRemove) {
#     log "Removing $app..."
#     Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $app } | Remove-AppxPackage -ErrorAction SilentlyContinue # windows store apps
#     Get-CimInstance -ClassName Win32_Product | Where-Object { $_.Name -like $app } | ForEach-Object { $_.Uninstall() } # for traditional apps installed from internet
# }
# # installing software
# log "Installing software..."
# # TODO: see if any software needs to be installed

##### AUTOMATIC UPDATES #####
log "Setting up automatic updates..."
# start update service and set to automatic
Start-Service -Name wuauserv
Set-Service -Name wuauserv -StartupType Automatic
# modify registry to check for updates automatically
$regPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force
}
Set-ItemProperty -Path $regPath -Name "FlightSetting" -Value 0
Set-ItemProperty -Path $regPath -Name "UserPreference" -Value 1
# force a manual check for updates to initialize the update process
$updateSession = New-Object -ComObject Microsoft.Update.Session
$updateSearcher = $updateSession.CreateUpdateSearcher()
$searchResult = $updateSearcher.Search("IsInstalled=0")

##### WINDOWS DEFENDER #####
log "Enabling and updating Windows Defender..."
# Enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Start-Service -Name WinDefend
# Update Windows Defender
Update-MpSignature
# rules
setx /M MP_FORCE_USE_SANDBOX 1
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions Enabled

##### DISABLE WINDOWS REMOTE MANAGEMENT #####
# log "Disabling Windows Remote Managerment..."
# Set-Item wsman:\localhost\client\trustedhosts * -Force
# Set-PSSessionConfiguration -Name "Microsoft.PowerShell" -SecurityDescriptorSddl "O:NSG:BAD:P(A;;GA;;;BA)(A;;GA;;;WD)(A;;GA;;;IU)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)"
#
# Stop-Service -Name winrm -Force
# Set-Service -Name winrm -StartupType Disabled
# winrm delete winrm/config/Listener?Address=*+Transport=HTTP
# winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
# Disable-PSRemoting -Force

##### DISABLE RDP #####
log "Securing RDP settings..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "UserAuthentication" -Value 1 # Network Level Authentication (NLA)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "SecurityLayer" -Value 1 # require NLA for connection
$userInput = Read-Host "Do you want to disable RDP? (Y/n): "
if ($userInput.ToLower() -eq 'n') {
    log "Starting and enabling RDP..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Start-Service -Name "TermService"
    Set-Service -Name "TermService" -StartupType Automatic
} else {
    log "Stopping and disabling RDP..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
    Stop-Service -Name "TermService" -Force
    Set-Service -Name "TermService" -StartupType Disabled
}

##### DISABLING TELNET #####
log "Disabling telnet..."
dism /online /Disable-feature /featurename:TelnetClient /NoRestart
dism /online /Disable-feature /featurename:TelnetServer /NoRestart

##### DISABLING AUTOPLAY #####
log "Disabling AutoPlay..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 0xFF

##### DISABLING ANONYMOUS LDAP #####
log "Disabling anonymous LDAP..."
Set-ADObject -Identity $ObjectPath -Add @{ 'msDS-Other-Settings' = 'DenyUnauthenticatedBind=1' }

##### REG KEYS #####
log "Setting registry keys..."
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f   
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f 
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "level" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d 3 /f
reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 1 /f
reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

##### CREATE GLOBAL OBJECTS CONFIGURATION #####
log "Preventing users from creating global objects..."
#TODO

##### AUDIT CREDENTIAL VALIDATION #####
log "Enabling Audit Credential Validation..."
do {
    $auditChoice = Read-Host "Do you want to enable Audit Credential Validation for (1) Success only, (2) Failure only, or (3) Both? Enter the number corresponding to your choice: "
    switch ($auditChoice) {
        "1" {
            # Enable Success only
            auditpol /set /subcategory:"Credential Validation" /success:enable /failure:disable
            log "Audit Credential Validation has been enabled for Success events only."
            $validChoice = $true
        }
        "2" {
            # Enable Failure only
            auditpol /set /subcategory:"Credential Validation" /success:disable /failure:enable
            log "Audit Credential Validation has been enabled for Failure events only."
            $validChoice = $true
        }
        "3" {
            # Enable both Success and Failure
            auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
            log "Audit Credential Validation has been enabled for both Success and Failure events."
            $validChoice = $true
        }
        Default {
            log "Invalid selection. Please try again."
            $validChoice = $false
        }
    }
} while (-not $validChoice)

##### CONFIGURE WINDOWS SMARTSCREEN #####
log "Blocking windows smartscreen..."
# $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
#
#$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
#$regKey = "SmartScreenEnabled"
#$desiredValue = "Block"  # or "Warn"
#if (-not (Test-Path $regPath)) {
#    log "Registry path '$regPath' does not exist. Creating it..."
#    New-Item -Path $regPath -Force
#}
#try {
#   Set-ItemProperty -Path $regPath -Name $regKey -Value $desiredValue -Type String
#    log "Successfully set '$regKey' to '$desiredValue'."
#} catch {
#    log_info "error: Failed to set the registry key '$regKey' to '$desiredValue'. Error: $_"
#    Write-Error "Failed to set the registry key '$regKey' to '$desiredValue'. Error: $_"
#}

##### PROMPT ADMINS BEFORE ELEVATING THEIR PRIVILEGES #####
log "Prompting admins before elevating their privileges..."
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$registryValueName = "ConsentPromptBehaviorAdmin"
$desiredBehavior = 4 # 3 = prompt for credentials, 4 = prompt for consent
Set-ItemProperty -Path $registryPath -Name $registryValueName -Value $desiredBehavior

##### REMOVING MEDIA FILES #####
log "Finding media files..."
$mediaFiles = Get-ChildItem -Path "C:\Users\*\*" -Recurse -Include "*.mp3", "*.mp4", "*.avi", "*.mkv", "*.flac", "*.wav", "*.mov", "*.wmv"
$imageFiles = Get-ChildItem -Path "C:\Users\*\*" -Recurse -Include "*.png", "*.jpg", "*.jpeg", "*.gif", "*.bmp", "*.tiff", "*.webp", "*.heif", "*.ico", "*.svg", "*.raw", "*.dng", "*.eps"
log "Media (Video/Audio):"
log $mediaFiles
log "Images:"
log $imageFiles
$confirmDeletion = Read-Host "Do you want to delete all media files (video and audio) from C:\Users\*\*? (Y/n): "
if ($confirmDeletion.ToLower() -eq 'n') {
    log "Media (video and audio) file deletion canceled."
} else {
    log "Deleting media (video and audio) files..."
    $mediaFiles | Remove-Item -Force -ErrorAction Continue
}
$confirmDeletion = Read-Host "Do you want to delete all images from C:\Users\*\*? (Y/n): "
if ($confirmDeletion.ToLower() -eq 'n') {
    log "Image file deletion canceled."
} else {
    log "Deleting image files..."
    $imageFiles | Remove-Item -Force -ErrorAction Continue
}

##### AUDIT POLICIES #####
log "Setting up audit policies..."
try {
    auditpol /set /category:"Account Logon" /success:enable 
    auditpol /set /category:"Account Logon" /failure:enable
    auditpol /set /category:"Account Management" /success:enable
    auditpol /set /category:"Account Management" /failure:enable
    auditpol /set /category:"DS Access" /success:enable
    auditpol /set /category:"DS Access" /failure:enable
    auditpol /set /category:"Logon/Logoff" /success:enable
    auditpol /set /category:"Logon/Logoff" /failure:enable
    auditpol /set /category:"Object Access" /success:enable
    auditpol /set /category:"Object Access" /failure:enable
    auditpol /set /category:"Policy Change" /success:enable
    auditpol /set /category:"Policy Change" /failure:enable
    auditpol /set /category:"Privilege Use" /success:enable
    auditpol /set /category:"Privilege Use" /failure:enable
    auditpol /set /category:"Detailed Tracking" /success:enable
    auditpol /set /category:"Detailed Tracking" /failure:enable
    auditpol /set /category:"System" /success:enable 
    auditpol /set /category:"System" /failure:enable
} catch {
    log_info "error: Failed to set audit policies: $_"
    Write-Error "Failed to set audit policies: $_"
}
# global audit policies
$OSWMI = Get-WmiObject Win32_OperatingSystem -Property Caption,Version
$OSName = $OSWMI.Caption
auditpol /resourceSACL /set /type:File /user:"Domain Admins" /success /failure /access:FW
auditpol /resourceSACL /set /type:Key /user:"Domain Admins" /success /failure /access:FW

##### GROUP POLICIES #####
log "Setting up group policies..."
# Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName PreventAutoRun -Type DWord -Data 1
# Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\SearchCompanion" -ValueName DisableContentFileUpdates -Type DWord -Data 1
# Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\IIS" -ValueName PreventIISInstall -Type DWord -Data 1
# Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName NoAutoUpdate -Type DWord -Data 0

$policies = @(
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"; ValueName = "PreventAutoRun"; Data = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion"; ValueName = "DisableContentFileUpdates"; Data = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\IIS"; ValueName = "PreventIISInstall"; Data = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; ValueName = "NoAutoUpdate"; Data = 0 }
)
foreach ($policy in $policies) {
    if (-not (Test-Path -Path $policy.Path)) {
        log "Creating registry path $($policy.Path)..."
        New-Item -Path $policy.Path -Force
    }
    log "Setting registry value: $($policy.Path)\$($policy.ValueName) to $($policy.Data)..."
    Set-ItemProperty -Path $policy.Path -Name $policy.ValueName -Value $policy.Data
}
gpupdate /force # reload group policies

##### DISABLING WINDOWS FEATURES #####
#log "Disabling certain windows features..."
#Disable-WindowsOptionalFeature -FeatureName RSAT-Routing -Online -NoRestart
#Disable-WindowsOptionalFeature -FeatureName FS-SMB1 -Online -NoRestart
#Disable-WindowsOptionalFeature -FeatureName SMB1Protocol -Online -NoRestart
#Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -Value 0
#Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0
#TODO

##### SERVICE MANAGEMENT #####
log "Managing services..."
log "Disabling certain services..."
# disabling
cmd.exe /c "sc stop TapiSrv"
cmd.exe /c "sc config TapiSrv start= disabled"
cmd.exe /c "sc stop TlntSvr"
cmd.exe /c "sc config TlntSvr start= disabled"
cmd.exe /c "sc stop ftpsvc"
cmd.exe /c "sc config ftpsvc start= disabled"
cmd.exe /c "sc stop SNMP"
cmd.exe /c "sc config SNMP start= disabled"
cmd.exe /c "sc stop SessionEnv"
cmd.exe /c "sc config SessionEnv start= disabled"
cmd.exe /c "sc stop TermService"
cmd.exe /c "sc config TermService start= disabled"
cmd.exe /c "sc stop UmRdpService"
cmd.exe /c "sc config UmRdpService start= disabled"
cmd.exe /c "sc stop SharedAccess"
cmd.exe /c "sc config SharedAccess start= disabled"
cmd.exe /c "sc stop remoteRegistry "
cmd.exe /c "sc config remoteRegistry start= disabled"
cmd.exe /c "sc stop SSDPSRV"
cmd.exe /c "sc config SSDPSRV start= disabled"
cmd.exe /c "sc stop W3SVC"
cmd.exe /c "sc config W3SVC start= disabled"
cmd.exe /c "sc stop SNMPTRAP"
cmd.exe /c "sc config SNMPTRAP start= disabled"
cmd.exe /c "sc stop remoteAccess"
cmd.exe /c "sc config remoteAccess start= disabled"
cmd.exe /c "sc stop RpcSs"
cmd.exe /c "sc config RpcSs start= disabled"
cmd.exe /c "sc stop HomeGroupProvider"
cmd.exe /c "sc config HomeGroupProvider start= disabled"
cmd.exe /c "sc stop HomeGroupListener"
cmd.exe /c "sc config HomeGroupListener start= disabled"
cmd.exe /c "sc stop telnet"
cmd.exe /c "sc config telnet start= disabled"
cmd.exe /c "sc stop upnphost"
cmd.exe /c "sc config upnphost start= disabled"
cmd.exe /c "sc stop IISADMIN"
cmd.exe /c "sc config IISADMIN start= disabled"
cmd.exe /c "sc stop ConfRoom"
cmd.exe /c "sc config ConfRoom start= disabled"
cmd.exe /c "sc stop RDSessMgr"
cmd.exe /c "sc config RDSessMgr start= disabled"
cmd.exe /c "sc stop ssdpsrv"
cmd.exe /c "sc config ssdpsrv start= disabled"
cmd.exe /c "sc stop Messenger"
cmd.exe /c "sc config Messenger start= disabled"
# enabling
log "Enabling certain services..."
cmd.exe /c "sc config EventLog start= auto"
cmd.exe /c "sc start EventLog"

##### ANTIVIRUS #####
# install antivirus and make another script for antivirus scanning

##### UPDATE #####
# log "Checking for Windows updates..."
# Install-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue
# Import-Module PSWindowsUpdate
# try {
#     Get-WindowsUpdate -AcceptAll -Install -AutoReboot
#     log "Windows updates completed."
# } catch {
#     log "Failed to complete Windows updates: $_"
# }
# # Update all applications using Winget
# log "Updating applications via Winget..."
# try {
#     winget upgrade --all --silent --accept-package-agreements --accept-source-agreements
#     log "Application updates completed."
# } catch {
#     log "Failed to update applications via Winget: $_"
# }
# # Update drivers using Device Manager
# log "Updating drivers..."
# try {
#     # Get a list of drivers that can be updated
#     $devices = Get-PnpDevice | Where-Object { $_.Status -eq "OK" }
#     foreach ($device in $devices) {
#         log "Updating driver for: $($device.Name)"
#         Update-PnpDevice -InstanceId $device.InstanceId -Confirm:$false
#     }
#     log "Driver updates completed."
# } catch {
#     log "Failed to update drivers: $_"
# }
# log "All updates completed."

##### RESTART #####
$choice = Read-Host "Do you want to restart the computer? (Y/n): "
if ($choice.ToLower() -eq 'n') {
    log "Restart canceled."
} else {
    Restart-Computer -Force
}

##### EXIT #####
exit