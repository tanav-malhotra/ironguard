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
# You can also view the license by running the `windows.ps1` script
# with the '-License' option.
######################################################################################

##### CHECK FOR ADMIN #####
Write-Host "Checking for admininstrative access..."
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as an administrator."
    exit
}

##### CHECKING PWSH INSTALLATION #####
$installedPS7 = Get-Command pwsh -ErrorAction SilentlyContinue
if ($installedPS7) {
    Write-Host "PowerShell 7 is already installed. Launching PowerShell 7..."
    Start-Process pwsh
    exit
}

##### UPDATE TO PWSH 7 #####
# TODO:
$ps7Url = "https://aka.ms/install-powershell.ps1" # stable release
Write-Host "Downloading PowerShell 7 installation script..."
Invoke-WebRequest -Uri $ps7Url -OutFile "$env:TEMP\install-powershell.ps1"
Write-Host "Running the PowerShell 7 installation script..."
Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$env:TEMP\install-powershell.ps1`"" -Wait
$installedPS7 = Get-Command pwsh -ErrorAction SilentlyContinue
Start-Process pwsh

##### EXIT #####
exit