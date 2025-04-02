############################################################################################################
#                                     MITS - Windows Update Automation                                        #
#                                                 Version 1.0.3                                             #
############################################################################################################
#region Synopsis
<#
.SYNOPSIS
    Automates the installation of Windows updates using the PSWindowsUpdate module.

.DESCRIPTION
    This script provides a streamlined way to check for and install Windows updates, including:
    - Automatic installation of required package providers (NuGet)
    - Installation and import of the PSWindowsUpdate module if not present
    - Detection of available Microsoft updates
    - Batch installation of all available updates
    - Detailed status reporting with color-coded output
    - Error handling for update operations

    The script is designed to be run with minimal user intervention and provides clear feedback
    during the update process.

.PARAMETER None
    This script does not accept parameters.

.NOTES
    Version:        1.0.3
    Author:         Bill Ulrich
    Creation Date:  4/1/2025
    Requires:       Administrator privileges
                    Internet connectivity
                    PowerShell 5.1+
    
.EXAMPLE
    .\Update_Windows.ps1
    
    Run the script with administrator privileges to automatically check for and install Windows updates.

.LINK
    https://github.com/mitsdev01/MITS
#>

Clear-Host

# Check if NuGet provider is installed
if (!(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    # Install NuGet provider
    Install-PackageProvider -Name NuGet -Force
}

# Ensure PSWindowsUpdate module is installed
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Install-Module -Name PSWindowsUpdate -Force -Confirm:$false -AllowClobber
}

try {
    Import-Module PSWindowsUpdate -ErrorAction Stop
} catch {
    Write-Host "Error importing PSWindowsUpdate module: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Check for updates
Write-Host "Checking for updates..." -ForegroundColor Cyan
try {
    $availableUpdates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
    
    # Display the total number of updates found
    $totalUpdates = $availableUpdates.Count
    Write-Host "Total Updates available: $totalUpdates" -ForegroundColor Yellow
    Start-Sleep -Seconds 3

    # Install updates
    if ($totalUpdates -gt 0) {
        Write-Host "Starting Windows Update installation..." -ForegroundColor Cyan
        try {
            # Install all updates at once instead of one by one
            Install-WindowsUpdate -AcceptAll -IgnoreReboot -AutoReboot:$false -Confirm:$false -ErrorAction Stop
            Write-Host "Windows Update installation completed successfully!" -ForegroundColor Green
        } catch {
            Write-Host "Error during update installation: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "No updates available." -ForegroundColor Green
    }
} catch {
    Write-Host "Error checking for updates: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host " "
Write-Host "`nScript completed. Please restart your computer if required." -ForegroundColor Cyan