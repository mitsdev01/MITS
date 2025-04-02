############################################################################################################
#                                     SOS - PowerShell Module Verification                                   #
#                                                 Version 1.0.0                                             #
############################################################################################################
#region Synopsis
<#
.SYNOPSIS
    Verifies and installs required PowerShell module dependencies for SOS scripts.

.DESCRIPTION
    This script ensures the proper configuration of PowerShell module dependencies, including:
    - Setting appropriate execution policy for module installation
    - Installing and configuring the NuGet package provider
    - Installing and importing the PowerShellGet module
    - Verifying successful installation of required components
    - Restoring original execution policy after completion
    
    The script runs with minimal user intervention and provides status feedback
    upon completion of key verification steps.

.PARAMETER None
    This script does not accept parameters.

.NOTES
    Version:        1.0.0
    Author:         Bill Ulrich
    Creation Date:  3/25/2025
    Requires:       PowerShell 5.1+
                    Internet connectivity for package downloads
    
.EXAMPLE
    .\Check-Modules.ps1
    
    Run the script to verify and install required PowerShell module dependencies.

.LINK
    https://github.com/mitsdev01/SOS
#>

# Set execution policy to bypass for this session
$originalExecutionPolicy = Get-ExecutionPolicy
Set-ExecutionPolicy Bypass -Scope Process -Force
$WarningPreference = "SilentlyContinue"
# Configure NuGet to install without prompts
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null

# Install and import the PowerShellGet module
Install-Module PowerShellGet -Force -AllowClobber -Scope CurrentUser | Out-Null
Import-Module PowerShellGet -Force

# Restore the original execution policy
Set-ExecutionPolicy $originalExecutionPolicy -Scope Process -Force

# Verify NuGet installation
if (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue) {
    Write-Output "NuGet package provider is installed successfully."
} else {
    Write-Output "Failed to install NuGet package provider."
}