############################################################################################################
#                                     MITS - New Workstation Baseline Script                                #
#                                                 Version 12.0.6k                                            #
############################################################################################################
<#
.SYNOPSIS
    Automates the configuration and deployment of a standardized Windows workstation environment.

.DESCRIPTION
    This script performs a comprehensive baseline setup for new Windows 10/11 workstations including:
    - ConnectWise Automate agent deployment
    - Power profile optimization
    - System configuration and hardening
    - Windows Update management
    - Microsoft 365 and Adobe Acrobat installation
    - Removal of bloatware and unnecessary features
    - BitLocker encryption configuration
    - System restore point creation

.PARAMETER None
    This script does not accept parameters.

.NOTES
    Version:        12.0.6j
    Author:         Bill Ulrich
    Creation Date:  4/2/2025
    Requires:       Administrator privileges
                    Windows 10/11 Professional
    
.EXAMPLE
    .\MITS-Baseline.ps1 
    
    Run the script with administrator privileges to execute the full baseline configuration.

.LINK
    https://github.com/mitsdev01/MITS
#>

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as an Administrator!" -ForegroundColor Red
    Start-Sleep -Seconds 8
    return
}

# Initial setup and version
$ScriptVersion = "12.0.6k"
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$TempFolder = "C:\temp"
$LogFile = "$TempFolder\$env:COMPUTERNAME-baseline.log"
# Store system type for use in termination handler
$global:IsMobileDevice = $false

Set-ExecutionPolicy RemoteSigned -Force *> $null

# Set up termination handler for Ctrl+C and window closing
$null = [Console]::TreatControlCAsInput = $true
# Register termination handler
$null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    Write-Host "`n`nScript termination detected. Performing cleanup..." -ForegroundColor Yellow
    # Create WakeLock exit flag to stop the WakeLock script if it's running
    if (-not (Test-Path "c:\temp\wakelock.flag")) {
        try {
            New-Item -Path "c:\temp\wakelock.flag" -ItemType File -Force | Out-Null
            Write-Host "WakeLock flag created to stop background script." -ForegroundColor Cyan
        }
        catch {
            Write-Host "Failed to create WakeLock flag: $_" -ForegroundColor Red
        }
    }
    
    # If mobile device, stop presentation settings
    if ($global:IsMobileDevice) {
        try {
            $presentationProcess = Get-Process | Where-Object { $_.Path -eq "C:\Windows\System32\PresentationSettings.exe" } -ErrorAction SilentlyContinue
            if ($presentationProcess) {
                Stop-Process -InputObject $presentationProcess -Force -ErrorAction SilentlyContinue
                Write-Host "Stopped presentation settings." -ForegroundColor Cyan
            }
        }
        catch {
            Write-Host "Failed to stop presentation settings: $_" -ForegroundColor Red
        }
    }
    
    # Re-enable Windows Update service if it was disabled
    try {
        $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        if ($wuService -and $wuService.StartType -eq 'Disabled') {
            Set-Service -Name wuauserv -StartupType Manual -ErrorAction SilentlyContinue
            Start-Service -Name wuauserv -ErrorAction SilentlyContinue
            Write-Host "Re-enabled Windows Update service." -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "Failed to re-enable Windows Update service: $_" -ForegroundColor Red
    }
    
    # Log termination
    Add-Content -Path $LogFile -Value "$(Get-Date) - Script terminated by user." -ErrorAction SilentlyContinue
    
    Write-Host "Cleanup completed. Exiting script." -ForegroundColor Yellow
}

# Create required directories
if (-not (Test-Path $TempFolder)) { New-Item -Path $TempFolder -ItemType Directory | Out-Null }
if (-not (Test-Path $LogFile)) { New-Item -Path $LogFile -ItemType File | Out-Null }

# Add log file header
$headerBorder = "=" * 80
$header = @"
$headerBorder
                        MITS - New Workstation Baseline Log
                             Version $ScriptVersion
                         $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
$headerBorder

Computer: $env:COMPUTERNAME
User: $env:USERNAME
Windows: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
$headerBorder

"@
Add-Content -Path $LogFile -Value $header

# Set working directory
Set-Location -Path $TempFolder

# Add the required Win32 API functions
Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    
    namespace Win32 {
        public class User32 {
            [DllImport("user32.dll", SetLastError = true)]
            public static extern bool SetWindowPos(IntPtr hWnd, int hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
        }
    }
"@

# Clear console window
Clear-Host

############################################################################################################
#                                                 Functions                                                #
#                                                                                                          #
############################################################################################################
#region Functions
function Print-Middle($Message, $Color = "White") {
    Write-Host (" " * [System.Math]::Floor(([System.Console]::BufferWidth / 2) - ($Message.Length / 2))) -NoNewline
    Write-Host -ForegroundColor $Color $Message
}

function Write-Delayed {
    param(
        [string]$Text, 
        [switch]$NewLine = $true,
        [System.ConsoleColor]$Color = [System.ConsoleColor]::White
    )
    
    # Add to log file
    Write-Log "$Text"
    
    # Save cursor position and console color
    $originalColor = [Console]::ForegroundColor
    [Console]::ForegroundColor = $Color
    
    # Do the visual character-by-character animation for the console
    foreach ($char in $Text.ToCharArray()) {
        [Console]::Write($char)
        Start-Sleep -Milliseconds 25
    }
    
    # Add newline if requested
    if ($NewLine) {
        [Console]::WriteLine()
    }
    
    # Restore original color
    [Console]::ForegroundColor = $originalColor
}

function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "[$timestamp] $Message"
}

function Write-TaskComplete {
    # Log to file
    Write-Log "Task completed successfully"
    
    # Write to both transcript and console without creating a new line
    Write-Host " done." -ForegroundColor Green -NoNewline
    
    # Add the newline after the "done." message
    Write-Host ""
}

function Write-TaskFailed {
    # Log to file
    Write-Log "Task failed"
    
    # Write to both transcript and console without creating a new line
    Write-Host " failed." -ForegroundColor Red -NoNewline
    
    # Add the newline after the "failed." message
    Write-Host ""
}

function Move-ProcessWindowToTopRight {
    param (
        [Parameter(Mandatory = $true)]
        [string]$processName
    )
    
    Add-Type -AssemblyName System.Windows.Forms
    
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $processes = Get-Process | Where-Object { $_.ProcessName -eq $processName }
    
    foreach ($process in $processes) {
        $hwnd = $process.MainWindowHandle
        if ($hwnd -eq [IntPtr]::Zero) { continue }
        
        $x = $screen.Right - 800
        $y = $screen.Top
        
        [void][Win32.User32]::SetWindowPos($hwnd, -1, $x, $y, 800, 600, 0x0040)
    }
}

function Is-Windows11 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption
    # Check for Windows 11
    return $osVersion -ge "10.0.22000" -and $osProduct -like "*Windows 11*"
}

function Is-Windows10 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption
    # Check for Windows 10
    return $osVersion -lt "10.0.22000" -and $osProduct -like "*Windows 10*"
}

function Show-SpinningWait {
    param (
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$DoneMessage = "done.",
        [Parameter(ValueFromRemainingArguments = $true)]
        [object[]]$ArgumentList,
        [switch]$SuppressOutput = $false
    )
    
    # Use our fixed Write-Delayed function for consistent output
    Write-Delayed "$Message" -NewLine:$false
    $spinner = @('/', '-', '\', '|')
    $spinnerIndex = 0
    $jobName = [Guid]::NewGuid().ToString()
    
    # Start the script block as a job
    $job = Start-Job -Name $jobName -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    
    # Display spinner while job is running
    while ($job.State -eq 'Running') {
        [Console]::Write($spinner[$spinnerIndex])
        Start-Sleep -Milliseconds 100
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    }
    
    # Get the job result - Get job output first for transcript
    $jobOutput = Receive-Job -Name $jobName
    
    # Log job output to transcript if there is any
    if ($jobOutput -and -not $SuppressOutput) {
        Write-Host "`nJob output: $($jobOutput -join "`n")" -ForegroundColor Gray
    }
    
    Remove-Job -Name $jobName
    
    # Write done message once (will be captured in transcript)
    # and handle visual formatting
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write($DoneMessage)
    [Console]::ResetColor()
    [Console]::WriteLine()
    
    # Log completion to the log file
    Write-Log "Completed: $Message"
    
    return $jobOutput
}

function Show-SpinnerWithProgressBar {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $true)]
        [string]$URL,
        [Parameter(Mandatory = $true)]
        [string]$OutFile,
        [string]$DoneMessage = "done."
    )
    
    # Use our fixed Write-Delayed function for consistent output
    Write-Delayed "$Message" -NewLine:$false
    
    # Create parent directory for output file if it doesn't exist
    $outDir = Split-Path -Parent $OutFile
    if (-not (Test-Path $outDir)) {
        New-Item -Path $outDir -ItemType Directory -Force | Out-Null
    }
    
    $spinner = @('/', '-', '\', '|')
    $spinnerIndex = 0
    $done = $false
    
    # Start download in a separate runspace
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $powerShell = [powershell]::Create()
    $powerShell.Runspace = $runspace
    
    # Add script to download file
    [void]$powerShell.AddScript({
        param($URL, $OutFile)
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($URL, $OutFile)
    }).AddArgument($URL).AddArgument($OutFile)
    
    # Start the download asynchronously
    $handle = $powerShell.BeginInvoke()
    
    # Display spinner while downloading
    try {
        while (-not $handle.IsCompleted) {
            # Write the current spinner character
            [Console]::Write($spinner[$spinnerIndex])
            Start-Sleep -Milliseconds 100
            [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
            $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
        }
        
        # Complete the async operation
        $powerShell.EndInvoke($handle) | Out-String | Write-Debug
    }
    catch {
        # Ensure errors are written to transcript
        Write-Host "`nError during download: $_" -ForegroundColor Red
    }
    finally {
        # Clean up resources
        $powerShell.Dispose()
        $runspace.Dispose()
        
        # Write done message once (will be captured in transcript)
        # and handle visual formatting
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write($DoneMessage)
        [Console]::ResetColor()
        [Console]::WriteLine()
        
        # Ensure it's in the transcript too
        #Write-Verbose "Finished: $Message $DoneMessage" -Verbose
    }
}

function Show-SpinnerAnimation {
    param (
        [ScriptBlock]$ScriptBlock,
        [string]$Message,
        [System.ConsoleColor]$SuccessColor = [System.ConsoleColor]::Green
    )
    
    $spinChars = '/', '-', '\', '|'
    $pos = 0
    $originalCursorVisible = [Console]::CursorVisible
    [Console]::CursorVisible = $false
    
    # Use our fixed Write-Delayed function for consistent output
    Write-Delayed $Message -NewLine:$false
    
    $job = Start-Job -ScriptBlock $ScriptBlock
    
    try {
        while ($job.State -eq 'Running') {
            [Console]::Write($spinChars[$pos])
            Start-Sleep -Milliseconds 100
            [Console]::Write("`b")
            $pos = ($pos + 1) % 4
        }
        
        # Get the job result
        $result = Receive-Job -Job $job
        
        # Display completion status
        [Console]::ForegroundColor = $SuccessColor
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()
        
        return $result
    }
    finally {
        Remove-Job -Job $job -Force
        [Console]::CursorVisible = $originalCursorVisible
    }
}

function Show-Spinner {
    param (
        [int]$SpinnerIndex,
        [string[]]$SpinnerChars = @('/', '-', '\', '|'),
        [int]$CursorLeft,
        [int]$CursorTop
    )
    
    # Use only Console methods to avoid writing to transcript
    [Console]::SetCursorPosition($CursorLeft, $CursorTop)
    [Console]::Write($SpinnerChars[$SpinnerIndex % $SpinnerChars.Length])
}

function Connect-VPN {
    if (Test-Path 'C:\Program Files\SonicWall\SSL-VPN\NetExtender\NXCLI.exe') {
        Write-Delayed "NetExtender detected successfully, starting connection..." -NewLine:$false
        Start-Process C:\temp\ssl-vpn.bat
        Start-Sleep -Seconds 10
        $connectionProfile = Get-NetConnectionProfile -InterfaceAlias "Sonicwall NetExtender"
        if ($connectionProfile) {
            Write-Delayed "The 'Sonicwall NetExtender' adapter is connected to SSLVPN." -NewLine:$true
        } else {
            Write-Delayed "The 'Sonicwall NetExtender' adapter is not connected to SSLVPN." -NewLine:$true
        }
    } else {
        Write-Delayed "SonicWall NetExtender not found!" -NewLine:$true -Color Red
    }
}

function Start-VssService {
    $vss = Get-Service -Name 'VSS' -ErrorAction SilentlyContinue
    if ($vss.Status -ne 'Running') {
        Write-Delayed "Starting Volume Shadow Copy service for restore point creation..." -NewLine:$false
        Start-Service VSS
        Write-TaskComplete
    }
}


function Remove-RestorePointFrequencyLimit {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "SystemRestorePointCreationFrequency" -Value 0
}

function Create-RestorePoint-WithTimeout {
    param (
        [string]$Description,
        [int]$TimeoutSeconds = 60
    )

    $job = Start-Job { Checkpoint-Computer -Description $using:Description -RestorePointType "MODIFY_SETTINGS" }
    $completed = Wait-Job $job -Timeout $TimeoutSeconds

    if (-not $completed) {
        Write-Error "  [-] Restore point creation timed out after $TimeoutSeconds seconds. Stopping job..."
        Stop-Job $job -Force
        Remove-Job $job
    } else {
        Receive-Job $job
        Write-Host "  [+] Restore point created successfully." -ForegroundColor Green
        Remove-Job $job
    }
}

#endregion Functions

############################################################################################################
#                                                Transcript Logging                                        #
#                                                                                                          #
############################################################################################################
#region Logging

# Start transcript logging with better handling
# Add a function to start transcript with better error handling
function Start-CleanTranscript {
    param (
        [string]$Path
    )
    
    try {
        # Stop any existing transcript
        try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
        
        # Start new transcript
        Start-Transcript -Path $Path -Force -ErrorAction Stop
        
        # Don't write the header here anymore, it will be displayed in the Title Screen section
        return $true
    }
    catch {
        Write-Warning "Failed to start transcript: $_"
        return $false
    }
}

# Call the function after the necessary variables are set
Start-CleanTranscript -Path "$TempFolder\$env:COMPUTERNAME-baseline_transcript.txt"
Clear-Host
############################################################################################################
#                                             Title Screen                                                 #
#                                                                                                          #
############################################################################################################
#region Title Screen

# Print Script Title - This will be displayed and captured in the transcript
$Padding = ("=" * [System.Console]::BufferWidth)
Write-Host -ForegroundColor "Red" $Padding -NoNewline
Print-Middle "MITS - New Workstation Baseline Script"
Write-Host -ForegroundColor Yellow "                                                   version $ScriptVersion"
Write-Host -ForegroundColor "Red" -NoNewline $Padding
Write-Host "  "
Start-Sleep -Seconds 2

############################################################################################################
#                                             Start Baseline                                               #
#                                                                                                          #
############################################################################################################
# Start baseline

# Baseline log file
#Write-Log "Automated workstation baseline has started"

# Check for required modules
Write-Host "`nPreparing required modules..." -NoNewline
$spinner = @('/', '-', '\', '|')
$spinnerIndex = 0
$originalCursorLeft = [Console]::CursorLeft
$originalCursorTop = [Console]::CursorTop

#  Run the module check in the background and show spinner
try {
    $job = Start-Job -ScriptBlock {
        Invoke-Expression (Invoke-RestMethod "https://raw.githubusercontent.com/mitsdev01/MITS/refs/heads/main/Check-Modules.ps1")
    }
    
    # Display the spinner while the job is running
    while ($job.State -eq 'Running') {
        Show-Spinner -SpinnerIndex $spinnerIndex -CursorLeft $originalCursorLeft -CursorTop $originalCursorTop
        Start-Sleep -Milliseconds 100
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    }
    
    # Get the job result and clean up
    $result = Receive-Job -Job $job
    Remove-Job -Job $job -Force
    
    # Clear the spinner character
    [Console]::SetCursorPosition($originalCursorLeft, $originalCursorTop)
    [Console]::Write(" ")
    
    # Show completion
    [Console]::SetCursorPosition($originalCursorLeft, $originalCursorTop)
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write("done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    
    # Write to transcript
    #Write-Host "Module check completed successfully" -ForegroundColor Green
    #Write-Log "Module check completed successfully"
}
catch {
    # Handle errors
    if ($job -and $job.State -eq 'Running') {
        Stop-Job -Job $job
        Remove-Job -Job $job -Force
    }
    
    # Clear the spinner character
    [Console]::SetCursorPosition($originalCursorLeft, $originalCursorTop)
    [Console]::Write(" ")
    
    # Show error
    [Console]::SetCursorPosition($originalCursorLeft, $originalCursorTop)
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write("failed.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    
    # Ensure error is written to transcript
    Write-Host "Module check failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "Module check failed: $($_.Exception.Message)"
}


############################################################################################################
#                                            Wakelock Configuration                                        #
#                                                                                                          #
############################################################################################################
#region WakeLock
try {
    $computerSystem = Get-CimInstance -ClassName CIM_ComputerSystem
    $pcSystemType = $computerSystem.PCSystemType
    
    # Check if the system is a mobile device (PCSystemType 2 = Mobile)
    if ($pcSystemType -eq 2) {
        # Set global flag for termination handler
        $global:IsMobileDevice = $true
        # Mobile device detected, launching presentation settings
        Start-Process -FilePath "C:\Windows\System32\PresentationSettings.exe" -ArgumentList "/start"
    } else {
        # For non-mobile devices, create a wake lock script
        $wakeLockScriptPath = "$TempFolder\WakeLock.ps1"
        $wakeLockContent = @'
# Load the necessary assembly for accessing Windows Forms functionality
Add-Type -AssemblyName System.Windows.Forms

# Define the path to the flag file
$flagFilePath = 'c:\temp\wakelock.flag'

# Infinite loop to send keys and check for the flag file
while ($true) {
    # Check if the flag file exists
    if (Test-Path $flagFilePath) {
        # If the flag file is found, exit the loop and script
        Write-Host "Flag file detected. Exiting script..."
        break
    } else {
        # If the flag file is not found, send the 'Shift + F15' keys
        [System.Windows.Forms.SendKeys]::SendWait('+{F15}')
        # Wait for 60 seconds before sending the keys again
        Start-Sleep -Seconds 60
    }
}
'@
        # Write the wake lock script to file
        Set-Content -Path $wakeLockScriptPath -Value $wakeLockContent
        
        # Launch the wake lock script in a minimized window
        Start-Process -FilePath "powershell.exe" -ArgumentList "-file $wakeLockScriptPath" -WindowStyle Minimized
        
        Write-Log "WakeLock script started to prevent system sleep"
    }
} catch {
    Write-Log "Failed to setup WakeLock: $_"
    Write-Error "Failed to setup WakeLock: $_"
}
#endregion WakeLock


<# Uncomment and change $user value to the user you want to use as the local admin account
############################################################################################################
#                                        Account Configuration                                             #
#                                                                                                          #
############################################################################################################
#region Local Admin 
# ---------------------------------------------------------------------
# Configure Local Admin Account
# ---------------------------------------------------------------------
# Check if the user 'mitsadmin' exists
$user = Get-LocalUser -Name 'mitsadmin' -ErrorAction SilentlyContinue

if ($user) {
    # Check if the password is set to 'Never Expire'
    if (-not $user.PasswordNeverExpires) {
        Write-Delayed "Setting mitsadmin password to 'Never Expire'..." -NewLine:$false
        $user | Set-LocalUser -PasswordNeverExpires $true
        Write-TaskComplete
        Write-Log "Set mitsadmin password to never expire"
    }
} else {
    Write-Host "Creating local mitsadmin & setting password to 'Never Expire'..." -NoNewline
    $Password = ConvertTo-SecureString "ChangeMe!" -AsPlainText -Force
    New-LocalUser "mitsadmin" -Password $Password -FullName "MITS Admin" -Description "mitsadmin Account" *> $null
    $newUser = Get-LocalUser -Name 'mitsadmin' -ErrorAction SilentlyContinue
    if ($newUser) {
        $newUser | Set-LocalUser -PasswordNeverExpires $true
        Add-LocalGroupMember -Group "Administrators" -Member "mitsadmin"
        Write-TaskComplete
        Write-Log "Created mitsadmin local admin account with non-expiring password"
    } else {
        Write-TaskFailed
        Write-Log "Failed to create mitsadmin account"
    }
}
#endregion LocalAdminAccount
#>

############################################################################################################
#                                        Windows Update Configuration                                      #
#                                                                                                          #
############################################################################################################
#region Windows Update
# Skip writing to transcript/output directly, just use console methods
# This prevents duplicate "Suspending Windows Update..." messages
[Console]::ForegroundColor = [System.ConsoleColor]::White
[Console]::Write("Suspending Windows Update...")
[Console]::ResetColor()

# Add to log file
Write-Log "Suspending Windows Update service"

# Initialize spinner
$spinner = @('/', '-', '\', '|')
$spinnerIndex = 0
[Console]::Write($spinner[$spinnerIndex])

# Stop the service first
try {
    # Update spinner
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
    
    Stop-Service -Name wuauserv -Force -ErrorAction Stop
    $stopSuccess = $true
    
    # Update spinner
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
} catch {
    $stopSuccess = $false
    Write-Log "Error stopping Windows Update service: $_"
}

# Then set startup type to disabled
try {
    # Update spinner
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
    
    Set-Service -Name wuauserv -StartupType Disabled -ErrorAction Stop
    $disableSuccess = $true
    
    # Update spinner
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
} catch {
    $disableSuccess = $false
    Write-Log "Error disabling Windows Update service: $_"
}

# Add a short delay for visual effect
Start-Sleep -Milliseconds 100

# Check both operations succeeded
$service = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if ($stopSuccess -and $disableSuccess -and $service.Status -eq 'Stopped') {
    # Clear the spinner character by moving cursor position back
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    
    # Use Write-Host for both transcript and console display
    Write-Host " done." -ForegroundColor Green
    
    Write-Log "Windows Update service suspended successfully"
} else {
    # Clear the spinner character by moving cursor position back
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    
    # Use Write-Host for both transcript and console display
    Write-Host " failed." -ForegroundColor Red
    
    Write-Log "Failed to suspend Windows Update service completely"
}
#endregion WindowsUpdate

############################################################################################################
#                                        Power Profile Configuration                                       #
#                                                                                                          #
############################################################################################################
#region Power Profile
Write-Delayed "Configuring Power Profile for all devices..." -NewLine:$false
Start-Sleep -Seconds 2

# Get active power scheme
$activeScheme = (powercfg -getactivescheme).Split()[3]

# Disable sleep and hibernation
powercfg /change standby-timeout-ac 0 *> $null
powercfg /change hibernate-timeout-ac 0 *> $null
powercfg /h off *> $null

Write-TaskComplete
Write-Log "Disabled sleep and hibernation mode"

# Configure Fast Startup
Write-Delayed "Disabling Fast Startup..." -NewLine:$false
$regKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
Set-ItemProperty -Path $regKeyPath -Name HiberbootEnabled -Value 0 *> $null
Write-TaskComplete
Write-Log "Fast startup disabled"

# Configure power button actions
Write-Delayed "Configuring 'Shutdown' power button action..." -NewLine:$false
powercfg -setacvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 3
powercfg -setdcvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 3
Write-TaskComplete
Write-Log "Power button action set to 'Shutdown'"

# Configure lid close action
Write-Delayed "Setting 'Do Nothing' lid close action..." -NewLine:$false
powercfg -setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 00000000
powercfg -setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 00000000
Write-TaskComplete
Write-Log "Lid close action set to 'Do Nothing' (applicable to laptops)"

# Configure standby settings
Write-Delayed "Setting Standby idle time to never on battery..." -NewLine:$false
powercfg -setdcvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0
Write-TaskComplete

Write-Delayed "Setting Standby idle time to never on AC power..." -NewLine:$false
powercfg -setacvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0
Write-TaskComplete

# Apply power scheme
Write-Delayed "Activating power profile..." -NewLine:$false
powercfg /S $activeScheme
Write-TaskComplete
Write-Log "Power profile configured to prevent sleep for all device types"
#endregion PowerProfile

#region SystemTime
Write-Delayed "Setting EST as default timezone..." -NewLine:$false

# Initialize spinner
$spinner = @('/', '-', '\', '|')
$spinnerIndex = 0
[Console]::Write($spinner[$spinnerIndex])

# Perform timezone operations
try {
    # Update spinner more frequently during operation
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
    Start-Sleep -Milliseconds 50
    
    Start-Service W32Time
    
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
    Start-Sleep -Milliseconds 50
    
    Set-TimeZone -Id "Eastern Standard Time"
    $success = $true
} catch {
    $success = $false
    Write-Log "Error setting timezone: $_"
}

# Replace spinner with done/failed message
[Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
if ($success) {
    # Use Write-Host for transcript logging
    Write-Host " done." -ForegroundColor Green
    Write-Log "Time zone set to Eastern Standard Time"
} else {
    # Use Write-Host for transcript logging
    Write-Host " failed." -ForegroundColor Red
    Write-Log "Failed to set time zone to Eastern Standard Time"
}

Write-Delayed "Syncing system clock..." -NewLine:$false

# Initialize spinner
$spinner = @('/', '-', '\', '|')
$spinnerIndex = 0
[Console]::Write($spinner[$spinnerIndex])

# Sync system clock
try {
    w32tm /resync -ErrorAction SilentlyContinue | Out-Null
    $success = $true
} catch {
    $success = $false
    Write-Log "Error syncing system clock: $_"
}

# Replace spinner with done/failed message
[Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
if ($success) {
    # Use Write-Host for transcript logging
    Write-Host " done." -ForegroundColor Green
    Write-Log "Synced system clock"
} else {
    # Use Write-Host for transcript logging
    Write-Host " failed." -ForegroundColor Red
    Write-Log "Failed to sync system clock"
}
#endregion System Time


############################################################################################################
#                                        Bitlocker Configuration                                           #
#                                                                                                          #
############################################################################################################
#region Bitlocker
# Check Bitlocker Compatibility -v2
$WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
$TPM = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -Class Win32_Tpm -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue

if ($WindowsVer -and $TPM -and $BitLockerReadyDrive) {
    # Check if Bitlocker is already configured on C:
    $BitLockerStatus = Get-BitLockerVolume -MountPoint $env:SystemDrive
    # Ensure the output directory exists
    $outputDirectory = "C:\temp"
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }
    if ($BitLockerStatus.ProtectionStatus -eq 'On') {
        # Bitlocker is already configured
        # Write to transcript
        Write-Host "Bitlocker is already configured on $env:SystemDrive - " -ForegroundColor Red -NoNewline
        
        # Setup for non-blocking read with timeout
        $timeoutSeconds = 10
        $endTime = (Get-Date).AddSeconds($timeoutSeconds)
        $userResponse = $null

        # Write prompt to transcript
        #Write-Host "Do you want to skip configuring Bitlocker? (yes/no)" -NoNewline
        
        # For visual appearance
        Write-Host -ForegroundColor Red "Do you want to skip configuring Bitlocker? (yes/no)" -NoNewline

        while ($true) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.KeyChar -match '^[ynYN]$') {
                    $userResponse = $key.KeyChar
                    # Log response for transcript
                    Write-Host "`nUser selected: $userResponse to skip Bitlocker configuration."
                    break
                }
            } elseif ((Get-Date) -ge $endTime) {
                # Log timeout for transcript
                #Write-Host "`nNo response received, skipping Bitlocker configuration..." -NoNewline
                #Write-Host " done." -ForegroundColor Green
                
                # For visual appearance
                Write-Host "`nNo response received, skipping Bitlocker configuration..." -NoNewline
                Write-Host -ForegroundColor Green " done."
                $userResponse = 'y' # Assume 'yes' to skip if no response
                break
            }
            Start-Sleep -Milliseconds 100
        }

        if ($userResponse -ine 'y') {
            # Disable BitLocker
            manage-bde -off $env:SystemDrive | Out-Null

            # Monitor decryption progress
            do {
                $status = manage-bde -status $env:SystemDrive
                $percentageEncrypted = ($status | Select-String -Pattern "Percentage Encrypted:.*").ToString().Split(":")[1].Trim()
                Write-Host "`rCurrent decryption progress: $percentageEncrypted" -NoNewline
                Start-Sleep -Seconds 1
            } until ($percentageEncrypted -eq "0.0%")
            Write-Host "`nDecryption of $env:SystemDrive is complete."
            # Reconfigure BitLocker
            Write-Delayed "Configuring Bitlocker Disk Encryption..." -NewLine:$false
            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector -WarningAction SilentlyContinue | Out-Null
            Start-Process 'manage-bde.exe' -ArgumentList " -on $env:SystemDrive -UsedSpaceOnly" -Verb runas -Wait | Out-Null
            Write-Host " done." -ForegroundColor Green
            # Verify volume key protector exists
            $BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
            if ($BitLockerVolume.KeyProtector) {
                #Write-Host "Bitlocker disk encryption configured successfully."
            } else {
                Write-Host "Bitlocker disk encryption is not configured."
            }
        }
    } else {
        # Bitlocker is not configured
        Write-Delayed "Configuring Bitlocker Disk Encryption..." -NewLine:$false
        
        # Initialize spinner
        $spinner = @('/', '-', '\', '|')
        $spinnerIndex = 0
        
        # Create the recovery key
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
        
        # Start showing spinner
        [Console]::Write($spinner[$spinnerIndex])
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
        
        # Add TPM key
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector -WarningAction SilentlyContinue | Out-Null
        
        # Update spinner
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        [Console]::Write($spinner[$spinnerIndex])
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
        
        # Wait for the protectors to take effect
        Start-Sleep -Seconds 5
        
        # Update spinner
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        [Console]::Write($spinner[$spinnerIndex])
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
        
        # Enable Encryption
        $encryptionProcess = Start-Process 'manage-bde.exe' -ArgumentList "-on $env:SystemDrive -UsedSpaceOnly" -Verb runas -PassThru -Wait
        
        # Update spinner during encryption wait
        for ($i = 0; $i -lt 10; $i++) {
            [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
            [Console]::Write($spinner[$spinnerIndex])
            $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
            Start-Sleep -Milliseconds 100
        }
        
        # Backup the Recovery to AD
        $RecoveryKeyGUID = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | 
                            Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'} | 
                            Select-Object -ExpandProperty KeyProtectorID
        
        # Update spinner
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        [Console]::Write($spinner[$spinnerIndex])
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
        
        # Try AD backup (may fail in non-domain environments)
        try {
            manage-bde.exe -protectors $env:SystemDrive -adbackup -id $RecoveryKeyGUID | Out-Null
        }
        catch {
            Write-Log "Failed to backup BitLocker recovery key to AD: $_"
        }
        
        # Write Recovery Key to a file
        manage-bde -protectors C: -get | Out-File "$outputDirectory\$env:computername-BitLocker.txt"
        
        # Verify volume key protector exists
        $BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
        
        # Replace spinner with done message
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        # Use Write-Host instead of Console method to ensure proper transcript logging
        Write-Host " done." -ForegroundColor Green
        
        if ($BitLockerVolume.KeyProtector) {
            # Get recovery information
            $recoveryId = $BitLockerVolume.KeyProtector | 
                Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | 
                ForEach-Object { $_.KeyProtectorId.Trim('{', '}') }
            
            $recoveryPassword = $BitLockerVolume.KeyProtector | 
                Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | 
                Select-Object -ExpandProperty RecoveryPassword
            
            # Display recovery info
            Write-Delayed "Bitlocker has been successfully configured." -NewLine:$true
            # Display recovery details
            Write-Host -ForegroundColor Cyan "Recovery ID: $recoveryId"
            Write-Host -ForegroundColor Cyan "Recovery Password: $recoveryPassword"
            
            # Log success
            Write-Log "BitLocker encryption configured successfully with Recovery ID: $recoveryId"
        } else {
            Write-Host -ForegroundColor Red "Bitlocker disk encryption is not configured."
            
            # Log failure
            Write-Log "Failed to configure BitLocker encryption"
        }
    }
} else {
    Write-Warning "Skipping Bitlocker Drive Encryption due to device not meeting hardware requirements."
    Write-Log "Skipping Bitlocker Drive Encryption due to device not meeting hardware requirements."
    Start-Sleep -Seconds 1
}
#endregion Bitlocker


############################################################################################################
#                                        System Restore Configuration                                      #
#                                                                                                          #
############################################################################################################
#region System Restore
Write-Delayed "Enabling System Restore..." -NewLine:$false

# Set RestorePoint Creation Frequency to 0 (allow multiple restore points)
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0 
Remove-RestorePointFrequencyLimit

# Enable system restore
Enable-ComputerRestore -Drive "C:\" -Confirm:$false
Write-TaskComplete
Write-Log "System Restore Enabled"
#endregion SystemRestore


############################################################################################################
#                                        Offline Files Configuration                                       #
#                                                                                                          #
############################################################################################################
#region Offline Files
Write-Delayed "Disabling Offline File Sync..." -NewLine:$false

# Set registry path for Offline Files
$registryPath = "HKLM:\System\CurrentControlSet\Services\CSC\Parameters"

# Check if the registry path exists, if not, create it
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -Force *> $null
}

# Disable Offline Files by setting Start value to 4
Set-ItemProperty -Path $registryPath -Name "Start" -Value 4 *> $null
Write-TaskComplete
Write-Log "Offline file sync disabled"
#endregion OfflineFiles


############################################################################################################
#                                   Profile Customization and Privacy Settings                             #
#                                                                                                          #
############################################################################################################
#region Profile Config
# Get all user SIDs for registry modifications
$UserSIDs = @()
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | 
    Where-Object {$_.PSChildName -match "S-1-5-21-(\d+-){4}$"} |
    Select-Object @{Name="SID"; Expression={$_.PSChildName}} |
    ForEach-Object {$UserSIDs += $_.SID}

# Disable Windows Feedback Experience
Write-Delayed "Disabling Windows Feedback Experience program..." -NewLine:$false
$Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
if (!(Test-Path $Advertising)) {
    New-Item $Advertising | Out-Null
}
if (Test-Path $Advertising) {
    Set-ItemProperty $Advertising Enabled -Value 0
    Write-TaskComplete
    Write-Log "Windows Feedback Experience disabled"
}

# Disable Cortana in Windows Search
Write-Delayed "Preventing Cortana from being used in Windows Search..." -NewLine:$false
$Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (!(Test-Path $Search)) {
    New-Item $Search -Force | Out-Null
}
if (Test-Path $Search) {
    Set-ItemProperty $Search AllowCortana -Value 0
    Write-TaskComplete
    Write-Log "Cortana disabled in Windows Search"
}

# Disable Bing Search in Start Menu
Write-Delayed "Disabling Bing Search in Start Menu..." -NewLine:$false
$WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (!(Test-Path $WebSearch)) {
    New-Item $WebSearch -Force | Out-Null
}
Set-ItemProperty $WebSearch DisableWebSearch -Value 1
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 -ErrorAction SilentlyContinue
Write-TaskComplete
Write-Log "Bing Search disabled in Start Menu"

# Disable Mixed Reality Portal
Write-Delayed "Disabling Mixed Reality Portal..." -NewLine:$false
$Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
if (Test-Path $Holo) {
    Set-ItemProperty $Holo FirstRunSucceeded -Value 0 -ErrorAction SilentlyContinue
}
if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic")) {
    New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic" -Force | Out-Null
}
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic" FirstRunSucceeded -Value 0 -ErrorAction SilentlyContinue
Write-TaskComplete
Write-Log "Mixed Reality Portal disabled"

# Disable Wi-Fi Sense
Write-Delayed "Disabling Wi-Fi Sense..." -NewLine:$false
$WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
$WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
$WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"

if (!(Test-Path $WifiSense1)) {
    New-Item $WifiSense1 -Force | Out-Null
}
Set-ItemProperty $WifiSense1 Value -Value 0 

if (!(Test-Path $WifiSense2)) {
    New-Item $WifiSense2 -Force | Out-Null
}
Set-ItemProperty $WifiSense2 Value -Value 0 

if (!(Test-Path $WifiSense3)) {
    New-Item $WifiSense3 -Force | Out-Null
}
Set-ItemProperty $WifiSense3 AutoConnectAllowedOEM -Value 0 
Write-TaskComplete
Write-Log "Wi-Fi Sense disabled"

# Disable Live Tiles
Write-Delayed "Disabling live tiles..." -NewLine:$false
$Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
if (!(Test-Path $Live)) {      
    New-Item $Live -Force | Out-Null
}  
if (Test-Path $Live) {
    Set-ItemProperty $Live NoTileApplicationNotification -Value 1 -ErrorAction SilentlyContinue
}
Write-TaskComplete
Write-Log "Live tiles disabled"

# Disable People icon on Taskbar
Write-Delayed "Disabling People icon on Taskbar..." -NewLine:$false
$People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
if (Test-Path $People) {
    Set-ItemProperty $People PeopleBand -Value 0 -ErrorAction SilentlyContinue
}
Write-TaskComplete
Write-Log "People icon disabled on Taskbar"

# Disable Cortana
Write-Delayed "Disabling Cortana..." -NewLine:$false
$Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
$Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
$Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"

if (!(Test-Path $Cortana1)) {
    New-Item $Cortana1 -Force | Out-Null
}
Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 

if (!(Test-Path $Cortana2)) {
    New-Item $Cortana2 -Force | Out-Null
}
Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 

if (!(Test-Path $Cortana3)) {
    New-Item $Cortana3 -Force | Out-Null
}
Set-ItemProperty $Cortana3 HarvestContacts -Value 0

# Apply to all user profiles
foreach ($sid in $UserSIDs) {
    $Cortana1 = "Registry::HKU\$sid\SOFTWARE\Microsoft\Personalization\Settings"
    $Cortana2 = "Registry::HKU\$sid\SOFTWARE\Microsoft\InputPersonalization"
    $Cortana3 = "Registry::HKU\$sid\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
    
    if (!(Test-Path $Cortana1)) {
        New-Item $Cortana1 -Force | Out-Null
    }
    Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 -ErrorAction SilentlyContinue
    
    if (!(Test-Path $Cortana2)) {
        New-Item $Cortana2 -Force | Out-Null
    }
    Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 -ErrorAction SilentlyContinue
    
    if (!(Test-Path $Cortana3)) {
        New-Item $Cortana3 -Force | Out-Null
    }
    Set-ItemProperty $Cortana3 HarvestContacts -Value 0 -ErrorAction SilentlyContinue
}
Write-TaskComplete
Write-Log "Cortana disabled"

# Remove 3D Objects from 'My Computer'
Write-Delayed "Removing 3D Objects from explorer 'My Computer' submenu..." -NewLine:$false
$Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
$Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"

if (Test-Path $Objects32) {
    Remove-Item $Objects32 -Recurse -Force
}
if (Test-Path $Objects64) {
    Remove-Item $Objects64 -Recurse -Force
}
Write-TaskComplete
Write-Log "3D Objects removed from explorer 'My Computer' submenu"

# Remove Microsoft Feeds
Write-Delayed "Removing Microsoft Feeds..." -NewLine:$false
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
$Name = "EnableFeeds"
$value = "0"

if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
Write-TaskComplete
Write-Log "Microsoft Feeds removed"

# Disable Scheduled Tasks
Write-Delayed "Disabling scheduled tasks..." -NewLine:$false

# Initialize spinner
$spinner = @('/', '-', '\', '|')
$spinnerIndex = 0
[Console]::Write($spinner[$spinnerIndex])

$taskList = @(
    'XblGameSaveTaskLogon',
    'XblGameSaveTask',
    'Consolidator',
    'UsbCeip',
    'DmClient',
    'DmClientOnScenarioDownload'
)

foreach ($task in $taskList) {
    # Update spinner before checking each task
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
    
    $scheduledTask = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue 
    if ($null -ne $scheduledTask) {
        # Update spinner before disabling task
        [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
        $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
        [Console]::Write($spinner[$spinnerIndex])
        
        Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
    }
    
    # Small delay for visual effect
    Start-Sleep -Milliseconds 100
}

# Replace spinner with done message
[Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
# Use Write-Host instead of Console methods
Write-Host " done." -ForegroundColor Green

Write-Log "Disabled unnecessary scheduled tasks"
#endregion Profile Customization

############################################################################################################
#                                            RMM Deployment                                                #
#                                                                                                          #
############################################################################################################
#region RMM Install

# ConnectWise Automate Agent Installation
$file = 'c:\temp\Warehouse-Agent_Install.MSI'
$agentName = "LTService"
$agentPath = "C:\Windows\LTSvc\"
$installerUri = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Warehouse-Agent_Install.MSI"
$agentIdKeyPath = "HKLM:\SOFTWARE\LabTech\Service"
$agentIdValueName = "ID"

# Check for existing LabTech agent
if (Get-Service $agentName -ErrorAction SilentlyContinue) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    [Console]::Write("Existing ConnectWise Automate installation found.")
} elseif (Test-Path $agentPath) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    Write-Delayed "ConnectWise Automate agent files are present, but the service is not installed." -NewLine:$false
    [Console]::ResetColor() 
    [Console]::WriteLine()
} else {
    Write-Delayed "Downloading ConnectWise Automate Agent..." -NewLine:$false
    try {
        Invoke-WebRequest -Uri $installerUri -OutFile $file
        Start-Sleep -Seconds 1
    } catch {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        Write-Delayed "ConnectWise Automate agent download failed!" -NewLine:$true
        [Console]::ResetColor() 
        [Console]::WriteLine()
        exit
    }
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.`n")
    [Console]::ResetColor()    
    Write-Delayed "Installing ConnectWise Automate Agent..." -NewLine:$false
    $process = Start-Process msiexec.exe -ArgumentList "/I $file /quiet" -PassThru
    $process.WaitForExit()
    if ($process.ExitCode -eq 0) {
        # Wait for the installation to complete
        Start-Sleep -Seconds 60
        [Console]::ForegroundColor = [System.ConsoleColor]::Green
        [Console]::Write(" done.")
        [Console]::ResetColor()
        [Console]::WriteLine()    
    } else {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Write(" failed.")
        [Console]::ResetColor()
        [Console]::WriteLine()    
        exit
    }
}

$agentServiceName = "LTService" # The name of the service installed by the ConnectWise Automate agent

# Check for the service
$service = Get-Service -Name $agentServiceName -ErrorAction SilentlyContinue
if ($null -ne $service) {
    if (Test-Path $agentIdKeyPath) {
        # Get the agent ID
        $agentId = Get-ItemProperty -Path $agentIdKeyPath -Name $agentIdValueName -ErrorAction SilentlyContinue
        if ($null -ne $agentId) {
            $LTAID = "`nConnectWise Automate Agent ID:"
            foreach ($Char in $LTAID.ToCharArray()) {
                [Console]::Write("$Char")
                Start-Sleep -Milliseconds 30
            }
            Start-Sleep -Seconds 1
            [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
            [Console]::Write(" $($agentId.$agentIdValueName)")
            [Console]::ResetColor()
            [Console]::WriteLine()    
        } else {
            [Console]::ForegroundColor = [System.ConsoleColor]::Red
            Write-Delayed "ConnectWise Automate agent ID not found." -NewLine:$true
            [Console]::ResetColor()
        }
} else {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    Write-Delayed "ConnectWise Automate agent is not installed." -NewLine:$true
            [Console]::ResetColor()
}
}
#endregion RMMDeployment

############################################################################################################
#                                          Office 365 Installation                                         #
#                                                                                                          #
############################################################################################################
#region M365 Install

# Install Office 365
$O365 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                             HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Microsoft 365 Apps for enterprise - en-us*" }

if ($O365) {
    Write-Host -ForegroundColor Cyan "Existing Microsoft Office installation found."
    Write-Log "Existing Microsoft Office installation found."
} else {
    $OfficePath = "c:\temp\OfficeSetup.exe"
    if (-not (Test-Path $OfficePath)) {
        $OfficeURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/OfficeSetup.exe"
        
        # Use spinner with progress bar for download
        Show-SpinnerWithProgressBar -Message "Downloading Microsoft Office 365..." -URL $OfficeURL -OutFile $OfficePath -DoneMessage " done."
    }
    
    # Validate successful download by checking the file size
    $FileSize = (Get-Item $OfficePath).Length
    $ExpectedSize = 7733536 # in bytes
    if ($FileSize -eq $ExpectedSize) {
        # Kill any running Office processes
        taskkill /f /im OfficeClickToRun.exe *> $null
        taskkill /f /im OfficeC2RClient.exe *> $null
        Start-Sleep -Seconds 10
        
        Show-SpinningWait -Message "Installing Microsoft Office 365..." -ScriptBlock {
            Start-Process -FilePath "c:\temp\OfficeSetup.exe" -Wait
            Start-Sleep -Seconds 15
        } -DoneMessage " done."
        
        if (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "Microsoft 365 Apps for enterprise - en-us"}) {
            Write-Log "Office 365 Installation Completed Successfully."
            Start-Sleep -Seconds 10
            taskkill /f /im OfficeClickToRun.exe *> $null
            taskkill /f /im OfficeC2RClient.exe *> $null
            Remove-Item -Path $OfficePath -force -ErrorAction SilentlyContinue
        } else {
            Write-Host -ForegroundColor Red "Microsoft Office 365 installation failed."
            Write-Log "Office 365 installation failed."
        }   
    }
    else {
        # Report download error
        Write-Log "Office download failed!"
        Write-Host -ForegroundColor Red "Download failed or file size does not match."
        Start-Sleep -Seconds 10
        Remove-Item -Path $OfficePath -force -ErrorAction SilentlyContinue
    }
} 
#endregion M365 Install


############################################################################################################
#                                        Adobe Acrobat Installation                                        #
#                                                                                                          #
############################################################################################################
#region Acrobat Install

# URL and file path for the Acrobat Reader installer
$URL = "https://axcientrestore.blob.core.windows.net/win11/AcroRdrDC2500120432_en_US.exe"
$AcroFilePath = "C:\temp\AcroRdrDC2500120432_en_US.exe"

# First, check if Adobe Acrobat Reader is already installed
$acrobatPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
$acrobatInstalled = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                      HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                     Where-Object { $_.DisplayName -like "*Adobe Acrobat Reader*" -or $_.DisplayName -like "*Adobe Acrobat DC*" }

if ((Test-Path $acrobatPath) -and $acrobatInstalled) {
    Write-Host "Existing Adobe Acrobat Reader installation found." -ForegroundColor Cyan
    Write-Log "Adobe Acrobat Reader already installed, skipped installation."
} else {
    # Create temp directory if it doesn't exist
    if (-not (Test-Path "C:\temp")) {
        New-Item -Path "C:\temp" -ItemType Directory -Force | Out-Null
    } 

    try {
        # Get the file size first
        $response = Invoke-WebRequest -Uri $URL -Method Head -ErrorAction Stop
        $fileSize = $response.Headers['Content-Length']
        
        # Download the Acrobat Reader installer with spinner AND progress bar
        Show-SpinnerWithProgressBar -Message "Downloading Adobe Acrobat Reader ($fileSize bytes)..." -URL $URL -OutFile $AcroFilePath -DoneMessage " done."
        
        $FileSize = (Get-Item $AcroFilePath).Length
        
        # Check if the file exists and has content
        if ((Test-Path $AcroFilePath -PathType Leaf) -and ($FileSize -gt 0)) {
            # Install Acrobat Reader with spinner
            $installResult = Show-SpinningWait -Message "Installing Adobe Acrobat Reader..." -ScriptBlock {
                # Start the installation process
                $process = Start-Process -FilePath "C:\temp\AcroRdrDC2500120432_en_US.exe" -ArgumentList "/sAll /rs /msi EULA_ACCEPT=YES /qn" -NoNewWindow -PassThru
                
                # Wait for initial process to complete
                $process | Wait-Process -Timeout 60 -ErrorAction SilentlyContinue
                
                # Look for Reader installer processes and wait
                $timeout = 300  # 5 minutes timeout
                $startTime = Get-Date
                
                do {
                    Start-Sleep -Seconds 5
                    $msiProcess = Get-Process -Name msiexec -ErrorAction SilentlyContinue
                    $readerProcess = Get-Process -Name Reader_en_install -ErrorAction SilentlyContinue
                    
                    $elapsedTime = (Get-Date) - $startTime
                    if ($elapsedTime.TotalSeconds -gt $timeout) {
                        break
                    }
                } while ($msiProcess -or $readerProcess)
                
                # Try to gracefully close any remaining installer processes
                Stop-Process -Name Reader_en_install -Force -ErrorAction SilentlyContinue
            }
            
            # Verify installation
            $acrobatPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
            $acrobatInstalled = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                                HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                                 Where-Object { $_.DisplayName -like "*Adobe Acrobat Reader*" -or $_.DisplayName -like "*Adobe Acrobat DC*" }
            
            if ((Test-Path $acrobatPath) -and $acrobatInstalled) {
                #Write-Host "Adobe Acrobat Reader installation completed successfully" -ForegroundColor Green
                Write-Log "Adobe Acrobat Reader installed successfully"
            } else {
                if (-not (Test-Path $acrobatPath)) {
                    Write-Host "Adobe Acrobat Reader executable not found" -ForegroundColor Yellow
                }
                if (-not $acrobatInstalled) {
                    Write-Host "Adobe Acrobat Reader not found in installed applications registry" -ForegroundColor Yellow
                }
                Write-Host "Adobe Acrobat Reader installation may not have completed properly" -ForegroundColor Yellow
                Write-Log "Adobe Acrobat Reader installation may not have completed properly"
            }
        } else {
            Write-Host "Download failed or file is empty" -ForegroundColor Red
            Write-Log "Adobe Acrobat Reader download failed or file is empty"
        }
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
        Write-Log "Error installing Adobe Acrobat Reader: $_"
    } finally {
        # Cleanup
        if (Test-Path $AcroFilePath) {
            Remove-Item -Path $AcroFilePath -Force -ErrorAction SilentlyContinue
            #Write-Host "Cleaned up installer file"
        }
    }
}
#endregion Acrobat Installation

#region NetExtender Install
############################################################################################################
#                                   SonicWall NetExtender Installation                                     #
#                                                                                                          #
############################################################################################################
#
# Install NetExtender
$SWNE = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                 HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Sonicwall NetExtender*" }
if ($SWNE) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Cyan
    [Console]::Write("Existing Sonicwall NetExtender installation found.")
    [Console]::ResetColor()
    [Console]::WriteLine()   
} else {
    $NEFilePath = "c:\temp\NXSetupU-x64-10.3.0.exe"
    if (-not (Test-Path $NEFilePath)) {
        $NEURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/NXSetupU-x64-10.3.0.exe"
        Invoke-WebRequest -OutFile $NEFilePath -Uri $NEURL -UseBasicParsing
    }
    # Validate successful download by checking the file size
    $NEGUI = "C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender\NEGui.exe"
    $FileSize = (Get-Item $NEFilePath).Length
    $ExpectedSize = 8234392 # in bytes 
    if ($FileSize -eq $ExpectedSize) {
        Write-Delayed "Installing Sonicwall NetExtender..." -NewLine:$false
        start-process -filepath $NEFilePath /S -Wait
        Write-TaskComplete
        if (Test-Path $NEGui) {
            Write-Log "Sonicwall NetExtender installation completed successfully."
            [Console]::ForegroundColor = [System.ConsoleColor]::Green
            Write-Delayed " done." -NewLine:$false
            [Console]::ResetColor()
            [Console]::WriteLine()
            Remove-Item -Path $NEFilePath -force -ErrorAction SilentlyContinue | Out-Null
        }
    } else {
        # Report download error
        Write-Log "Sonicwall NetExtender download failed!"
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        Write-Delayed "Download failed! File does not exist or size does not match." -NewLine:$false
        [Console]::ResetColor()
        [Console]::WriteLine()    
        Remove-Item -Path $NEFilePath -force -ErrorAction SilentlyContinue | Out-Null
    }
}
#endregion NetExtender Install

############################################################################################################
#                                           Bloatware Cleanup                                              #
#                                                                                                          #
############################################################################################################
#region Bloatware Cleanup

Write-Delayed "Initiating cleaning up of Windows bloatware..." -NewLine:$false

# Initialize spinner animation
$spinner = @('/', '-', '\', '|')
$spinnerIndex = 0
[Console]::Write($spinner[$spinnerIndex])

# Determine which Windows version and set up background debloat task
if (Is-Windows11) {
    try {
        $Win11DebloatURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/MITS-Debloat.zip"
        $Win11DebloatFile = "c:\temp\MITS-Debloat.zip"
        Invoke-WebRequest -Uri $Win11DebloatURL -OutFile $Win11DebloatFile -UseBasicParsing -ErrorAction Stop 
        
        Expand-Archive $Win11DebloatFile -DestinationPath 'c:\temp\MITS-Debloat' -Force
        
        # Launch the debloat script without creating a second window
        Start-Process powershell -ArgumentList "-WindowStyle Hidden","-Command Invoke-Expression -Command '& ''C:\temp\MITS-Debloat\MITS-Debloat.ps1'' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -DisableLockscreenTips -DisableSuggestions -ShowKnownFileExt -TaskbarAlignLeft -HideSearchTb -DisableWidgets -Silent'"
        
        Write-Log "Windows 11 Debloat started in background, running silently."
        $osType = "Windows 11"
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}
elseif (Is-Windows10) {
    try {
        $MITSDebloatURL = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/MITS-Debloat.zip"
        $MITSDebloatFile = "c:\temp\MITS-Debloat.zip"
        Invoke-WebRequest -Uri $MITSDebloatURL -OutFile $MITSDebloatFile -UseBasicParsing -ErrorAction Stop 
        
        Expand-Archive $MITSDebloatFile -DestinationPath c:\temp\MITS-Debloat -Force
        
        # Launch the debloat script without creating a second window
        Start-Process powershell -ArgumentList "-WindowStyle Hidden","-Command Invoke-Expression -Command '& ''C:\temp\MITS-Debloat\MITS-Debloat.ps1'' -RemoveApps -DisableBing -RemoveGamingApps -ClearStart -ShowKnownFileExt -Silent'"
        
        Write-Log "Windows 10 Debloat started in background, running silently."
        $osType = "Windows 10"
    }
    catch {
        Write-Error "An error occurred: $($Error[0].Exception.Message)"
    }
}

# Show spinner animation for 30 seconds while debloat runs in background
$startTime = Get-Date
$duration = New-TimeSpan -Seconds 30
while ((Get-Date) - $startTime -lt $duration) {
    Start-Sleep -Milliseconds 250
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
}

# Replace spinner with done message
[Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
Write-Host " done." -ForegroundColor Green

# Log completion
if ($osType) {
    Write-Log "$osType Debloat running in background"
}
#endregion Bloatware Cleanup

############################################################################################################
#                                           System Restore Point                                           #
#                                                                                                          #
############################################################################################################
#region System Restore
# Create a restore point
Start-VssService
Remove-RestorePointFrequencyLimit
Write-Delayed "Creating a system restore point..." -NewLine:$false

# Initialize spinner
$spinner = @('/', '-', '\', '|')
$spinnerIndex = 0
[Console]::Write($spinner[$spinnerIndex])

# Set up the job to create the restore point
$job = Start-Job -ScriptBlock { 
    Checkpoint-Computer -Description "MITS New Workstation Baseline Completed - $(Get-Date -Format 'MM-dd-yyyy HH:mm:t')" -RestorePointType "MODIFY_SETTINGS" 
}

# Display spinner while job is running (max 90 seconds)
$timeout = 90
$startTime = Get-Date
$success = $false

while (($job.State -eq 'Running') -and (((Get-Date) - $startTime).TotalSeconds -lt $timeout)) {
    Start-Sleep -Milliseconds 100
    [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
    $spinnerIndex = ($spinnerIndex + 1) % $spinner.Length
    [Console]::Write($spinner[$spinnerIndex])
}

# Check if job completed or timed out
if ($job.State -eq 'Running') {
    # Job timed out
    Stop-Job $job
    $success = $false
} else {
    # Job completed, check result
    $result = Receive-Job $job
    $success = $true
}

# Remove the job
Remove-Job $job -Force

# Clear the spinner character
[Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)

# Display result
if ($success) {
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" created successfully.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    Write-Log "System restore point created successfully"
} else {
    [Console]::ForegroundColor = [System.ConsoleColor]::Red
    [Console]::Write(" Failed to create restore point.")
    [Console]::ResetColor()
    [Console]::WriteLine()
    Write-Log "Failed to create system restore point"
}
#endregion System Restore Point

############################################################################################################
#                                        Cleanup and Finalization                                        #
#                                                                                                          #
############################################################################################################
#region Baseline Cleanup
#Start-Sleep -seconds 60
# Enable and start Windows Update Service
Write-Delayed "Enabling Windows Update Service..." -NewLine:$false
Set-Service -Name wuauserv -StartupType Manual
Start-Sleep -seconds 3
Start-Service -Name wuauserv
Start-Sleep -Seconds 5
$service = Get-Service -Name wuauserv
if ($service.Status -eq 'Running') {
    # Use a single Write-Host for both transcript and console display
    Write-Host " done." -ForegroundColor Green
    
    Write-Log "Windows Update Service enabled and started successfully."
} else {
    # Use a single Write-Host for both transcript and console display
    Write-Host " failed." -ForegroundColor Red
    
    Write-Log "Windows Update Service failed to enable and start."
}

# Installing Windows Updates
function Set-UsoSvcAutomatic {
    try {
        # Set service to Automatic
        Set-Service -Name "UsoSvc" -StartupType Automatic
        
        # Start the service
        Start-Service -Name "UsoSvc"
        
        # Verify the service status
        $service = Get-Service -Name "UsoSvc"
    }
    catch {
        Write-Error "Failed to configure UsoSvc: $($_.Exception.Message)"
    }
}
Write-Delayed "Checking for Windows Updates..." -NewLine:$false
Set-UsoSvcAutomatic
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mitsdev01/MITS/refs/heads/main/Update_Windows.ps1" -OutFile "c:\temp\update_windows.ps1"


$ProgressPreference = 'Continue'
if (Test-Path "c:\temp\update_windows.ps1") {
    $updatePath = "C:\temp\Update_Windows.ps1"
    $null = Start-Process PowerShell -ArgumentList "-NoExit", "-File", $updatePath *> $null
    Start-Sleep -seconds 3
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.SendKeys]::SendWait('%{TAB}')
    Move-ProcessWindowToTopRight -processName "Windows PowerShell" | Out-Null
    Start-Sleep -Seconds 1
    
    # Use a single Write-Host for both transcript and console display
    Write-Host " done." -ForegroundColor Green
    
    Write-Log "All available Windows updates are installed."
     
} else {
    # Use a single Write-Host for both transcript and console display
    Write-Host "Windows Update execution failed!" -ForegroundColor Red
    
    Write-Log "Windows Update execution failed!"
}


############################################################################################################
#                                            LocalAD/AzureAD Join                                          #
#                                                                                                          #
############################################################################################################
#region AD/AzureAD Join
Write-Delayed "Starting Domain/AzureAD Join Task..." -NewLine:$true
$ProgressPreference = 'SilentlyContinue'
try {
    Invoke-WebRequest -Uri "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ssl-vpn.bat" -OutFile "c:\temp\ssl-vpn.bat"
} catch {
    Write-Delayed "Failed to download SSL VPN installer: $_" -NewLine:$true -Color Red
    exit 1
}
$ProgressPreference = 'Continue'

$validChoice = $false
do {
    $choice = Read-Host -Prompt "Do you want to connect to SSL VPN? (Y/N)"
    switch ($choice) {
        "Y" {
            Connect-VPN
            $validChoice = $true
        }
        "N" {
            Write-Delayed "Skipping VPN Connection Setup..." -NewLine:$true
            $validChoice = $true
        }
        default {
            Write-Delayed "Invalid choice. Please enter Y or N." -NewLine:$true
            $validChoice = $false
        }
    }
} while (-not $validChoice)

$validChoice = $false
do {
    $choice = Read-Host -Prompt "Do you want to join a domain or Azure AD? (A for Azure AD, S for domain)"
    switch ($choice) {
        "S" {
            $username = Read-Host -Prompt "Enter the username for the domain join operation"
            $password = Read-Host -Prompt "Enter the password for the domain join operation" -AsSecureString
            $cred = New-Object System.Management.Automation.PSCredential($username, $password)
            $domain = Read-Host -Prompt "Enter the domain name for the domain join operation"
            try {
                Add-Computer -DomainName $domain -Credential $cred 
                Write-Delayed "Domain join operation completed successfully." -NewLine:$true
                $validChoice = $true
            } catch {
                Write-Delayed "Failed to join the domain." -NewLine:$true
                $validChoice = $true
            }
        }
        "A" {
            Write-Delayed "Starting Azure AD Join operation using Work or School account..." -NewLine:$true
            Start-Process "ms-settings:workplace"
            Start-Sleep -Seconds 3
            $output = dsregcmd /status | Out-String
            if ($output -match 'AzureAdJoined\s+:\s+(YES|NO)') {
                $azureAdJoinedValue = $matches[1]
            } else {
                $azureAdJoinedValue = "Not Found"
            }
            Write-Delayed "AzureADJoined: $azureAdJoinedValue" -NewLine:$true
            $validChoice = $true
        }
        default {
            Write-Delayed "Invalid choice. Please enter A or S." -NewLine:$true
            $validChoice = $false
        }
    }
} while (-not $validChoice)
#endregion AD/AzureAD Join


# Create WakeLock exit flag to stop the WakeLock script
Write-Delayed "Creating WakeLock exit flag..." -NewLine:$false
try {
    # Create the flag file to signal the WakeLock script to exit
    New-Item -Path "c:\temp\wakelock.flag" -ItemType File -Force | Out-Null
    Write-TaskComplete
    Write-Log "WakeLock flag file created to stop WakeLock script"
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    Write-Log "Error creating WakeLock exit flag: $_"
}

# Define temp files to clean up
$TempFiles = @(
    "c:\temp\MITS-Debloat.zip",
    "c:\temp\MITS-Debloat",
    "c:\temp\update_windows.ps1",
    "c:\temp\BaselineComplete.ps1",
    "C:\temp\AcroRdrDC2500120432_en_US.exe",
    "c:\temp\$env:COMPUTERNAME-baseline.txt",
    "c:\temp\ssl-vpn.bat",
    "mits-rename-complete.flag" 
)

Write-Delayed "Cleaning up temporary files..." -NewLine:$false

# Keep track of success for all deletions
$allSuccessful = $true

# Delete only specific temp files
foreach ($file in $TempFiles) {
    if (Test-Path $file) {
        try {
            if ((Get-Item $file) -is [System.IO.DirectoryInfo]) {
                # It's a directory, use -Recurse
                Remove-Item -Path $file -Recurse -Force -ErrorAction Stop
            } else {
                # It's a file
                Remove-Item -Path $file -Force -ErrorAction Stop
            }
            Write-Log "Removed temporary file/folder: $file"
        } catch {
            $allSuccessful = $false
            Write-Log "Failed to remove: $file - $($_.Exception.Message)"
        }
    }
}

# Don't remove the wakelock.flag until the very end
if (Test-Path "c:\temp\wakelock.flag") {
    Remove-Item -Path "c:\temp\wakelock.flag" -Force -ErrorAction SilentlyContinue
}

# Report success in console and log
if ($allSuccessful) {
    Write-TaskComplete
} else {
    Write-Host " completed with some errors." -ForegroundColor Yellow
}

Write-Log "Temporary file cleanup completed successfully."
#endregion Baseline Cleanup


############################################################################################################
#                                           Baseline Summary                                               #
#                                                                                                          #
############################################################################################################
#region Summary
# Display Baseline Summary
Write-Host ""
$Padding = ("=" * [System.Console]::BufferWidth)
# Visual formatting
Write-Host -ForegroundColor "Red" $Padding
Print-Middle "MITS Baseline Script Completed Successfully" "Green"
Print-Middle "Reboot recommended to finalize changes" "Yellow"
Write-Host -ForegroundColor "Red" $Padding

# Visual formatting
Write-Host -ForegroundColor "Cyan" "Logs are available at:"
Write-Host "  * $LogFile"
Write-Host "  * $TempFolder\$env:COMPUTERNAME-baseline_transcript.txt"
Invoke-WebRequest -uri "https://raw.githubusercontent.com/mitsdev01/MITS/main/BaselineComplete.ps1" -OutFile "c:\temp\BaselineComplete.ps1"
$scriptPath = "c:\temp\BaselineComplete.ps1"
Invoke-Expression "start powershell -ArgumentList '-noexit','-File $scriptPath'"
Write-Host " "
Write-Host " "
#endregion Summary

# Stopping transcript
Stop-Transcript *> $null

# Update log file with completion
Write-Log "Automated workstation baseline has completed successfully"

# Add footer to log file
$footerBorder = "=" * 80
$footer = @"
$footerBorder
                Baseline Configuration Completed Successfully
                      $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
$footerBorder
"@
Add-Content -Path $LogFile -Value $footer

Read-Host -Prompt "Press enter to exit"
Stop-Process -Id $PID -Force

