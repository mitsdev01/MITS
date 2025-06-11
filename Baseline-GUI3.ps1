############################################################################################################
#                                     MITS - New Workstation Baseline Script                               #
#                                                 Version 3.0.4                                            #
############################################################################################################
#region Synopsis
<#
.SYNOPSIS
    Provides an easy to use GUI to automate the configuration and deployment of a standardized Windows workstation environment.

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
    Version:        3.0.4
    Author:         Bill Ulrich
    Creation Date:  4/25/2025
    Requires:       Administrator privileges
                    Windows 10/11 Professional
    
.EXAMPLE
    .\Baseline-GUI.ps1
    
    Run the script with administrator privileges to execute the full baseline configuration.

.LINK
    https://github.com/mitsdev01/MITS
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Command,
    [switch]$AutoStart
)

# --- Elevation Check and Auto-Rerun as Administrator ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Script is not running as administrator. Attempting to relaunch with elevation..." -ForegroundColor Yellow
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Get-Process -Id $PID).Path
    $psi.Arguments = '"' + $MyInvocation.MyCommand.Definition + '"' +
        $(if ($Command) { " -Command '$Command'" } else { "" }) +
        $(if ($AutoStart) { " -AutoStart" } else { "" })
    $psi.Verb = 'runas'
    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    } catch {
        Write-Host "Elevation cancelled or failed. Exiting script." -ForegroundColor Red
    }
    exit
}


#region Variables & Types
# Script Version and Global Variables
$Global:ScriptVersion = "1.0.8c"
$Global:ProgressData = @{}
$Global:LogLines = New-Object System.Collections.ObjectModel.ObservableCollection[string]
$Global:TaskList = @()
$Global:TempFolder = "C:\temp"
$Global:CancelRequested = $false
$Global:SkipHashCheck = $true  # Set to true to skip hash check during development
$Global:IsMobileDevice = $false  # Will be set later based on system check
$Global:DecryptedURLs = $null
$Global:DecryptedS1Links = $null
$Global:SepPath = "$Global:TempFolder\s1t.enc"
$Global:UrlPath = "$Global:TempFolder\murls.enc"
$Global:ModuleTrackerPath = Join-Path $Global:TempFolder "modules_installed.track"
$Global:iconPath = Join-Path $Global:TempFolder "mits.ico"
$Global:SpawnedProcesses = @()
$ErrorActionPreference = "SilentlyContinue"
$WarningActionPreference = "SilentlyContinue"
# Unified logging configuration
$Global:LogConfig = @{
    LogPath = "C:\temp"  
    LogFile = "$env:COMPUTERNAME-baseline.log"
    MaxLogSize = 5MB
    MaxLogFiles = 5
    LogLevel = "INFO" # ERROR, WARNING, INFO, DEBUG
}

# Add Windows API declarations at the very beginning
$Global:WinAPICode = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public class WinAPI {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetConsoleCtrlHandler(HandlerRoutine handler, bool add);
    
    public delegate bool HandlerRoutine(CtrlTypes ctrlType);
    
    public enum CtrlTypes {
        CTRL_C_EVENT = 0,
        CTRL_BREAK_EVENT = 1,
        CTRL_CLOSE_EVENT = 2,
        CTRL_LOGOFF_EVENT = 5,
        CTRL_SHUTDOWN_EVENT = 6
    }
    
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    
    [DllImport("user32.dll")]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    
    [DllImport("user32.dll")]
    public static extern bool IsWindow(IntPtr hWnd);
    
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
    
    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentProcessId();
    
    [DllImport("user32.dll")]
    public static extern bool IsIconic(IntPtr hWnd);
    
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
    
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetWindowPos(IntPtr hWnd, int hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
    
    public const int SW_HIDE = 0;
    public const int SW_SHOW = 5;
    public const int SW_RESTORE = 9;
    public const int WM_CLOSE = 0x0010;
}

namespace Win32 {
    public class User32 {
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetWindowPos(IntPtr hWnd, int hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
    }
}

namespace Console {
    public class Window {
        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
        
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
    }
}
'@

# Only add the WinAPI type if it does not already exist
if (-not ([System.Management.Automation.PSTypeName]'WinAPI').Type) {
    Add-Type -TypeDefinition $Global:WinAPICode -ErrorAction Stop
}

# Load required assemblies
try {
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
} catch {
    Write-Error "Failed to load required assemblies: $_"
    exit 1
}




############################################################################################################
#                                             Integrity Check                                              #
#                                                                                                          #
############################################################################################################
#region Integrity Check

# Add secure password handling
$salt = "MITS-Baseline-2025"
$correctHash = "LqcMRwZUJsYz/0I4JmMd4OAjVksUA9t7knCsehQOEpWqWxyA6HjcRR5vU0VT9Bhoi4YYurBmtQPqKembVT/KiQ=="
$password = "thisisunsafe"
# Define secure hash function for password verification
function Get-SecureHash {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Password,
        [Parameter(Mandatory = $true)]
        [string]$Salt
    )
    
    $encoding = [System.Text.Encoding]::UTF8
    $bytes = $encoding.GetBytes($Password + $Salt)
    $sha512 = [System.Security.Cryptography.SHA512]::Create()
    $hash = $sha512.ComputeHash($bytes)
    $sha512.Dispose()
    return [System.Convert]::ToBase64String($hash)
}

function Get-StandardizedFileHash {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    # Read file with UTF8 encoding without BOM
    $content = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::UTF8)
    
    # Normalize all line endings to LF only
    $content = $content.Replace("`r`n", "`n").Replace("`r", "`n")
    
    # Convert to byte array with UTF8 encoding
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    
    # Calculate hash
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($bytes)
    $sha256.Dispose()
    
    # Convert to uppercase hex string
    return [BitConverter]::ToString($hashBytes).Replace("-", "")
}

function Test-ScriptIntegrity {
    param(
        [string]$ScriptPath = $PSCommandPath
    )
    
    try {
        # Check if we're updating the hash
        if ($Command -eq "Update-ScriptHash" -and $ScriptPath) {
            Write-Host "Updating script hash..." -ForegroundColor Cyan
            
            try {
                # Calculate hash using our standardized function
                $newHash = Get-StandardizedFileHash -FilePath $ScriptPath
                
                Write-Host "New hash calculated: $newHash" -ForegroundColor Yellow
                
                # Create a hash file for manual upload to Azure Blob Storage
                $hashFilePath = Join-Path (Split-Path $ScriptPath -Parent) "MITS_Baseline-GUI.hash"
                Set-Content -Path $hashFilePath -Value $newHash -Force -NoNewline
                
                Write-Host "Hash file created at: $hashFilePath" -ForegroundColor Green
                Write-Host "Please upload this file to storage blob manually through the Azure portal." -ForegroundColor Cyan
                
                exit 0
            }
            catch {
                Write-Host "Error updating script hash: $_" -ForegroundColor Red
                exit 1
            }
        }

        # Download the hash file from Azure
        $hashUrl = "https://axcientrestore.blob.core.windows.net/win11/MITS_Baseline-GUI.hash"
        $expectedHash = $null
        
        try {
            $ProgressPreference = 'SilentlyContinue'
            $expectedHash = (New-Object System.Net.WebClient).DownloadString($hashUrl).Trim()
            $ProgressPreference = 'Continue'
        }
        catch {
            throw "Failed to download hash file: $_"
        }
        
        if ([string]::IsNullOrEmpty($expectedHash)) {
            throw "Downloaded hash file is empty"
        }
        
        # Calculate current file hash
        $currentHash = Get-StandardizedFileHash -FilePath $ScriptPath
        
        # Compare hashes
        if ($currentHash -ne $expectedHash) {
            Write-Host "`n" # Add blank line
            Write-Host "WARNING: SCRIPT INTEGRITY CHECK FAILED!" -ForegroundColor Red
            Write-Host "Expected hash: $expectedHash" -ForegroundColor Cyan
            Write-Host "Current hash:  $currentHash" -ForegroundColor Yellow
            Write-Host "`nThis script may have been modified or may be corrupted!" -ForegroundColor Red
            Write-Host "`n`nEnter the override password to continue anyway, or press Cancel to exit.`n"
            
            # Create password input dialog
            $form = New-Object System.Windows.Forms.Form
            $form.Text = "Script Integrity Check Failed!"
            $form.Size = New-Object System.Drawing.Size(400,200)
            $form.StartPosition = "CenterScreen"
            $form.FormBorderStyle = "FixedDialog"
            $form.MaximizeBox = $false
            $form.MinimizeBox = $false
            $form.TopMost = $true
            $form.BackColor = [System.Drawing.Color]::FromArgb(255,255,230,230) # Light red background

            # Add a red border panel for error effect
            $borderPanel = New-Object System.Windows.Forms.Panel
            $borderPanel.BackColor = [System.Drawing.Color]::Crimson
            $borderPanel.Size = New-Object System.Drawing.Size(396, 196)
            $borderPanel.Location = New-Object System.Drawing.Point(2,2)
            $form.Controls.Add($borderPanel)

            # Place all controls on top of the border panel
            # First label: bold, centered
            $labelBold = New-Object System.Windows.Forms.Label
            $labelBold.Location = New-Object System.Drawing.Point(10, 20)
            $labelBold.Size = New-Object System.Drawing.Size(360, 20)
            $labelBold.Text = "Script integrity check failed!"
            $labelBold.Font = New-Object System.Drawing.Font($labelBold.Font, [System.Drawing.FontStyle]::Bold)
            $labelBold.BackColor = [System.Drawing.Color]::FromArgb(255,255,230,230)
            $labelBold.TextAlign = 'MiddleCenter'
            $borderPanel.Controls.Add($labelBold)

            # Second label: normal, just below the bold label
            $label = New-Object System.Windows.Forms.Label
            $label.Location = New-Object System.Drawing.Point(10, 45)
            $label.Size = New-Object System.Drawing.Size(360, 20)
            $label.Text = "Enter the bypass password to continue:"
            $label.BackColor = [System.Drawing.Color]::FromArgb(255,255,230,230)
            $label.TextAlign = 'TopLeft'
            $borderPanel.Controls.Add($label)

            # Password input field: below the labels
            $textBox = New-Object System.Windows.Forms.TextBox
            $textBox.Location = New-Object System.Drawing.Point(10, 70)
            $textBox.Size = New-Object System.Drawing.Size(360, 20)
            $textBox.PasswordChar = '*'
            $borderPanel.Controls.Add($textBox)

            $okButton = New-Object System.Windows.Forms.Button
            $okButton.Location = New-Object System.Drawing.Point(200,120)
            $okButton.Size = New-Object System.Drawing.Size(75,23)
            $okButton.Text = "OK"
            $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $borderPanel.Controls.Add($okButton)
            $form.AcceptButton = $okButton

            $cancelButton = New-Object System.Windows.Forms.Button
            $cancelButton.Location = New-Object System.Drawing.Point(290,120)
            $cancelButton.Size = New-Object System.Drawing.Size(75,23)
            $cancelButton.Text = "Cancel"
            $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
            $borderPanel.Controls.Add($cancelButton)
            $form.CancelButton = $cancelButton

            # Add error icon
            $icon = [System.Drawing.SystemIcons]::Error
            $form.Icon = $icon

            # Add keystroke monitoring
            $script:currentInput = ""
            $textBox.Add_TextChanged({
                $script:currentInput = $textBox.Text
                $attemptedHash = Get-SecureHash -Password $script:currentInput -Salt $salt
                if ($attemptedHash -eq $correctHash) {
                    $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
                    $form.Close()
                }
            })

            # Add form shown event to force focus
            $form.Add_Shown({
                $form.Activate()
                [void][WinAPI]::SetForegroundWindow($form.Handle)
                $textBox.Focus()
            })

            $form.TopMost = $true
            $result = $form.ShowDialog()

            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                $attemptedHash = Get-SecureHash -Password $textBox.Text -Salt $salt
                if ($attemptedHash -ne $correctHash) {
                    Write-Warning "Invalid bypass password"
                    return $false
                }
            } else {
                return $false
            }
        }
        
        return $true
    }
    catch {
        Write-Warning "Script integrity check failed: $_"
        return $false
    }
}

# Perform integrity check before proceeding
if (-not (Test-ScriptIntegrity)) {
    Write-Error "Script integrity check failed. Exiting."
    exit 1
}
#endregion

# Function to minimize console window
function Minimize-ConsoleWindow {
    $consolePtr = [Console.Window]::GetConsoleWindow()
    [Console.Window]::ShowWindow($consolePtr, 6)  # 6 = SW_MINIMIZE
}

Minimize-ConsoleWindow

# Download banner image
try {
    $bannerPath = "$Global:TempFolder\adv-banner.png"
    $iconPath = "$Global:TempFolder\mits.ico"
    
    # Check if either file is missing
    if (-not (Test-Path $bannerPath) -or -not (Test-Path $iconPath)) {
        $ProgressPreference = 'SilentlyContinue'
        
        # Download banner if missing
        if (-not (Test-Path $bannerPath)) {
            Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/adv-banner.png" -OutFile $bannerPath -ErrorAction Stop
        }
        
        # Download icon if missing
        if (-not (Test-Path $iconPath)) {
            Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/mits.ico" -OutFile $iconPath -ErrorAction Stop
        }
        
        $ProgressPreference = 'Continue'
        
        # Verify files exist and have content
        foreach ($file in @($bannerPath, $iconPath)) {
            if (-not (Test-Path $file)) {
                throw "Failed to download $(Split-Path $file -Leaf)"
            }
            
            $fileSize = (Get-Item $file).Length
            if ($fileSize -eq 0) {
                Remove-Item $file -Force
                throw "Downloaded $(Split-Path $file -Leaf) is empty"
            }
        }
    }
}
catch {
    Write-Warning "Failed to download resources: $_"
    # Don't exit - the GUI will still work without the resources
} 


# Force WPF to use software rendering to avoid blank window on lid-closed laptops
[System.Windows.Media.RenderOptions]::ProcessRenderMode = 'SoftwareOnly'


############################################################################################################
#                                                 Functions                                                #
#                                                                                                          #
############################################################################################################
#region Core Functions
# Unified logging function
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("ERROR", "WARNING", "INFO", "DEBUG")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsoleOutput
    )
    
    # Skip if log level is lower than configured level
    $logLevels = @{
        "ERROR" = 4
        "WARNING" = 3
        "INFO" = 2
        "DEBUG" = 1
    }
    
    if ($logLevels[$Level] -lt $logLevels[$Global:LogConfig.LogLevel]) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Add stack trace for errors
    if ($Level -eq "ERROR") {
        $stackTrace = (Get-PSCallStack | Select-Object -Skip 1 | Format-Table -HideTableHeaders | Out-String).Trim()
        $logEntry += "`nStack Trace:`n$stackTrace"
    }
    
    # Write to log file
    $logFile = Join-Path $Global:LogConfig.LogPath $Global:LogConfig.LogFile
    $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
    
    # Rotate logs if needed
    if ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -gt $Global:LogConfig.MaxLogSize) {
        $logFiles = Get-ChildItem -Path $Global:LogConfig.LogPath -Filter "baseline-gui*.log" | Sort-Object LastWriteTime -Descending
        for ($i = $logFiles.Count; $i -ge $Global:LogConfig.MaxLogFiles; $i--) {
            Remove-Item $logFiles[$i-1].FullName -Force
        }
        $newLogFile = Join-Path $Global:LogConfig.LogPath "baseline-gui_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        Rename-Item -Path $logFile -NewName (Split-Path $newLogFile -Leaf) -Force
    }
    
    # Write to console with appropriate colors
    if (-not $NoConsoleOutput) {
        switch ($Level) {
            "ERROR" { Write-Host $logEntry -ForegroundColor Red }
            "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
            "INFO" { Write-Host $logEntry -ForegroundColor White }
            "DEBUG" { Write-Host $logEntry -ForegroundColor Gray }
        }
    }
}

# Function to write to UI log and file
function Write-UILog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [System.Windows.Media.Color]$Color = [System.Windows.Media.Colors]::Black,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("ERROR", "WARNING", "INFO", "DEBUG")]
        [string]$Level = "INFO"
    )

    try {
        # Don't attempt UI updates if window is closing
        if ($Global:WindowIsClosing) {
            Write-Log $Message -Level $Level
            return
        }

        # Check if we're on the UI thread
        if (-not [System.Windows.Threading.Dispatcher]::CurrentDispatcher.CheckAccess()) {
            # If not on UI thread, use BeginInvoke instead of Invoke for better responsiveness
            $Global:Form.Dispatcher.BeginInvoke([Action]{
                Write-UILog -Message $Message -Color $Color -Level $Level
            }, [System.Windows.Threading.DispatcherPriority]::Background)
            return
        }

        # Create timestamp and log text
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logText = "[$timestamp] $Message"
        
        # Add to log lines
        $Global:LogLines.Add($logText)

        # Update UI less frequently to improve performance
        if ($Global:LogLines.Count % 5 -eq 0) {
            [System.Windows.Data.CollectionViewSource]::GetDefaultView($Global:LogLines).Refresh()
            if ($Global:LogScroller -ne $null) {
                $Global:LogScroller.ScrollToBottom()
            }
        }

        # Also write to log file
        Write-Log -Message $Message -Level $Level -NoConsoleOutput
    }
    catch {
        Write-Log "Error in Write-UILog: $_" -Level ERROR
    }
}

# Function to write to both UI and file log
function Write-DebugLog {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    # Write to UI log if possible
    try {
        Write-UILog $Message -Color $Color
    } catch {
        # UI might be closed, ignore the error
    }
    
    # Always write to console and file
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logMessage = "[$timestamp] $Message"
    Write-Host $logMessage
    
    $logPath = Join-Path $Global:TempFolder 'window-debug.log'
    try {
        Add-Content -Path $logPath -Value $logMessage -Force
    } catch {
        Write-Host "Failed to write to log file: $_"
    }
}

# Function to find Windows Terminal window
function Find-WindowsTerminal {
    $terminalHwnd = [IntPtr]::Zero
    $windowTitle = New-Object System.Text.StringBuilder 256
    $className = New-Object System.Text.StringBuilder 256
    
    #Write-DebugLog "Searching for Windows Terminal window..." -Color "Cyan"
    
    # Store all found windows for debugging
    $foundWindows = @()
    
    $callback = [WinAPI+EnumWindowsProc]{
        param([IntPtr] $hwnd, [IntPtr] $lparam)
        
        [void][WinAPI]::GetWindowText($hwnd, $windowTitle, $windowTitle.Capacity)
        [void][WinAPI]::GetClassName($hwnd, $className, $className.Capacity)
        
        $title = $windowTitle.ToString()
        $class = $className.ToString()
        
        # Log all windows we find for debugging
        if (-not [string]::IsNullOrWhiteSpace($title)) {
            $foundWindows += "Window - Class: $class, Title: $title"
            #Write-DebugLog "Found window - Class: $class, Title: $title" -Color "Cyan"
        }
        
        # Look for Windows Terminal window
        if ($class -eq "CASCADIA_HOSTING_WINDOW_CLASS") {
            #Write-DebugLog "Found Windows Terminal window - Class: $class, Title: $title" -Color "Green"
            $script:terminalHwnd = $hwnd
            return $false  # Stop enumeration
        }
        
        # Fallback to PowerShell window if no Windows Terminal found
        if ($class -eq "ConsoleWindowClass" -and $title -like "*Windows PowerShell*") {
            #Write-DebugLog "Found PowerShell window - Class: $class, Title: $title" -Color "Green"
            $script:terminalHwnd = $hwnd
            # Continue enumeration in case we find Windows Terminal
        }
        
        return $true  # Continue enumeration
    }
    
    [void][WinAPI]::EnumWindows($callback, [IntPtr]::Zero)
    
    if ($terminalHwnd -eq [IntPtr]::Zero) {
        #Write-DebugLog "No Windows Terminal window found. Found windows:" -Color "Yellow"
        foreach ($window in $foundWindows) {
            #Write-DebugLog $window -Color "Yellow"
        }
    }
    
    return $terminalHwnd
}

# Function to restore console window
function Show-ConsoleWindow {
    #Write-DebugLog "Attempting to restore terminal window..." -Color "Cyan"
    
    # Use stored handle if available, otherwise find the window
    $terminalWindow = if ($Global:TerminalWindowHandle -ne $null) { 
        #Write-DebugLog "Using stored terminal window handle" -Color "Cyan"
        $Global:TerminalWindowHandle 
    } else { 
        #Write-DebugLog "No stored handle, searching for window" -Color "Yellow"
        Find-WindowsTerminal 
    }
    
    if ($terminalWindow -ne [IntPtr]::Zero) {
        #Write-DebugLog "Found terminal window, checking state..." -Color "Cyan"
        
        # Try multiple times to restore the window
        $maxAttempts = 3
        $attempt = 1
        $success = $false
        
        while (-not $success -and $attempt -le $maxAttempts) {
            #Write-DebugLog "Restore attempt $attempt of $maxAttempts" -Color "Cyan"
            
            # First try to restore from minimized state
            if ([WinAPI]::IsIconic($terminalWindow)) {
                #Write-DebugLog "Window is minimized, restoring..." -Color "Cyan"
                $success = [WinAPI]::ShowWindow($terminalWindow, [WinAPI]::SW_RESTORE)
            }
            
            # Then ensure it's visible
            if (-not $success) {
                #Write-DebugLog "Trying to show window..." -Color "Cyan"
                $success = [WinAPI]::ShowWindow($terminalWindow, [WinAPI]::SW_SHOW)
            }
            
            if ($success) {
                #Write-DebugLog "Show/Restore operation succeeded" -Color "Green"
                [WinAPI]::SetForegroundWindow($terminalWindow)
                Start-Sleep -Milliseconds 250  # Give Windows more time to restore
            } else {
                #Write-DebugLog "Show/Restore operation failed, retrying..." -Color "Yellow"
                Start-Sleep -Milliseconds 500  # Longer delay between attempts
            }
            
            $attempt++
        }
        
        if (-not $success) {
            #Write-DebugLog "Failed to restore window after $maxAttempts attempts" -Color "Red"
        }
    } else {
        #Write-DebugLog "No terminal window handle found to restore" -Color "Yellow"
    }
}

# Function to terminate all related PowerShell processes
function Stop-RelatedPowerShellProcesses {
    try {
        $currentPid = $PID
        $currentProcess = Get-Process -Id $currentPid
        $parentPid = (Get-CimInstance Win32_Process -Filter "ProcessId = $currentPid").ParentProcessId

        # Get all powershell.exe processes
        $psProcesses = Get-Process -Name powershell -ErrorAction SilentlyContinue

        foreach ($psProc in $psProcesses) {
            $psParentPid = (Get-CimInstance Win32_Process -Filter "ProcessId = $($psProc.Id)").ParentProcessId
            if (
                $psProc.Id -eq $currentPid -or
                $psParentPid -eq $currentPid -or
                $psProc.Id -eq $parentPid
            ) {
                try {
                    $psProc.Kill()
                } catch {}
            }
        }
    } catch {}
}

# Define the cleanup function
function Global:Remove-SensitiveFiles {
    param([switch]$Force)
    
    Write-Log "Close Terminal window to release job monitors!" -Level WARNING
    
    # Force close WPF window if it exists
    if ($Global:Form -and $Force) {
        try {
            $Global:Form.Dispatcher.Invoke([Action]{
                $Global:Form.Close()
            }, [System.Windows.Threading.DispatcherPriority]::Send)
        }
        catch {
            Write-Log "Error closing WPF window: $_" -Level ERROR
        }
    }
    
    # Delete sensitive files with retry logic
    $files = @(
        "c:\temp\s1t.enc",
        "c:\temp\murls.enc",
        "c:\temp\adv-banner.png",
        "c:\temp\mits.ico"
    )
    foreach ($file in $files) {
        if (Test-Path $file) {
            $retryCount = 0
            $maxRetries = 3
            $deleted = $false
            
            while (-not $deleted -and $retryCount -lt $maxRetries) {
                try {
                    Remove-Item -Path $file -Force -ErrorAction Stop
                    Write-Log "Successfully deleted file: $file" -Level INFO
                    $deleted = $true
                }
                catch {
                    $retryCount++
                    if ($retryCount -lt $maxRetries) {
                        Write-Log "Failed to delete $file (attempt $retryCount of $maxRetries). Retrying..." -Level WARNING
                        Start-Sleep -Seconds 1
                    }
                    else {
                        Write-Log "Failed to delete $file after $maxRetries attempts: $_" -Level ERROR
                    }
                }
            }
        }
    }
}

# Function to track spawned processes
function Start-TrackedProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$ArgumentList = @(),
        [switch]$Wait,
        [switch]$NoNewWindow,
        [switch]$PassThru,
        [string]$Verb
    )
    try {
        # Always start with a fresh hashtable
        $processParams = @{}
        $processParams['FilePath'] = $FilePath
        $processParams['PassThru'] = $true

        if ($ArgumentList -and $ArgumentList.Count -gt 0 -and -not ($ArgumentList -contains $null)) {
            if (-not $processParams.ContainsKey('ArgumentList')) {
                $processParams['ArgumentList'] = $ArgumentList
            }
        }
        if ($NoNewWindow) {
            if (-not $processParams.ContainsKey('NoNewWindow')) {
                $processParams['NoNewWindow'] = $true
            }
        }
        if ($Verb) {
            if (-not $processParams.ContainsKey('Verb')) {
                $processParams['Verb'] = $Verb
            }
        }
        $process = Start-Process @processParams

        if ($process) {
            # Store process info in tracking array
            $Global:SpawnedProcesses += @{
                Id = $process.Id
                Name = $process.ProcessName
                StartTime = Get-Date
                FilePath = $FilePath  # Use FilePath instead of Path to avoid confusion
            }

            # Handle Wait parameter if specified
            if ($Wait) {
                $process | Wait-Process
            }

            # Return process object if PassThru is specified
            if ($PassThru) {
                return $process
            }
        }
    }
    catch {
        Write-UILog "Error starting tracked process: $_" -Color "Red"
        throw
    }
}

# Function to cleanup all spawned processes
function Stop-AllTrackedProcesses {
    Write-UILog "Cleaning up spawned processes..." -Color "Cyan"
    
    foreach ($procInfo in $Global:SpawnedProcesses) {
        try {
            $process = Get-Process -Id $procInfo.Id -ErrorAction SilentlyContinue
            if ($process) {
                Write-UILog "Stopping process: $($procInfo.Name) (ID: $($procInfo.Id))" -Color "Cyan"
                
                # Try graceful shutdown first
                if (-not $process.HasExited) {
                    $process.CloseMainWindow() | Out-Null
                    if (-not $process.WaitForExit(3000)) {
                        # Force kill if graceful shutdown fails
                        $process | Stop-Process -Force
                    }
                }
            }
        }
        catch {
            Write-UILog "Error stopping process $($procInfo.Name): $_" -Color "Red"
        }
    }
    
    # Clear the tracked processes array
    $Global:SpawnedProcesses = @()
}

# Function to check required modules
function Check-RequiredModules {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    
    try {
        # Check for tracker file
        if (Test-Path $Global:ModuleTrackerPath) {
            Write-UILog "Module installation tracker found - skipping module check..." -Color "Green"
            Update-Progress -Completed $TaskNumber -Total $TotalTasks -Status "Module check skipped (previously completed)"
            return $true
        }

        Update-Progress -Completed ($TaskNumber - 1) -Total $TotalTasks -Status "Retrieving module check script..."
        Write-UILog "Checking required modules..."
        
        # Get the URL from decrypted URLs
        $moduleUrl = Get-DecryptedURL -Key 'CheckModules'
        if (-not $moduleUrl) {
            throw "Failed to get module check URL"
        }
        
        # First try to get the script content
        try {
            $scriptContent = Invoke-RestMethod -Uri $moduleUrl -TimeoutSec 120
            Write-UILog "Module check script retrieved successfully"
            Write-UILog "Script content length: $($scriptContent.Length) characters"
        }
        catch {
            throw "Failed to download module check script: $_"
        }
        
        # Execute the script directly instead of using a job
        Write-UILog "Executing module check script..."
        try {
            # Create a temporary file for the script
            $tempScriptPath = Join-Path $Global:TempFolder "ModuleCheck_$(Get-Random).ps1"
            $scriptContent | Out-File -FilePath $tempScriptPath -Encoding UTF8
            
            Write-UILog "Starting module installation process..."
            
            # Run the script and capture output
            $processOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tempScriptPath *>&1
            
            # Log the output
            if ($processOutput) {
                foreach ($line in $processOutput) {
                    if ($line -is [System.Management.Automation.ErrorRecord]) {
                        Write-UILog $line.Exception.Message -Color "Red"
                    } else {
                        Write-UILog $line
                    }
                }
            }
            
            # Clean up
            Remove-Item -Path $tempScriptPath -Force -ErrorAction SilentlyContinue
            
            # Verify required modules are installed
            $requiredModules = @('PowerShellGet', 'PackageManagement')
            foreach ($module in $requiredModules) {
                Write-UILog "Verifying $module installation..."
                $moduleCheck = Get-Module -ListAvailable -Name $module -ErrorAction SilentlyContinue
                if (-not $moduleCheck) {
                    throw "Required module $module is not installed after installation attempt"
                }
                Write-UILog "Verified $module is installed" -Color "Green"
            }
            
            # Create tracker file after successful installation
            try {
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $content = @"
Modules installed successfully on $timestamp
Required modules:
- PowerShellGet
- PackageManagement
"@
                Set-Content -Path $Global:ModuleTrackerPath -Value $content -Force
                Write-UILog "Created module installation tracker file" -Color "Green"
            }
            catch {
                Write-UILog "Warning: Failed to create module tracker file: $_" -Color "Yellow"
                # Continue anyway since modules are installed
            }
            
            Write-UILog "Module check completed successfully" -Color "Green"
            Update-Progress -Completed $TaskNumber -Total $TotalTasks -Status "Module check completed"
            return $true
        }
        catch {
            Write-UILog "Error executing module check script: $($_.Exception.Message)" -Color "Red"
            Write-UILog "Stack trace: $($_.ScriptStackTrace)" -Color "Red"
            throw
        }
    }
    catch {
        Write-UILog "Module check failed: $($_.Exception.Message)" -Color "Red"
        if ($_.ScriptStackTrace) {
            Write-UILog "Stack trace: $($_.ScriptStackTrace)" -Color "Red"
        }
        return $false
    }
}

# Function to create system restore point
function Create-RestorePoint {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    
    try {
        Write-UILog "Starting system restore point creation..." -Color "Cyan"
        Update-Progress -Completed ($TaskNumber - 1) -Total $TotalTasks -Status "Creating system restore point..."

        # Set progress bar to indeterminate mode removed - handled by Start-Baseline

        # Remove restore point frequency limit by modifying registry
        Write-UILog "Removing restore point frequency limit..." -Color "Cyan"
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
        
        try {
            # Backup current values
            $originalSysRestoreConfig = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            
            # Disable restore point frequency limit
            Set-ItemProperty -Path $regPath -Name "SystemRestorePointCreationFrequency" -Value 0 -Type DWord -Force
            Write-UILog "Successfully disabled restore point frequency limit" -Color "Green"
        }
        catch {
            Write-UILog "Warning: Could not modify restore point frequency limit: $_" -Color "Yellow"
        }

        # Get initial restore points for comparison
        $initialPoints = Get-ComputerRestorePoint | Select-Object -Last 1
        Write-UILog "Getting initial restore point state..." -Color "Cyan"

        # Enable System Restore if not already enabled
        Write-UILog "Ensuring System Restore is enabled..." -Color "Cyan"
        try {
            $srService = Get-Service -Name "VSS" -ErrorAction Stop
            if ($srService.Status -ne "Running") {
                Start-Service -Name "VSS" -ErrorAction Stop
                Write-UILog "Started Volume Shadow Copy Service" -Color "Green"
            }
            
            Enable-ComputerRestore -Drive "C:\" -Confirm:$false -ErrorAction Stop
            Write-UILog "System Restore enabled successfully" -Color "Green"
        }
        catch {
            Write-UILog "Warning: Error configuring System Restore: $_" -Color "Yellow"
        }

        Start-Sleep -Seconds 2

        Write-UILog "Creating system restore point..." -Color "Cyan"

        # Set up the job to create the restore point
        $job = Start-Job -ScriptBlock { 
            $description = "MITS New Workstation Baseline - $(Get-Date -Format 'MM-dd-yyyy HH:mm')"
            
            # Try using WMI first as it's often more reliable
            try {
                $sr = Get-WmiObject -Namespace "root\default" -Class "SystemRestore" -ErrorAction Stop
                $result = $sr.CreateRestorePoint($description, 100, 7)
                return @{
                    Method = "WMI"
                    Success = ($result.ReturnValue -eq 0)
                    ReturnValue = $result.ReturnValue
                }
            }
            catch {
                # Fall back to Checkpoint-Computer if WMI method fails
                try {
                    $result = Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS"
                    return @{
                        Method = "Checkpoint"
                        Success = $result
                        ReturnValue = if ($result) { 0 } else { 1 }
                    }
                }
                catch {
                    return @{
                        Method = "Failed"
                        Success = $false
                        Error = $_.Exception.Message
                    }
                }
            }
        }

        # Wait for job completion with timeout
        $timeout = 90
        $startTime = Get-Date
        $success = $false

        while (($job.State -eq 'Running') -and (((Get-Date) - $startTime).TotalSeconds -lt $timeout)) {
            Start-Sleep -Milliseconds 100
            
            # Update the status with elapsed time
            $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds)
            $Global:Form.Dispatcher.Invoke([Action]{
                $Global:CurrentTaskText.Text = "Creating system restore point... (${elapsed}s)"
                 # Process UI events to keep indeterminate animation running
                [System.Windows.Forms.Application]::DoEvents()
            })
        }

        # Check job result
        if ($job.State -eq 'Running') {
            Write-UILog "Restore point creation job timed out after $timeout seconds" -Color "Red"
            Stop-Job $job
            $success = $false
        } else {
            $result = Receive-Job $job
            Write-UILog "Job completed using method: $($result.Method)" -Color "Cyan"
            $success = $result.Success
            
            if (-not $success) {
                Write-UILog "Job reported failure with return value: $($result.ReturnValue)" -Color "Red"
                if ($result.Error) {
                    Write-UILog "Error details: $($result.Error)" -Color "Red"
                }
            }
        }

        # Remove the job
        Remove-Job $job -Force

        # Try to restore original frequency limit if we modified it
        if ($originalSysRestoreConfig) {
            try {
                $originalFreq = $originalSysRestoreConfig.SystemRestorePointCreationFrequency
                Set-ItemProperty -Path $regPath -Name "SystemRestorePointCreationFrequency" -Value $originalFreq -Type DWord -Force
            }
            catch {
                Write-UILog "Warning: Could not restore original frequency limit: $_" -Color "Yellow"
            }
        }

        # Reset progress bar to normal mode removed - handled by Start-Baseline

        # Verify restore point was created by checking multiple times
        Write-UILog "Verifying restore point creation..." -Color "Cyan"
        $maxAttempts = 6
        $attempt = 0
        $verificationSuccess = $false

        while ($attempt -lt $maxAttempts) {
            $attempt++
            Start-Sleep -Seconds 5  # Wait between checks
            
            try {
                $latestPoint = Get-ComputerRestorePoint | Select-Object -Last 1
                
                if ($latestPoint -and 
                    ($initialPoints -eq $null -or 
                     $latestPoint.SequenceNumber -gt $initialPoints.SequenceNumber)) {
                    $verificationSuccess = $true
                    Write-UILog "Verified new restore point creation (Attempt $attempt)" -Color "Green"
                    break
                }
                
                Write-UILog "Verification attempt $attempt of $maxAttempts - Waiting for restore point to appear..." -Color "Yellow"
            }
            catch {
                Write-UILog "Error during verification attempt $attempt`: $_" -Color "Yellow"
            }
            # Process UI events during sleep
            [System.Windows.Forms.Application]::DoEvents()
        }

        if ($verificationSuccess -or $success) {
            Write-UILog "System restore point created successfully" -Color "Green"
            Update-Progress -Completed $TaskNumber -Total $TotalTasks -Status "System restore point created"
            return $true
        }
        else {
            throw "Failed to verify restore point creation after $maxAttempts attempts"
        }
    }
    catch {
        Write-UILog "Error creating system restore point: $_" -Color "Red"
        Write-UILog "Stack trace: $($_.ScriptStackTrace)" -Color "Red"
        
        # Reset progress bar to normal mode removed - handled by Start-Baseline
        
        return $false
    }
}

# Function to decrypt files using AES
function Decrypt-SoftwareURLs {
  param (
      [string]$FilePath = "$Global:TempFolder\murls.enc", # Default to murls.enc
      [switch]$ShowDebug
  )
  
  try {
      # Create a fixed encryption key (32 bytes for AES-256)
      $key = [byte[]]@(
          0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
          0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
          0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
          0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
      )

      # Read the encrypted file
      if (-not (Test-Path $FilePath)) {
          throw "Encrypted file not found: $FilePath"
      }

      $encryptedData = [System.IO.File]::ReadAllBytes($FilePath)

      # Extract IV (first 16 bytes)
      $iv = $encryptedData[0..15]

      # Extract encrypted data (remaining bytes)
      $encryptedBytes = $encryptedData[16..($encryptedData.Length - 1)]

      # Create AES object
      $aes = [System.Security.Cryptography.Aes]::Create()
      $aes.Key = $key
      $aes.IV = $iv
      $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
      $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

      try {
          # Create decryptor
          $decryptor = $aes.CreateDecryptor()
          
          # Decrypt the data
          $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
          
          # Convert bytes to string
          $json = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
          
          # Convert JSON to PowerShell object
          $result = $json | ConvertFrom-Json

          return $result
      }
      finally {
          if ($decryptor) { $decryptor.Dispose() }
          if ($aes) { $aes.Dispose() }
      }
  }
  catch {
      Write-UILog "Failed to decrypt file $FilePath : $_" -Color "Red"
      return $null
  }
}

# Function to decrypt SentinelOne links file using AES
function Decrypt-SentinelOneLinks {
  param (
      [string]$FilePath = "$Global:TempFolder\s1t.enc", # Default to SEPLinks.enc
      [switch]$ShowDebug
  )

  try {
      # Create a fixed encryption key (32 bytes for AES-256) - Ensure this matches the encryption key
      $key = [byte[]]@(
          0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
          0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
          0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
          0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
      )

      # Read the encrypted file
      if (-not (Test-Path $FilePath)) {
          throw "Encrypted SentinelOne links file not found: $FilePath"
      }

      $encryptedData = [System.IO.File]::ReadAllBytes($FilePath)

      # Extract IV (first 16 bytes)
      $iv = $encryptedData[0..15]

      # Extract encrypted data (remaining bytes)
      $encryptedBytes = $encryptedData[16..($encryptedData.Length - 1)]

      # Create AES object
      $aes = [System.Security.Cryptography.Aes]::Create()
      $aes.Key = $key
      $aes.IV = $iv
      $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
      $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

      try {
          # Create decryptor
          $decryptor = $aes.CreateDecryptor()
          
          # Decrypt the data
          $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
          
          # Convert bytes to string
          $json = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
          
          # Convert JSON to PowerShell object
          $result = $json | ConvertFrom-Json

          return $result
      }
      finally {
          if ($decryptor) { $decryptor.Dispose() }
          if ($aes) { $aes.Dispose() }
      }
  }
  catch {
      Write-UILog "Failed to decrypt SentinelOne links file $FilePath : $_" -Color "Red"
      return $null
  }
}

function Decrypt-s1tLinks {
    param (
        [string]$InputFile = "c:\temp\s1t.enc"
    )

    try {
        # Check if file exists
        if (-not (Test-Path $InputFile)) {
            Write-Host "File not found: $InputFile" -ForegroundColor Red
            return
        }

        # Display file info
        $fileInfo = Get-Item $InputFile
        #Write-Host "File: $InputFile" -ForegroundColor Cyan
        #Write-Host "Size: $($fileInfo.Length) bytes" -ForegroundColor Cyan
        #Write-Host "Last Modified: $($fileInfo.LastWriteTime)" -ForegroundColor Cyan

        # Read the encrypted file
        $encryptedData = [System.IO.File]::ReadAllBytes($InputFile)
        #Write-Host "Read $($encryptedData.Length) bytes of encrypted data" -ForegroundColor Yellow

        # Display first 32 bytes for debugging
        #Write-Host "First 32 bytes of encrypted data:" -ForegroundColor Yellow
        #for ($i = 0; $i -lt [Math]::Min(32, $encryptedData.Length); $i++) {
        #    Write-Host -NoNewline "$($encryptedData[$i].ToString('X2')) "
        #    if (($i + 1) % 16 -eq 0) { Write-Host "" }
        #}
        #Write-Host ""

        # Extract IV (first 16 bytes)
        $iv = $encryptedData[0..15]
        #Write-Host "Extracted IV:" -ForegroundColor Yellow
        #$iv | ForEach-Object { Write-Host -NoNewline "$($_.ToString('X2')) " }
        #Write-Host ""

        # Extract encrypted data (remaining bytes)
        $encryptedBytes = $encryptedData[16..($encryptedData.Length - 1)]
        #Write-Host "Extracted $($encryptedBytes.Length) bytes of actual encrypted data" -ForegroundColor Yellow

        # Create a fixed encryption key (32 bytes for AES-256)
        $key = [byte[]]@(
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
        )

        # Display decryption key
        #Write-Host "Decryption Key:" -ForegroundColor Yellow
        #$key | ForEach-Object { Write-Host -NoNewline "$($_.ToString('X2')) " }
        #Write-Host ""

        # Create AES object
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        try {
            # Create decryptor
            $decryptor = $aes.CreateDecryptor()
            
            # Decrypt the data
            #Write-Host "Attempting to decrypt data..." -ForegroundColor Yellow
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
            #Write-Host "Successfully decrypted $($decryptedBytes.Length) bytes" -ForegroundColor Green
            
            # Convert bytes to string
            $json = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
            #Write-Host "Decrypted JSON:" -ForegroundColor Green
            #Write-Host $json
            
            # Convert JSON to PowerShell object
            $installerLinks = $json | ConvertFrom-Json
            #Write-Host "Successfully converted JSON to object" -ForegroundColor Green
            
            # Display object type and properties
            #Write-Host "Object Type: $($installerLinks.GetType().FullName)" -ForegroundColor Cyan
            #Write-Host "Properties:" -ForegroundColor Cyan
            $installerLinks.PSObject.Properties | ForEach-Object {
                #Write-Host "  $($_.Name) : $($_.Value)"
            }
            
            return $installerLinks
        }
        finally {
            if ($decryptor) { $decryptor.Dispose() }
            if ($aes) { $aes.Dispose() }
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Exception details: $($_)" -ForegroundColor Red
    }
}

# Function to safely get URL from decrypted data
function Get-DecryptedURL {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Key,
        
        [Parameter(Mandatory = $false)]
        [PSObject]$DecryptedObject = $Global:DecryptedURLs
    )
    
    try {
        #Write-UILog "Attempting to get URL for key: $Key" -Color "Cyan"
        
        if ($null -eq $DecryptedObject) {
            Write-UILog "ERROR: DecryptedURLs is null. URLs have not been initialized." -Color "Red"
            throw "DecryptedURLs is null. URLs have not been initialized."
        }
        
        if ($DecryptedObject.PSObject.Properties[$Key]) {
            #Write-UILog "Successfully retrieved URL for key: $Key" -Color "Green"
            return $DecryptedObject.$Key
        }
        
        Write-UILog "Key '$Key' not found in decrypted URLs" -Color "Red"
        return $null
    }
    catch {
        Write-UILog "Error retrieving URL for key '$Key': $_" -Color "Red"
        throw "Error retrieving URL for key '$Key': $_"
    }
}

# Function to get client-specific SentinelOne URL
function Get-SentinelOneClientURL {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ClientName,
        
        [Parameter(Mandatory = $false)]
        [object]$SentinelOneLinksData = $Global:DecryptedS1Links
    )
    
    try {
        if ($null -eq $SentinelOneLinksData) {
            Write-UILog "SentinelOne Links data is null. Cannot retrieve URL for '$ClientName'" -Color "Red"
            return $null
        }

        # Access the URL directly using the client name as the key
        # Use PSObject.Properties for robust checking on PSCustomObject
        $prop = $SentinelOneLinksData.PSObject.Properties[$ClientName]
        if ($null -eq $prop) {
            Write-UILog "Client '$ClientName' not found in decrypted SentinelOne Links data" -Color "Red"
            # Try to fall back to Default if available
            $defaultProp = $SentinelOneLinksData.PSObject.Properties["Default"]
            if ($null -ne $defaultProp) {
                Write-UILog "Using Default SentinelOne URL instead" -Color "Yellow"
                return $defaultProp.Value
            }
            return $null
        }

        # Return the value of the property
        return $prop.Value
    }
    catch {
        Write-UILog "Error retrieving SentinelOne URL for client '$ClientName': $_" -Color "Red"
        return $null
    }
}

# Function to process and validate all URLs
function Initialize-URLs {
    try {
        Write-Log "Starting URL initialization..." -Level INFO
        Write-Log "Temp folder path: $Global:TempFolder" -Level DEBUG
        
        # Run the heavy operations in a background job
        $job = Start-Job -ScriptBlock {
            param($TempFolder)
            
            # Validate paths before trying to decrypt
            $urlsPath = "$TempFolder\murls.enc"
            $s1Path = "$TempFolder\s1t.enc"
            
            # Download files if needed
            if (-not (Test-Path $urlsPath)) {
                $ProgressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/murls.enc" -OutFile $urlsPath
                $ProgressPreference = 'Continue'
            }
            
            if (-not (Test-Path $s1Path)) {
                throw "SentinelOne Links file not found at: $s1Path"
            }
            
            # Return paths for verification
            return @{
                UrlsPath = $urlsPath
                S1Path = $s1Path
            }
        } -ArgumentList $Global:TempFolder
        
        # Wait for job completion with timeout
        $timeout = 30
        $completed = $job | Wait-Job -Timeout $timeout
        
        if (-not $completed) {
            Stop-Job $job
            throw "URL initialization timed out after $timeout seconds"
        }
        
        $result = Receive-Job $job
        Remove-Job $job
        
        if (-not $result) {
            throw "Failed to initialize URL files"
        }
        
        # Now decrypt the files
        Write-Log "Decrypting configuration files..." -Level INFO
        $Global:DecryptedURLs = Decrypt-SoftwareURLs -FilePath $result.UrlsPath
        if ($null -eq $Global:DecryptedURLs) {
            throw "Failed to decrypt software URLs"
        }
        
        $Global:DecryptedS1Links = Decrypt-s1tLinks -FilePath $result.S1Path
        if ($null -eq $Global:DecryptedS1Links) {
            throw "Failed to decrypt SentinelOne links"
        }
        
        Write-Log "Initialization completed successfully" -Level INFO
        return $true
    }
    catch {
        Write-Log "Failed to process configuration files: $_" -Level ERROR
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level DEBUG
        [System.Windows.MessageBox]::Show(
            "Failed to process configuration files.`n`nError: $_",
            "Configuration Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
        return $false
    }
}

# Function to get system information
function Get-SystemInfo {
  # Get Computer Name
  $Global:ComputerNameText.Text = $env:COMPUTERNAME
  
  # Get OS Info
  $osInfo = Get-WmiObject -Class Win32_OperatingSystem
  $Global:OSNameText.Text = $osInfo.Caption
  $Global:OSVersionText.Text = "$($osInfo.Version) (Build $($osInfo.BuildNumber))"
  
  # Get Processor Info
  $processorInfo = Get-WmiObject -Class Win32_Processor
  $Global:ProcessorText.Text = "$($processorInfo.Name)"
  
  # Get Memory Info
  $totalMemory = [Math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 2)
  $Global:MemoryText.Text = "$totalMemory GB"
  
  # Get System Drive Info
  $systemDrive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
  $freeSpace = [Math]::Round($systemDrive.FreeSpace / 1GB, 2)
  $totalSpace = [Math]::Round($systemDrive.Size / 1GB, 2)
  $freePercentage = [Math]::Round(($systemDrive.FreeSpace / $systemDrive.Size) * 100, 0)
  $usedPercentage = 100 - $freePercentage
  $Global:SystemDriveText.Text = "$($env:SystemDrive): $freeSpace GB free of $totalSpace GB"
  $Global:DriveSpaceBar.Value = $usedPercentage
  $Global:FreeSpaceText.Text = "Free Space: $freePercentage%"
  
  # Get Last Boot Time and Uptime
  $bootTime = $osInfo.ConvertToDateTime($osInfo.LastBootUpTime)
  $Global:LastBootText.Text = $bootTime.ToString("yyyy-MM-dd HH:mm:ss")
  
  $uptime = (Get-Date) - $bootTime
  $uptimeText = "$($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"
  $Global:UptimeText.Text = $uptimeText

  # Get memory usage
  $osInfo = Get-WmiObject -Class Win32_OperatingSystem
  $totalMemory = [math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 2)
  $freeMemory = [math]::Round($osInfo.FreePhysicalMemory / 1MB, 2)
  $usedMemory = $totalMemory - $freeMemory
  $usedPercent = [math]::Round(($usedMemory / $totalMemory) * 100, 0)
  $Global:MemoryUsageBar.Value = $usedPercent
  $Global:MemoryUsageText.Text = "$usedPercent% used ($usedMemory GB / $totalMemory GB)"
}

# Function to check if the OS is Windows 11
function Is-Windows11 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption
    # Check for Windows 11
    return $osVersion -ge "10.0.22000" -and $osProduct -like "*Windows 11*"
}

# Function to check if the OS is Windows 10
function Is-Windows10 {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osProduct = $osInfo.Caption
    # Check for Windows 10
    return $osVersion -lt "10.0.22000" -and $osProduct -like "*Windows 10*"
}

# Function to install Adobe Reader
function Install-AdobeReader {
    param (
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    
    Write-UILog "Starting Adobe Reader installation process..."
    #Write-UILog "Validating temp folder: $Global:TempFolder"

    # Validate temp folder
    if (-not $Global:TempFolder) {
        Write-UILog "ERROR: Temp folder path is null"
        throw "Temp folder path is null. Global temp folder not initialized."
    }

    if (-not (Test-Path $Global:TempFolder)) {
        Write-UILog "Temp folder does not exist. Attempting to create it..."
        try {
            New-Item -Path $Global:TempFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-UILog "Successfully created temp folder at: $Global:TempFolder"
        }
        catch {
            Write-UILog "ERROR: Failed to create temp folder: $_"
            throw "Failed to create temp folder: $_"
        }
    }

    Write-Log "Using temp folder: $Global:TempFolder" -Level DEBUG

    # Initialize paths
    $ReaderPath = Join-Path $Global:TempFolder "AcroRdrDC2500120432_en_US.exe"
    Write-Log "Adobe Reader installer path will be: $ReaderPath" -Level DEBUG

    # Check for existing installation
    Write-Log "Checking for existing Adobe Reader installation..." -Level INFO
    $possiblePaths = @(
        "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
        "${env:ProgramFiles}\Adobe\Acrobat Reader DC\Reader\AcroRd64.exe",
        "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
        "${env:ProgramFiles}\Adobe\Acrobat DC\Acrobat\Acrobat.exe"
    )

    $acrobatInstalled = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*Adobe Acrobat*" }

    $installedPath = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($installedPath -and $acrobatInstalled) {
        #$version = $acrobatInstalled.DisplayVersion
        #$name = $acrobatInstalled.DisplayName
        Write-Log "Adobe Reader (Installed)" -Level INFO
        return $true
    }

    Write-Log "Adobe Reader is not installed. Proceeding with installation..." -Level INFO
    # Only update progress if we have valid task numbers
    if ($TotalTasks -gt 0) {
        Update-Progress -Status "Installing Adobe Reader..." -PercentComplete (($TaskNumber / $TotalTasks) * 100)
    } else {
        Update-Progress -Status "Installing Adobe Reader..."
    }

    try {
        # Get encrypted URL
        Write-Log "Retrieving Adobe Reader download URL..." -Level INFO
        $url = Get-DecryptedURL -Key 'AdobeURL'
        if ([string]::IsNullOrEmpty($url)) {
            Write-Log "ERROR: Failed to get Adobe Reader download URL" -Level ERROR
            throw "Adobe Reader download URL is null or empty"
        }
        Write-Log "Successfully retrieved download URL" -Level DEBUG

        # Get the file size first
        Write-Log "Getting installer file size..." -Level INFO
        $response = Invoke-WebRequest -Uri $url -Method Head -ErrorAction Stop
        $fileSize = $response.Headers['Content-Length']
        Write-Log "Expected installer size: $fileSize bytes" -Level DEBUG

        # Download installer
        Write-Log "Downloading Adobe Reader installer..." -Level INFO
        try {
            $ProgressPreference = 'SilentlyContinue'
            $startTime = Get-Date
            Invoke-WebRequest -Uri $url -OutFile $ReaderPath -UseBasicParsing
            $downloadDuration = (Get-Date) - $startTime
            $ProgressPreference = 'Continue'
            Write-Log "Download completed in $($downloadDuration.TotalSeconds) seconds" -Level INFO
        }
        catch {
            Write-Log "ERROR: Failed to download Adobe Reader installer: $_" -Level ERROR
            Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level DEBUG
            throw "Failed to download Adobe Reader installer: $_"
        }

        if (-not (Test-Path $ReaderPath)) {
            Write-Log "ERROR: Adobe Reader installer not found at expected path after download" -Level ERROR
            throw "Adobe Reader installer not found after download"
        }

        $downloadedSize = (Get-Item $ReaderPath).Length
        Write-Log "Successfully downloaded Adobe Reader installer to: $ReaderPath" -Level INFO
        Write-Log "Downloaded file size: $downloadedSize bytes" -Level DEBUG

        # Stop any running Adobe processes
        Write-Log "Stopping any running Adobe processes..." -Level INFO
        $adobeProcesses = Get-Process | Where-Object { $_.Name -like "*acro*" -or $_.Name -like "*adobe*" }
        foreach ($proc in $adobeProcesses) {
            try {
                Write-Log "Stopping process: $($proc.Name) (ID: $($proc.Id))" -Level DEBUG
                Stop-Process -InputObject $proc -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log "Warning: Failed to stop process $($proc.Name): $_" -Level WARNING
            }
        }
        Start-Sleep -Seconds 2

        # Install Adobe Reader
        Write-Log "Starting Adobe Reader installation..." -Level INFO
        $startTime = Get-Date
        $process = Start-TrackedProcess -FilePath $ReaderPath -ArgumentList "/sAll /rs /msi EULA_ACCEPT=YES /qn" -NoNewWindow -PassThru -Verb runas
        
        # Wait for initial process to complete
        $process | Wait-Process -Timeout 90 -ErrorAction SilentlyContinue
        
        # Monitor installation progress
        $timeout = 300  # 5 minutes timeout
        $startTime = Get-Date
        
        Write-Log "Monitoring installation progress..." -Level INFO
        do {
            Start-Sleep -Seconds 2
            [System.Windows.Forms.Application]::DoEvents()
            
            $msiProcess = Get-Process -Name msiexec -ErrorAction SilentlyContinue
            $readerProcess = Get-Process -Name Reader_en_install -ErrorAction SilentlyContinue
            
            $elapsedTime = (Get-Date) - $startTime
            if ($elapsedTime.TotalSeconds -gt $timeout) {
                Write-Log "Installation timeout reached after $timeout seconds" -Level WARNING
                break
            }
        } while ($msiProcess -or $readerProcess)
        
        # Try to gracefully close any remaining installer processes
        Write-Log "Cleaning up installer processes..." -Level INFO
        Stop-Process -Name Reader_en_install -Force -ErrorAction SilentlyContinue

        # Verify installation
        Write-Log "Verifying installation..." -Level INFO
        Start-Sleep -Seconds 20  # Allow time for registration
        
        $verificationAttempts = 0
        $maxAttempts = 3
        $installVerified = $false
        
        while ($verificationAttempts -lt $maxAttempts -and -not $installVerified) {
            $verificationAttempts++
            Write-Log "Verification attempt $verificationAttempts of $maxAttempts" -Level INFO
            
            $acrobatPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
            $acrobatInstalled = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                              HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                                              Where-Object { $_.DisplayName -like "*Adobe Acrobat*" }

            if ((Test-Path $acrobatPath) -and $acrobatInstalled) {
                Write-Log "Adobe Reader (Installed)" -Level INFO
                $installVerified = $true
            } else {
                if (-not (Test-Path $acrobatPath)) {
                    Write-Log "ERROR: Adobe Reader executable not found at expected path" -Level ERROR
                }
                if (-not $acrobatInstalled) {
                    Write-Log "ERROR: Adobe Reader not found in installed applications registry" -Level ERROR
                }
                Start-Sleep -Seconds 10
            }
        }

        if ($installVerified) {
            Write-Log "Adobe Reader installation completed and verified successfully" -Level INFO
            return $true
        } else {
            Write-Log "Failed to verify Adobe Reader installation after $maxAttempts attempts" -Level ERROR
            throw "Adobe Reader installation verification failed"
        }
    }
    catch {
        Write-Log "ERROR in Install-AdobeReader: $_" -Level ERROR
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level DEBUG
        throw $_
    }
    finally {
        # Cleanup
        if (Test-Path $ReaderPath) {
            Write-Log "Cleaning up temporary files..." -Level INFO
            Remove-Item -Path $ReaderPath -Force -ErrorAction SilentlyContinue
            Write-Log "Cleanup completed" -Level INFO
        }
        Write-Log "Adobe Reader installation task finished" -Level INFO
    }
}

function Install-CWAutomate {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    try {
        Write-UILog "Starting ConnectWise Automate Agent installation..." -Color "Cyan"
        $file = 'c:\temp\Warehouse-Agent_Install.MSI'
        $agentName = "LTService"
        $agentPath = "C:\Windows\LTSvc\"
        $installerUri = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/Warehouse-Agent_Install.MSI"
        $agentIdKeyPath = "HKLM:\SOFTWARE\LabTech\Service"
        $agentIdValueName = "ID"

        # Check for existing LabTech agent
        if (Get-Service $agentName -ErrorAction SilentlyContinue) {
            Write-UILog "Existing ConnectWise Automate installation found." -Color "Cyan"
            return $true
        } elseif (Test-Path $agentPath) {
            Write-UILog "ConnectWise Automate agent files are present, but the service is not installed." -Color "Red"
            return $false
        } else {
            Write-UILog "Downloading ConnectWise Automate Agent..." -Color "Cyan"
            try {
                Invoke-WebRequest -Uri $installerUri -OutFile $file -UseBasicParsing
                Start-Sleep -Seconds 1
            } catch {
                Write-UILog "ConnectWise Automate agent download failed!" -Color "Red"
                return $false
            }
            Write-UILog "Download complete. Installing ConnectWise Automate Agent..." -Color "Cyan"
            # Start the installation process
            $process = Start-Process msiexec.exe -ArgumentList "/I $file /quiet" -PassThru
            $process.WaitForExit()
            if ($process.ExitCode -eq 0) {
                # Wait for services to fully initialize
                Start-Sleep -Seconds 60
                Write-UILog "ConnectWise Automate Agent installation complete." -Color "Green"
            } else {
                Write-UILog "ConnectWise Automate Agent installation failed." -Color "Red"
                return $false
            }
        }

        # Check for the service
        $service = Get-Service -Name $agentName -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            if (Test-Path $agentIdKeyPath) {
                # Get the agent ID
                $agentId = Get-ItemProperty -Path $agentIdKeyPath -Name $agentIdValueName -ErrorAction SilentlyContinue
                if ($null -ne $agentId) {
                    Write-UILog "ConnectWise Automate Agent ID: $($agentId.$agentIdValueName)" -Color "Cyan"
                } else {
                    Write-UILog "ConnectWise Automate agent ID not found." -Color "Red"
                }
            } else {
                Write-UILog "ConnectWise Automate agent is not installed." -Color "Red"
            }
        }
        return $true
    } catch {
        Write-UILog "Error during ConnectWise Automate Agent installation: $_" -Color "Red"
        return $false
    }
}

# Function to test if the Datto agent is installed
function Test-AutomateInstallation {
    $service = Get-Service $agentName -ErrorAction SilentlyContinue
    $serviceExists = $null -ne $service
    $filesExist = Test-Path $agentPath
    
    return @{
        ServiceExists = $serviceExists
        ServiceRunning = if ($serviceExists) { $service.Status -eq 'Running' } else { $false }
        FilesExist = $filesExist
    }
}

# Progress tracking functions
function Update-Progress {
    param(
        [int]$Completed,
        [int]$Total,
        [string]$Status = ""
    )
    try {
        if ($Total -eq 0) { return }
        $percentage = [math]::Min(100, [math]::Max(0, ($Completed / $Total) * 100))
        
        $Global:Form.Dispatcher.Invoke([Action]{
            $Global:MainProgressBar.Value = $percentage
            $Global:ProgressTextDisplay.Text = "Overall Progress: ${percentage}%"
            if ($Status) {
                $Global:CurrentTaskText.Text = $Status
            }
            # Force immediate UI update
            $Global:MainProgressBar.UpdateLayout()
            $Global:ProgressTextDisplay.UpdateLayout()
            $Global:CurrentTaskText.UpdateLayout()
            [System.Windows.Forms.Application]::DoEvents()
        }, [System.Windows.Threading.DispatcherPriority]::Send)
    }
    catch {
        Write-UILog "Error in Update-Progress: $_" -Color "Red"
    }
}

function Update-SubProgress {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks,
        [int]$SubCompleted,
        [int]$SubTotal,
        [string]$Status = ""
    )
    try {
        if ($TotalTasks -eq 0 -or $SubTotal -eq 0) { return }
        
        # Calculate the percentage range for this task
        $taskSize = 100.0 / $TotalTasks
        $startPercent = ($TaskNumber - 1) * $taskSize
        $subPercentage = ($SubCompleted / $SubTotal) * $taskSize
        
        $totalPercentage = [math]::Min(100, [math]::Max(0, $startPercent + $subPercentage))
        
        $Global:Form.Dispatcher.Invoke([Action]{
            $Global:MainProgressBar.Value = $totalPercentage
            $Global:ProgressTextDisplay.Text = "Overall Progress: ${totalPercentage}%"
            if ($Status) {
                $Global:CurrentTaskText.Text = $Status
            }
            # Force immediate UI update
            $Global:MainProgressBar.UpdateLayout()
            $Global:ProgressTextDisplay.UpdateLayout()
            $Global:CurrentTaskText.UpdateLayout()
            [System.Windows.Forms.Application]::DoEvents()
        }, [System.Windows.Threading.DispatcherPriority]::Send)
    }
    catch {
        Write-UILog "Error in Update-SubProgress: $_" -Color "Red"
    }
}

# Core configuration functions
function Configure-PowerProfile {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    try {
        Write-UILog "Configuring power profile settings..." -Color "Cyan"
        
        # Disable sleep for both AC and DC
        Write-UILog "Disabling sleep timeouts..." -Color "Cyan"
        Update-SubProgress -TaskNumber $TaskNumber -TotalTasks $TotalTasks -SubCompleted 1 -SubTotal 4 -Status "Disabling sleep..."
        
        try {
            powercfg.exe /change standby-timeout-ac 0
            powercfg.exe /change standby-timeout-dc 0
            Write-UILog "Successfully disabled sleep timeouts" -Color "Green"
        } catch {
            Write-UILog "Error disabling sleep timeouts: $_" -Color "Red"
            throw
        }
        
        # Disable hibernation
        Write-UILog "Disabling hibernation..." -Color "Cyan"
        Update-SubProgress -TaskNumber $TaskNumber -TotalTasks $TotalTasks -SubCompleted 2 -SubTotal 4 -Status "Disabling hibernation..."
        
        try {
            powercfg.exe /hibernate off
            Write-UILog "Successfully disabled hibernation" -Color "Green"
        } catch {
            Write-UILog "Error disabling hibernation: $_" -Color "Red"
            throw
        }
        
        # Disable fast startup
        Write-UILog "Disabling fast startup..." -Color "Cyan"
        Update-SubProgress -TaskNumber $TaskNumber -TotalTasks $TotalTasks -SubCompleted 3 -SubTotal 4 -Status "Disabling fast startup..."
        
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
            if (!(Test-Path $regPath)) {
                Write-UILog "Creating registry path: $regPath" -Color "Cyan"
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "HiberbootEnabled" -Value 0 -Type DWord -Force
            Write-UILog "Successfully disabled fast startup" -Color "Green"
        } catch {
            Write-UILog "Error disabling fast startup: $_" -Color "Red"
            throw
        }
        
        Update-SubProgress -TaskNumber $TaskNumber -TotalTasks $TotalTasks -SubCompleted 4 -SubTotal 4 -Status "Power profile configured"
        Write-UILog "Power profile configuration completed successfully" -Color "Green"
        return $true
    }
    catch {
        Write-UILog "Error configuring power profile: $_" -Color "Red"
        Write-UILog "Stack trace: $($_.ScriptStackTrace)" -Color "Red"
        return $false
    }
}

function Start-Runspace {
    param(
        [ScriptBlock]$ScriptBlock,
        [hashtable]$SyncHash
    )
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = "STA"
    $runspace.ThreadOptions = "ReuseThread"
    $runspace.Open()
    $ps = [PowerShell]::Create()
    $ps.Runspace = $runspace
    $ps.AddScript($ScriptBlock).AddArgument($SyncHash) | Out-Null
    return $ps
}

# Function to install Windows Updates
function Configure-WindowsUpdate {
    param(
        [bool]$IncludeDrivers,
        [int]$TaskNumber,
        [int]$TotalTasks
    )

    # Prepare a synchronized hashtable for cross-thread GUI updates
    $syncHash = [hashtable]::Synchronized(@{
        Form = $Global:Form
        ProgressBar = $Global:MainProgressBar
        TaskText = $Global:CurrentTaskText
        LogLines = $Global:LogLines
        ProgressText = $Global:ProgressTextDisplay
        CancelRequested = { $Global:CancelRequested }
    })

    $scriptBlock = {
        param($sync)
        try {
            $sync.Form.Dispatcher.Invoke([Action]{ $sync.ProgressBar.IsIndeterminate = $true })
            $sync.Form.Dispatcher.Invoke([Action]{ $sync.TaskText.Text = "Checking for Windows Updates..." })

            # Ensure PSWindowsUpdate is available
            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Install-PackageProvider -Name NuGet -Force -ErrorAction Stop
                Install-Module -Name PSWindowsUpdate -Force -Confirm:$false -AllowClobber -ErrorAction Stop
            }
            Import-Module PSWindowsUpdate -ErrorAction Stop

            # Configure driver updates if requested
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"
            if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "SearchOrderConfig" -Value ([int]$IncludeDrivers) -Type DWord -Force

            $sync.Form.Dispatcher.Invoke([Action]{ $sync.TaskText.Text = "Searching for updates..." })
            $updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop

            # Filter out driver updates if IncludeDrivers is false
            if (-not $IncludeDrivers) {
                $updates = $updates | Where-Object {
                    ($_.Title -notmatch '(?i)driver') -and ($_.Title -notmatch '(?i)softwarecomponent')
                }
            }

            $total = $updates.Count
            if ($total -eq 0) {
                $sync.Form.Dispatcher.Invoke([Action]{ $sync.TaskText.Text = "No updates available." })
                $sync.Form.Dispatcher.Invoke([Action]{ $sync.ProgressBar.IsIndeterminate = $false })
                return $true
            }

            $sync.Form.Dispatcher.Invoke([Action]{ $sync.TaskText.Text = "$total updates found. Downloading and installing..." })
            $completed = 0

            foreach ($update in $updates) {
                if (& $sync.CancelRequested) {
                    $sync.Form.Dispatcher.Invoke([Action]{ $sync.TaskText.Text = "Update cancelled by user." })
                    $sync.Form.Dispatcher.Invoke([Action]{ $sync.ProgressBar.IsIndeterminate = $false })
                    return $false
                }

                $title = $update.Title
                $sync.Form.Dispatcher.Invoke([Action]{ $sync.TaskText.Text = "Installing: $title" })
                $sync.Form.Dispatcher.Invoke([Action]{ $sync.LogLines.Add("Installing: $title") })

                try {
                    Install-WindowsUpdate -KBArticleID $update.KBArticleIDs -AcceptAll -IgnoreReboot -AutoReboot:$false -Confirm:$false -ErrorAction Stop | ForEach-Object {
                        $sync.Form.Dispatcher.Invoke([Action]{ $sync.LogLines.Add($_.ToString()) })
                    }
                } catch {
                    $sync.Form.Dispatcher.Invoke([Action]{ $sync.LogLines.Add("Failed to install $title`: $_") })
                }

                $completed++
                $percent = [math]::Round(($completed / $total) * 100)
                $sync.Form.Dispatcher.Invoke([Action]{
                    $sync.ProgressBar.Value = $percent
                    $sync.ProgressText.Text = "Windows Update Progress: $percent%"
                })
            }

            $sync.Form.Dispatcher.Invoke([Action]{ $sync.TaskText.Text = "Windows Updates completed." })
            $sync.Form.Dispatcher.Invoke([Action]{ $sync.ProgressBar.IsIndeterminate = $false })
            return $true
        } catch {
            $sync.Form.Dispatcher.Invoke([Action]{ $sync.TaskText.Text = "Windows Update failed: $_" })
            $sync.Form.Dispatcher.Invoke([Action]{ $sync.ProgressBar.IsIndeterminate = $false })
            $sync.Form.Dispatcher.Invoke([Action]{ $sync.LogLines.Add("Windows Update failed: $_") })
            return $false
        }
    }

    # Start the runspace and wait for completion
    $ps = Start-Runspace -ScriptBlock $scriptBlock -SyncHash $syncHash
    $asyncResult = $ps.BeginInvoke()

    # Wait for the runspace to finish (with timeout)
    $timeout = 1800
    $startTime = Get-Date
    while (-not $asyncResult.IsCompleted -and ((Get-Date) - $startTime).TotalSeconds -lt $timeout) {
        Start-Sleep -Milliseconds 500
        [System.Windows.Forms.Application]::DoEvents()
        if ($Global:CancelRequested) { break }
    }
    $ps.EndInvoke($asyncResult)

    $Global:Form.Dispatcher.Invoke([Action]{ $Global:MainProgressBar.IsIndeterminate = $false })
    return -not $Global:CancelRequested
}

# Function to remove Windows bloatware
function Remove-WindowsBloatware {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    try {
        Write-UILog "Starting bloatware removal..." -Color "Cyan"
        Update-SubProgress -TaskNumber $TaskNumber -TotalTasks $TotalTasks -SubCompleted 1 -SubTotal 1 -Status "Running SOS-Debloat..."

        $Win11DebloatURL = Get-DecryptedURL -Key "Win11DebloatURL"
        $Win10DebloatURL = Get-DecryptedURL -Key "Win10DebloatURL"

        if ([string]::IsNullOrWhiteSpace($Win11DebloatURL)) { throw "Failed to load Win11DebloatURL from encrypted file." }
        if ([string]::IsNullOrWhiteSpace($Win10DebloatURL)) { throw "Failed to load Win10DebloatURL from encrypted file." }

        $debloatProc = $null
        if (Is-Windows11) {
            try {
                $Win11DebloatFile = "c:\temp\SOS-Debloat.zip"
                Invoke-WebRequest -Uri $Win11DebloatURL -OutFile $Win11DebloatFile -UseBasicParsing -ErrorAction Stop
                Expand-Archive $Win11DebloatFile -DestinationPath 'c:\temp\SOS-Debloat' -Force
                $debloatProc = Start-TrackedProcess -FilePath "powershell.exe" -ArgumentList @(
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-File", "C:\temp\SOS-Debloat\MITS-Debloat.ps1",
                    "-RemoveApps",
                    "-DisableBing",
                    "-RemoveGamingApps",
                    "-ClearStart",
                    "-DisableLockscreenTips",
                    "-DisableSuggestions",
                    "-ShowKnownFileExt",
                    "-TaskbarAlignLeft",
                    "-HideSearchTb",
                    "-DisableWidgets",
                    "-Silent"
                ) -PassThru
            } catch {
                Write-UILog "Error during Windows 11 debloat: $_" -Color "Red"
                return $false
            }
        } elseif (Is-Windows10) {
            try {
                $SOSDebloatFile = "c:\temp\SOS-Debloat.zip"
                Invoke-WebRequest -Uri $Win10DebloatURL -OutFile $SOSDebloatFile -UseBasicParsing -ErrorAction Stop
                Expand-Archive $SOSDebloatFile -DestinationPath c:\temp\SOS-Debloat -Force
                $debloatProc = Start-TrackedProcess -FilePath "powershell" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "C:\temp\SOS-Debloat\MITS-Debloat.ps1", "-RemoveApps", "-DisableBing", "-RemoveGamingApps", "-ClearStart", "-ShowKnownFileExt", "-Silent" -PassThru -Wait:$false
            } catch {
                Write-UILog "Error during Windows 10 debloat: $_" -Color "Red"
                return $false
            }
        } else {
            Write-UILog "Unsupported Windows version" -Color "Red"
            return $false
        }
        # Poll for process completion
        if ($debloatProc) {
            while (-not $debloatProc.HasExited) {
                Start-Sleep -Milliseconds 500
                [System.Windows.Forms.Application]::DoEvents()
            }
            Write-UILog "Bloatware removal completed successfully" -Color "Green"
            return $true
        } else {
            Write-UILog "Failed to start debloat process" -Color "Red"
            return $false
        }
    } catch {
        Write-UILog "Error removing bloatware: $_" -Color "Red"
        return $false
    }
}

# Function to configure BitLocker
function Configure-BitLocker {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    
    try {
        Write-UILog "Starting BitLocker configuration..."
        
        # Safe progress update that checks for zero
        if ($TotalTasks -gt 0) {
            Update-Progress -Status "Configuring BitLocker..." -PercentComplete (($TaskNumber / $TotalTasks) * 100)
        } else {
            Update-Progress -Status "Configuring BitLocker..." -PercentComplete 0
        }

        # Check system requirements
        Write-UILog "Checking system requirements..."
        $WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
        $TPM = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -Class Win32_Tpm -ErrorAction SilentlyContinue
        $BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue

        if (-not ($WindowsVer -and $TPM -and $BitLockerReadyDrive)) {
            Write-UILog "Skipping BitLocker configuration - Device does not meet hardware requirements" -Color "Yellow"
            return $false
        }

        # Check if BitLocker is already configured
        $BitLockerStatus = Get-BitLockerVolume -MountPoint $env:SystemDrive
        if ($BitLockerStatus.ProtectionStatus -eq 'On') {
            Write-UILog "BitLocker is already configured on $env:SystemDrive" -Color "Cyan"
            
            # Create a dialog to ask if user wants to reconfigure
            $result = [System.Windows.MessageBox]::Show(
                "BitLocker is already configured on $env:SystemDrive.`nDo you want to reconfigure it?",
                "BitLocker Configuration",
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Question
            )

            if ($result -eq [System.Windows.MessageBoxResult]::No) {
                Write-UILog "Skipping BitLocker reconfiguration as requested" -Color "Yellow"
                return $true
            }

            # Disable BitLocker
            Write-UILog "Disabling existing BitLocker configuration..."
            manage-bde -off $env:SystemDrive | Out-Null

            # Monitor decryption progress
            do {
                $status = manage-bde -status $env:SystemDrive
                $percentageEncrypted = ($status | Select-String -Pattern "Percentage Encrypted:.*").ToString().Split(":")[1].Trim()
                Write-UILog "Current decryption progress: $percentageEncrypted" -Color "Cyan"
                Start-Sleep -Seconds 1
            } until ($percentageEncrypted -eq "0.0%")
            
            Write-UILog "Decryption of $env:SystemDrive is complete" -Color "Green"
        }

        # Configure BitLocker
        Write-UILog "Configuring BitLocker Disk Encryption..." -Color "Cyan"
        
        # Create recovery key
        Write-UILog "Creating recovery key protector..."
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
        
        # Add TPM key
        Write-UILog "Adding TPM protector..."
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector -WarningAction SilentlyContinue | Out-Null
        
        # Wait for protectors to take effect
        Start-Sleep -Seconds 5
        
        # Enable encryption
        Write-UILog "Enabling encryption..."
        $encryptionProcess = Start-TrackedProcess -FilePath 'manage-bde.exe' -ArgumentList "-on $env:SystemDrive -UsedSpaceOnly" -Verb runas -PassThru -Wait
        
        # Backup recovery key to AD if possible
        $RecoveryKeyGUID = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | 
                            Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'} | 
                            Select-Object -ExpandProperty KeyProtectorID
        
        try {
            Write-UILog "Attempting to backup recovery key to Active Directory..."
            manage-bde.exe -protectors $env:SystemDrive -adbackup -id $RecoveryKeyGUID | Out-Null
            Write-UILog "Successfully backed up recovery key to Active Directory" -Color "Green"
        }
        catch {
            Write-UILog "Failed to backup BitLocker recovery key to AD: $_" -Color "Yellow"
        }
        
        # Save recovery key to file
        Write-UILog "Saving recovery key to file..."
        $outputDirectory = $Global:TempFolder
        manage-bde -protectors C: -get | Out-File "$outputDirectory\$env:computername-BitLocker.txt"
        
        # Verify configuration
        $BitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
        if ($BitLockerVolume.KeyProtector) {
            # Get recovery information
            $recoveryId = $BitLockerVolume.KeyProtector | 
                Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | 
                ForEach-Object { $_.KeyProtectorId.Trim('{', '}') }
            
            $recoveryPassword = $BitLockerVolume.KeyProtector | 
                Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -like "*"} | 
                Select-Object -ExpandProperty RecoveryPassword
            
            # Display recovery info
            Write-UILog "BitLocker has been successfully configured" -Color "Green"
            Write-UILog "Recovery ID: $recoveryId" -Color "Cyan"
            Write-UILog "Recovery Password: $recoveryPassword" -Color "Cyan"
            Write-UILog "Recovery key has been saved to: $outputDirectory\$env:computername-BitLocker.txt" -Color "Cyan"
            
            # Show recovery info in a message box
            [System.Windows.MessageBox]::Show(
                "BitLocker has been successfully configured.`n`n" +
                "Recovery ID: $recoveryId`n" +
                "Recovery Password: $recoveryPassword`n`n" +
                "Recovery key has been saved to:`n$outputDirectory\$env:computername-BitLocker.txt",
                "BitLocker Configuration Complete",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information
            )
            
            # Safe progress update for completion
            if ($TotalTasks -gt 0) {
                Update-Progress -Completed $TaskNumber -Total $TotalTasks -Status "BitLocker configuration completed"
            }
            
            return $true
        } else {
            Write-UILog "BitLocker disk encryption is not configured" -Color "Red"
            return $false
        }
    }
    catch {
        Write-UILog "Error configuring BitLocker: $_" -Color "Red"
        return $false
    }
}

# Install SentinelOne EDR
function Install-SentinelOneEDR {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    
    # Skip if user requested exit/cancel
    if ($Global:CancelRequested) {
        Write-Log "SentinelOne installation skipped due to user exit/cancel." -Level WARNING
        return $false
    }
    try {
        Write-Log "Starting SentinelOne Endpoint installation..." -Level INFO
        #Write-Log "Task number: $TaskNumber of $TotalTasks" -Level DEBUG
        Update-Progress -Completed ($TaskNumber - 1) -Total $TotalTasks -Status "Installing SentinelOne Endpoint..."

        $ProgressPreference = "SilentlyContinue"
        $existingInstall = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*SentinelOne*" }
        if ($existingInstall) {
            Write-Log "Found existing SentinelOne installation:" -Level WARNING
            Write-Log "  Name: $($existingInstall.Name)" -Level WARNING
            Write-Log "  Version: $($existingInstall.Version)" -Level WARNING
            Write-Log "  Vendor: $($existingInstall.Vendor)" -Level WARNING
            $result = [System.Windows.MessageBox]::Show(
                "SentinelOne is already installed.`nDo you want to proceed with reinstallation?",
                "SentinelOne Installation",
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Question
            )
            if ($result -eq [System.Windows.MessageBoxResult]::No) {
                Write-Log "User chose not to reinstall SentinelOne" -Level INFO
                return $true
            }
            Write-Log "User chose to proceed with reinstallation" -Level INFO
        }
        try {
            $scriptPath = Join-Path $Global:TempFolder "Deploy-SentinelOneAV.ps1"
            Write-Log "Installation script will be downloaded to: $scriptPath" -Level DEBUG
            $startTime = Get-Date
            Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/Deploy-SentinelOne.ps1" -OutFile $scriptPath -UseBasicParsing
            $downloadDuration = (Get-Date) - $startTime
            if (-not (Test-Path $scriptPath)) {
                throw "Failed to download SentinelOne installation script"
            }
            $fileSize = (Get-Item $scriptPath).Length
            Write-Log "Successfully downloaded SentinelOne installation script ($fileSize bytes) in $($downloadDuration.TotalSeconds) seconds" -Level INFO
        } catch {
            Write-Log "Failed to download SentinelOne installation script: $_" -Level ERROR
            Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level DEBUG
            throw "Failed to download SentinelOne installation script: $_"
        }
        Write-Log "Starting SentinelOne installation process..." -Level INFO
        $startTime = Get-Date
        $process = Start-TrackedProcess -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $scriptPath -Wait:$false -PassThru
        # Poll for process completion
        if ($process) {
            while (-not $process.HasExited) {
                if ($Global:CancelRequested) {
                    Write-Log "SentinelOne installation cancelled by user during process execution." -Level WARNING
                    try { $process.Kill() } catch {}
                    Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
                    if (Test-Path "C:\temp\s1t.enc") {
                        Remove-Item -Path "C:\temp\s1t.enc" -Force -ErrorAction SilentlyContinue
                    }
                    $ProgressPreference = "Continue"
                    Write-Log "SentinelOne installation task finished" -Level INFO
                    return $false
                }
                Start-Sleep -Milliseconds 500
                [System.Windows.Forms.Application]::DoEvents()
            }
        }
        $installDuration = (Get-Date) - $startTime
        Write-Log "SentinelOne installation process completed in $($installDuration.TotalSeconds) seconds" -Level INFO
        if ($process.ExitCode -ne 0) {
            Write-Log "Installation canceled by user" -Level WARNING
            Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
            if (Test-Path "C:\temp\s1t.enc") {
                Remove-Item -Path "C:\temp\s1t.enc" -Force -ErrorAction SilentlyContinue
            }
            $ProgressPreference = "Continue"
            Write-Log "SentinelOne installation task finished" -Level INFO
            return $false
        }
        # Check for cancel before verification
        if ($Global:CancelRequested) {
            Write-Log "Skipping SentinelOne installation verification due to user exit/cancel." -Level WARNING
            Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
            if (Test-Path "C:\temp\s1t.enc") {
                Remove-Item -Path "C:\temp\s1t.enc" -Force -ErrorAction SilentlyContinue
            }
            $ProgressPreference = "Continue"
            Write-Log "SentinelOne installation task finished" -Level INFO
            return $false
        }
        Write-Log "Verifying SentinelOne installation..." -Level INFO
        Start-Sleep -Seconds 10
        $verificationAttempts = 0
        $maxAttempts = 1
        $installVerified = $false
        while ($verificationAttempts -lt $maxAttempts -and -not $installVerified) {
            if ($Global:CancelRequested) {
                Write-Log "Skipping SentinelOne installation verification during attempts due to user exit/cancel." -Level WARNING
                break
            }
            $verificationAttempts++
            Write-Log "Verification attempt $verificationAttempts of $maxAttempts" -Level INFO
            $sentinel = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq "Sentinel Agent" }
            if ($sentinel) {
                Write-Log "SentinelOne installation verified:" -Level INFO
                Write-Log "  Name: $($sentinel.Name)" -Level INFO
                Write-Log "  Version: $($sentinel.Version)" -Level INFO
                Write-Log "  Vendor: $($sentinel.Vendor)" -Level INFO
                $installVerified = $true
            } else {
                Write-Log "SentinelOne installation not found on attempt $verificationAttempts" -Level WARNING
                Start-Sleep -Seconds 10
            }
        }
        Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
        if (Test-Path "C:\temp\s1t.enc") {
            Remove-Item -Path "C:\temp\s1t.enc" -Force -ErrorAction SilentlyContinue
        }
        $ProgressPreference = "Continue"
        if ($installVerified) {
            Write-Log "SentinelOne installation completed and verified successfully" -Level INFO
            Update-Progress -Completed $TaskNumber -Total $TotalTasks -Status "SentinelOne installation completed"
            return $true
        } else {
            Write-Log "Failed to verify SentinelOne installation after $maxAttempts attempts" -Level ERROR
            return $false
        }
    } catch {
        Write-Log "Error installing SentinelOne EDR: $_" -Level ERROR
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level DEBUG
        return $false
    } finally {
        $ProgressPreference = "Continue"
        Write-Log "SentinelOne installation task finished" -Level INFO
    }
}

# Install M365 apps for business
function Install-Office365 {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    try {
        Write-Log "Starting Microsoft 365 installation..." -Level INFO
        #Write-Log "Task number: $TaskNumber of $TotalTasks" -Level DEBUG
        Update-Progress -Completed ($TaskNumber - 1) -Total $TotalTasks -Status "Installing Microsoft 365..."

        # Check for existing installation
        Write-Log "Checking for existing Microsoft 365 installation..." -Level INFO
        $O365 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Where-Object { $_.DisplayName -like "*Microsoft 365 Apps for enterprise - en-us*" }

        if ($O365) {
            Write-Log "Existing Microsoft 365 installation found:" -Level INFO
            Write-Log "  Display Name: $($O365.DisplayName)" -Level INFO
            Write-Log "  Version: $($O365.DisplayVersion)" -Level INFO
            Write-Log "  Install Date: $($O365.InstallDate)" -Level INFO
            Update-Progress -Completed $TaskNumber -Total $TotalTasks -Status "Microsoft 365 already installed"
            return $true
        }

        # Set up installation
        $OfficePath = "$Global:TempFolder\OfficeSetup.exe"
        Write-Log "Office installer will be downloaded to: $OfficePath" -Level DEBUG
        
        # Download Office installer
        Write-Log "Retrieving Microsoft Office 365 download URL..." -Level INFO
        
        # Get the URL from decrypted URLs
        $OfficeURL = Get-DecryptedURL -Key 'OfficeURL'
        Write-Log "OfficeURL retrieved: $OfficeURL" -Level DEBUG
        if ([string]::IsNullOrWhiteSpace($OfficeURL)) { 
            Write-Log "ERROR: Failed to get Office installation URL" -Level ERROR
            throw "Failed to get Office installation URL" 
        }
        
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $OfficeURL -OutFile $OfficePath -ErrorAction Stop
            $ProgressPreference = 'Continue'
            Write-Log "Office installer download completed." -Level INFO
        }
        catch {
            Write-Log "ERROR: Failed to download Office installer: $_" -Level ERROR
            Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level DEBUG
            throw "Failed to download Office installer: $_"
        }

        # Validate download
        if (-not (Test-Path $OfficePath)) {
            Write-Log "ERROR: Office installer not found after download" -Level ERROR
            throw "Office installer not found after download"
        }
        $FileSize = (Get-Item $OfficePath).Length
        Write-Log "Downloaded Office installer size: $FileSize bytes" -Level DEBUG

        # Kill any running Office processes
        Write-UILog "Stopping any running Office processes..." -Color "Cyan"
        Stop-Process -Name "OfficeClickToRun" -Force -ErrorAction SilentlyContinue
        Stop-Process -Name "OfficeC2RClient" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 10

        # Install Office
        Write-UILog "Installing Microsoft Office 365... This may take some time." -Color "Yellow"
        try {
            $installProcess = Start-TrackedProcess -FilePath $OfficePath -ArgumentList @() -Wait -PassThru -NoNewWindow
            Write-Log "Office installer process started." -Level INFO
            if ($installProcess.ExitCode -ne 0) {
                Write-Log "Office installation failed with exit code: $($installProcess.ExitCode)" -Level ERROR
                throw "Office installation failed with exit code: $($installProcess.ExitCode)"
            }
        }
        catch {
            Write-Log "ERROR: Error during Office installation: $_" -Level ERROR
            Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level DEBUG
            throw "Error during Office installation: $_"
        }

        # Wait for installation to complete and verify
        Write-UILog "Waiting for installation to complete..." -Color "Cyan"
        Start-Sleep -Seconds 15

        # Verify installation
        $installed = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
                    Where-Object {$_.DisplayName -like "Microsoft 365 Apps for enterprise - en-us"}
        if ($installed) {
            Write-UILog "Microsoft 365 installation completed successfully" -Color "Green"
            # Final cleanup
            Write-UILog "Performing final cleanup..." -Color "Cyan"
            Stop-Process -Name "OfficeClickToRun" -Force -ErrorAction SilentlyContinue
            Stop-Process -Name "OfficeC2RClient" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $OfficePath -Force -ErrorAction SilentlyContinue
            Update-Progress -Completed $TaskNumber -Total $TotalTasks -Status "Microsoft 365 installed"
            return $true
        } else {
            Write-Log "ERROR: Microsoft 365 installation verification failed" -Level ERROR
            throw "Microsoft 365 installation verification failed"
        }
    }
    catch {
        Write-Log "ERROR in Install-Office365: $_" -Level ERROR
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level DEBUG
        throw $_
    }
    finally {
        $ProgressPreference = "Continue"
    }
}

# Install Sonicwall SSL VPN Client 10.3.1
Function Install-SonicwallVpnClient {
    try {
        $SWNE = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                     HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Where-Object { $_.DisplayName -like "*SonicWall NetExtender*" }
        if ($SWNE) {
            Write-UILog "Existing Sonicwall NetExtender installation found." -Color Cyan
            return $true
        } else {
            $NEFilePath = "c:\temp\NXSetupU-x64-10.3.1.exe"
            if (-not (Test-Path $NEFilePath)) {
                $NEURL = "https://axcientrestore.blob.core.windows.net/win11/NXSetupU-x64-10.3.1.exe"
                Write-UILog "Downloading Sonicwall NetExtender installer..." -Color Cyan
                Invoke-WebRequest -OutFile $NEFilePath -Uri $NEURL -UseBasicParsing
            }
            $NEGui = "C:\Program Files\SonicWall\SSL-VPN\NetExtender\NetExtender.exe"
            $FileSize = (Get-Item $NEFilePath).Length
            $ExpectedSize = 8226288
            if ($FileSize -eq $ExpectedSize) {
                Write-UILog "Installing Sonicwall NetExtender..." -Color Cyan
                $proc = Start-Process -FilePath $NEFilePath -ArgumentList "/S" -PassThru
                while (-not $proc.HasExited) {
                    Start-Sleep -Milliseconds 500
                    [System.Windows.Forms.Application]::DoEvents()
                }
                if (Test-Path $NEGui) {
                    Write-UILog "Sonicwall NetExtender installation completed successfully." -Color Green
                    Remove-Item -Path $NEFilePath -Force -ErrorAction SilentlyContinue | Out-Null
                    return $true
                } else {
                    Write-UILog "Sonicwall NetExtender installation failed: NEGui.exe not found after install." -Color Red
                    return $false
                }
            } else {
                Write-UILog "Sonicwall NetExtender download failed! File does not exist or size does not match." -Color Red
                Remove-Item -Path $NEFilePath -Force -ErrorAction SilentlyContinue | Out-Null
                return $false
            }
        }
    } catch {
        Write-UILog "Error during Sonicwall NetExtender installation: $_" -Color Red
        return $false
    }
}

function Connect-VPN {
    if (Test-Path 'C:\Program Files\SonicWall\SSL-VPN\NetExtender\NXCLI.exe') {
        Write-UILog "NetExtender detected successfully, starting connection..."
        Start-Process C:\temp\ssl-vpn.bat
        Start-Sleep -Seconds 10
        $connectionProfile = Get-NetConnectionProfile -InterfaceAlias "Sonicwall NetExtender"
        if ($connectionProfile) {
            Write-UILog "The 'Sonicwall NetExtender' adapter is connected to SSLVPN."
        } else {
            Write-UILog "The 'Sonicwall NetExtender' adapter is not connected to SSLVPN." 
        }
    } else {
        Write-UILog "SonicWall NetExtender not found!"
    }
}

<# Function to join the computer to a domain via GUI prompt
function Join-Domain {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [switch]$SkipVPN,
        
        [Parameter(Mandatory=$false)]
        [string]$VPNUrl = "https://advancestuff.hostedrmm.com/labtech/transfer/installers/ssl-vpn.bat"
    )

    Write-UILog "Starting Domain/AzureAD Join Task..." -Color "Cyan"
    
    # Handle VPN connection if not skipped
    if (-not $SkipVPN) {
        $ProgressPreference = 'SilentlyContinue'
        try {
            # Create temp directory if it doesn't exist
            if (-not (Test-Path "c:\temp")) {
                New-Item -Path "c:\temp" -ItemType Directory -Force | Out-Null
            }
            
            Write-UILog "Downloading SSL VPN installer..." -Color "Cyan"
            Invoke-WebRequest -Uri $VPNUrl -OutFile "c:\temp\ssl-vpn.bat" -ErrorAction Stop
            Write-UILog "SSL VPN installer downloaded successfully" -Color "Green"
        } catch {
            Write-UILog "Failed to download SSL VPN installer: $_" -Color "Red"
            return 1
        }
        $ProgressPreference = 'Continue'

        $validChoice = $false
        do {
            $choice = Read-Host -Prompt "Do you want to connect to SSL VPN? (Y/N)"
            switch ($choice) {
                "Y" {
                    Write-UILog "Attempting to connect to SSL VPN..." -Color "Cyan"
                    Connect-VPN
                    
                    # Verify VPN connection
                    Start-Sleep -Seconds 5
                    $connectionProfile = Get-NetConnectionProfile -InterfaceAlias "Sonicwall NetExtender" -ErrorAction SilentlyContinue
                    if ($connectionProfile) {
                        Write-UILog "Successfully connected to SSL VPN" -Color "Green"
                        $validChoice = $true
                    } else {
                        Write-UILog "Failed to verify VPN connection. Please check your connection manually." -Color "Yellow"
                        $retry = Read-Host -Prompt "Would you like to retry VPN connection? (Y/N)"
                        if ($retry -ne "Y") {
                            $validChoice = $true
                        }
                    }
                }
                "N" {
                    Write-UILog "Skipping VPN Connection Setup..." -Color "Yellow"
                    $validChoice = $true
                }
                default {
                    Write-UILog "Invalid choice. Please enter Y or N." -Color "Red"
                    $validChoice = $false
                }
            }
        } while (-not $validChoice)
    }

    # Domain/AzureAD Join Process
    $validChoice = $false
    do {
        $choice = Read-Host -Prompt "Do you want to join a domain or Azure AD? (1 for Azure AD, 2 for domain)"
        switch ($choice) {
            "2" {
                Write-UILog "Starting domain join process..." -Color "Cyan"
                $username = Read-Host -Prompt "Enter the username for the domain join operation"
                $password = Read-Host -Prompt "Enter the password for the domain join operation" -AsSecureString
                $cred = New-Object System.Management.Automation.PSCredential($username, $password)
                $domain = Read-Host -Prompt "Enter the domain name for the domain join operation"
                
                try {
                    Write-UILog "Attempting to join domain: $domain" -Color "Cyan"
                    Add-Computer -DomainName $domain -Credential $cred -ErrorAction Stop
                    Write-UILog "Domain join operation completed successfully" -Color "Green"
                    $validChoice = $true
                    return 0
                } catch {
                    Write-UILog "Failed to join the domain: $_" -Color "Red"
                    $retry = Read-Host -Prompt "Would you like to retry domain join? (Y/N)"
                    if ($retry -ne "Y") {
                        $validChoice = $true
                        return 1
                    }
                }
            }
            "1" {
                Write-UILog "Starting Azure AD Join operation..." -Color "Cyan"
                try {
                    # Check if already joined to Azure AD
                    $output = dsregcmd /status | Out-String
                    if ($output -match 'AzureAdJoined\s+:\s+YES') {
                        Write-UILog "Computer is already joined to Azure AD" -Color "Yellow"
                        $validChoice = $true
                        return 0
                    }
                    
                    # Open Azure AD join settings
                    Write-UILog "Opening Azure AD join settings..." -Color "Cyan"
                    Start-Process "ms-settings:workplace"
                    
                    # Wait for user to complete the process
                    $complete = $false
                    $attempts = 0
                    $maxAttempts = 30
                    
                    while (-not $complete -and $attempts -lt $maxAttempts) {
                        Start-Sleep -Seconds 10
                        $output = dsregcmd /status | Out-String
                        if ($output -match 'AzureAdJoined\s+:\s+YES') {
                            Write-UILog "Successfully joined Azure AD" -Color "Green"
                            $complete = $true
                            $validChoice = $true
                            return 0
                        }
                        $attempts++
                        Write-UILog "Waiting for Azure AD join to complete... (Attempt $attempts of $maxAttempts)" -Color "Cyan"
                    }
                    
                    if (-not $complete) {
                        Write-UILog "Azure AD join process timed out. Please check the status manually." -Color "Yellow"
                        $validChoice = $true
                        return 1
                    }
                } catch {
                    Write-UILog "Error during Azure AD join process: $_" -Color "Red"
                    $validChoice = $true
                    return 1
                }
            }
            default {
                Write-UILog "Invalid choice. Please enter 1 or 2." -Color "Red"
            }
        }
    } while (-not $validChoice)
}
#>

function Join-Domain {
    [CmdletBinding()]
    param ()

    # Prompt user via GUI if they want to connect to SSL VPN
    $vpnResult = [System.Windows.MessageBox]::Show(
        "Do you want to connect to SSL VPN before joining the domain?",
        "SSL VPN Connection",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Question
    )

    if ($vpnResult -eq [System.Windows.MessageBoxResult]::Yes) {
        # Download the latest ssl-vpn.bat
        $batUrl = "https://axcientrestore.blob.core.windows.net/win11/ssl-vpn2.bat"
        $batPath = "C:\temp\ssl-vpn.bat"
        Invoke-WebRequest -Uri $batUrl -OutFile $batPath -UseBasicParsing
    
        # Launch the batch file and wait for it to close
        $proc = Start-Process -FilePath $batPath -WindowStyle Normal -PassThru
        $Global:Form.Dispatcher.Invoke([Action]{
            $Global:CurrentTaskText.Text = "Waiting for SSL VPN connection window to close..."
        })
        $proc.WaitForExit()
    }

    # Prompt user for domain join info via GUI
    # Create a simple form for domain join credentials
    Add-Type -AssemblyName PresentationFramework

    $form = New-Object Windows.Window
    $form.Title = "Domain Join"
    $form.Width = 350
    $form.Height = 220
    $form.WindowStartupLocation = "CenterScreen"

    $grid = New-Object Windows.Controls.Grid
    $form.Content = $grid

    $labels = @("Domain:", "Username:", "Password:")
    for ($i = 0; $i -lt $labels.Count; $i++) {
        $row = New-Object Windows.Controls.RowDefinition
        $row.Height = "Auto"
        $grid.RowDefinitions.Add($row)
        $label = New-Object Windows.Controls.Label
        $label.Content = $labels[$i]
        $label.Margin = "10,10,0,0"
        [Windows.Controls.Grid]::SetRow($label, $i)
        [Windows.Controls.Grid]::SetColumn($label, 0)
        $grid.Children.Add($label)
    }

    $domainBox = New-Object Windows.Controls.TextBox
    $domainBox.Margin = "100,10,10,0"
    [Windows.Controls.Grid]::SetRow($domainBox, 0)
    [Windows.Controls.Grid]::SetColumn($domainBox, 1)
    $grid.Children.Add($domainBox)

    $userBox = New-Object Windows.Controls.TextBox
    $userBox.Margin = "100,10,10,0"
    [Windows.Controls.Grid]::SetRow($userBox, 1)
    [Windows.Controls.Grid]::SetColumn($userBox, 1)
    $grid.Children.Add($userBox)

    $passBox = New-Object Windows.Controls.PasswordBox
    $passBox.Margin = "100,10,10,0"
    [Windows.Controls.Grid]::SetRow($passBox, 2)
    [Windows.Controls.Grid]::SetColumn($passBox, 1)
    $grid.Children.Add($passBox)

    # Add OK button
    $okButton = New-Object Windows.Controls.Button
    $okButton.Content = "OK"
    $okButton.Width = 80
    $okButton.Margin = "10,20,10,10"
    [Windows.Controls.Grid]::SetRow($okButton, 3)
    [Windows.Controls.Grid]::SetColumn($okButton, 1)
    $grid.RowDefinitions.Add((New-Object Windows.Controls.RowDefinition))
    $grid.Children.Add($okButton)

    $okButton.Add_Click({
        $form.DialogResult = $true
        $form.Close()
    })

    $form.ShowDialog() | Out-Null

    $domain = $domainBox.Text
    $username = $userBox.Text
    $password = $passBox.Password

    if (-not $domain -or -not $username -or -not $password) {
        [System.Windows.MessageBox]::Show("Domain, username, and password are required.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        return
    }

    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ("$domain\$username", $securePassword)

    # Run the domain join in a background job
    $Global:Form.Dispatcher.Invoke([Action]{
        $Global:CurrentTaskText.Text = "Joining domain in background..."
    })

    $job = Start-Job -ScriptBlock {
        param($domain, $cred)
        try {
            Add-Computer -DomainName $domain -Credential $cred -ErrorAction Stop
            Restart-Computer
            return "Domain join successful. Restarting computer..."
        } catch {
            return "Domain join failed: $($_.Exception.Message)"
        }
    } -ArgumentList $domain, $cred

    # Poll for job completion and update UI
    while ($job.State -eq 'Running') {
        Start-Sleep -Seconds 2
        $Global:Form.Dispatcher.Invoke([Action]{
            $Global:CurrentTaskText.Text = "Joining domain... (please wait)"
        })
    }

    $result = Receive-Job $job
    Remove-Job $job

    [System.Windows.MessageBox]::Show($result, "Domain Join Result", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    $Global:Form.Dispatcher.Invoke([Action]{
        $Global:CurrentTaskText.Text = $result
    })
}

# Function to get count of user-selected tasks (excluding required tasks)
function Get-SelectedTaskCount {
    $count = 0
    #Write-UILog "Counting selected tasks..." -Color "Cyan"
    
    # Check each task directly
    if ($Global:cbDeployRMM.IsChecked) {
        #Write-UILog "Deploy RMM is checked" -Color "Cyan"
        $count++
    }

    if ($Global:cbProfileCustomization.IsChecked) {
        #Write-UILog "User Profile Customization is checked" -Color "Cyan"
        $count++
    }
    
    if ($Global:cbPowerProfile.IsChecked) {
        #Write-UILog "Configure Power Profile is checked" -Color "Cyan"
        $count++
    } 
    
    if ($Global:cbWindowsUpdate.IsChecked) {
        #Write-UILog "Configure Windows Update is checked" -Color "Cyan"
        $count++
    }

    if ($Global:cbDriverUpdates.IsChecked) {
        #Write-UILog "Include Driver Updates is checked" -Color "Cyan"
        $count++
    }

    if ($Global:cbOffice365.IsChecked) {
        #Write-UILog "Install Microsoft 365 is checked" -Color "Cyan"
        $count++
    }

    if ($Global:cbAdobeReader.IsChecked) {
        #Write-UILog "Install Adobe Reader is checked" -Color "Cyan"
        $count++
    }

    if ($Global:cbSonicwallVpn.IsChecked) {
        Write-UILog "Install Sonicwall SSL VPN client is checked" -Color "Cyan"
        $count++
    }

    if ($Global:cbBitLocker.IsChecked) {
        #Write-UILog "Configure BitLocker is checked" -Color "Cyan"
        $count++
    }

    if ($Global:cbSentinelOne.IsChecked) {
        #Write-UILog "Install SentinelOne Endpoint is checked" -Color "Cyan"
        $count++
    }

    if ($Global:cbCreateRestorePoint.IsChecked) {
        #Write-UILog "Create System Restore Point is checked" -Color "Cyan"
        $count++
    }

    if ($Global:cbRemoveBloatware.IsChecked) {
        #Write-UILog "Remove Bloatware is checked" -Color "Cyan"
        $count++

    }

    if ($Global:cbJoinDomain.IsChecked) {
        #Write-UILog "Domain Join is checked" -Color "Cyan" 
        $count++
    }
    
    Write-UILog "Total selected tasks: $count" -Color "Cyan"
    return $count
}

# Validation functions
function Test-TasksSelected {
    try {
        Write-UILog "Testing for selected tasks..." -Color "Cyan"
        
        # Debug: Print current checkbox states
        Write-UILog "Current checkbox states:" -Color "Cyan"
        Write-UILog "Deploy RMM: $($Global:cbDeployRMM.IsChecked)" -Color "Cyan"
        Write-UILog "User Profile Customization: $($Global:cbProfileCustomization.IsChecked)" -Color "Cyan"
        Write-UILog "Power Profile Customization: $($Global:cbPowerProfile.IsChecked)" -Color "Cyan"
        Write-UILog "Install Windows Updates: $($Global:cbWindowsUpdate.IsChecked)" -Color "Cyan"
        Write-UILog "Include Driver Updates: $($Global:cbDriverUpdates.IsChecked)" -Color "Cyan"
        Write-UILog "Install Microsoft 365: $($Global:cbOffice365.IsChecked)" -Color "Cyan"
        Write-UILog "Install Adobe Reader: $($Global:cbAdobeReader.IsChecked)" -Color "Cyan"
        Write-UILog "Install Sonicwall SSL VPN client: $($Global:cbSonicwallVpn.IsChecked)" -Color "Cyan"
        Write-UILog "Configure BitLocker: $($Global:cbBitLocker.IsChecked)" -Color "Cyan"
        Write-UILog "Install SentinelOne EDR: $($Global:cbSentinelOne.IsChecked)" -Color "Cyan"
        Write-UILog "Create System Restore Point: $($Global:cbCreateRestorePoint.IsChecked)" -Color "Cyan"
        Write-UILog "Remove Bloatware: $($Global:cbRemoveBloatware.IsChecked)" -Color "Cyan"
        Write-UILog "Domain Join: $($Global:cbJoinDomain.IsChecked)" -Color "Cyan"
        
        
        # Get selected task count
        $selectedCount = Get-SelectedTaskCount
        Write-UILog "Final selected tasks count: $selectedCount" -Color "Cyan"
        return $selectedCount -gt 0
    }
    catch {
        Write-UILog "Error in Test-TasksSelected: $_" -Color "Red"
        return $false
    }
}

# Function to configure system time and timezone
function Configure-SystemTime {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    
    try {
        Write-UILog "Configuring system time settings..." -Color "Cyan"
        
        # Start the Windows Time service
        Write-UILog "Starting Windows Time service..." -Color "Cyan"
        Start-Service W32Time
        
        # Set timezone to EST
        Write-UILog "Setting timezone to Eastern Standard Time..." -Color "Cyan"
        Set-TimeZone -Id "Eastern Standard Time" -ErrorAction Stop
        
        # Sync time
        Write-UILog "Synchronizing system clock..." -Color "Cyan"
        w32tm /resync -ErrorAction SilentlyContinue | Out-Null
        
        Write-UILog "System time configuration completed successfully" -Color "Green"
        return $true
    }
    catch {
        Write-UILog "Error configuring system time: $_" -Color "Red"
        return $false
    }
}

# Function to configure privacy settings
function Configure-PrivacySettings {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    
    try {
        Write-UILog "Configuring Windows privacy settings..." -Color "Cyan"
        
        # Get all user SIDs for registry modifications
        $UserSIDs = @()
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | 
            Where-Object {$_.PSChildName -match "S-1-5-21-(\d+-){4}$"} |
            Select-Object @{Name="SID"; Expression={$_.PSChildName}} |
            ForEach-Object {$UserSIDs += $_.SID}

        # Disable Windows Feedback Experience
        Write-UILog "Disabling Windows Feedback Experience..." -Color "Cyan"
        $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
        if (!(Test-Path $Advertising)) {
            New-Item $Advertising -Force | Out-Null
        }
        Set-ItemProperty $Advertising Enabled -Value 0

        # Disable Cortana
        Write-UILog "Disabling Cortana..." -Color "Cyan"
        $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        if (!(Test-Path $Search)) {
            New-Item $Search -Force | Out-Null
        }
        Set-ItemProperty $Search AllowCortana -Value 0

        # Disable Bing Search
        Write-UILog "Disabling Bing Search..." -Color "Cyan"
        Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 -ErrorAction SilentlyContinue

        # Remove 3D Objects
        Write-UILog "Removing 3D Objects from explorer..." -Color "Cyan"
        $Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
        $Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
        Remove-Item -Path $Objects32 -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $Objects64 -Force -ErrorAction SilentlyContinue

        # Disable scheduled tasks
        Write-UILog "Disabling unnecessary scheduled tasks..." -Color "Cyan"
        $tasks = @(
            'XblGameSaveTaskLogon',
            'XblGameSaveTask',
            'Consolidator',
            'UsbCeip',
            'DmClient',
            'DmClientOnScenarioDownload'
        )
        foreach ($task in $tasks) {
            Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
        }

        Write-UILog "Privacy settings configured successfully" -Color "Green"
        return $true
    }
    catch {
        Write-UILog "Error configuring privacy settings: $_" -Color "Red"
        return $false
    }
}

# Function to configure offline files
function Configure-OfflineFiles {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    
    try {
        Write-UILog "Disabling offline files..." -Color "Cyan"
        
        $registryPath = "HKLM:\System\CurrentControlSet\Services\CSC\Parameters"
        
        if (-not (Test-Path -Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $registryPath -Name "Start" -Value 4 -Type DWord -Force
        
        Write-UILog "Offline files have been disabled successfully" -Color "Green"
        return $true
    }
    catch {
        Write-UILog "Error disabling offline files: $_" -Color "Red"
        return $false
    }
}

# Function to configure VSS service
function Configure-VssService {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    
    try {
        Write-UILog "Configuring Volume Shadow Copy Service..." -Color "Cyan"
        
        $vss = Get-Service -Name 'VSS' -ErrorAction SilentlyContinue
        if ($vss.Status -ne 'Running') {
            Write-UILog "Starting VSS service..." -Color "Cyan"
            Start-Service VSS
        }
        
        # Configure registry for restore point frequency
        Write-UILog "Configuring restore point settings..." -Color "Cyan"
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
        if (!(Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "SystemRestorePointCreationFrequency" -Value 0 -Type DWord -Force
        
        Write-UILog "VSS service configuration completed successfully" -Color "Green"
        return $true
    }
    catch {
        Write-UILog "Error configuring VSS service: $_" -Color "Red"
        return $false
    }
}

# Function to configure Update service
function Configure-UpdateService {
    param(
        [int]$TaskNumber,
        [int]$TotalTasks
    )
    
    try {
        Write-UILog "Configuring Update Orchestrator Service..." -Color "Cyan"
        
        # Set UsoSvc to Automatic
        Set-Service -Name "UsoSvc" -StartupType Automatic
        
        # Start the service
        Start-Service -Name "UsoSvc"
        
        # Verify the service status
        $service = Get-Service -Name "UsoSvc"
        if ($service.Status -eq 'Running' -and $service.StartType -eq 'Automatic') {
            Write-UILog "Update service configured successfully" -Color "Green"
            return $true
        } else {
            throw "Failed to configure Update service. Status: $($service.Status), StartType: $($service.StartType)"
        }
    }
    catch {
        Write-UILog "Error configuring Update service: $_" -Color "Red"
        return $false
    }
}

# Cleanup function to kill tracked PowerShell child processes
function Cleanup-SpawnedPowerShell {
    foreach ($childPid in $Global:SpawnedPowerShellPIDs) {
        try {
            $proc = Get-Process -Id $childPid -ErrorAction SilentlyContinue
            if ($proc) {
                $proc | Stop-Process -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    $Global:SpawnedPowerShellPIDs = @()
}

# Function to cleanup all spawned processes
function Stop-AllTrackedProcesses {
    Write-UILog "Cleaning up spawned processes..." -Color "Cyan"
    
    foreach ($procInfo in $Global:SpawnedProcesses) {
        try {
            $process = Get-Process -Id $procInfo.Id -ErrorAction SilentlyContinue
            if ($process) {
                Write-UILog "Stopping process: $($procInfo.Name) (ID: $($procInfo.Id))" -Color "Cyan"
                
                # Try graceful shutdown first
                if (-not $process.HasExited) {
                    $process.CloseMainWindow() | Out-Null
                    if (-not $process.WaitForExit(3000)) {
                        # Force kill if graceful shutdown fails
                        $process | Stop-Process -Force
                    }
                }
            }
        }
        catch {
            Write-UILog "Error stopping process $($procInfo.Name): $_" -Color "Red"
        }
    }
    
    # Clear the tracked processes array
    $Global:SpawnedProcesses = @()
}

function Minimize-ConsoleWindow {
    $hwnd = Find-WindowsTerminal
    if ($hwnd -ne [IntPtr]::Zero) {
        [WinAPI]::ShowWindow($hwnd, 6)  # 6 = SW_MINIMIZE
        Write-DebugLog "Minimized terminal window at startup" -Color "Yellow"
    } else {
        #Write-DebugLog "Could not find terminal window to minimize at startup" -Color "Red"
    }
}
Minimize-ConsoleWindow

function Get-WindowsTerminalHostWindow {
    $windowTitle = New-Object System.Text.StringBuilder 256
    $className = New-Object System.Text.StringBuilder 256
    $hostHwnd = [IntPtr]::Zero

    $callback = [WinAPI+EnumWindowsProc]{
        param([IntPtr] $hwnd, [IntPtr] $lparam)
        [void][WinAPI]::GetClassName($hwnd, $className, $className.Capacity)
        $class = $className.ToString()
        if ($class -eq "CASCADIA_HOSTING_WINDOW_CLASS") {
            $script:hostHwnd = $hwnd
            return $false
        }
        return $true
    }
    [void][WinAPI]::EnumWindows($callback, [IntPtr]::Zero)
    return $hostHwnd
}

function Restore-WindowsTerminalHostWindow {
    if ($Global:WindowsTerminalHostHandle -ne $null -and $Global:WindowsTerminalHostHandle -ne [IntPtr]::Zero) {
        Write-DebugLog "Restoring Windows Terminal host window: $Global:WindowsTerminalHostHandle"
        [WinAPI]::ShowWindow($Global:WindowsTerminalHostHandle, [WinAPI]::SW_RESTORE)
        [WinAPI]::SetForegroundWindow($Global:WindowsTerminalHostHandle)
    } else {
        Write-DebugLog "No Windows Terminal host window handle stored for restoration"
    }
}

function Start-TrackedPowerShellProcess {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList = @()
    )
    
    # Use Start-TrackedProcess instead of Start-Process
    $proc = Start-TrackedProcess -FilePath $FilePath -ArgumentList $ArgumentList -PassThru
    if ($proc) {
        $Global:SpawnedPowerShellPIDs += $proc.Id
    }
    return $proc
}

function Start-BaselineAutomatically {
    Write-UILog "Auto-start parameter detected. Starting baseline process automatically..."
    
    if (Test-TasksSelected) {
        # Configure UI elements and start baseline
        $Global:btnStart.IsEnabled = $false
        $Global:btnCancel.IsEnabled = $true
        $Global:MainProgressBar.IsIndeterminate = $true
        
        # Start baseline directly
        Start-Baseline
    } else {
        [System.Windows.MessageBox]::Show(
            "No tasks were selected. Please select at least one task.",
            "Error",
            "OK",
            "Error"
        )
        $Global:Form.Close()
    }
}

function Initialize-BaselineTasks {
    #Write-UILog "Initializing tasks..." -Color "Cyan"
    
    # Debug: Check checkbox states directly
    Write-UILog "Current checkbox states:" -Color "Cyan"
    #Start-Sleep -Seconds 1
    Write-UILog "Custom profile configuration settings: $($Global:cbProfileCustomization.IsChecked )"
    #Start-Sleep -Seconds 1
    Write-UILog "Create System Restore Point: $($Global:cbCreateRestorePoint.IsChecked)" -Color "Cyan"
    #Start-Sleep -Seconds 1
    Write-UILog "Configure Power Profile: $($Global:cbPowerProfile.IsChecked)" -Color "Cyan"
    #Start-Sleep -Seconds 1
    Write-UILog "Install Windows Updates: $($Global:cbWindowsUpdate.IsChecked)" -Color "Cyan"
    #Start-Sleep -Seconds 1
    Write-UILog "Include Driver Updates: $($Global:cbDriverUpdates.IsChecked)" -Color "Cyan"
    #Start-Sleep -Seconds 1
    Write-UILog "Install Microsoft 365: $($Global:cbOffice365.IsChecked)" -Color "Cyan"
    #Start-Sleep -Seconds 1
    Write-UILog "Install Adobe Reader: $($Global:cbAdobeReader.IsChecked)" -Color "Cyan"
    #Start-Sleep -Seconds 1
    Write-UILog "Remove Bloatware: $($Global:cbRemoveBloatware.IsChecked)" -Color "Cyan"
    #Start-Sleep -Seconds 1
    Write-UILog "Configure BitLocker: $($Global:cbBitLocker.IsChecked)" -Color "Cyan"
    #Start-Sleep -Seconds 1
    Write-UILog "Install SentinelOne Endpoint: $($Global:cbSentinelOne.IsChecked)" -Color "Cyan"
    #Start-Sleep -Seconds 1
    Write-UILog "Join Domain: $($Global:cbJoinDomain.IsChecked)" -Color "Cyan"
    #Start-Sleep -Seconds 1
    Write-UILog "Install Sonicwall SSL VPN Client: $($Global:cbSonicwallVpn.IsChecked)" -Color "Cyan"
    #Start-Sleep -Seconds 1
    
    $Global:TaskList = @(
        @{
            Name = "Checking Required Modules"
            Action = { Check-RequiredModules }
            Enabled = { return $true }
            Weight = 5
        }
    )

    # Only add these if Profile Configuration is checked
    if ($Global:cbProfileCustomization.IsChecked) {
        $Global:TaskList += @(
            @{
                Name = "Configuring System Time"
                Action = { Configure-SystemTime }
                Enabled = { return $true }
                Weight = 2
            },
            @{
                Name = "Configuring Privacy Settings"
                Action = { Configure-PrivacySettings }
                Enabled = { return $true }
                Weight = 5
            },
            @{
                Name = "Configuring Offline Files"
                Action = { Configure-OfflineFiles }
                Enabled = { return $true }
                Weight = 2
            },
            @{
                Name = "Configuring VSS Service"
                Action = { Configure-VssService }
                Enabled = { return $true }
                Weight = 2
            },
            @{
                Name = "Configuring Update Service"
                Action = { Configure-UpdateService }
                Enabled = { return $true }
                Weight = 2
            }
        )
    }
    #Start-Sleep -Seconds 1
    # Add tasks based on checkbox states
    if ($Global:cbDeployRMM.IsChecked) {
        Write-UILog "Adding Deploy RMM task" -Color "Cyan"
        $Global:TaskList += @{
            Name = "Installing ConnectWise Automate RMM Agent"
            Action = { Install-CWAutomate }
            Enabled = { return $true }
            Weight = 10
        }
    }
    #Start-Sleep -Seconds 1
    # Add tasks based on checkbox states
    if ($Global:cbCreateRestorePoint.IsChecked) {
        Write-UILog "Adding System Restore Point task" -Color "Cyan"
        $Global:TaskList += @{
            Name = "Creating System Restore Point"
            Action = { Create-RestorePoint }
            Enabled = { return $true }
            Weight = 10
        }
    }
     #Start-Sleep -Seconds 1
     if ($Global:cbProfileCustomization.IsChecked) {
        Write-UILog "Adding Profile configuration task" -Color "Cyan"
        $Global:TaskList += @{
            Name = "Configuring Power Profile"
            Action = { Configure-PowerProfile }
            Enabled = { return $true }
            Weight = 5
        }
    }
    #Start-Sleep -Seconds 1
    if ($Global:cbPowerProfile.IsChecked) {
        Write-UILog "Adding Power Profile task" -Color "Cyan"
        $Global:TaskList += @{
            Name = "Configuring Power Profile"
            Action = { Configure-PowerProfile }
            Enabled = { return $true }
            Weight = 5
        }
    }
    #Start-Sleep -Seconds 1
    if ($Global:cbSentinelOne.IsChecked) {
        Write-UILog "Adding SentinelOne EDR installation task" -Color "Cyan"
        $Global:TaskList += @{
            Name = "Installing SentinelOne EDR"
            Action = { Install-SentinelOneEDR }
            Enabled = { return $true }
            Weight = 15
        }
    }
    #Start-Sleep -Seconds 1
    if ($Global:cbOffice365.IsChecked) {
        Write-UILog "Adding Microsoft 365 installation task" -Color "Cyan"
        $Global:TaskList += @{
            Name = "Installing Microsoft 365"
            Action = { Install-Office365 }
            Enabled = { return $true }
            Weight = 15
        }
    }
    #Start-Sleep -Seconds 1
    if ($Global:cbAdobeReader.IsChecked) {
        Write-UILog "Adding Adobe Reader installation task" -Color "Cyan"
        $Global:TaskList += @{
            Name = "Installing Adobe Reader"
            Action = { Install-AdobeReader }
            Enabled = { return $true }
            Weight = 10
        }
    }
    #Start-Sleep -Seconds 1
    if ($Global:cbRemoveBloatware.IsChecked) {
        Write-UILog "Adding Remove Bloatware task" -Color "Cyan"
        $Global:TaskList += @{
            Name = "Removing Bloatware"
            Action = { Remove-WindowsBloatware }
            Enabled = { return $true }
            Weight = 10
        }
    }
    #Start-Sleep -Seconds 1
    if ($Global:cbBitLocker.IsChecked) {
        Write-UILog "Adding BitLocker configuration task" -Color "Cyan"
        $Global:TaskList += @{
            Name = "Configuring BitLocker"
            Action = { Configure-BitLocker }
            Enabled = { return $true }
            Weight = 10
        }
    }
    #Start-Sleep -Seconds 1
    if ($Global:cbJoinDomain.IsChecked) {
        Write-UILog "Adding Domain Join task" -Color "Cyan"
        $Global:TaskList += @{
            Name = "Joining Domain"
            Action = { Join-Domain }
            Enabled = { return $true }
            Weight = 10
        }
    }
    #Start-Sleep -Seconds 1
    if ($Global:cbWindowsUpdate.IsChecked) {
        Write-UILog "Adding install Windows updates task" -Color "Cyan"
        $Global:TaskList += @{
            Name = "Installing Windows Updates"
            Action = { Configure-WindowsUpdate }
            Enabled = { return $true }
            Weight = 10
        }
    }
    #Start-Sleep -Seconds 1
    if ($Global:cbDriverUpdates.IsChecked) {
        Write-UILog "Adding Driver Updates task" -Color "Cyan"
        $Global:TaskList += @{
            Name = "Installing Driver Updates"
            Action = { Configure-WindowsUpdate -IncludeDrivers $true }
            Enabled = { return $true }
            Weight = 5
        }
    }
    #Start-Sleep -Seconds 1
    if ($Global:cbSonicwallVpn.IsChecked) {
        Write-UILog "Adding Sonicwall SSL VPN installation task" -Color "Cyan"
        $Global:TaskList += @{
            Name = "Installing Sonicwall SSL VPN Client"
            Action = { Install-SonicwallVpnClient }
            Enabled = { return $true }
            Weight = 5
        }
    }
    Write-UILog "Task list initialized with $($Global:TaskList.Count) tasks" -Color "Cyan"
}

# Function to start the baseline process
function Start-Baseline {
    try {
        # Set progress bar to indeterminate mode (scrolling/active) for the entire baseline process
        $Global:Form.Dispatcher.Invoke([Action]{
            $Global:MainProgressBar.IsIndeterminate = $true
        }, [System.Windows.Threading.DispatcherPriority]::Send)

        # Ensure s1t.enc and murls.enc are present
        $SepPath = "$Global:TempFolder\s1t.enc"
        $UrlPath = "$Global:TempFolder\murls.enc"
        if (-not (Test-Path $SepPath)) {
            try {
                Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/s1t.enc" -OutFile $SepPath -ErrorAction Stop
                Write-UILog "Downloaded s1t.enc" -Color "Green"
            } catch {
                Write-UILog "Failed to download s1t.enc: $_" -Color "Red"
                throw
            }
        }
        if (-not (Test-Path $UrlPath)) {
            try {
                Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/murls.enc" -OutFile $UrlPath -ErrorAction Stop
                Write-UILog "Downloaded murls.enc" -Color "Green"
            } catch {
                Write-UILog "Failed to download murls.enc: $_" -Color "Red"
                throw
            }
        }

        # Clear existing log entries and reset progress
        $Global:LogLines.Clear()
        
        # Set progress bar to indeterminate mode (scrolling)
        $Global:Form.Dispatcher.Invoke([Action]{
            $Global:MainProgressBar.Value = 0
            $Global:MainProgressBar.IsIndeterminate = $true
            $Global:ProgressTextDisplay.Text = "Initializing..."
            $Global:CurrentTaskText.Text = "Starting baseline process..."
            $Global:btnStart.IsEnabled = $false
            $Global:btnCancel.IsEnabled = $true
        }, [System.Windows.Threading.DispatcherPriority]::Send)

        # Run initialization in a background thread, then start the timer-driven task queue
        $Global:Form.Dispatcher.BeginInvoke([Action]{
            try {
                # Initialize URLs first
                Write-UILog "Initializing configuration..." -Color "Cyan"
                if (-not (Initialize-URLs)) {
                    throw "Failed to initialize required URLs"
                }

                # Initialize tasks
                Write-UILog "Initializing tasks..." -Color "Cyan"
                Initialize-BaselineTasks

                # Prepare the task queue
                $Global:TaskQueue = [System.Collections.Queue]::new()
                foreach ($task in $Global:TaskList) {
                    $Global:TaskQueue.Enqueue($task)
                }
                $Global:CurrentTask = 0
                $Global:FailedTasks = @()
                $Global:TotalTasks = $Global:TaskQueue.Count

                Write-UILog "Starting baseline process with $($Global:TotalTasks) enabled tasks..."
                Update-Progress -Completed 0 -Total $Global:TotalTasks -Status "Starting baseline process..."

                # Set up a DispatcherTimer to process tasks one by one
                if ($Global:TaskTimer) { $Global:TaskTimer.Stop(); $Global:TaskTimer = $null }
                $Global:TaskTimer = New-Object System.Windows.Threading.DispatcherTimer
                $Global:TaskTimer.Interval = [TimeSpan]::FromMilliseconds(200)
                $Global:TaskTimer.Add_Tick({
                    if ($Global:TaskQueue.Count -eq 0 -or $Global:CancelRequested) {
                        $Global:TaskTimer.Stop()
                        # Show completion message, update UI, etc.
                        $Global:Form.Dispatcher.Invoke([Action]{
                            $Global:btnStart.IsEnabled = $true
                            $Global:btnCancel.IsEnabled = $false
                            $Global:MainProgressBar.IsIndeterminate = $false
                        }, [System.Windows.Threading.DispatcherPriority]::Send)
                        if ($Global:CancelRequested) {
                            Write-UILog "Baseline process cancelled by user" -Color "Yellow"
                        } elseif ($Global:FailedTasks.Count -gt 0) {
                            Write-UILog "Baseline completed with warnings!`n" -Color "Yellow"
                            Write-UILog "The following tasks failed:" -Color "Yellow"
                            foreach ($failedTask in $Global:FailedTasks) {
                                Write-UILog " - $failedTask" -Color "Yellow"
                            }
                            [System.Windows.MessageBox]::Show(
                                "Baseline process completed with warnings! `n`nThe following tasks failed:  `n" +
                                ($Global:FailedTasks -join "`n "),
                                "Baseline Complete",
                                "OK",
                                "Warning"
                            )
                        } else {
                            Write-UILog "Baseline process completed successfully!" -Color "Green"
                            [System.Windows.MessageBox]::Show(
                                "Baseline process completed successfully!",
                                "Success",
                                "OK",
                                "Information"
                            )
                        }
                        return
                    }
                    $task = $Global:TaskQueue.Dequeue()
                    $Global:CurrentTask++
                    Write-UILog "Starting task: $($task.Name)" -Color "Cyan"
                    try {
                        $success = & $task.Action -TaskNumber $Global:CurrentTask -TotalTasks $Global:TotalTasks
                        if (-not $success) {
                            $Global:FailedTasks += $task.Name
                        }
                    } catch {
                        Write-UILog "Error in task $($task.Name): $_" -Color "Red"
                        $Global:FailedTasks += $task.Name
                    }
                    # UI updates and DoEvents are handled by Write-UILog and Update-Progress
                })
                $Global:TaskTimer.Start()
            }
            catch {
                Write-UILog "Error during baseline process: $_" -Color "Red"
                [System.Windows.MessageBox]::Show(
                    "An error occurred during the baseline process: $_",
                    "Error",
                    "OK",
                    "Error"
                )
                $Global:Form.Dispatcher.Invoke([Action]{
                    $Global:btnStart.IsEnabled = $true
                    $Global:btnCancel.IsEnabled = $false
                    $Global:MainProgressBar.IsIndeterminate = $false
                }, [System.Windows.Threading.DispatcherPriority]::Send)
            }
        }, [System.Windows.Threading.DispatcherPriority]::Background)
    }
    catch {
        Write-UILog "Error starting baseline process: $_" -Color "Red"
        $Global:Form.Dispatcher.Invoke([Action]{
            $Global:btnStart.IsEnabled = $true
            $Global:btnCancel.IsEnabled = $false
            $Global:MainProgressBar.IsIndeterminate = $false
        }, [System.Windows.Threading.DispatcherPriority]::Send)
    }
}
#endregion

############################################################################################################
#                                                 XAML GUI code                                            #
#                                                                                                          #
############################################################################################################

#region XAML and UI Functions
# Create the XAML for our GUI
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="900"
        Height="770"
        ResizeMode="CanMinimize"
        Title="MITS Workstation Baseline Utility"
        WindowStartupLocation="CenterScreen">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="Margin" Value="5" />
      <Setter Property="Padding" Value="10,5" />
      <Setter Property="Foreground" Value="White" />
      <Setter Property="BorderThickness" Value="0" />
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}"
                    CornerRadius="3">
              <ContentPresenter HorizontalAlignment="Center"
                                VerticalAlignment="Center" />
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Opacity" Value="0.85" />
        </Trigger>
        <Trigger Property="IsEnabled" Value="False">
          <Setter Property="Opacity" Value="0.5" />
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="ProgressBar">
      <Setter Property="Margin" Value="5" />
      <Setter Property="Height" Value="15" />
      <Setter Property="Foreground" Value="#4d842e" />
      <Setter Property="Background" Value="#E6E6E6" />
      <Setter Property="BorderThickness" Value="0" />
      <Style.Triggers>
        <Trigger Property="IsIndeterminate" Value="True">
          <Setter Property="Foreground" Value="#4d842e" />
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Margin" Value="5,2" />
      <Setter Property="VerticalAlignment" Value="Center" />
    </Style>
  </Window.Resources>
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="90" />
      <!-- Header -->
      <RowDefinition Height="295.654415174488" />
      <!-- Main content -->
      <RowDefinition Height="0.933118603881122*" />
      <!-- Baseline Progress -->
    </Grid.RowDefinitions>
    <!-- Header -->
    <Border Grid.Row="0">
      <Grid>
        <Image x:Name="BannerImage"
               Source="c:\temp\adv-banner.png"
               Stretch="UniformToFill" />
        <TextBlock HorizontalAlignment="Center"
                   VerticalAlignment="Center"
                   FontSize="32"
                   FontWeight="Bold"
                   Foreground="White"
                   Text="Workstation Baseline Utility">
          <TextBlock.Effect>
            <DropShadowEffect Color="Black"
                              BlurRadius="4"
                              Opacity="0.6"
                              ShadowDepth="2" />
          </TextBlock.Effect>
        </TextBlock>
        <TextBlock x:Name="FreeSpaceText"
                   Margin="0,0,20,0"
                   HorizontalAlignment="Right"
                   VerticalAlignment="Center"
                   FontSize="14"
                   Foreground="White"
                   Text="Free Space: 0%" />
      </Grid>
    </Border>
    <!-- Main Content: System Info + Config Options -->
    <Grid Margin="10,11.4,10.4,334.4"
          HorizontalAlignment="Stretch"
          VerticalAlignment="Stretch"
          Grid.Column="0"
          Grid.Row="1"
          Grid.RowSpan="2">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*" />
        <ColumnDefinition Width="*" />
      </Grid.ColumnDefinitions>
      <!-- System Information Panel -->
      <Border Margin="0,0,5,0"
              BorderBrush="#CCCCCC"
              BorderThickness="1"
              Grid.Column="0">
        <Grid Width="409" Height="273" Margin="10">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto" />
            <RowDefinition Height="*" />
          </Grid.RowDefinitions>
          <Grid HorizontalAlignment="Stretch"
                VerticalAlignment="Stretch"
                Grid.Column="0"
                Grid.Row="0"
                Grid.RowSpan="2">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto" />
              <!-- Computer Name -->
              <RowDefinition Height="Auto" />
              <!-- OS Name -->
              <RowDefinition Height="Auto" />
              <!-- OS Version -->
              <RowDefinition Height="Auto" />
              <!-- Processor -->
              <RowDefinition Height="Auto" />
              <!-- Memory -->
              <RowDefinition Height="Auto" />
              <!-- System Drive Row -->
              <RowDefinition Height="Auto" />
              <!-- System Drive Bar -->
              <RowDefinition Height="Auto" />
              <!-- Memory Usage Row -->
              <RowDefinition Height="Auto" />
              <!-- Memory Usage Bar -->
              <RowDefinition Height="Auto" />
              <!-- Last Boot Time -->
              <RowDefinition Height="Auto" />
              <!-- Uptime -->
              <RowDefinition Height="*" />
              <!-- Spacer -->
            </Grid.RowDefinitions>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="140" />
              <ColumnDefinition Width="*" />
            </Grid.ColumnDefinitions>
            <!-- Computer Name -->
            <TextBlock Margin="2.6,4.8,0,4.8"
                       HorizontalAlignment="Left"
                       VerticalAlignment="Center"
                       FontWeight="Bold"
                       Text="Computer Name:"
                       Grid.Column="0"
                       Grid.Row="0" />
            <TextBlock x:Name="ComputerNameText"
                       Margin="0,5"
                       Text="WORKSTATION"
                       Grid.Column="1"
                       Grid.Row="0" />
            <!-- Operating System -->
            <TextBlock Margin="2.6,4.8,0,4.8"
                       HorizontalAlignment="Left"
                       VerticalAlignment="Center"
                       FontWeight="Bold"
                       Text="Operating System:"
                       Grid.Column="0"
                       Grid.Row="1" />
            <TextBlock x:Name="OSNameText"
                       Margin="0,5"
                       Text="Windows 11"
                       Grid.Column="1"
                       Grid.Row="1" />
            <!-- OS Version -->
            <TextBlock Margin="2.6,4.8,0,4.8"
                       HorizontalAlignment="Left"
                       VerticalAlignment="Center"
                       FontWeight="Bold"
                       Text="OS Version:"
                       Grid.Column="0"
                       Grid.Row="2" />
            <TextBlock x:Name="OSVersionText"
                       Margin="0,5"
                       Text="10.0.22631"
                       Grid.Column="1"
                       Grid.Row="2" />
            <!-- Processor -->
            <TextBlock Margin="2.6,4.8,0,4.8"
                       HorizontalAlignment="Left"
                       VerticalAlignment="Center"
                       FontWeight="Bold"
                       Text="Processor:"
                       Grid.Column="0"
                       Grid.Row="3" />
            <TextBlock x:Name="ProcessorText"
                       Margin="0,5"
                       Text="Intel Core i7"
                       Grid.Column="1"
                       Grid.Row="3" />
            <!-- Memory -->
            <TextBlock Margin="2.6,4.8,0,4.8"
                       HorizontalAlignment="Left"
                       VerticalAlignment="Center"
                       FontWeight="Bold"
                       Text="Memory:"
                       Grid.Column="0"
                       Grid.Row="4" />
            <TextBlock x:Name="MemoryText"
                       Margin="0,5"
                       Text="16 GB"
                       Grid.Column="1"
                       Grid.Row="4" />
            <!-- System Drive Row -->
            <TextBlock Margin="2.6,4.8,0,4.8"
                       HorizontalAlignment="Left"
                       VerticalAlignment="Center"
                       FontWeight="Bold"
                       Text="System Drive:"
                       Grid.Column="0"
                       Grid.Row="5" />
            <TextBlock x:Name="SystemDriveText"
                       Margin="0,5"
                       HorizontalAlignment="Left"
                       VerticalAlignment="Center"
                       Text="C: 100 GB free"
                       Grid.Column="1"
                       Grid.Row="5" />
            <!-- System Drive Bar -->
            <ProgressBar x:Name="DriveSpaceBar"
                         Height="15"
                         Margin="0,0,0,0"
                         HorizontalAlignment="Stretch"
                         VerticalAlignment="Center"
                         Grid.Column="0"
                         Grid.ColumnSpan="2"
                         Grid.Row="6" />
            <!-- Memory Usage Row -->
            <TextBlock Margin="2.6,4.8,0,4.8"
                       HorizontalAlignment="Left"
                       VerticalAlignment="Center"
                       FontWeight="Bold"
                       Text="Memory Usage:"
                       Grid.Column="0"
                       Grid.Row="7" />
            <TextBlock x:Name="MemoryUsageText"
                       Margin="0,5"
                       HorizontalAlignment="Left"
                       VerticalAlignment="Center"
                       Text="0% used (0 GB / 0 GB)"
                       Grid.Column="1"
                       Grid.Row="7" />
            <!-- Memory Usage Bar -->
            <ProgressBar x:Name="MemoryUsageBar"
                         Height="15"
                         Margin="0,0,0,0"
                         HorizontalAlignment="Stretch"
                         VerticalAlignment="Center"
                         Grid.Column="0"
                         Grid.ColumnSpan="2"
                         Grid.Row="8" />
            <!-- Last Boot Time -->
            <TextBlock Width="87"
                       Height="14.800000000000011"
                       Margin="3,0,0,0"
                       HorizontalAlignment="Left"
                       VerticalAlignment="Center"
                       FontWeight="Bold"
                       Text="Last Boot Time:"
                       Grid.Column="0"
                       Grid.Row="9" />
            <TextBlock x:Name="LastBootText"
                       Margin="0,8,0,6.40000000000001"
                       HorizontalAlignment="Stretch"
                       VerticalAlignment="Stretch"
                       Text="2023-05-01 08:00:00"
                       Grid.Column="1"
                       Grid.Row="9" />
            <!-- Uptime -->
            <TextBlock Width="45"
                       Height="25.199999999999989"
                       Margin="6,0,0,0"
                       HorizontalAlignment="Left"
                       VerticalAlignment="Center"
                       FontWeight="Bold"
                       Text="Uptime:"
                       Grid.Column="0"
                       Grid.Row="10"
                       Grid.RowSpan="2" />
            <TextBlock x:Name="UptimeText"
                       Margin="0,3.00000000000003,0,13.8"
                       HorizontalAlignment="Stretch"
                       VerticalAlignment="Stretch"
                       Text="1 day, 2 hours, 15 minutes"
                       Grid.Column="1"
                       Grid.Row="11" />
            <!-- Spacer -->
            <TextBlock Text="" Grid.Column="0" Grid.Row="11" />
          </Grid>
        </Grid>
      </Border>
      <!-- Configuration Options Panel -->
      <Border Margin="5,0,0,0"
              BorderBrush="#CCCCCC"
              BorderThickness="1"
              Grid.Column="1">
        <Grid Width="409" Height="281" Margin="10">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto" />
            <RowDefinition Height="*" />
          </Grid.RowDefinitions>
          <TextBlock Margin="2.6,0,-2.6,9.6"
                     HorizontalAlignment="Stretch"
                     VerticalAlignment="Stretch"
                     FontSize="14"
                     FontWeight="Bold"
                     Text="Configuration Options"
                     Grid.Column="0"
                     Grid.Row="0" />
          <Grid Grid.Row="1">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="200" />
              <ColumnDefinition Width="*" />
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
              <RowDefinition Height="Auto" />
            </Grid.RowDefinitions>
            <CheckBox x:Name="cbDeployRMM"
                      Content="Deploy RMM"
                      IsChecked="False"
                      Grid.Column="0"
                      Grid.Row="0" />
            <TextBlock VerticalAlignment="Center"
                       Foreground="#666666"
                       Text="(Install ConnectWise Automate agent)"
                       Grid.Column="1"
                       Grid.Row="0" />
            <CheckBox x:Name="cbProfileCustomization"
                      Content=" Profile Configuration"
                      Margin="4.79999999999995,0,4.80000000000004,0"
                      HorizontalAlignment="Stretch"
                      VerticalAlignment="Center"
                      IsChecked="True"
                      Grid.Column="0"
                      Grid.Row="1" />
            <TextBlock Margin="0,1.39999999999998,0,18.6"
                       HorizontalAlignment="Stretch"
                       VerticalAlignment="Stretch"
                       Foreground="#FF666666"
                       Text=" Standard profile configurations"
                       Grid.Column="1"
                       Grid.Row="1"
                       Grid.RowSpan="2" />
            <CheckBox x:Name="cbPowerProfile"
                      Content=" Power Profile Settings"
                      FontSize="12"
                      IsChecked="True"
                      Grid.Column="0"
                      Grid.Row="2" />
            <TextBlock VerticalAlignment="Center"
                       FontSize="12"
                       Foreground="#666666"
                       Text=" Disable sleep, hibernation, fast startup"
                       Grid.Column="1"
                       Grid.Row="2" />
            <CheckBox x:Name="cbWindowsUpdate"
                      Content=" Windows Updates"
                      IsChecked="True"
                      Grid.Column="0"
                      Grid.Row="3" />
            <TextBlock VerticalAlignment="Center"
                       Foreground="#666666"
                       Text=" Install available Windows updates"
                       Grid.Column="1"
                       Grid.Row="3" />
            <CheckBox x:Name="cbDriverUpdates"
                      Content=" Include Driver Updates"
                      IsChecked="False"
                      Grid.Column="0"
                      Grid.Row="4" />
            <TextBlock VerticalAlignment="Center"
                       Foreground="#666666"
                       Text=" Include system driver updates"
                       Grid.Column="1"
                       Grid.Row="4" />
            <CheckBox x:Name="cbOffice365"
                      Content=" Microsoft 365"
                      IsChecked="True"
                      Grid.Column="0"
                      Grid.Row="5" />
            <TextBlock VerticalAlignment="Center"
                       Foreground="#666666"
                       Text=" Microsoft 365 Apps for Business"
                       Grid.Column="1"
                       Grid.Row="5" />
            <CheckBox x:Name="cbAdobeReader"
                      Content=" Adobe Reader"
                      IsChecked="True"
                      Grid.Column="0"
                      Grid.Row="6" />
            <TextBlock VerticalAlignment="Center"
                       Foreground="#666666"
                       Text=" Adobe Reader"
                       Grid.Column="1"
                       Grid.Row="6" />
            <CheckBox x:Name="cbRemoveBloatware"
                      Content=" Remove Bloatware"
                      IsChecked="True"
                      Grid.Column="0"
                      Grid.Row="11" />
            <TextBlock VerticalAlignment="Center"
                       Foreground="#666666"
                       Text=" Remove unnecessary apps &amp; features"
                       Grid.Column="1"
                       Grid.Row="11" />
            <CheckBox x:Name="cbJoinDomain"
                      Content=" Domain Join"
                      IsChecked="True"
                      Grid.Column="0"
                      Grid.Row="12" />
            <TextBlock Margin="0,0,0,0"
                       HorizontalAlignment="Stretch"
                       VerticalAlignment="Center"
                       Foreground="#FF666666"
                       Text=" Join machine to local domain"
                       Grid.Column="1"
                       Grid.Row="12" />
            <CheckBox x:Name="cbBitLocker"
                      Content=" BitLocker Encryption"
                      IsChecked="True"
                      Grid.Column="0"
                      Grid.Row="8" />
            <TextBlock VerticalAlignment="Center"
                       Foreground="#666666"
                       Text=" Configure BitLocker encryption"
                       Grid.Column="1"
                       Grid.Row="8" />
            <CheckBox x:Name="cbSentinelOne"
                      Content=" SentinelOne EDR"
                      IsChecked="True"
                      Grid.Column="0"
                      Grid.Row="9" />
            <TextBlock VerticalAlignment="Center"
                       Foreground="#666666"
                       Text=" Install SentinelOne EDR"
                       Grid.Column="1"
                       Grid.Row="9" />
            <CheckBox x:Name="cbCreateRestorePoint"
                      Content=" System Restore Point"
                      IsChecked="True"
                      Grid.Column="0"
                      Grid.Row="10" />
            <TextBlock VerticalAlignment="Center"
                       Foreground="#FF666666"
                       Text=" Create a system restore checkpoint"
                       Grid.Column="1"
                       Grid.Row="10" />
            <CheckBox x:Name="cbSonicwallVpn"
                      Content=" Sonicwall SSL VPN"
                      IsChecked="True"
                      Grid.Column="0"
                      Grid.Row="7" />
            <TextBlock Margin="0,0,0,0"
                       HorizontalAlignment="Stretch"
                       VerticalAlignment="Center"
                       Foreground="#666666"
                       Text=" Install Sonicwall SSL VPN Client"
                       Grid.Column="1"
                       Grid.Row="7" />
            <CheckBox x:Name="cbSystemTime"
                      Content="Configure System Time"
                      IsChecked="True"
                      Visibility="Collapsed"
                      Grid.Column="0"
                      Grid.Row="13" />
            <TextBlock VerticalAlignment="Center"
                       Foreground="#666666"
                       Text=""
                       Visibility="Collapsed"
                       Grid.Column="1"
                       Grid.Row="13" />
            <CheckBox x:Name="cbPrivacySettings"
                      Content="Configure Privacy Settings"
                      IsChecked="True"
                      Visibility="Collapsed"
                      Grid.Column="0"
                      Grid.Row="14" />
            <TextBlock VerticalAlignment="Center"
                       Foreground="#666666"
                       Text=""
                       Visibility="Collapsed"
                       Grid.Column="1"
                       Grid.Row="14" />
            <CheckBox x:Name="cbOfflineFiles"
                      Content="Configure Offline Files"
                      IsChecked="True"
                      Visibility="Collapsed"
                      Grid.Column="0"
                      Grid.Row="15" />
            <TextBlock VerticalAlignment="Center"
                       Foreground="#666666"
                       Text=""
                       Visibility="Collapsed"
                       Grid.Column="1"
                       Grid.Row="15" />
            <CheckBox x:Name="cbVssService"
                      Content="Configure VSS Service"
                      IsChecked="True"
                      Visibility="Collapsed"
                      Grid.Column="0"
                      Grid.Row="16" />
            <TextBlock VerticalAlignment="Center"
                       Foreground="#666666"
                       Text=""
                       Visibility="Collapsed"
                       Grid.Column="1"
                       Grid.Row="16" />
          </Grid>
        </Grid>
      </Border>
    </Grid>
    <!-- Baseline Progress Section -->
    <Border Margin="10,25.2,10.4,9.39999999999998"
            HorizontalAlignment="Stretch"
            VerticalAlignment="Stretch"
            BorderBrush="#CCCCCC"
            BorderThickness="1"
            Grid.Column="0"
            Grid.Row="2">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto" />
          <!-- Progress Header -->
          <RowDefinition Height="*" />
          <!-- Log Output -->
          <RowDefinition Height="Auto" />
          <!-- Progress Bar -->
          <RowDefinition Height="Auto" />
          <!-- Buttons -->
        </Grid.RowDefinitions>
        <!-- Progress Header -->
        <Border Background="#F2F2F2"
                BorderBrush="#CCCCCC"
                BorderThickness="0,0,0,1"
                Grid.Row="0">
          <TextBlock Margin="10,5"
                     FontSize="14"
                     FontWeight="Bold"
                     Text="Baseline Progress" />
        </Border>
        <!-- Progress Details and Log Output -->
        <Grid Margin="10" Grid.Row="1">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto" />
            <RowDefinition Height="*" />
          </Grid.RowDefinitions>
          <StackPanel Grid.Row="0">
            <TextBlock x:Name="ProgressTextDisplay"
                       Margin="0,0,0,5"
                       Text="Overall Progress: 0%" />
            <TextBlock x:Name="CurrentTaskText"
                       Margin="0,0,0,5"
                       Text="Ready to start baseline process" />
          </StackPanel>
          <Border BorderBrush="#CCCCCC" BorderThickness="1" Grid.Row="1">
            <ScrollViewer x:Name="LogScroller"
                          Background="#FAFAFA"
                          VerticalScrollBarVisibility="Auto">
              <ItemsControl x:Name="LogOutput" Margin="5">
                <ItemsControl.ItemTemplate>
                  <DataTemplate>
                    <TextBlock Margin="0,1" Text="{Binding}" TextWrapping="Wrap" />
                  </DataTemplate>
                </ItemsControl.ItemTemplate>
              </ItemsControl>
            </ScrollViewer>
          </Border>
        </Grid>
        <Grid Margin="0,0,0,0" Background="#F2F2F2" Grid.Row="2">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*" />
            <ColumnDefinition Width="Auto" />
            <ColumnDefinition Width="Auto" />
          </Grid.ColumnDefinitions>
          <ProgressBar x:Name="MainProgressBar"
                       Margin="10"
                       IsIndeterminate="False"
                       Value="0"
                       Grid.Column="0" />
          <Button x:Name="btnStart"
                  Content="Start Baseline"
                  Width="125"
                  Height="35"
                  Margin="0,10,5,10"
                  Background="#4d842e"
                  Grid.Column="1" />
          <Button x:Name="btnCancel"
                  Content="Abort Process"
                  Width="125"
                  Height="35"
                  Margin="5,10,10,10"
                  Background="#D32F2F"
                  IsEnabled="False"
                  Grid.Column="2" />
        </Grid>
        <!-- Progress Bar -->
        <!-- Button Area -->
      </Grid>
    </Border>
  </Grid>
</Window>
"@

# Import WPF components
$reader = New-Object System.Xml.XmlNodeReader $xaml
$Global:Form = [Windows.Markup.XamlReader]::Load($reader)

#endregion 

# Attach cleanup to WPF window close event
$Global:Form.Add_Closed({
    Remove-SensitiveFiles -Force
})

# Get form elements by name
$form_Elements = @(
    'FreeSpaceText', 'ComputerNameText', 'OSNameText', 'OSVersionText',
    'ProcessorText', 'MemoryText', 'SystemDriveText', 'DriveSpaceBar', 'LastBootText',
    'UptimeText', 'MemoryUsageBar', 'MemoryUsageText', 'cbProfileCustomization', 'cbSystemTime', 'cbPrivacySettings', 'cbOfflineFiles', 'cbVssService',
    'cbPowerProfile', 'cbWindowsUpdate', 'cbDriverUpdates', 'cbDeployRMM', 'cbOffice365', 'cbAdobeReader',
    'cbRemoveBloatware', 'cbSonicwallVpn', 'cbBitLocker', 'cbSentinelOne', 'cbCreateRestorePoint', 'cbJoinDomain',
    'ProgressTextDisplay', 'CurrentTaskText', 'LogScroller', 'LogOutput', 'MainProgressBar',
    'btnStart', 'btnCancel'
)

# Create variables for each named element
foreach ($element in $form_Elements) {
    Set-Variable -Name "Global:$element" -Value $Global:Form.FindName($element)
}

foreach ($element in $form_Elements) {
    if (-not (Get-Variable -Name "Global:$element" -ValueOnly)) {
        Write-Host "Warning: Could not find control $element in the XAML." -ForegroundColor Yellow
    }
}

# Enable all checkboxes safely after initialization
$checkboxes = @(
    $Global:cbDeployRMM,
    $Global:cbProfileCustomization,
    $Global:cbPowerProfile,
    $Global:cbWindowsUpdate,
    $Global:cbDriverUpdates,
    $Global:cbOffice365,
    $Global:cbAdobeReader,
    $Global:cbSonicwallVpn,
    $Global:cbBitLocker,
    $Global:cbSentinelOne,
    $Global:cbCreateRestorePoint,
    $Global:cbRemoveBloatware,
    $Global:cbJoinDomain
)
foreach ($cb in $checkboxes) {
    if ($cb) { $cb.IsEnabled = $true }
    else { Write-Host "Warning: Checkbox is null!" -ForegroundColor Yellow }
}

# Set window icon if the icon file exists
if (Test-Path $iconPath) {
    $iconUri = New-Object System.Uri($iconPath)
    $iconSource = New-Object System.Windows.Media.Imaging.BitmapImage($iconUri)
    $Global:Form.Icon = $iconSource
}

# Bind LogOutput to LogLines
$Global:LogOutput.ItemsSource = $Global:LogLines

# Get system information
Get-SystemInfo

# Initialize progress tracking variables
$script:CurrentTaskNumber = 0
$script:TotalTasks = 0

# Set up event handlers
$Global:cbProfileCustomization.Add_Checked({
    if ($Global:cbSystemTime) { $Global:cbSystemTime.IsEnabled = $true }
    if ($Global:cbPrivacySettings) { $Global:cbPrivacySettings.IsEnabled = $true }
    if ($Global:cbOfflineFiles) { $Global:cbOfflineFiles.IsEnabled = $true }
    if ($Global:cbVssService) { $Global:cbVssService.IsEnabled = $true }
})

$Global:cbProfileCustomization.Add_Unchecked({
    if ($Global:cbSystemTime) { $Global:cbSystemTime.IsEnabled = $false }
    if ($Global:cbPrivacySettings) { $Global:cbPrivacySettings.IsEnabled = $false }
    if ($Global:cbOfflineFiles) { $Global:cbOfflineFiles.IsEnabled = $false }
    if ($Global:cbVssService) { $Global:cbVssService.IsEnabled = $false }
})

# Start button click event
$Global:btnStart.Add_Click({
    # Check if any tasks are selected
    if (-not (Test-TasksSelected)) {
        [System.Windows.MessageBox]::Show(
            "Please select at least one task to perform before starting the baseline process.",
            "No Tasks Selected",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        )
        
        # Highlight the options section by flashing the checkboxes
        $Global:Form.Dispatcher.Invoke([Action]{
            $checkboxes = @(
                $Global:cbDeployRMM,
                $Global:cbProfileCustomization,
                $Global:cbPowerProfile,
                $Global:cbWindowsUpdate,
                $Global:cbDriverUpdates,
                $Global:cbOffice365,
                $Global:cbAdobeReader,
                $Global:cbSonicwallVpn
                $Global:cbBitLocker,
                $Global:cbSentinelOne,
                $Global:cbCreateRestorePoint,
                $Global:cbRemoveBloatware,         
                $Global:cbJoinDomain
            )
            
            # Store original backgrounds
            $originalBackgrounds = $checkboxes | ForEach-Object { $_.Background }
            
            # Flash background color 3 times
            for ($i = 0; $i -lt 3; $i++) {
                # Highlight
                foreach ($cb in $checkboxes) {
                    $cb.Background = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Colors]::LightYellow)
                }
                $Global:Form.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
                Start-Sleep -Milliseconds 200
                
                # Restore
                for ($j = 0; $j -lt $checkboxes.Count; $j++) {
                    $checkboxes[$j].Background = $originalBackgrounds[$j]
                }
                $Global:Form.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
                Start-Sleep -Milliseconds 200
            }
        })
        return
    }

    $sentinel = Get-WmiObject -Class Win32_Product | Where-Object { 
        $_.Name -eq "*Sentinel Agent*" 
    }
    if ($sentinel) {
        $Global:cbSentinelOne.IsChecked = $false
        $Global:cbSentinelOne.IsEnabled = $false
        $Global:cbSentinelOne.Content = "SentinelOne EDR (Installed)"
    }

    # Clear existing log entries
    $Global:LogLines.Clear()
    $Global:MainProgressBar.Value = 0
    $Global:ProgressTextDisplay.Text = "Overall Progress: 0%"
    $Global:CurrentTaskText.Text = "Starting baseline process..."
    
    Write-UILog "Starting baseline process..."
    Start-Sleep -Milliseconds 50  # Allow UI to update
    Start-Baseline
})

# Cancel button click event
$Global:btnCancel.Add_Click({
    $Global:CancelRequested = $true
    $Global:btnCancel.IsEnabled = $false
    Write-UILog "Cancellation requested. Waiting for current task to complete..." -Color "Orange"
})

# Add click handlers for all checkboxes
$Global:cbCreateRestorePoint.Add_Click({
    Write-UILog "Create System Restore Point checkbox clicked: $($Global:cbCreateRestorePoint.IsChecked)" -Color "Cyan"
})

$Global:cbPowerProfile.Add_Click({
    Write-UILog "Configure Power Profile checkbox clicked: $($Global:cbPowerProfile.IsChecked)" -Color "Cyan"
})

$Global:cbProfileCustomization.Add_Click({
    Write-UILog "Standard profile configurations checkbox clicked: $($Global:cbProfileCustomization.IsChecked)" -color "Cyan" 
})

$Global:cbWindowsUpdate.Add_Click({
    Write-UILog "Configure Windows Update checkbox clicked: $($Global:cbWindowsUpdate.IsChecked)" -Color "Cyan"
})

$Global:cbDriverUpdates.Add_Click({
    Write-UILog "Include Driver Updates checkbox clicked: $($Global:cbDriverUpdates.IsChecked)" -Color "Cyan"
})

$Global:cbDeployRMM.Add_Click({
    Write-UILog "Deploy RMM checkbox clicked: $($Global:cbDeployRMM.IsChecked)" -Color "Cyan"
})

$Global:cbOffice365.Add_Click({
    Write-UILog "Install Microsoft 365 checkbox clicked: $($Global:cbOffice365.IsChecked)" -Color "Cyan"
})

$Global:cbAdobeReader.Add_Click({
    Write-UILog "Install Adobe Reader checkbox clicked: $($Global:cbAdobeReader.IsChecked)" -Color "Cyan"
})

$Global:cbRemoveBloatware.Add_Click({
    Write-UILog "Remove Bloatware checkbox clicked: $($Global:cbRemoveBloatware.IsChecked)" -Color "Cyan"
})

$Global:cbSonicwallVpn.Add_Click({
    Write-UILog "Install Sonicwall SSL VPN checkbox clicked: $($Global:cbSonicwallVpn.IsChecked)" -Color "Cyan"
})

$Global:cbBitLocker.Add_Click({
    Write-UILog "Configure BitLocker checkbox clicked: $($Global:cbBitLocker.IsChecked)" -Color "Cyan"
})

$Global:cbSentinelOne.Add_Click({
    Write-UILog "Install SentinelOne Endpoint checkbox clicked: $($Global:cbSentinelOne.IsChecked)" -Color "Cyan"
})

$Global:cbJoinDomain.Add_Click({
    Write-UILog "Join Domain checkbox clicked: $($Global:cbJoinDomain.IsChecked)" -Color "Cyan"
})

# Set up initial UI state
$Global:Form.Add_Loaded({
    # --- Ensure window is on top and focused ---
    $Global:Form.Topmost = $true
    $Global:Form.Activate()
    $Global:Form.Focus()
    # Optionally, set Topmost back to false if you don't want it to stay always-on-top:
    # $Global:Form.Topmost = $false

    # Disable the Start button immediately
    $Global:Form.Dispatcher.Invoke([Action]{
        $Global:btnStart.IsEnabled = $false
        # Disable all configuration checkboxes at startup
        $checkboxes = @(
            $Global:cbDeployRMM,
            $Global:cbProfileCustomization,
            $Global:cbPowerProfile,
            $Global:cbWindowsUpdate,
            $Global:cbDriverUpdates,
            $Global:cbOffice365,
            $Global:cbAdobeReader,
            $Global:cbSonicwallVpn,
            $Global:cbBitLocker,
            $Global:cbSentinelOne,
            $Global:cbCreateRestorePoint,
            $Global:cbRemoveBloatware,
            $Global:cbJoinDomain
        )
        foreach ($cb in $checkboxes) { $cb.IsEnabled = $false }
    }, [System.Windows.Threading.DispatcherPriority]::Send)

    $Global:Form.Dispatcher.Invoke({
        # SentinelOne check
        $sentinel = Get-WmiObject -Class Win32_Product | Where-Object {
            $_.Name -like "*SentinelOne*" -or $_.Name -like "*Sentinel Agent*"
        }
        if ($sentinel) {
            $Global:cbSentinelOne.IsChecked = $false
            $Global:cbSentinelOne.IsEnabled = $false
            $Global:cbSentinelOne.Content = "SentinelOne EDR (Installed)"
        }
        # ... other detection logic ...
    }, [System.Windows.Threading.DispatcherPriority]::Send)

    # --- Initialization Timer Logic ---
    $script:initSeconds = 0
    $script:initTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:initTimer.Interval = [TimeSpan]::FromSeconds(1)
    $script:initTimer.Add_Tick({
        $script:initSeconds++
        $Global:Form.Dispatcher.Invoke([Action]{
            $Global:CurrentTaskText.Text = "Initializing... ($script:initSeconds seconds)"
        })
    })
    $script:initSeconds = 0
    $script:initTimer.Start()

    Write-UILog "Starting baseline initialization, please wait..." -Color "Cyan"
    
    # Run initialization in a background thread
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.BeginInvoke(
        [Action]{
            try {
                # Download required files first
                $SepPath = "$Global:TempFolder\s1t.enc"
                $UrlPath = "$Global:TempFolder\murls.enc"
                if (-not (Test-Path $SepPath)) {
                    try {
                        Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/s1t.enc" -OutFile $SepPath -ErrorAction Stop
                        #Write-UILog "Downloaded s1t.enc" -Color "Green"
                    } catch {
                        Write-UILog "Failed to download s1t.enc: $_" -Color "Red"
                        throw
                    }
                    $Global:Form.Dispatcher.Invoke([Action]{ [System.Windows.Forms.Application]::DoEvents() })
                }
                if (-not (Test-Path $UrlPath)) {
                    try {
                        Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/murls.enc" -OutFile $UrlPath -ErrorAction Stop
                        #Write-UILog "Downloaded murls.enc" -Color "Green"
                    } catch {
                        Write-UILog "Failed to download murls.enc: $_" -Color "Red"
                        throw
                    }
                    $Global:Form.Dispatcher.Invoke([Action]{ [System.Windows.Forms.Application]::DoEvents() })
                }

                # Set window icon and banner
                if (Test-Path $iconPath) {
                    $icon = New-Object System.Windows.Media.Imaging.IconBitmapDecoder(
                        (New-Object System.Uri($iconPath, [System.UriKind]::Absolute)),
                        [System.Windows.Media.Imaging.BitmapCreateOptions]::None,
                        [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
                    )
                    $Global:Form.Dispatcher.Invoke({ $Global:Form.Icon = $icon.Frames[0] })
                    $Global:Form.Dispatcher.Invoke([Action]{ [System.Windows.Forms.Application]::DoEvents() })
                }

                if (Test-Path $bannerPath) {
                    $bannerUri = New-Object System.Uri($bannerPath, [System.UriKind]::Absolute)
                    $bannerImage = New-Object System.Windows.Media.Imaging.BitmapImage($bannerUri)
                    $Global:Form.Dispatcher.Invoke({ $Global:Form.FindName("BannerImage").Source = $bannerImage })
                    $Global:Form.Dispatcher.Invoke([Action]{ [System.Windows.Forms.Application]::DoEvents() })
                }

                # Initialize URLs
                Write-UILog "Secure URLs initialized successfully..." -Color "Cyan"
                if (-not (Initialize-URLs)) {
                    throw "Failed to initialize required URLs"
                }
                $Global:Form.Dispatcher.Invoke([Action]{ [System.Windows.Forms.Application]::DoEvents() })

                Write-UILog "Checking for existing applications..." -Color "Cyan"
                # Get system information
                Get-SystemInfo
                $Global:Form.Dispatcher.Invoke([Action]{ [System.Windows.Forms.Application]::DoEvents() })

                # Check installed software and update UI accordingly
                $Global:Form.Dispatcher.Invoke({
                    
                    # SonicWall NetExtender check
                    $SWNE = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                    HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                    Where-Object { $_.DisplayName -like "*SonicWall NetExtender*" }
                    if ($SWNE) {
                    $Global:cbSonicwallVpn.IsChecked = $false
                    $Global:cbSonicwallVpn.IsEnabled = $false
                    $Global:cbSonicwallVpn.Content = "SW NetExtender (Installed)"
                    }


                    # Adobe Reader check
                    $possiblePaths = @(
                        "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
                        "${env:ProgramFiles}\Adobe\Acrobat Reader DC\Reader\AcroRd64.exe",
                        "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
                        "${env:ProgramFiles}\Adobe\Acrobat DC\Acrobat\Acrobat.exe"
                    )

                    $acrobatInstalled = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*Adobe Acrobat*" }

                    $installedPath = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

                    if ($installedPath -and $acrobatInstalled) {
                        $version = $acrobatInstalled.DisplayVersion
                        $name = $acrobatInstalled.DisplayName
                        $Global:cbAdobeReader.IsChecked = $false
                        $Global:cbAdobeReader.IsEnabled = $false
                        $Global:cbAdobeReader.Content = "$name (v$version)"
                    }

                    # Office 365 check
                    $O365 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                        HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                            Where-Object { $_.DisplayName -like "*Microsoft 365 Apps*" }
                    if ($O365) {
                        $Global:cbOffice365.IsChecked = $false
                        $Global:cbOffice365.IsEnabled = $false
                        $Global:cbOffice365.Content = "Microsoft 365 (Installed)"
                    }

                    # SentinelOne check
                    $sentinel = Get-WmiObject -Class Win32_Product | Where-Object { 
                        $_.Name -like "*SentinelOne*" -or $_.Name -like "*Sentinel Agent*" 
                    }
                    if ($sentinel) {
                        $Global:cbSentinelOne.IsChecked = $false
                        $Global:cbSentinelOne.IsEnabled = $false
                        $Global:cbSentinelOne.Content = "SentinelOne EDR (Installed)"
                    }
                   
                    #  CWAutomate check
                    $CWAutomateInstalled = $false
                    if (Test-Path 'C:\Windows\LTSvc') {
                        $CWAutomateInstalled = $true
                    } else {
                        try {
                            $reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\LabTech\Service' -ErrorAction SilentlyContinue
                            if ($reg -and $reg.BasePath -eq 'C:\Windows\LTSvc') {
                                $CWAutomateInstalled = $true
                            }
                        } catch {}
                    }
                    if ($CWAutomateInstalled) {
                        $Global:cbDeployRMM.IsChecked = $false
                        $Global:cbDeployRMM.IsEnabled = $false
                        $Global:cbDeployRMM.Content = "CWAutomate Agent (Installed)"
                    }

                    # BitLocker check
                    try {
                        $bitLockerStatus = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
                        if ($bitLockerStatus -and $bitLockerStatus.ProtectionStatus -eq 'On') {
                            $Global:cbBitLocker.IsChecked = $false
                            $Global:cbBitLocker.IsEnabled = $false
                            $Global:cbBitLocker.Content = "BitLocker Encryption (Enabled)"
                        }
                    } catch {}
                })

                Write-UILog "Background initialization completed" -Color "Green"

                # Re-enable all configuration checkboxes after initialization
                $Global:Form.Dispatcher.Invoke([Action]{
                    $checkboxes = @(
                        $Global:cbDeployRMM,
                        $Global:cbProfileCustomization,
                        $Global:cbPowerProfile,
                        $Global:cbWindowsUpdate,
                        $Global:cbDriverUpdates,
                        $Global:cbOffice365,
                        $Global:cbAdobeReader,
                        $Global:cbSonicwallVpn,
                        $Global:cbBitLocker,
                        $Global:cbSentinelOne,
                        $Global:cbCreateRestorePoint,
                        $Global:cbRemoveBloatware,
                        $Global:cbJoinDomain
                    )
                    foreach ($cb in $checkboxes) {
                        $cb.IsEnabled = $true
                    }
                }, [System.Windows.Threading.DispatcherPriority]::Send)
                $Global:Form.Dispatcher.Invoke([Action]{ [System.Windows.Forms.Application]::DoEvents() })
                $Global:Form.Dispatcher.Invoke({
                    # SentinelOne check
                    $sentinel = Get-WmiObject -Class Win32_Product | Where-Object {
                        $_.Name -like "*SentinelOne*" -or $_.Name -like "*Sentinel Agent*"
                    }
                    if ($sentinel) {
                        $Global:cbSentinelOne.IsChecked = $false
                        $Global:cbSentinelOne.IsEnabled = $false
                        $Global:cbSentinelOne.Content = "SentinelOne EDR (Installed)"
                    }
                    # ... other detection logic ...
                }, [System.Windows.Threading.DispatcherPriority]::Send)
                # Detection logic: disable checkboxes for installed software (MUST BE AFTER enabling all checkboxes)
                $Global:Form.Dispatcher.Invoke({
                    # SonicWall NetExtender check
                    $SWNE = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                    HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                    Where-Object { $_.DisplayName -like "*SonicWall NetExtender*" }
                    if ($SWNE) {
                        $Global:cbSonicwallVpn.IsChecked = $false
                        $Global:cbSonicwallVpn.IsEnabled = $false
                        $Global:cbSonicwallVpn.Content = "SW NetExtender (Installed)"
                    }

                    # Adobe Reader check
                    $possiblePaths = @(
                        "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
                        "${env:ProgramFiles}\Adobe\Acrobat Reader DC\Reader\AcroRd64.exe",
                        "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
                        "${env:ProgramFiles}\Adobe\Acrobat DC\Acrobat\Acrobat.exe"
                    )

                    $acrobatInstalled = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*Adobe Acrobat*" }

                    $installedPath = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

                    if ($installedPath -and $acrobatInstalled) {
                        $Global:cbAdobeReader.IsChecked = $false
                        $Global:cbAdobeReader.IsEnabled = $false
                        $Global:cbAdobeReader.Content = "Adobe Acrobat (Installed)"
                    }

                    # Office 365 check
                    $O365 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                            HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                            Where-Object { $_.DisplayName -like "*Microsoft 365 Apps*" }
                    if ($O365) {
                        $Global:cbOffice365.IsChecked = $false
                        $Global:cbOffice365.IsEnabled = $false
                        $Global:cbOffice365.Content = "Microsoft 365 (Installed)"
                    }

                    # BitLocker check
                    try {
                        $bitLockerStatus = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
                        if ($bitLockerStatus -and $bitLockerStatus.ProtectionStatus -eq 'On') {
                            $Global:cbBitLocker.IsChecked = $false
                            $Global:cbBitLocker.IsEnabled = $false
                            $Global:cbBitLocker.Content = "BitLocker Encryption (Enabled)"
                        }
                    } catch {}
                })

                # Finally, enable the Start button
                $Global:Form.Dispatcher.Invoke([Action]{
                    $Global:btnStart.IsEnabled = $true
                }, [System.Windows.Threading.DispatcherPriority]::Send)

                # If autostart is enabled, start the baseline process
                if ($AutoStart) {
                    $Global:Form.Dispatcher.Invoke({ Start-BaselineAutomatically })
                }
                # After all initialization is complete:
                $script:initTimer.Stop()
                $Global:Form.Dispatcher.Invoke([Action]{
                    $Global:CurrentTaskText.Text = "Ready to start baseline process!"
                })
            }
            catch {
                Write-UILog "Error during initialization: $_" -Color "Red"
                # Keep button disabled if initialization failed
                $Global:Form.Dispatcher.Invoke([Action]{
                    $Global:btnStart.IsEnabled = $false
                }, [System.Windows.Threading.DispatcherPriority]::Send)
            }
        },
        [System.Windows.Threading.DispatcherPriority]::Background
    )
})

# Show the WPF window
$Global:Form.ShowDialog()
exit
# Set up termination handler for Ctrl+C and window closing
$null = [Console]::TreatControlCAsInput = $true
# Register termination handler
$null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    Write-Host "PowerShell Engine Exiting Event Triggered" -ForegroundColor Yellow
    # Delete sensitive files
    $sensitiveFiles = @("c:\temp\s1t.enc", "c:\temp\murls.enc", "c:\temp\adv-banner.png", "c:\temp\mits.ico")
    foreach ($file in $sensitiveFiles) {
        if (Test-Path $file) {
            try {
                Write-Host "Attempting to delete: ${file}" -ForegroundColor Yellow
                Remove-Item $file -Force -ErrorAction Stop
                Write-Host "Successfully deleted sensitive file: ${file}" -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to delete sensitive file ${file}: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "File does not exist: ${file}" -ForegroundColor Yellow
        }
    }

    # Create WakeLock exit flag to stop the WakeLock script if it's running
    if (-not (Test-Path "c:\temp\wakelock.flag")) {
        try {
            New-Item -Path "c:\temp\wakelock.flag" -ItemType File -Force | Out-Null
        }
        catch {
            Write-UILog "Failed to create WakeLock flag: $_" -Color "Red"
        }
    }
    
    # If mobile device, stop presentation settings
    if ($global:IsMobileDevice) {
        try {
            $presentationProcess = Get-Process | Where-Object { $_.Path -eq "C:\Windows\System32\PresentationSettings.exe" } -ErrorAction SilentlyContinue
            if ($presentationProcess) {
                Stop-Process -InputObject $presentationProcess -Force -ErrorAction SilentlyContinue
                Write-UILog "Stopped presentation settings." -Color "Cyan"
            }
        }
        catch {
            Write-UILog "Failed to stop presentation settings: $_" -Color "Red"
        }
    }
    
    # Re-enable Windows Update service if it was disabled
    try {
        $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        if ($wuService -and $wuService.StartType -eq 'Disabled') {
            Set-Service -Name wuauserv -StartupType Manual -ErrorAction SilentlyContinue
            Start-Service -Name wuauserv -ErrorAction SilentlyContinue
            Write-UILog "Re-enabled Windows Update service." -Color "Cyan"
        }
    }
    catch {
        Write-UILog "Failed to re-enable Windows Update service: $_" -Color "Red"
    }
    
    # Log termination
    Add-Content -Path $LogFile -Value "$(Get-Date) - Script terminated by user." -ErrorAction SilentlyContinue
    Write-UILog "Cleanup completed. Exiting script." -Color "Yellow"
}


# Create a background job to monitor and clean up files
$cleanupScript = {
    $files = @("c:\temp\s1t.enc", "c:\temp\murls.enc", "c:\temp\adv-banner.png", "c:\temp\mits.ico")
    $consoleWindow = [WinAPI]::GetConsoleWindow()
    $wpfWindow = [WinAPI]::FindWindow("HwndWrapper[Baseline-GUI;;", $null)
    
    while ($true) {
        # Check if console window is closed
        if (-not [WinAPI]::IsWindow($consoleWindow)) {
            Write-Log "Console window closed, cleaning up files" -Level INFO
            foreach ($file in $files) {
                if (Test-Path $file) {
                    try {
                        Remove-Item -Path $file -Force -ErrorAction Stop
                        Write-Log "Successfully deleted file: $file" -Level INFO
                    }
                    catch {
                        Write-Log "Failed to delete file: $file - $_" -Level ERROR
                    }
                }
            }
            break
        }
        
        # Check if WPF window is closed
        if (-not [WinAPI]::IsWindow($wpfWindow)) {
            Write-Log "WPF window closed, cleaning up files" -Level INFO
            foreach ($file in $files) {
                if (Test-Path $file) {
                    try {
                        Remove-Item -Path $file -Force -ErrorAction Stop
                        Write-Log "Successfully deleted file: $file" -Level INFO
                    }
                    catch {
                        Write-Log "Failed to delete file: $file - $_" -Level ERROR
                    }
                }
            }
            break
        }
        
        Start-Sleep -Seconds 1
    }
}

# Start the cleanup monitoring job
$cleanupJob = Start-Job -ScriptBlock $cleanupScript
Write-Log "Started cleanup monitoring job" -Level INFO

# Register cleanup for PowerShell exit
$null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    Write-Log "PowerShell exit detected" -Level INFO
    Remove-SensitiveFiles -Force
    if ($cleanupJob) {
        Stop-Job -Job $cleanupJob
        Remove-Job -Job $cleanupJob
        Write-Log "Cleanup job stopped and removed" -Level INFO
    }
}

# Register cleanup for both PowerShell exit and console close
$cleanup = {
    Write-Log "Cleanup triggered..." -Level INFO
    if (Test-Path "c:\temp\s1t.enc") { 
        try {
            Remove-Item "c:\temp\s1t.enc" -Force
            Write-Log "Successfully deleted s1t.enc" -Level INFO
        }
        catch {
            Write-Log "Failed to delete s1t.enc: $_" -Level ERROR
        }
    }
    if (Test-Path "c:\temp\murls.enc") { 
        try {
            Remove-Item "c:\temp\murls.enc" -Force
            Write-Log "Successfully deleted murls.enc" -Level INFO
        }
        catch {
            Write-Log "Failed to delete murls.enc: $_" -Level ERROR
        }
    }
    if (Test-Path "c:\temp\adv-banner.png") { 
        try {
            Remove-Item "c:\temp\adv-banner.png" -Force
            Write-Log "Successfully deleted adv-banner.png" -Level INFO
        }
        catch {
            Write-Log "Failed to delete adv-banner.png: $_" -Level ERROR
        }
    }
    if (Test-Path "c:\temp\mits.ico") { 
        try {
            Remove-Item "c:\temp\mits.ico" -Force
            Write-Log "Successfully deleted mits.ico" -Level INFO
        }
        catch {
            Write-Log "Failed to delete mits.ico: $_" -Level ERROR
        }
    }
    if ($cleanupJob) {
        Stop-Job -Job $cleanupJob
        Remove-Job -Job $cleanupJob
        Write-Log "Cleanup job stopped and removed" -Level INFO
    }
}

$null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action $cleanup

# Enhanced console close handler
$Global:ConsoleCloseHandler = {
    param([WinAPI+CtrlTypes]$ctrlType)
    
    switch ($ctrlType) {
        ([WinAPI+CtrlTypes]::CTRL_CLOSE_EVENT) {
            Write-Log "Console close detected" -Level INFO
            Remove-SensitiveFiles -Force
            [Environment]::Exit(0)
            return $true
        }
        ([WinAPI+CtrlTypes]::CTRL_LOGOFF_EVENT) {
            Write-Log "Logoff detected" -Level INFO
            Remove-SensitiveFiles -Force
            return $true
        }
        ([WinAPI+CtrlTypes]::CTRL_SHUTDOWN_EVENT) {
            Write-Log "Shutdown detected" -Level INFO
            Remove-SensitiveFiles -Force
            return $true
        }
        default {
            return $false
        }
    }
}

# Register the console handler
$Global:Handler = [WinAPI+HandlerRoutine]$Global:ConsoleCloseHandler
[WinAPI]::SetConsoleCtrlHandler($Global:Handler, $true)

# Register PowerShell exit event as backup
$null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    Write-Log "PowerShell exit detected" -Level INFO
    Remove-SensitiveFiles -Force
}

# Create a background job to monitor for console window closure
$monitorJob = Start-Job -ScriptBlock {
    $consoleWindow = [WinAPI]::GetConsoleWindow()
    while ($true) {
        if (-not [WinAPI]::ShowWindow($consoleWindow, 0)) {
            # Console window is closed
            Remove-Item -Path "c:\temp\s1t.enc" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "c:\temp\murls.enc" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "c:\temp\adv-banner.png" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "c:\temp\mits.ico" -Force -ErrorAction SilentlyContinue
            break
        }
        Start-Sleep -Seconds 1
    }
}


# Add this to the WPF window close event and PowerShell exit event
$Global:Form.Add_Closed({
    Remove-SensitiveFiles -Force
})

# Also add to PowerShell exit event
$null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    Write-Host "PowerShell exit detected" -ForegroundColor Yellow
    Remove-SensitiveFiles -Force
    Cleanup-SpawnedPowerShell
    if ($cleanupJob) {
        Stop-Job -Job $cleanupJob
        Remove-Job -Job $cleanupJob
    }
}



# Modify the window close event handler
$Global:Form.Add_Closed({
    Write-DebugLog "WPF window closing, initiating cleanup..." -Color "Cyan"
    
    # Stop all tracked processes
    Stop-AllTrackedProcesses
    
    # Remove sensitive files
    Remove-SensitiveFiles -Force
    
    # Additional cleanup for any running jobs
    Get-Job | Where-Object { $_.State -eq 'Running' } | Stop-Job -PassThru | Remove-Job -Force
    Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue
    
    Write-DebugLog "Cleanup completed" -Color "Green"
    
    # Show and restore console window with multiple attempts
    Write-DebugLog "Starting window restoration process..." -Color "Cyan"
    
    try {
        $terminalWindow = Find-WindowsTerminal
        if ($terminalWindow -ne [IntPtr]::Zero) {
            Write-DebugLog "Found terminal window, restoring..." -Color "Cyan"
            [WinAPI]::ShowWindow($terminalWindow, [WinAPI]::SW_RESTORE)
            [WinAPI]::SetForegroundWindow($terminalWindow)
        }
    } catch {
        Write-DebugLog "Error during window restoration: $_" -Color "Red"
    }
    
    Write-DebugLog "Window restoration completed" -Color "Green"
    
    # Clear the stored handle
    $Global:TerminalWindowHandle = $null

    # Terminate the original powershell.exe process
    try {
        Write-DebugLog "Terminating original powershell.exe process (PID: $PID)" -Color "Red"
        Stop-Process -Id $PID -Force
    } catch {
        Write-DebugLog "Failed to terminate powershell.exe process: $_" -Color "Red"
    }
})

# Also add cleanup to PowerShell exit event
$null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    Write-Host "PowerShell exit detected" -ForegroundColor Yellow
    Stop-AllTrackedProcesses
    Remove-SensitiveFiles -Force
    Show-ConsoleWindow
}

try {
    $testLogPath = Join-Path $Global:TempFolder 'window-debug.log'
    Add-Content -Path $testLogPath -Value "[TEST] Script started at $(Get-Date)" -Force
    #Write-Host "[DEBUG] Test log written to $testLogPath"
} catch {
    Write-Host "[ERROR] Failed to write test log: $_"
}

$Global:WindowsTerminalHostHandle = Get-WindowsTerminalHostWindow
#Write-DebugLog "Stored Windows Terminal host window handle: $Global:WindowsTerminalHostHandle"

if ($Global:WindowsTerminalHostHandle -ne [IntPtr]::Zero) {
    [WinAPI]::ShowWindow($Global:WindowsTerminalHostHandle, 6)  # 6 = SW_MINIMIZE
    #Write-DebugLog "Minimized Windows Terminal host window at startup"
}


# Single, consolidated initialization and window setup
[System.Windows.Media.RenderOptions]::ProcessRenderMode = 'SoftwareOnly'

# Create the window reader
$reader = New-Object System.Xml.XmlNodeReader $xaml
$Global:Form = [Windows.Markup.XamlReader]::Load($reader)

# Get form elements by name
$form_Elements = @(
    'FreeSpaceText', 'ComputerNameText', 'OSNameText', 'OSVersionText',
    'ProcessorText', 'MemoryText', 'SystemDriveText', 'DriveSpaceBar', 'LastBootText',
    'UptimeText', 'cbProfileCustomization', 'cbSystemTime', 'cbPrivacySettings', 'cbOfflineFiles', 'cbVssService',
    'cbPowerProfile', 'cbWindowsUpdate', 'cbDeployRMM', 'cbDriverUpdates', 'cbOffice365', 'cbAdobeReader',
    'cbRemoveBloatware', 'cbBitLocker', 'cbSentinelOne', 'cbCreateRestorePoint', 'cbJoinDomain',
    'ProgressTextDisplay', 'CurrentTaskText', 'LogScroller', 'LogOutput', 'MainProgressBar',
    'btnStart', 'btnCancel'
)

# Create variables for each named element
foreach ($element in $form_Elements) {
    Set-Variable -Name "Global:$element" -Value $Global:Form.FindName($element)
}

# After creating the form and before showing the window, disable the Start Baseline button
$Global:btnStart.IsEnabled = $false

# Bind LogOutput to LogLines
$Global:LogOutput.ItemsSource = $Global:LogLines

# Set up event handlers
$Global:btnStart.Add_Click({
    if (-not (Test-TasksSelected)) {
        [System.Windows.MessageBox]::Show(
            "Please select at least one task to perform before starting the baseline process.",
            "No Tasks Selected",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        )
        return
    }
    
    $Global:LogLines.Clear()
    $Global:MainProgressBar.Value = 0
    $Global:ProgressTextDisplay.Text = "Overall Progress: 0%"
    $Global:CurrentTaskText.Text = "Starting baseline process..."
    
    Write-UILog "Starting baseline process..."
    Start-Baseline
})

$Global:btnCancel.Add_Click({
    $Global:CancelRequested = $true
    $Global:btnCancel.IsEnabled = $false
    Write-UILog "Cancellation requested. Waiting for current task to complete..." -Color "Orange"
})

# Show the window
#$Global:Form.ShowDialog()

# After integrity check, but before WPF window creation
# Download adv-banner.png and mits.ico
if (-not (Test-Path $Global:TempFolder)) {
    New-Item -Path $Global:TempFolder -ItemType Directory -Force | Out-Null
}
$bannerPath = "$Global:TempFolder\adv-banner.png"
$iconPath   = "$Global:TempFolder\mits.ico"
if (-not (Test-Path $bannerPath)) {
    try {
        Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/adv-banner.png" -OutFile $bannerPath -ErrorAction Stop
    } catch {
        Write-Host "Failed to download adv-banner.png: $_" -ForegroundColor Red
    }
}
if (-not (Test-Path $iconPath)) {
    try {
        Invoke-WebRequest -Uri "https://axcientrestore.blob.core.windows.net/win11/mits.ico" -OutFile $iconPath -ErrorAction Stop
    } catch {
        Write-Host "Failed to download mits.ico: $_" -ForegroundColor Red
    }
}





