############################################################################################################
#                                   MITS - Rename and Baseline Launcher                                     #
#                                                 Version 1.0.6                                            #
############################################################################################################
#region Synopsis
<#
.SYNOPSIS
    Initiates computer rename and schedules the MITS baseline script to run after reboot.

.DESCRIPTION
    This script performs the following operations in sequence:
    - Prompts the user to rename the computer
    - Creates a scheduled task to run the MITS baseline script after the next login
    - Triggers an automatic system reboot
    
    After reboot, the script will automatically launch the MITS baseline configuration
    when the specified user logs in.

.PARAMETER UserName
    The username that will log in after reboot. The baseline script will run under this user's context.
    Default: current user

.NOTES
    Version:        1.0.6
    Author:         Bill Ulrich
    Creation Date:  4/1/2025
    Requires:       Administrator privileges
                    Windows 10/11 Professional
    
.EXAMPLE
    .\BaselineLauncher.ps1
    
    Run the script with administrator privileges to rename the computer and schedule the baseline.

.EXAMPLE
    .\BaselineLauncher.ps1 -UserName "Administrator"
    
    Rename the computer and schedule the baseline to run when the Administrator logs in after reboot.

.LINK
    https://github.com/mitsdev01/MITS
#>

param (
    [string]$UserName = $env:USERNAME
)

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as an Administrator!" -ForegroundColor Red
    Start-Sleep -Seconds 5
    exit
}

$ScriptVersion = "1.0.6"

#Start-Transcript -Path "c:\temp\baseline-launcher.log"

# Create a temporary directory if it doesn't exist
$tempFolder = "C:\temp"
if (-not (Test-Path -Path $tempFolder)) {
    New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null
}

# Function to display messages with delays
function Write-Delayed {
    param(
        [string]$Text, 
        [switch]$NewLine = $true,
        [System.ConsoleColor]$Color = [System.ConsoleColor]::White
    )
    $currentColor = [Console]::ForegroundColor
    [Console]::ForegroundColor = $Color
    foreach ($Char in $Text.ToCharArray()) {
        [Console]::Write("$Char")
        Start-Sleep -Milliseconds 25
    }
    if ($NewLine) {
        [Console]::WriteLine()
    }
    [Console]::ForegroundColor = $currentColor
}

function Write-TaskComplete {
    [Console]::ForegroundColor = [System.ConsoleColor]::Green
    [Console]::Write(" done.")
    [Console]::ResetColor()
    [Console]::WriteLine()
}

function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = "$tempFolder\rename-and-baseline.log"
    Add-Content -Path $logFile -Value "[$timestamp] $Message"
}

# Function to properly center text in console
function Print-Center {
    param (
        [string]$Message,
        [System.ConsoleColor]$Color = [System.ConsoleColor]::White
    )
    
    $consoleWidth = [Console]::BufferWidth
    $spaces = [Math]::Max(0, [Math]::Floor(($consoleWidth - $Message.Length) / 2))
    $paddedMessage = " " * $spaces + $Message
    
    Write-Host $paddedMessage -ForegroundColor $Color
}

# Display header
Clear-Host
Write-Host ("=" * [Console]::BufferWidth) -ForegroundColor Green
Print-Center "MITS - New Workstation Baseline Launcher"
Print-Center "Version $ScriptVersion" "Yellow"
Write-Host ("=" * [Console]::BufferWidth) -ForegroundColor Green
Write-Host ""

Write-Log "Rename and Baseline script started"

# Create the startup script that will run after reboot
$startupScript = @'
# Wait for network connectivity
$startTime = Get-Date
$timeout = 120 # seconds to wait for network
$connected = $false

while (-not $connected -and ((Get-Date) - $startTime).TotalSeconds -lt $timeout) {
    if (Test-Connection 8.8.8.8 -Count 1 -Quiet) {
        $connected = $true
    } else {
        Start-Sleep -Seconds 5
    }
}

# Start a new PowerShell window and execute the baseline script
Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', "irm bit.ly/mits-baseline-v3 | iex" -WindowStyle Normal

# Remove this scheduled task after execution
Unregister-ScheduledTask -TaskName "MITS-Baseline-Startup" -Confirm:$false
'@

# Save the startup script to a file
$startupScriptPath = "$tempFolder\MITS-Baseline-Startup.ps1"
Set-Content -Path $startupScriptPath -Value $startupScript -Force
Write-Log "Created startup script at $startupScriptPath"

# Create tracker file to indicate rename was already attempted
$trackerFilePath = "$tempFolder\mits-rename-complete.flag"
New-Item -Path $trackerFilePath -ItemType File -Force | Out-Null
Write-Log "Created rename tracker file at $trackerFilePath"

# Rename machine functionality with GUI prompt
Write-Delayed "Prompting for new machine rename..." -NewLine:$false
try {
    # Load required assemblies for GUI
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Add P/Invoke declarations for setting window position and foreground
    Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        
        public class ForegroundWindow {
            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool SetForegroundWindow(IntPtr hWnd);
            
            [DllImport("user32.dll")]
            public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
            
            [DllImport("user32.dll", SetLastError = true)]
            public static extern bool BringWindowToTop(IntPtr hWnd);
            
            [DllImport("user32.dll")]
            public static extern IntPtr GetForegroundWindow();
            
            [DllImport("user32.dll")]
            public static extern bool FlashWindow(IntPtr hwnd, bool bInvert);

            [DllImport("user32.dll")]
            public static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
            
            public const int GWL_EXSTYLE = -20;
            public const int WS_EX_TOPMOST = 0x0008;
        }
"@

    # Create form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Rename Machine"
    $form.Size = New-Object System.Drawing.Size(400, 200)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    
    # Create label
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10, 20)
    $label.Size = New-Object System.Drawing.Size(380, 20)
    $label.Text = "Enter new machine name (15 characters max, no spaces):"
    $form.Controls.Add($label)

    # Create textbox
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(10, 50)
    $textBox.Size = New-Object System.Drawing.Size(360, 20)
    $textBox.MaxLength = 15
    $textBox.Text = $env:COMPUTERNAME
    $form.Controls.Add($textBox)

    # Create status label
    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Location = New-Object System.Drawing.Point(10, 80)
    $statusLabel.Size = New-Object System.Drawing.Size(380, 20)
    $statusLabel.ForeColor = [System.Drawing.Color]::Red
    $form.Controls.Add($statusLabel)

    # Create OK button
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75, 120)
    $okButton.Size = New-Object System.Drawing.Size(100, 30)
    $okButton.Text = "Rename"
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($okButton)
    $form.AcceptButton = $okButton

    # Create Cancel button
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(225, 120)
    $cancelButton.Size = New-Object System.Drawing.Size(100, 30)
    $cancelButton.Text = "Skip"
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($cancelButton)
    $form.CancelButton = $cancelButton

    # Validate name when text changes
    $textBox.Add_TextChanged({
        $newName = $textBox.Text
        if ($newName -match '\s') {
            $statusLabel.Text = "Machine name cannot contain spaces"
            $okButton.Enabled = $false
        } elseif ($newName.Length -eq 0) {
            $statusLabel.Text = "Machine name cannot be empty"
            $okButton.Enabled = $false
        } elseif ($newName -notmatch '^[a-zA-Z0-9\-]+$') {
            $statusLabel.Text = "Only letters, numbers, and hyphens are allowed"
            $okButton.Enabled = $false
        } else {
            $statusLabel.Text = ""
            $okButton.Enabled = $true
        }
    })

    # Additional form setup before showing
    $form.Add_Shown({
        # Set focus to the form
        $form.Activate()
        $form.Focus()
        
        # Delay to ensure other operations are complete
        Start-Sleep -Milliseconds 100
        
        # These force the window to be on top and active
        [ForegroundWindow]::BringWindowToTop($form.Handle)
        [ForegroundWindow]::SetForegroundWindow($form.Handle)
        [ForegroundWindow]::ShowWindow($form.Handle, 5) # SW_SHOW
        
        # Flash the window to get attention
        [ForegroundWindow]::FlashWindow($form.Handle, $true)
        
        # Set window as topmost via the Windows API
        [ForegroundWindow]::SetWindowLong($form.Handle, [ForegroundWindow]::GWL_EXSTYLE, 
            [ForegroundWindow]::WS_EX_TOPMOST)
    })

    # Show the form
    $result = $form.ShowDialog()

    # Computer rename required?
    $renameRequired = $false

    # If OK was clicked and the name is different
    if ($result -eq [System.Windows.Forms.DialogResult]::OK -and $textBox.Text -ne $env:COMPUTERNAME) {
        $newName = $textBox.Text
        
        # Validate name
        if ($newName -match '^[a-zA-Z0-9\-]{1,15}$') {
            # Rename the machine
            Rename-Computer -NewName $newName -Force *> $null # Suppress all output
            Write-Log "Machine renamed to: $newName (requires restart)"
            $renameRequired = $true
            
            # Create a topmost message box for confirmation
            $confirmBox = New-Object System.Windows.Forms.Form
            $confirmBox.TopMost = $true
            [System.Windows.Forms.MessageBox]::Show(
                $confirmBox,
                "Computer has been renamed to '$newName'. `n             System will reboot automatically.",
                "Rename Successful",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null # Suppress the result
            Write-TaskComplete
            Start-Sleep -Seconds 3
        } else {
            Write-Log "Invalid Machine name entered: $newName"
            
            # Create a topmost message box for error
            $errorBox = New-Object System.Windows.Forms.Form
            $errorBox.TopMost = $true
            [System.Windows.Forms.MessageBox]::Show(
                $errorBox,
                "Invalid Machine name. Continuing without rename.", 
                "Rename Failed", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null # Suppress the result
            Write-Host " skipped - invalid name." -ForegroundColor Yellow
        }
    } else {
        Write-Log "Machine rename skipped by user"
        Write-Host " skipped." -ForegroundColor Yellow
    }

    # Create scheduled task to run after login
    Write-Delayed "Creating startup task for baseline script..." -NewLine:$false

    # Delete any existing task with the same name
    Unregister-ScheduledTask -TaskName "MITS-Baseline-Startup" -Confirm:$false -ErrorAction SilentlyContinue

    # Create the scheduled task
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$startupScriptPath`""
    
    # Run the task when the user logs on
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserName
    
    # Configure the settings
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    
    # Register the task
    Register-ScheduledTask -TaskName "MITS-Baseline-Startup" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null
    
    Write-TaskComplete
    Write-Log "Created scheduled task 'MITS-Baseline-Startup' to run after logon for user $UserName"

    # Prepare for restart
    Write-Delayed "Preparing for system restart..." -NewLine:$false
    Start-Sleep -Seconds 2
    Write-TaskComplete
    
    # Log the restart
    $null = Write-Log "System restart initiated"
    
    # Suppress any potential output
    $null = $Padding
    $null = $paddingSize
    $null = $consoleWidth
    
    # Countdown timer - now before the banner
    for ($i = 10; $i -gt 0; $i--) {
        Write-Host "Restarting in $i seconds..." -ForegroundColor Yellow
        Start-Sleep -Seconds 1
    }
    
    # Display restart message - moved after countdown
    Write-Host ""
    $Padding = ("=" * [Console]::BufferWidth)
    Write-Host -ForegroundColor "Green" $Padding
    
    # First message
    $message = "System is restarting now"
    $consoleWidth = [Console]::BufferWidth
    $paddingSize = [Math]::Max(0, [Math]::Floor(($consoleWidth / 2) - ($message.Length / 2)))
    $paddedMessage = (" " * $paddingSize) + $message
    Write-Host $paddedMessage -ForegroundColor "Yellow"
    
    # Second message
    $message = "The baseline script will run automatically after login"
    $paddingSize = [Math]::Max(0, [Math]::Floor(($consoleWidth / 2) - ($message.Length / 2)))
    $paddedMessage = (" " * $paddingSize) + $message
    Write-Host $paddedMessage -ForegroundColor "Cyan"
    
    Write-Host -ForegroundColor "Green" $Padding
    Write-Host ""
    
    # Restart the computer
    #Stop-Transcript | Out-Null
    Restart-Computer -Force

} catch {
    Write-Host " failed: $_" -ForegroundColor Red
    Write-Log "Error in workflow: $_"
    
    # Ask user if they want to continue to restart
    $continue = Read-Host "An error occurred. Do you still want to restart the computer? (Y/N)"
    if ($continue -eq "Y" -or $continue -eq "y") {
        Write-Log "User chose to restart despite error"
        Restart-Computer -Force
    } else {
        Write-Log "User aborted restart after error"
        Write-Host "Restart aborted. You will need to restart the computer manually and run the baseline script." -ForegroundColor Red
    }
} 