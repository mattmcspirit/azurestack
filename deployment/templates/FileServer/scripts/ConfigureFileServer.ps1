[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $fileServerAdminUserName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [SecureString] $fileServerAdminPassword,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $fileShareOwnerUserName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [SecureString] $fileShareOwnerPassword,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $fileShareUserUserName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [SecureString] $fileShareUserPassword
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

$ScriptLocation = Get-Location

### SET LOG LOCATION ###
$logPath = "$($env:SystemDrive)\ConfigureFileServer"

if (![System.IO.Directory]::Exists("$logPath")) {
    New-Item -Path $logFolder -ItemType Directory -Force -ErrorAction Stop
}

### START LOGGING ###
$runTime = $(Get-Date).ToString("MMdd-HHmmss")
$fullLogPath = "$logPath\ConfigFS$runTime.txt"
Start-Transcript -Path "$fullLogPath" -Append
Write-Host "Creating log folder"
Write-Host "Log folder has been created at $logPath"
Write-Host "Log file stored at $fullLogPath"
Write-Host "Starting logging"
Write-Host "Log started at $runTime"

### CONFIG POWER OPTIONS ###
Write-Host "Configure Power Options to High performance mode."
POWERCFG.EXE /S SCHEME_MIN

### CONFIG ACCOUNTS ###
try {
    # Get the built in Admin group
    Write-Host "Getting local administrator group"
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'

    # Create or update with the new File Server Owner
    Write-Host "Checking to see if $fileServerOwnerUserName currently exists"
    if (Get-LocalUser -Name $fileServerOwnerUserName -ErrorAction SilentlyContinue) {
        Write-Host "$fileServerOwnerUserName has been located. Updating settings."
        Set-LocalUser -Name $fileServerOwnerUserName -Password $fileShareOwnerPassword -AccountNeverExpires -PasswordNeverExpires $true -Verbose -ErrorAction Stop
        Enable-LocalUser -Name $fileServerOwnerUserName -Verbose -ErrorAction Stop
    }
    else {
        Write-Host "$fileServerOwnerUserName does not exist.  Create new account with correct settings."
        New-LocalUser -Name $fileServerOwnerUserName -Password $fileShareOwnerPassword -AccountNeverExpires -PasswordNeverExpires -Verbose -ErrorAction Stop
        Write-Host "Adding $fileServerOwnerUserName to the local admins group."
        Add-LocalGroupMember -Group $adminGroup -Member $fileServerOwnerUserName -Verbose -ErrorAction Stop
    }

    # Create or update with the new File Server User
    Write-Host "Checking to see if $fileServerUserUserName currently exists"
    if (Get-LocalUser -Name $fileShareUserUserName -ErrorAction SilentlyContinue) {
        Write-Host "$fileServerUserUserName has been located. Updating settings."
        Set-LocalUser -Name $fileShareUserUserName -Password $fileShareUserPassword -AccountNeverExpires -PasswordNeverExpires $true -Verbose -ErrorAction Stop
        Enable-LocalUser -Name $fileShareUserUserName -Verbose -ErrorAction Stop
    }
    else {
        Write-Host "$fileServerUserUserName does not exist.  Create new account with correct settings."
        New-LocalUser -Name $fileShareUserUserName -Password $fileShareUserPassword -AccountNeverExpires -PasswordNeverExpires
    }
}
catch {
    Write-Host "Something went wrong with the configuration of the accounts. Please review the log file at $fullLogPath and rerun."
    Set-Location $ScriptLocation
    throw $_.Exception.Message
    return
}

try {
    ### CREATE WEBSITES FOLDER ###
    Write-Host "Checking to see if the websites folder exists."
    $websitesFolder = "$($env:SystemDrive)\websites"
    if (![System.IO.Directory]::Exists("$websitesFolder")) {
        Write-Host "Websites folder does not exist, creating it."
        New-Item -Path $websitesFolder -ItemType Directory -Force -ErrorAction Stop -Verbose
    }
    Write-Host "Checking to see if websites SMB share exists."
    if (!(Get-SmbShare -Name websites)) {
        Write-Host "Websites SMB share does not exist, creating it."
        New-SmbShare -Name websites -Path $websitesFolder -CachingMode None -FullAccess Everyone -Verbose -ErrorAction Stop
    }
    ### SET WEBSITES FOLDER PERMISSIONS ###
    Write-Host "Setting ACLs for access to the websites folder."
    CMD.EXE /C "icacls $websitesFolder /reset"
    CMD.EXE /C "icacls $websitesFolder /grant Administrators:(OI)(CI)(F)"
    CMD.EXE /C "icacls $websitesFolder /grant $($fileShareOwnerUserName):(OI)(CI)(M)"
    CMD.EXE /C "icacls $websitesFolder /inheritance:r"
    CMD.EXE /C "icacls $websitesFolder /grant $($fileShareUserUserName):(CI)(S,X,RA)"
    CMD.EXE /C "icacls $websitesFolder /grant *S-1-1-0:(OI)(CI)(IO)(RA,REA,RD)"
}
catch {
    Write-Host "Something went wrong with the configuration of the websites content folder. Please review the log file at $fullLogPath and rerun."
    Set-Location $ScriptLocation
    throw $_.Exception.Message
    return
}

### UPDATE FIREWALL ###
try {
    Write-Host "Updating firewall rule to allow file sharing."
    Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Set-NetFirewallRule -Profile 'Any' -Enabled True -Verbose -Confirm:$false
}
catch {
    Write-Host "Something went wrong with the configuration of the firewall. Please review the log file at $fullLogPath and rerun."
    Set-Location $ScriptLocation
    throw $_.Exception.Message
    return
}

$endTime = $(Get-Date).ToString("MMdd-HHmmss")
Write-Host "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue