[CmdletBinding()]
param (
    [string] $fileShareAdminUserName,
    [string] $fileShareAdminPassword,
    [string] $fileShareOwnerUserName,
    [string] $fileShareOwnerPassword,
    [string] $fileShareUserUserName,
    [string] $fileShareUserPassword
)

function Log($out) {
    $out = [System.DateTime]::Now.ToString("yyyy.MM.dd hh:mm:ss") + " ---- " + $out;
    Write-Output $out;
}

# Force use of TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

$ScriptLocation = Get-Location

### SET LOG LOCATION ###
$logPath = "$($env:SystemDrive)\ConfigureFileServer"

if (![System.IO.Directory]::Exists("$logPath")) {
    New-Item -Path $logPath -ItemType Directory -Force -ErrorAction Stop
}

### START LOGGING ###
$runTime = $(Get-Date).ToString("MMdd-HHmmss")
$fullLogPath = "$logPath\ConfigFS$runTime.txt"
Start-Transcript -Path "$fullLogPath" -Append
Log "Creating log folder"
Log "Log folder has been created at $logPath"
Log "Log file stored at $fullLogPath"
Log "Starting logging"
Log "Log started at $runTime"

### CONFIG POWER OPTIONS ###
Log "Configure Power Options to High performance mode."
POWERCFG.EXE /S SCHEME_MIN

### CREATE STRONG PASSWORDS ###
Log "Configuring strong passwords for the user accounts"
$strFileShareAdminPassword = ConvertTo-SecureString $fileShareAdminPassword -Force -AsPlainText -Verbose
$strFileShareOwnerPassword = ConvertTo-SecureString $fileShareOwnerPassword -Force -AsPlainText -Verbose
$strFileShareUserPassword = ConvertTo-SecureString $fileShareUserPassword -Force -AsPlainText -Verbose

### CONFIG ACCOUNTS ###
try {
    # Get the built in Admin group
    Log "Getting local administrator group"
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'

    # Create or update with the new File Server Owner
    Log "Checking to see if $fileShareOwnerUserName currently exists"
    if (Get-LocalUser -Name $fileShareOwnerUserName -ErrorAction SilentlyContinue) {
        Log "$fileShareOwnerUserName has been located. Updating settings."
        Set-LocalUser -Name $fileShareOwnerUserName -Password $strFileShareOwnerPassword -AccountNeverExpires -PasswordNeverExpires $true -Verbose -ErrorAction Stop
        Enable-LocalUser -Name $fileShareOwnerUserName -Verbose -ErrorAction Stop
    }
    else {
        Log "$fileShareOwnerUserName does not exist.  Create new account with correct settings."
        New-LocalUser -Name $fileShareOwnerUserName -Password $strFileShareOwnerPassword -AccountNeverExpires -PasswordNeverExpires -Verbose -ErrorAction Stop
        Log "Adding $fileShareOwnerUserName to the local admins group."
        Add-LocalGroupMember -Group $adminGroup -Member $fileShareOwnerUserName -Verbose -ErrorAction Stop
    }

    # Create or update with the new File Server User
    Log "Checking to see if $fileShareUserUserName currently exists"
    if (Get-LocalUser -Name $fileShareUserUserName -ErrorAction SilentlyContinue) {
        Log "$fileShareUserUserName has been located. Updating settings."
        Set-LocalUser -Name $fileShareUserUserName -Password $strFileShareUserPassword -AccountNeverExpires -PasswordNeverExpires $true -Verbose -ErrorAction Stop
        Enable-LocalUser -Name $fileShareUserUserName -Verbose -ErrorAction Stop
    }
    else {
        Log "$fileShareUserUserName does not exist.  Create new account with correct settings."
        New-LocalUser -Name $fileShareUserUserName -Password $strFileShareUserPassword -AccountNeverExpires -PasswordNeverExpires
    }
}
catch {
    Log "Something went wrong with the configuration of the accounts. Please review the log file at $fullLogPath and rerun."
    Set-Location $ScriptLocation
    throw $_.Exception.Message
    return
}

try {
    ### CREATE WEBSITES FOLDER ###
    Log "Checking to see if the websites folder exists."
    $websitesFolder = "$($env:SystemDrive)\websites"
    if (![System.IO.Directory]::Exists("$websitesFolder")) {
        Log "Websites folder does not exist, creating it."
        New-Item -Path $websitesFolder -ItemType Directory -Force -ErrorAction Stop -Verbose
    }
    Log "Checking to see if websites SMB share exists."
    if (!(Get-SmbShare -Name websites -ErrorAction SilentlyContinue -Verbose)) {
        Log "Websites SMB share does not exist, creating it."
        New-SmbShare -Name websites -Path $websitesFolder -CachingMode None -FullAccess Everyone -Verbose -ErrorAction Stop
    }
    ### SET WEBSITES FOLDER PERMISSIONS ###
    Log "Setting ACLs for access to the websites folder."
    CMD.EXE /C "icacls $websitesFolder /reset"
    CMD.EXE /C "icacls $websitesFolder /grant Administrators:(OI)(CI)(F)"
    CMD.EXE /C "icacls $websitesFolder /grant $($fileShareOwnerUserName):(OI)(CI)(M)"
    CMD.EXE /C "icacls $websitesFolder /inheritance:r"
    CMD.EXE /C "icacls $websitesFolder /grant $($fileShareUserUserName):(CI)(S,X,RA)"
    CMD.EXE /C "icacls $websitesFolder /grant *S-1-1-0:(OI)(CI)(IO)(RA,REA,RD)"
}
catch {
    Log "Something went wrong with the configuration of the websites content folder. Please review the log file at $fullLogPath and rerun."
    Set-Location $ScriptLocation
    throw $_.Exception.Message
    return
}

### UPDATE FIREWALL ###
try {
    Log "Updating firewall rule to allow file sharing."
    Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Set-NetFirewallRule -Profile 'Any' -Enabled True -Verbose -Confirm:$false
}
catch {
    Log "Something went wrong with the configuration of the firewall. Please review the log file at $fullLogPath and rerun."
    Set-Location $ScriptLocation
    throw $_.Exception.Message
    return
}

$endTime = $(Get-Date).ToString("MMdd-HHmmss")
Log "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue