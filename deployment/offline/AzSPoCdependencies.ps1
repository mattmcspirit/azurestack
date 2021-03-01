<#
.SYNOPSYS

    The purpose of this script is to automate the download of all files and scripts required for installing all services on an Azure Stack system, that are to be
    configured by the Azure Stack POC Configurator.

.VERSION

    2008  Latest version, to align with current Azure Stack POC Configurator version.

.AUTHOR

    Matt McSpirit
    Blog: http://www.mattmcspirit.com
    Email: matt.mcspirit@microsoft.com 
    Twitter: @mattmcspirit

.CREDITS

    Jon LaBelle - https://jonlabelle.com/snippets/view/powershell/download-remote-file-with-retry-support

.GUIDANCE

    Please refer to the Readme.md (https://github.com/mattmcspirit/azurestack/blob/master/deployment/offline/README.md) for recommended
    deployment parameter usage and instructions.

#>

#####################################################################################################
# This sample script is not supported under any Microsoft standard support program or service.      #
# The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims     #
# all implied warranties including, without limitation, any implied warranties of merchantability   #
# or of fitness for a particular purpose. The entire risk arising out of the use or performance of  #
# the sample scripts and documentation remains with you. In no event shall Microsoft, its authors,  #
# or anyone else involved in the creation, production, or delivery of the scripts be liable for any #
# damages whatsoever (including, without limitation, damages for loss of business profits, business #
# interruption, loss of business information, or other pecuniary loss) arising out of the use of or #
# inability to use the sample scripts or documentation, even if Microsoft has been advised of the   #
# possibility of such damages                                                                       #
#####################################################################################################

[CmdletBinding()]
param (
    # Path to store downloaded files
    [parameter(Mandatory = $true)]
    [String]$downloadPath,

    # Path to Windows Server 2016 Datacenter Evaluation ISO file
    [parameter(Mandatory = $true)]
    [String]$ISOPath,

    # Path to Windows Server 2019 Datacenter Evaluation ISO file
    [parameter(Mandatory = $false)]
    [String]$ISOPath2019,

    # This is used mainly for testing, when you want to run against a specific GitHub branch. Master should be used for all non-testing scenarios.
    [Parameter(Mandatory = $false)]
    [String] $branch
)

$VerbosePreference = "Continue"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$scriptStep = ""
try { Stop-Transcript | Out-Null } catch { }

### CUSTOM VERBOSE FUNCTION #################################################################################################################################
#############################################################################################################################################################
function Write-CustomVerbose {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string]$Message = ''
    )
    begin { }
    process {
        $verboseTime = (Get-Date).ToShortTimeString()
        # Function for displaying formatted log messages.  Also displays time in minutes since the script was started
        Write-Verbose -Message "[$verboseTime]::[$scriptStep]:: $Message"
    }
    end { }
}

### DOWNLOADER FUNCTION #####################################################################################################################################
#############################################################################################################################################################
function DownloadWithRetry([string] $downloadURI, [string] $downloadLocation, [int] $retries) {
    while ($true) {
        try {
            (New-Object System.Net.WebClient).DownloadFile($downloadURI, $downloadLocation)
            break
        }
        catch {
            $exceptionMessage = $_.Exception.Message
            Write-CustomVerbose -Message "Failed to download '$downloadURI': $exceptionMessage"
            if ($retries -gt 0) {
                $retries--
                Write-CustomVerbose -Message "Waiting 10 seconds before retrying. Retries left: $retries"
                Start-Sleep -Seconds 10
            }
            else {
                $exception = $_.Exception
                throw $exception
            }
        }
    }
}

### VALIDATION ##############################################################################################################################################
#############################################################################################################################################################

$scriptStep = "VALIDATION"
Write-CustomVerbose -Message "Validating if running under Admin Privileges"
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-CustomVerbose -Message "User is not administrator - please ensure you're running as Administrator (right-click, Run as administrator)" 
    exit
}

try {
    if (!$branch) {
        $branch = "master"
    }
    $urlToTest = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/README.md"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $statusCode = Invoke-WebRequest "$urlToTest" -UseBasicParsing -ErrorAction SilentlyContinue | ForEach-Object { $_.StatusCode } -ErrorAction SilentlyContinue
    if ($statusCode -eq 200) {
        Write-Host "Accessing $urlToTest - Status Code is 200 - URL is valid" -ForegroundColor Green
    }
}
catch {
    $statusCode = [int]$_.Exception.Response.StatusCode
    Write-Host "Accessing $urlToTest - Status Code is $statusCode - URL is invalid" -ForegroundColor Red
    Write-Host "If you're not sure, don't specify a branch, and 'master' will be used. Error details: `r`n" -ForegroundColor Red
    throw "Invalid Github branch specified. You tried to access $urlToTest, which doesn't exist. Status Code: $statusCode - exiting process"
}

### GET START TIME ###
$startTime = Get-Date -Format g
$sw = [Diagnostics.Stopwatch]::StartNew()

### SET LOCATION ###
$ScriptLocation = Get-Location

### Validate download path (should already exist) ###
$validDownloadPath = [System.IO.Directory]::Exists($downloadPath)
if ($validDownloadPath -eq $true) {
    Write-CustomVerbose -Message "Download path exists and is valid" 
    Write-CustomVerbose -Message "Files will be stored at $downloadPath" 
    $downloadPath = Set-Location -Path "$downloadPath" -PassThru
}
elseif ($validDownloadPath -eq $false) {
    $downloadPath = Read-Host "Download path is invalid - please enter a valid path to store your downloads"
    $validDownloadPath = [System.IO.Directory]::Exists($downloadPath)
    if ($validDownloadPath -eq $false) {
        Write-CustomVerbose -Message "No valid folder path was entered again. Exiting process..." -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
    elseif ($validDownloadPath -eq $true) {
        Write-CustomVerbose -Message "Download path exists and is valid" 
        Write-CustomVerbose -Message "Files will be stored at $downloadPath" 
        $downloadPath = Set-Location -Path "$downloadPath" -PassThru
    }
}

### Start Logging ###
$logTime = $(Get-Date).ToString("MMdd-HHmmss")
$logPath = "$downloadPath\AzSPoCDependencyLog$logTime.txt"
$logStart = Start-Transcript -Path "$logPath" -Append
Write-CustomVerbose -Message $logStart
Write-Host "Creating log folder"
Write-Host "Log folder has been created in your $downloadPath"
Write-Host "Log will be written to $logPath"
Write-Host "Starting logging"
Write-Host "Log started at $logTime"

try {
    Write-CustomVerbose -Message "Validating Windows Server 2016 RTM ISO path"
    # If this deployment is PartialOnline/Offline and using the Zip, we need to search for the ISO
    $validISOPath = [System.IO.File]::Exists($ISOPath)
    $validISOfile = [System.IO.Path]::GetExtension("$ISOPath")
    if ($validISOPath -eq $true -and $validISOfile -eq ".iso") {
        Write-CustomVerbose -Message "Found path to a valid ISO file. Need to confirm that this is a valid Windows Server 2016 RTM ISO." 
        $ISOPath = [System.IO.Path]::GetFullPath($ISOPath)
        Write-CustomVerbose -Message "The ISO file found at $ISOPath will be validated to ensure it is build 14393" 
    }
    elseif ($validISOPath -eq $false -or $validISOfile -ne ".iso") {
        $ISOPath = Read-Host "ISO path is invalid - please enter a valid path to the Windows Server 2016 RTM ISO"
        $validISOPath = [System.IO.File]::Exists($ISOPath)
        $validISOfile = [System.IO.Path]::GetExtension("$ISOPath")
        if ($validISOPath -eq $false -or $validISOfile -ne ".iso") {
            Write-CustomVerbose -Message "No valid path to a Windows Server 2016 RTM ISO was entered again. Exiting process..." -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
        elseif ($validISOPath -eq $true -and $validISOfile -eq ".iso") {
            Write-CustomVerbose -Message "Found path to a valid ISO file. Need to confirm that this is a valid Windows Server 2016 RTM ISO."
            $ISOPath = [System.IO.Path]::GetFullPath($ISOPath)
            Write-CustomVerbose -Message "The ISO file found at $ISOPath will be validated to ensure it is build 14393" 
        }
    }
    # Mount the ISO, check the image for the version, then dismount
    Remove-Variable -Name buildVersion -ErrorAction SilentlyContinue
    $isoMountForVersion = Mount-DiskImage -ImagePath $ISOPath -StorageType ISO -PassThru
    $isoDriveLetterForVersion = ($isoMountForVersion | Get-Volume).DriveLetter
    $wimPath = "$IsoDriveLetterForVersion`:\sources\install.wim"
    $buildVersion = (dism.exe /Get-WimInfo /WimFile:$wimPath /index:1 | Select-String "Version ").ToString().Split(".")[2].Trim()
    Dismount-DiskImage -ImagePath $ISOPath
    Write-CustomVerbose -Message "The ISO file found at $ISOpath has a Windows Server build version of: $buildVersion"
    if ($buildVersion -ne "14393") {
        Throw "The Windows Server $buildVersion does not equal 14393 - this is not a valid Windows Server 2016 RTM ISO image. Please check your image, and rerun the script"
    }
    else {
        Write-CustomVerbose -Message "The Windows Server $buildVersion does equal 14393, which is a valid build number and the process will continue"
    }
}
catch {
    #Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    throw $_.Exception.Message
    return
}

### Validate path to ISO File ###
$scriptStep = "VALIDATE 2016 ISO"
Write-CustomVerbose -Message "Checking to see if the path to the ISO exists"
$validISOPath = [System.IO.File]::Exists($ISOPath)
$validISOfile = [System.IO.Path]::GetExtension("$ISOPath")

If ($validISOPath -eq $true -and $validISOfile -eq ".iso") {
    Write-CustomVerbose -Message "Found path to valid ISO file" 
    $ISOPath = [System.IO.Path]::GetFullPath($ISOPath)
    Write-CustomVerbose -Message "The Windows Server 2016 Eval found at $ISOPath will be used" 
}
elseif ($validISOPath -eq $false -or $validISOfile -ne ".iso") {
    $ISOPath = Read-Host "ISO path is invalid - please enter a valid path to the Windows Server 2016 ISO"
    $validISOPath = [System.IO.File]::Exists($ISOPath)
    $validISOfile = [System.IO.Path]::GetExtension("$ISOPath")
    if ($validISOPath -eq $false -or $validISOfile -ne ".iso") {
        Write-CustomVerbose -Message "No valid path to a Windows Server 2016 ISO was entered again. Exiting process..." -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
    elseif ($validISOPath -eq $true -and $validISOfile -eq ".iso") {
        Write-CustomVerbose -Message "Found path to valid ISO file" 
        $ISOPath = [System.IO.Path]::GetFullPath($ISOPath)
        Write-CustomVerbose -Message "The Windows Server 2016 Eval found at $ISOPath will be used" 
    }
}
if ($ISOPath2019) {
    $scriptStep = "VALIDATE 2019 ISO"
    try {
        Write-CustomVerbose -Message "Validating Windows Server 2019 ISO path"
        # If this deployment is PartialOnline/Offline and using the Zip, we need to search for the ISO
        $validISOPath2019 = [System.IO.File]::Exists($ISOPath2019)
        $valid2019ISOfile = [System.IO.Path]::GetExtension("$ISOPath2019")
        if ($validISOPath2019 -eq $true -and $valid2019ISOfile -eq ".iso") {
            Write-CustomVerbose -Message "Found path to a valid ISO file. Need to confirm that this is a valid Windows Server 2019 RTM ISO." 
            $ISOPath2019 = [System.IO.Path]::GetFullPath($ISOPath2019)
            Write-CustomVerbose -Message "The ISO file found at $ISOPath2019 will be validated to ensure it is build 17763" 
        }
        elseif ($validISOPath2019 -eq $false -or $valid2019ISOfile -ne ".iso") {
            $ISOPath2019 = Read-Host "ISO path is invalid - please enter a valid path to the Windows Server 2019 RTM ISO"
            $validISOPath2019 = [System.IO.File]::Exists($ISOPath2019)
            $valid2019ISOfile = [System.IO.Path]::GetExtension("$ISOPath2019")
            if ($validISOPath2019 -eq $false -or $valid2019ISOfile -ne ".iso") {
                Write-CustomVerbose -Message "No valid path to a Windows Server 2019 RTM ISO was entered again. Exiting process..." -ErrorAction Stop
                Set-Location $ScriptLocation
                return
            }
            elseif ($validISOPath2019 -eq $true -and $valid2019ISOfile -eq ".iso") {
                Write-CustomVerbose -Message "Found path to a valid ISO file. Need to confirm that this is a valid Windows Server 2019 RTM ISO."
                $ISOPath2019 = [System.IO.Path]::GetFullPath($ISOPath2019)
                Write-CustomVerbose -Message "The ISO file found at $ISOPath2019 will be validated to ensure it is build 17763"
            }
        }
        # Mount the ISO, check the image for the version, then dismount
        Remove-Variable -Name buildVersion -ErrorAction SilentlyContinue
        $isoMountForVersion = Mount-DiskImage -ImagePath $ISOPath2019 -StorageType ISO -PassThru
        $isoDriveLetterForVersion = ($isoMountForVersion | Get-Volume).DriveLetter
        $wimPath = "$IsoDriveLetterForVersion`:\sources\install.wim"
        $buildVersion = (dism.exe /Get-WimInfo /WimFile:$wimPath /index:1 | Select-String "Version ").ToString().Split(".")[2].Trim()
        Dismount-DiskImage -ImagePath $ISOPath2019
        Write-CustomVerbose -Message "The ISO file found at $ISOpath2019 has a Windows Server build version of: $buildVersion"
        if ($buildVersion -ne "17763") {
            Throw "Build version: $buildVersion does not equal 17763 - this is not a valid Windows Server 2019 RTM ISO image. Please check your image, and rerun the script"
        }
        else {
            Write-CustomVerbose -Message "The Windows Server $buildVersion does equal 17763, which is a valid build number and the process will continue"
        }
    }
    catch {
        #Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        throw $_.Exception.Message
        return
    }
}

### Configure PowerShell ###############################################################################################################################
########################################################################################################################################################

Write-CustomVerbose -Message "Configuring the PSGallery Repo for Azure Stack PowerShell Modules"
Unregister-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
Register-PsRepository -Default
Get-PSRepository -Name "PSGallery"
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
Get-PSRepository -Name "PSGallery"

### Create Folder Structure ############################################################################################################################
########################################################################################################################################################

$scriptStep = "CREATE FOLDERS"
### Create root AzSPoCfiles FOLDER and sub folder structure ###
$AzSPoCFilePathExists = [System.IO.Directory]::Exists("$downloadPath\AzSPoCfiles")
if ($AzSPoCFilePathExists -eq $true) {
    $AzSPoCFilePath = "$downloadPath\AzSPoCfiles"
    Write-CustomVerbose -Message "Azure Stack POC files folder exists at $downloadPath - no need to create it."
    Write-CustomVerbose -Message "Download files will be placed in $downloadPath\AzSPoCfiles"
    $i = 0 
    While ($i -le 3) {
        Remove-Item "$AzSPoCFilePath\*" -Exclude "*.iso" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue -Verbose
        $i++
    }
}
elseif ($AzSPoCFilePathExists -eq $false) {
    # Create the Azure Stack POC folder.
    Write-CustomVerbose -Message "Azure Stack POC files folder doesn't exist within $downloadPath, creating it"
    $AzSPoCFilePath = mkdir "$downloadPath\AzSPoCfiles" -Force
}

$azsPath = mkdir "$AzSPoCFilePath\AzSFiles" -Force
$packagePath = mkdir "$azsPath\packages" -Force
$sqlLocalDBpath = mkdir "$azsPath\SqlLocalDB" -Force
$azCopyPath = mkdir "$azsPath\azcopy" -Force
$hostAppsPath = mkdir "$azsPath\hostapps" -Force
$templatePath = mkdir "$azsPath\templates" -Force
$scriptPath = mkdir "$azsPath\scripts" -Force
$binaryPath = mkdir "$azsPath\binaries" -Force
$psPath = mkdir "$azsPath\powershell" -Force
$psScriptPath = mkdir "$azsPath\powershell\Scripts" -Force
$dbPath = mkdir "$azsPath\databases" -Force
$imagesPath = mkdir "$azsPath\images" -Force
$isoTarget2016 = mkdir "$AzSPoCFilePath\2016iso" -Force
if ($ISOPath2019) {
    $isoTarget2019 = mkdir "$AzSPoCFilePath\2019iso" -Force
    mkdir "$imagesPath\2019" -Force
}
mkdir "$imagesPath\2016" -Force
$ubuntuPath = mkdir "$imagesPath\UbuntuServer" -Force
$appServicePath = mkdir "$azsPath\appservice" -Force
$extensionPath = mkdir "$azsPath\appservice\extension" -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

### Create Download Table ##############################################################################################################################
########################################################################################################################################################
$scriptStep = "CREATE TABLE"
$tableSuccess = $false
$tableRetries = 1
While (($tableSuccess -eq $false) -and ($tableRetries -le 10)) {
    try {
        Write-CustomVerbose -Message "Creating table to store list of downloads"
        Write-Host "Attempting to generate table. This is attempt: $tableRetries"
        $table = New-Object System.Data.DataTable
        $table.Clear()
        $table.Columns.Add("productName", "string") | Out-Null
        $table.Columns.Add("filename", "string") | Out-Null
        $table.Columns.Add("path", "string") | Out-Null
        $table.Columns.Add("Uri", "string") | Out-Null

        # AzSPoC.ps1 Script
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/AzSPoC.ps1"
        $row.filename = "AzSPoC.ps1"; $row.path = "$downloadPath"; $row.productName = "Azure Stack POC Configurator Script"; $Table.Rows.Add($row)
        # SqlLocalDB MSI
        $row = $table.NewRow(); $row.Uri = "https://download.microsoft.com/download/E/F/2/EF23C21D-7860-4F05-88CE-39AA114B014B/SqlLocalDB.msi"
        $row.filename = "SqlLocalDB.msi"; $row.path = "$sqlLocalDBPath"; $row.productName = "SqlLocalDB"; $Table.Rows.Add($row)
        # AZCopy MSI
        $row = $table.NewRow(); $row.Uri = "https://aka.ms/azcopyforazurestack20171109"
        $row.filename = "AzCopy.msi"; $row.path = "$azCopyPath"; $row.productName = "AzCopy"; $Table.Rows.Add($row)
        # Azure Stack Tools
        $row = $table.NewRow(); $row.Uri = "https://github.com/Azure/AzureStack-Tools/archive/master.zip"
        $row.filename = "Master.zip"; $row.path = "$azsPath"; $row.productName = "Azure Stack Tools"; $Table.Rows.Add($row)
        # Ubuntu Server 16.04 Image
        $row = $table.NewRow(); $row.Uri = "https://cloud-images.ubuntu.com/releases/xenial/release-20210224/ubuntu-16.04-server-cloudimg-amd64-azure.vhd.tar.gz"
        $row.filename = "UbuntuServer16.04.20210224.tar.gz"; $row.path = "$ubuntuPath"; $row.productName = "Ubuntu Server 16.04 LTS TAR GZ file"; $Table.Rows.Add($row)
        # Ubuntu Server AZPKG
        $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/Ubuntu/Canonical.UbuntuServer1604LTS-ARM.1.0.0.azpkg"
        $row.filename = "Canonical.UbuntuServer1604LTS-ARM.1.0.0.azpkg"; $row.path = "$packagePath"; $row.productName = "Ubuntu Server Marketplace Package"; $Table.Rows.Add($row)
        # Convert-WindowsImage.ps1 Script
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/scripts/Convert-WindowsImage.ps1"
        $row.filename = "Convert-WindowsImage.ps1"; $row.path = "$imagesPath"; $row.productName = "Convert-WindowsImage.ps1 VHD Creation Tool"; $Table.Rows.Add($row)
        # VM Endpoint Aliases Doc
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/packages/Aliases/aliases.json"
        $row.filename = "aliases.json"; $row.path = "$imagesPath"; $row.productName = "VM aliases endpoint doc"; $Table.Rows.Add($row)
        # Windows Server DC AZPKG
        $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/WindowsServer/Microsoft.WindowsServer2016Datacenter-ARM.1.0.0.azpkg"
        $row.filename = "Microsoft.WindowsServer2016Datacenter-ARM.1.0.0.azpkg"; $row.path = "$packagePath"; $row.productName = "Windows Server 2016 Datacenter Marketplace Package"; $Table.Rows.Add($row)
        # Windows Server DC Core AZPKG
        $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/WindowsServer/Microsoft.WindowsServer2016DatacenterServerCore-ARM.1.0.0.azpkg"
        $row.filename = "Microsoft.WindowsServer2016DatacenterServerCore-ARM.1.0.0.azpkg"; $row.path = "$packagePath"; $row.productName = "Windows Server 2016 Datacenter Core Marketplace Package"; $Table.Rows.Add($row)
        if ($ISOPath2019) {
            # Windows Server 2019 DC AZPKG
            $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/WindowsServer/Microsoft.WindowsServer2019Datacenter-ARM.1.0.0.azpkg"
            $row.filename = "Microsoft.WindowsServer2019Datacenter-ARM.1.0.0.azpkg"; $row.path = "$packagePath"; $row.productName = "Windows Server 2019 Datacenter Marketplace Package"; $Table.Rows.Add($row)
            # Windows Server 2019 DC Core AZPKG
            $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/WindowsServer/Microsoft.WindowsServer2019DatacenterServerCore-ARM.1.0.0.azpkg"
            $row.filename = "Microsoft.WindowsServer2019DatacenterServerCore-ARM.1.0.0.azpkg"; $row.path = "$packagePath"; $row.productName = "Windows Server 2019 Datacenter Core Marketplace Package"; $Table.Rows.Add($row)
        }
        # MYSQL AZPKG
        $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/MySQL/AzureStackPOC.MySQL.1.0.0.azpkg"
        $row.filename = "AzureStackPOC.MySQL.1.0.0.azpkg"; $row.path = "$packagePath"; $row.productName = "MySQL Marketplace Package"; $Table.Rows.Add($row)
        # MYSQL8 AZPKG
        $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/MySQL/AzureStackPOC.MySQL8.1.0.0.azpkg"
        $row.filename = "AzureStackPOC.MySQL8.1.0.0.azpkg"; $row.path = "$packagePath"; $row.productName = "MySQL Marketplace Package"; $Table.Rows.Add($row)
        # SQL AZPKG
        $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/MSSQL/AzureStackPOC.MSSQL.1.0.0.azpkg"
        $row.filename = "AzureStackPOC.MSSQL.1.0.0.azpkg"; $row.path = "$packagePath"; $row.productName = "SQL Server Marketplace Package"; $Table.Rows.Add($row)
        # MySQL RP (Old)
        $row = $table.NewRow(); $row.Uri = "https://aka.ms/azurestackmysqlrp11470"
        $row.filename = "MySQLOld.exe"; $row.path = "$dbPath"; $row.productName = "MySQL Resource Provider Files"; $Table.Rows.Add($row)
        # MySQL RP (New)
        $row = $table.NewRow(); $row.Uri = "https://aka.ms/azshmysqlrp11931"
        $row.filename = "MySQLNew.exe"; $row.path = "$dbPath"; $row.productName = "MySQL Resource Provider Files"; $Table.Rows.Add($row)
        # MySQL RP Helper MSI
        $row = $table.NewRow(); $row.Uri = "https://dev.mysql.com/get/Download/sConnector-Net/mysql-connector-net-6.10.5.msi"
        $row.filename = "mysql-connector-net-6.10.5.msi"; $row.path = "$dbPath"; $row.productName = "MySQL Resource Provider Files Offline Connector"; $Table.Rows.Add($row)
        # SQL RP (Old)
        $row = $table.NewRow(); $row.Uri = "https://aka.ms/azurestacksqlrp11470"
        $row.filename = "SQLServerOld.exe"; $row.path = "$dbPath"; $row.productName = "SQL Server Resource Provider Files"; $Table.Rows.Add($row)
        # SQL RP (New)
        $row = $table.NewRow(); $row.Uri = "https://aka.ms/azurestacksqlrp11931"
        $row.filename = "SQLServerNew.exe"; $row.path = "$dbPath"; $row.productName = "SQL Server Resource Provider Files"; $Table.Rows.Add($row)
        # MySQL 5.7 Install Script
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/scripts/install_MySQL_Offline.sh"
        $row.filename = "install_MySQL.sh"; $row.path = "$scriptPath"; $row.productName = "MySQL install script"; $Table.Rows.Add($row)
        # MySQL 8 Install Script
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/scripts/install_MySQL8_Offline.sh"
        $row.filename = "install_MySQL8.sh"; $row.path = "$scriptPath"; $row.productName = "MySQL 8 install script"; $Table.Rows.Add($row)

        ### Grab the MySQL Offline Binaries - used when Azure Stack system is deployed in a completely offline mode
        ### The MySQL script would usually install MySQL via apt-get, however in an offline mode, this isn't possible, hence
        ### we download them here, and upload them to local Azure Stack storage as part of the Azure Stack POC Configurator

        ### MySQL 5.7 ### (Simplified - correct as of 3/25/2020)
        $mysqlURLs = @()
        $mysqlURLs.Clear()
        $mysqlURLs = "http://mirrors.edge.kernel.org/ubuntu/pool/main/liba/libaio/libaio1_0.3.110-2_amd64.deb", 
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libh/libhtml-tagset-perl/libhtml-tagset-perl_3.20-2_all.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libu/liburi-perl/liburi-perl_1.71-1_all.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libh/libhtml-parser-perl/libhtml-parser-perl_3.72-1_amd64.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libl/liblwp-mediatypes-perl/liblwp-mediatypes-perl_6.02-1_all.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libc/libcgi-pm-perl/libcgi-pm-perl_4.26-1_all.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libf/libfcgi-perl/libfcgi-perl_0.77-1build1_amd64.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libc/libcgi-fast-perl/libcgi-fast-perl_2.10-1_all.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libt/libtimedate-perl/libtimedate-perl_2.3000-2_all.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libi/libio-html-perl/libio-html-perl_1.001-1_all.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libh/libhtml-template-perl/libhtml-template-perl_2.95-2_all.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libe/libencode-locale-perl/libencode-locale-perl_1.05-1_all.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libh/libhttp-date-perl/libhttp-date-perl_6.02-1_all.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libh/libhttp-message-perl/libhttp-message-perl_6.11-1_all.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/libe/libevent/libevent-core-2.0-5_2.0.21-stable-2ubuntu0.16.04.1_amd64.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/m/mysql-5.7/mysql-common_5.7.32-0ubuntu0.16.04.1_all.deb",
     
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/m/mysql-5.7/mysql-client-core-5.7_5.7.32-0ubuntu0.16.04.1_amd64.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/m/mysql-5.7/mysql-client-5.7_5.7.32-0ubuntu0.16.04.1_amd64.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/m/mysql-5.7/mysql-server-core-5.7_5.7.32-0ubuntu0.16.04.1_amd64.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/main/m/mysql-5.7/mysql-server-5.7_5.7.32-0ubuntu0.16.04.1_amd64.deb"

        foreach ($url in $mysqlURLs) {
            $row = $table.NewRow(); $row.Uri = "$url"
            $productname = (($url.Substring($url.LastIndexOf("/") + 1)).Split("_", 2)[0])
            $filename = $productname + ".deb"
            $row.filename = "$filename"; $row.path = "$binaryPath"; $row.productName = "MySQL $productname dependency"; $Table.Rows.Add($row)
        }

        ### MySQL 8 ### (Simplified - correct as of 3/25/2020)
        $mysql8URLs = @()
        $mysql8URLs.Clear()
        $mysql8URLs = "https://dev.mysql.com/get/mysql-apt-config_0.8.15-1_all.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/universe/m/mecab/libmecab2_0.996-1.2ubuntu1_amd64.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/universe/m/mecab/mecab-utils_0.996-1.2ubuntu1_amd64.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/universe/m/mecab-ipadic/mecab-ipadic_2.7.0-20070801+main-1_all.deb",
        "http://mirrors.edge.kernel.org/ubuntu/pool/universe/m/mecab-ipadic/mecab-ipadic-utf8_2.7.0-20070801+main-1_all.deb",
        "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/mysql-common_8.0.19-1ubuntu16.04_amd64.deb",
        "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/mysql-community-client-core_8.0.19-1ubuntu16.04_amd64.deb",
        "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/mysql-community-client_8.0.19-1ubuntu16.04_amd64.deb",
        "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/mysql-client_8.0.19-1ubuntu16.04_amd64.deb",
        "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/mysql-community-server-core_8.0.19-1ubuntu16.04_amd64.deb",
        "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/mysql-community-server_8.0.19-1ubuntu16.04_amd64.deb",
        "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/mysql-server_8.0.19-1ubuntu16.04_amd64.deb"
        
        foreach ($url in $mysql8URLs) {
            $row = $table.NewRow(); $row.Uri = "$url"
            $productname = (($url.Substring($url.LastIndexOf("/") + 1)).Split("_", 2)[0])
            $filename = $productname + "_8_.deb"
            $row.filename = "$filename"; $row.path = "$binaryPath"; $row.productName = "MySQL 8 $productname dependency"; $Table.Rows.Add($row)
        }

        ### SQL Server ###

        # SQL Server Install Script
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/scripts/install_MSSQL_Offline.sh"
        $row.filename = "install_MSSQL.sh"; $row.path = "$scriptPath"; $row.productName = "SQL Server Install Script"; $Table.Rows.Add($row)

        ### Grab the SQL Server 2017 for Ubuntu Offline Binaries - used when Azure Stack POC system is deployed in a completely offline mode
        ### The SQL Server 2017 script would usually install SQL Server via apt-get, however in an offline mode, this isn't possible, hence
        ### we download them here, and upload them to local Azure Stack storage as part of the Azure Stack POC Configurator

        # SQL Server 2017 Main Binary
        $WebResponse = Invoke-WebRequest "https://packages.microsoft.com/ubuntu/16.04/mssql-server-2017/pool/main/m/mssql-server/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mssql-server*amd64.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "https://packages.microsoft.com/ubuntu/16.04/mssql-server-2017/pool/main/m/mssql-server/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mssql-server.deb"; $row.path = "$binaryPath"; $row.productName = "SQL Server 2017 binary"; $Table.Rows.Add($row)

        # SQL Server 2017 Offline Dependency #1
        $WebResponse = Invoke-WebRequest "https://packages.ubuntu.com/xenial/amd64/libjemalloc1/download" -UseBasicParsing
        $downloadFileURL = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "*libjemalloc1*amd64.deb") } | Sort-Object | Select-Object -First 1).href.ToString()
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mssql-libjemalloc.deb"; $row.path = "$binaryPath"; $row.productName = "SQL Server 2017 libjemalloc dependency"; $Table.Rows.Add($row)

        # SQL Server 2017 Offline Dependency #2
        $WebResponse = Invoke-WebRequest "https://packages.ubuntu.com/xenial/amd64/libc++1/download" -UseBasicParsing
        $downloadFileURL = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "*libc++1*amd64.deb") } | Sort-Object | Select-Object -First 1).href.ToString()
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mssql-libc.deb"; $row.path = "$binaryPath"; $row.productName = "SQL Server 2017 libc dependency"; $Table.Rows.Add($row)

        # SQL Server 2017 Offline Dependency #3
        $WebResponse = Invoke-WebRequest "https://packages.ubuntu.com/xenial/amd64/libc++abi1/download" -UseBasicParsing
        $downloadFileURL = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "*libc++abi1*amd64.deb") } | Sort-Object | Select-Object -First 1).href.ToString()
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mssql-libcabi.deb"; $row.path = "$binaryPath"; $row.productName = "SQL Server 2017 libcabi dependency"; $Table.Rows.Add($row)

        # SQL Server 2017 Offline Dependency #4
        $WebResponse = Invoke-WebRequest "https://packages.ubuntu.com/xenial/amd64/gdb/download" -UseBasicParsing
        $downloadFileURL = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "*gdb_7*amd64.deb") } | Sort-Object | Select-Object -First 1).href.ToString()
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mssql-gdb.deb"; $row.path = "$binaryPath"; $row.productName = "SQL Server 2017 gdb dependency"; $Table.Rows.Add($row)

        # SQL Server 2017 Offline Dependency #5
        $WebResponse = Invoke-WebRequest "https://packages.ubuntu.com/xenial/amd64/libsss-nss-idmap0/download" -UseBasicParsing
        $downloadFileURL = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "*libsss-nss-idmap0*amd64.deb") } | Sort-Object | Select-Object -First 1).href.ToString()
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mssql-libsss.deb"; $row.path = "$binaryPath"; $row.productName = "SQL Server 2017 libsss dependency"; $Table.Rows.Add($row)

        # SQL Server 2017 Offline Dependency #6
        $WebResponse = Invoke-WebRequest "https://packages.ubuntu.com/xenial/amd64/libbabeltrace1/download" -UseBasicParsing
        $downloadFileURL = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "*libbabeltrace1_1.3*amd64.deb") } | Sort-Object | Select-Object -First 1).href.ToString()
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mssql-libbabeltrace1.deb"; $row.path = "$binaryPath"; $row.productName = "SQL Server 2017 libbabeltrace1 dependency"; $Table.Rows.Add($row)

        # SQL Server 2017 Offline Dependency #7
        $WebResponse = Invoke-WebRequest "https://packages.ubuntu.com/xenial/amd64/libbabeltrace-ctf1/download" -UseBasicParsing
        $downloadFileURL = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "*libbabeltrace-ctf1*amd64.deb") } | Sort-Object | Select-Object -First 1).href.ToString()
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mssql-libbabeltrace-ctf1.deb"; $row.path = "$binaryPath"; $row.productName = "SQL Server 2017 libbabeltrace-ctf1 dependency"; $Table.Rows.Add($row)

        # SQL Server 2017 Offline Dependency #8
        $WebResponse = Invoke-WebRequest "https://packages.ubuntu.com/xenial/amd64/libcurl3/download" -UseBasicParsing
        $downloadFileURL = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "*libcurl3_7.4*amd64.deb") } | Sort-Object | Select-Object -First 1).href.ToString()
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mssql-libcurl3.deb"; $row.path = "$binaryPath"; $row.productName = "SQL Server 2017 libcurl3 dependency"; $Table.Rows.Add($row)

        # SQL Server 2017 Offline Dependency #9
        $WebResponse = Invoke-WebRequest "https://packages.ubuntu.com/xenial/amd64/libsasl2-modules-gssapi-mit/download" -UseBasicParsing
        $downloadFileURL = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "*libsasl2-modules-gssapi-mit*amd64.deb") } | Sort-Object | Select-Object -First 1).href.ToString()
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mssql-libsasl2.deb"; $row.path = "$binaryPath"; $row.productName = "SQL Server 2017 libsasl2 dependency"; $Table.Rows.Add($row)

        # Add MySQL Hosting Server Template
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/templates/MySQLHosting/azuredeploy.json"
        $row.filename = "mySqlHostingTemplate.json"; $row.path = "$templatePath"; $row.productName = "Add MySQL Hosting Server template for deployment"; $Table.Rows.Add($row)
        # Add SQL Hosting Server Template
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/templates/SQLHosting/azuredeploy.json"
        $row.filename = "sqlHostingTemplate.json"; $row.path = "$templatePath"; $row.productName = "Add SQL Server Hosting Server template for deployment"; $Table.Rows.Add($row)
        # File Server Template
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/templates/FileServer/azuredeploy.json"
        $row.filename = "FileServerTemplate.json"; $row.path = "$templatePath"; $row.productName = "File Server template for deployment"; $Table.Rows.Add($row)
        # File Server PowerShell Script
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/templates/FileServer/scripts/ConfigureFileServer.ps1"
        $row.filename = "ConfigureFileServer.ps1"; $row.path = "$scriptPath"; $row.productName = "File Server script for deployment"; $Table.Rows.Add($row)
        # App Service Helper Scripts
        $row = $table.NewRow(); $row.Uri = "https://aka.ms/appsvconmashelpers"
        $row.filename = "appservicehelper.zip"; $row.path = "$appServicePath"; $row.productName = "App Service Resource Provider Helper files"; $Table.Rows.Add($row)
        # App Service Installer
        $row = $table.NewRow(); $row.Uri = "https://aka.ms/appsvconmasinstaller"
        $row.filename = "appservice.exe"; $row.path = "$appServicePath"; $row.productName = "App Service installer"; $Table.Rows.Add($row)
        # App Service PreDeployment JSON
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/appservice/AppServiceDeploymentSettings.json"
        $row.filename = "AppSvcPre.json"; $row.path = "$appServicePath"; $row.productName = "App Service Pre-Deployment JSON Configuration"; $Table.Rows.Add($row)
        # App Service Custom Script Extension
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/appservice/extension/CSE.zip"
        $row.filename = "CSE.zip"; $row.path = "$extensionPath"; $row.productName = "App Service Custom Script Extension"; $Table.Rows.Add($row)
    
        # Grab the MSI/Exe packages to be installed
        # VScode Package
        $row = $table.NewRow(); $row.Uri = "https://aka.ms/win32-x64-user-stable"
        $row.filename = "vscode.exe"; $row.path = "$hostAppsPath"; $row.productName = "VScode Exe"; $Table.Rows.Add($row)
        # Putty Package
        $row = $table.NewRow(); $row.Uri = "https://the.earth.li/~sgtatham/putty/0.72/w64/putty-64bit-0.72-installer.msi"
        $row.filename = "putty.msi"; $row.path = "$hostAppsPath"; $row.productName = "Putty MSI"; $Table.Rows.Add($row)
        # WinSCP Package
        $WebResponse = Invoke-WebRequest "https://chocolatey.org/packages/winscp.install" -UseBasicParsing
        $downloadFileURL = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "*chocolatey.org/api/v2/package/winscp.install/*") } | Sort-Object | Select-Object -First 1).href.ToString()
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "WinSCP.zip"; $row.path = "$hostAppsPath"; $row.productName = "WinSCP Zip"; $Table.Rows.Add($row)
        # Chrome Package
        $row = $table.NewRow(); $row.Uri = "http://dl.google.com/edgedl/chrome/install/GoogleChromeStandaloneEnterprise64.msi"
        $row.filename = "googlechrome.msi"; $row.path = "$hostAppsPath"; $row.productName = "Chrome MSI"; $Table.Rows.Add($row)
        # WinDirStat Package
        $row = $table.NewRow(); $row.Uri = "https://windirstat.mirror.wearetriple.com/wds_current_setup.exe"
        $row.filename = "windirstat.exe"; $row.path = "$hostAppsPath"; $row.productName = "WinDirStat Exe"; $Table.Rows.Add($row)
        # Azure CLI Package
        $row = $table.NewRow(); $row.Uri = "https://aka.ms/installazurecliwindows"
        $row.filename = "azurecli.msi"; $row.path = "$hostAppsPath"; $row.productName = "Azure CLI MSI"; $Table.Rows.Add($row)
        # Python Exe Installer
        $WebResponse = Invoke-WebRequest "https://www.python.org/downloads/windows/" -UseBasicParsing
        $downloadFileURL = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "https://www.python.org/ftp/python/*amd64.exe") } | Sort-Object | Select-Object -First 1).href.ToString()
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "python3.exe"; $row.path = "$hostAppsPath"; $row.productName = "Python 3 Exe Installer"; $Table.Rows.Add($row)
        # PIP package
        $WebResponse = Invoke-WebRequest "https://pypi.org/project/pip/#files" -UseBasicParsing
        $downloadFileURL = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "*pip-*.whl") } | Sort-Object | Select-Object -First 1).href.ToString()
        $downloadFileName = $downloadFileURL.Substring($downloadFileURL.LastIndexOf("/") + 1)
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "$downloadFileName"; $row.path = "$hostAppsPath"; $row.productName = "PIP Wheel"; $Table.Rows.Add($row)
        # Certifi package
        $WebResponse = Invoke-WebRequest "https://pypi.org/project/certifi/#files" -UseBasicParsing
        $downloadFileURL = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "*certifi*.whl") } | Sort-Object | Select-Object -First 1).href.ToString()
        $downloadFileName = $downloadFileURL.Substring($downloadFileURL.LastIndexOf("/") + 1)
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "$downloadFileName"; $row.path = "$hostAppsPath"; $row.productName = "Certifi Wheel"; $Table.Rows.Add($row)
        Write-CustomVerbose -Message "The following files will be downloaded:"
        $table | Format-Table -AutoSize
        $tableSuccess = $true
        Write-CustomVerbose -Message "Table created successfully!"
    }
    catch [System.Net.WebException] { 
        Write-Host "An exception was caught: $($_.Exception.Message)"
        Write-Host "The URL that was attempted was: $($_.Exception.Response.ResponseURI.OriginalString)"
        Write-Host "Table creation failed. We will attempt this again, up to 10 times. Waiting 5 seconds before retrying."
        $tableRetries++
        Start-Sleep -Seconds 5
    }
}
if (($tableSuccess -eq $false) -and ($tableRetries -gt 10)) {
    throw "Table creation failed after $tableRetries attempts. Check your internet connection, then rerun. Exiting process."
    Set-Location $ScriptLocation
    return
}

### Download Artifacts #################################################################################################################################
########################################################################################################################################################

$scriptStep = "DOWNLOADS"
try {
    foreach ($dependency in $table) {
        Write-CustomVerbose -Message "Downloading the $($dependency.productName) from $($dependency.uri) and storing at $($dependency.path)\$($dependency.filename)."
        DownloadWithRetry -downloadURI "$($dependency.uri)" -downloadLocation "$($dependency.path)\$($dependency.filename)" -retries 10
    }
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### EXTRACT WINSCP #################################################################################################################################
########################################################################################################################################################

$scriptStep = "WINSCP"
try {
    Set-Location $hostAppsPath
    Expand-Archive -Path ".\WinSCP.zip" -DestinationPath ".\WinSCP" -Force -Verbose
    Get-ChildItem -Path ".\WinSCP\*" -Recurse -Include *.exe -Force -Verbose | Rename-Item -NewName "WinSCP.exe" -Verbose -Force
    Get-ChildItem -Path ".\WinSCP\*" -Recurse -Include *.exe -Force -Verbose | Move-Item -Destination "$hostAppsPath" -Verbose -Force
    Remove-Item -Path "WinSCP.zip" -Verbose -Force
    Remove-Item -Path ".\WinSCP\" -Recurse -Verbose -Force
    Set-Location $ScriptLocation
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Generate App Service Offline ZIP ###################################################################################################################
########################################################################################################################################################

$scriptStep = "APPSERVICE"
$appServiceLogTime = $(Get-Date).ToString("MMdd-HHmmss")
$appServiceLogPath = "$appServicePath\AppServiceLog$appServiceLogTime.txt"
Set-Location "$appServicePath"
Write-CustomVerbose -Message "Starting download of the App Service binaries"
Start-Process -FilePath .\appservice.exe -ArgumentList "/quiet /log $appServiceLogPath CreateOfflineInstallationPackage OfflineInstallationPackageFile=$appServicePath\appserviceoffline.zip" -PassThru

while ((Get-Process AppService -ErrorAction SilentlyContinue).Responding) {
    Write-CustomVerbose -Message "App Service offline zip file being created. This process generally takes a few minutes, so please be patient. Checking again in 10 seconds"
    Start-Sleep -Seconds 10
}
if (!(Get-Process AppService -ErrorAction SilentlyContinue).Responding) {
    Write-CustomVerbose -Message "App Service offline zip file creation has completed."
}

$appServiceErrorCode = "Exit code: 0xffffffff"
Write-CustomVerbose -Message "Checking App Service log file for issues"
if ($(Select-String -Path $appServiceLogPath -Pattern "$appServiceErrorCode" -SimpleMatch -Quiet) -eq "True") {
    Write-CustomVerbose -Message "App Service offline zip file creation failed with $appServiceErrorCode"
    Write-CustomVerbose -Message "An error has occurred during creation. Please check the App Service log at $appServiceLogPath"
    throw "App Service offline zip file creation failed with $appServiceErrorCode. Please check the App Service log at $appServiceLogPath"
}
else {
    Write-CustomVerbose -Message "App Service log file indicates successful offline zip file creation"
    $i = 1
    While ($i -le 5) {
        Remove-Item "$appServiceLogPath" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue -Verbose
        $i++
    }
}

### Download PowerShell ################################################################################################################################
########################################################################################################################################################

$scriptStep = "POWERSHELL"
try {
    Write-CustomVerbose -Message "Downloading PowerShell Modules for AzureRM, Az Azure Stack and SQL Server" -ErrorAction Stop
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name PowerShellGet -Path $psPath -Force -RequiredVersion 2.2.3 | Out-Null
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name Az -Path $psPath -Force -RequiredVersion 0.10.0-preview | Out-Null
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name AzureStack -Path $psPath -Force -RequiredVersion 2.0.2-preview | Out-Null
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name AzureRM -Path $psPath -Force -RequiredVersion 2.3.0 | Out-Null
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name AzureRM -Path $psPath -Force -RequiredVersion 2.5.0 | Out-Null
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name SQLServer -Path $psPath -Force | Out-Null
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name 7Zip4PowerShell -Path $psPath -Force | Out-Null
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Download PowerShell Scripts ########################################################################################################################
########################################################################################################################################################

$scriptStep = "POWERSHELLSCRIPTS"
try {
    Write-CustomVerbose -Message "Downloading PowerShell scripts used for deployment" -ErrorAction Stop
    $scriptBaseURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/powershell"
    $scriptArray = @()
    $scriptArray.Clear()
    $scriptArray = "AddAppServicePreReqs.ps1", "AddDBHosting.ps1", "AddDBRPImage.ps1", "AddDBSkuQuota.ps1", "AddGalleryItems.ps1", "AddImage.ps1", "AddVMExtensions.ps1", `
        "DeployAppService.ps1", "DeployDBRP.ps1", "DeployVM.ps1", "DownloadAppService.ps1", "DownloadWinUpdates.ps1", "GetJobStatus.ps1", "UploadScripts.ps1"
    foreach ($script in $scriptArray) {
        $scriptDownloadPath = "$psScriptPath\$script"
        DownloadWithRetry -downloadURI "$scriptBaseURI/$script" -downloadLocation $scriptDownloadPath -retries 10
    }
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Copy Windows Server ISOs & Download Updates ##########################################################################################################
#########################################################################################################################################################

$scriptStep = "WINDOWSSERVER2016ISO"
### Copy ISO file to $downloadPath ###
try {
    Write-CustomVerbose -Message "Copying Windows Server 2016 ISO image to $isoTarget2016" -ErrorAction Stop
    $ISOFile = Split-Path $ISOPath -leaf
    $ISOinDownloadPath = [System.IO.File]::Exists("$isoTarget2016\$ISOFile")
    if (!$ISOinDownloadPath) {
        Copy-Item "$ISOPath" -Destination "$isoTarget2016" -Force -Verbose
        $ISOPath = "$isoTarget2016\$ISOFile"
    }
    else {
        Write-CustomVerbose -Message "Windows Server 2016 ISO image exists within $isoTarget2016." -ErrorAction Stop
        Write-CustomVerbose -Message "Full path is $isoTarget2016\$ISOFile" -ErrorAction Stop
        $ISOPath = "$isoTarget2016\$ISOFile"
    }
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

if ($ISOPath2019) {
    $scriptStep = "WINDOWSSERVER2019ISO"
    ### Copy ISO file to $downloadPath ###
    try {
        Write-CustomVerbose -Message "Copying Windows Server 2019 ISO image to $isoTarget2019" -ErrorAction Stop
        $ISOFile2019 = Split-Path $isoPath2019 -leaf
        $ISOinDownloadPath = [System.IO.File]::Exists("$isoTarget2019\$ISOFile2019")
        if (!$ISOinDownloadPath) {
            Copy-Item "$isoPath2019" -Destination "$isoTarget2019" -Force -Verbose
            $ISOPath2019 = "$isoTarget2019\$ISOFile2019"
        }
        else {
            Write-CustomVerbose -Message "Windows Server 2019 ISO image exists within $isoTarget2019." -ErrorAction Stop
            Write-CustomVerbose -Message "Full path is $isoTarget2019\$ISOFile2019" -ErrorAction Stop
            $isoPath2019 = "$isoTarget2016\$ISOFile2019"
        }
    }
    catch {
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}

$scriptStep = "WINDOWSUPDATES"
try {
    if ($ISOPath2019) {
        $versionArray = @("2016", "2019")
    }
    else {
        $versionArray = @("2016")
    }
    # Install kbupdate to download update files
    Write-Host "Installing kbupdate module to obtain Windows Updates"
    Install-Module -Name kbupdate -Force -ErrorAction Stop -Verbose
    foreach ($v in $versionArray) {
        # Mount the ISO, check the image for the version, then dismount
        Remove-Variable -Name buildVersion -ErrorAction SilentlyContinue
        if ($v -eq "2019") {
            $ISOPath = $ISOPath2019
        }
        $isoMountForVersion = Mount-DiskImage -ImagePath $ISOPath -StorageType ISO -PassThru
        $isoDriveLetterForVersion = ($isoMountForVersion | Get-Volume).DriveLetter
        $wimPath = "$IsoDriveLetterForVersion`:\sources\install.wim"
        $buildVersion = (dism.exe /Get-WimInfo /WimFile:$wimPath /index:1 | Select-String "Version ").ToString().Split(".")[2].Trim()
        Dismount-DiskImage -ImagePath $ISOPath
        Write-Host "You're missing at least one of the Windows Server $v Datacenter images, so we'll first download the latest Cumulative Update."
        
        # Define parameters
        Write-Host "Defining StartKB"
        if ($v -eq "2019") {
            $StartKB = 'https://support.microsoft.com/en-us/help/4464619'
            $netKB = 'https://support.microsoft.com/en-us/help/4466961'
        }
        else {
            $StartKB = 'https://support.microsoft.com/en-us/help/4000825'
        }
        $SearchString = 'Cumulative.*Server.*x64'
        Write-Host "StartKB is: $StartKB and Search String is: $SearchString"
        # Define the arrays that will be used later
        $KBs = @()
    
        ### Firstly, check for build 14393, and if so, download the Servicing Stack Update or other MSUs will fail to apply.
        Write-Host "Checking build number to determine Servicing Stack Updates"
        if ($buildVersion -eq "14393") {
            $rss = "https://support.microsoft.com/app/content/api/content/feeds/sap/en-us/6ae59d69-36fc-8e4d-23dd-631d98bf74a9/rss"
            $rssFeed = [xml](New-Object System.Net.WebClient).DownloadString($rss)
            $feed = $rssFeed.rss.channel.item | Where-Object { $_.title -like "*Servicing Stack Update*Windows 10*" }
            $feed = ($feed | Where-Object { $_.title -like "*1607*" } | Select-Object -Property Link | Sort-Object link) | Select-Object -Last 1
            $ssuKB = "KB" + ($feed.link).Split('/')[4]
            $microCodeFeed = $rssFeed.rss.channel.item | Where-Object { $_.description -like "*microcode updates from Intel*version 1607*" }
            $microCodeFeed = ($microCodeFeed | Select-Object -Property Link | Sort-Object link) | Select-Object -Last 1
            $microCodeKB = "KB" + ($microCodeFeed.link).Split('/')[4]
        }
        elseif ($buildVersion -eq "17763") {
            $rss = "https://support.microsoft.com/app/content/api/content/feeds/sap/en-us/6ae59d69-36fc-8e4d-23dd-631d98bf74a9/rss"
            $rssFeed = [xml](New-Object System.Net.WebClient).DownloadString($rss)
            $feed = $rssFeed.rss.channel.item | Where-Object { $_.title -like "*Servicing Stack Update*Windows 10*" }
            $feed = ($feed | Where-Object { $_.title -like "*1809*" } | Select-Object -Property Link | Sort-Object link) | Select-Object -Last 1
            $ssuKB = "KB" + ($feed.link).Split('/')[4]
            $microCodeFeed = $rssFeed.rss.channel.item | Where-Object { $_.description -like "*microcode updates from Intel*version 1809*" }
            $microCodeFeed = ($microCodeFeed | Select-Object -Property Link | Sort-Object link) | Select-Object -Last 1
            $microCodeKB = "KB" + ($microCodeFeed.link).Split('/')[4]
        }

        $KBs += "$ssuKB"
        $KBs += "$microCodeKB"

        Write-Host "Getting info for removal of Adobe Flash Player"
        $rssFeed = [xml](New-Object System.Net.WebClient).DownloadString($rss)
        $feed = $rssFeed.rss.channel.item | Where-Object { $_.title -like "*Adobe Flash Player*" }
        $feed = ($feed | Select-Object -Property Link | Sort-Object link -Descending) | Select-Object -First 1
        $flashKB = "KB" + ($feed.link).Split('/')[4]
        $KBs += $flashKB

        # Find the KB Article Number for the latest Windows Server Cumulative Update
        Write-Host "Accessing $StartKB to retrieve the list of updates."
        $cumulativekbID = (Invoke-WebRequest -Uri $StartKB -UseBasicParsing).RawContent -split "`n"
        $cumulativekbID = ($cumulativekbID | Where-Object { ($_ -like "*a class=*$buildVersion*") -and ($_ -notlike "*a class=*preview*") } | Select-Object -First 1)
        $cumulativekbID = "KB" + ((($cumulativekbID -split "KB", 2)[1]) -split "\s", 2)[0]

        if (!$cumulativekbID) {
            Write-Host "No Windows Update KB found - this is an error. Your Windows Server images will be out of date"
        }
        else {
            $KBs += "$cumulativekbID"
        }

        if ($v -eq "2019") {

            # Find the KB Article Number for the latest Cumulative Update for .NET Framework
            Write-Host "Accessing $netKB to retrieve the list of updates."
            $NETkbID = (Invoke-WebRequest -Uri $netKB -UseBasicParsing).RawContent -split "`n"
            $NETkbID = ($NETkbID | Where-Object { ($_ -like "*a class=*Cumulative Update for .NET Framework*") -and ($_ -notlike "*a class=*preview*") } | Select-Object -First 1)
            $NETkbID = "KB" + ((($NETkbID -split "KB", 2)[1]) -split "\s", 2)[0]

            if (!$NETkbID) {
                Write-Host "No Windows Update KB found - this is an error. Your Windows Server images will not have the latest .NET update"
            }
            else {
                $KBs += "$NETkbID"
            }
        }

        Write-Host "List of KBs to download is as follows:"
        $kbDisplay = $KBs -join "`r`n"
        Write-Host "$kbDisplay"
        $Urls = @()
        foreach ($KB in $KBs) {
            $link = $null
            $link = (Get-KbUpdate -Architecture x64 -OperatingSystem "Windows Server $v" -Latest -Pattern $KB -ErrorAction SilentlyContinue -Verbose:$false).Link | Select-Object -First 1
            while (!$link) {
                Write-Host "Failed to get the URL for $KB - retrying in 30 seconds"
                Start-Sleep -Seconds 30
                $link = (Get-KbUpdate -Architecture x64 -OperatingSystem "Windows Server $v" -Latest -Pattern $KB -ErrorAction SilentlyContinue -Verbose:$false).Link | Select-Object -First 1
            }
            $Urls += $link
        }
        Write-Host "List of URLs that will be used for downloading files:"
        $urlDisplay = $Urls -join "`r`n"
        Write-Host "$urlDisplay"
    
        # Download the corresponding Windows Server Cumulative Update (and possibly, Servicing Stack Updates)
        foreach ( $Url in $Urls ) {
            $filename = (($Url.Substring($Url.LastIndexOf("/") + 1)).Split("-", 2)[1])
            $filename = $filename -replace "_.*\.", "."
            $target = "$((Get-Item $azsPath).FullName)\images\$v\$filename"
            if (!(Test-Path -Path $target)) {
                if ((Test-Path -Path "$((Get-Item $azsPath).FullName)\images\$v\$($buildVersion)_ssu_$($ssuKB).msu")) {
                    Remove-Item -Path "$((Get-Item $azsPath).FullName)\images\$v\$($buildVersion)_ssu_$($ssuKB).msu" -Force -Verbose -ErrorAction Stop
                }
                Write-Host "Update will be stored at $target"
                Write-Host "These can be larger than 1GB, so may take a few minutes."
                DownloadWithRetry -downloadURI "$Url" -downloadLocation "$target" -retries 10
            }
            else {
                Write-Host "File exists: $target. Skipping download."
            }
        }
    
        # If this is for Build 14393, rename the .msu for the servicing stack update, to ensure it gets applied in the correct order when patching the WIM file.
                    
        if ((Test-Path -Path "$((Get-Item $azsPath).FullName)\images\$v\$($buildVersion)_ssu_$($ssuKB).msu")) {
            Write-Host "The $buildVersion Servicing Stack Update already exists within the target folder"
        }
        else {
            Write-Host "Renaming the Servicing Stack Update to ensure it is applied in the correct order"
            Get-ChildItem -Path "$azsPath\images\$v\" -Filter *.msu | Where-Object { $_.FullName -like "*$($ssuKB)*" } | Rename-Item -NewName "$($buildVersion)_ssu_$($ssuKB).msu" -Force -ErrorAction Stop -Verbose
        }
        # All updates should now be downloaded - time to distribute them into correct folders.
        New-Item -ItemType Directory -Path "$azsPath\images\$v\SSU" -Force | Out-Null
        New-Item -ItemType Directory -Path "$azsPath\images\$v\CU" -Force | Out-Null
        Get-ChildItem -Path "$azsPath\images\$v\" -Filter *.msu -ErrorAction SilentlyContinue | Where-Object { $_.FullName -like "*ssu*" } | Move-Item -Destination "$azsPath\images\$v\SSU" -Force -ErrorAction Stop -Verbose
        Get-ChildItem -Path "$azsPath\images\$v\" -Filter *.msu -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike "*ssu*" } | Move-Item -Destination "$azsPath\images\$v\CU" -Force -ErrorAction Stop -Verbose
    }
    Write-Host "Removing kbupdate module"
    Remove-Module -Name kbupdate -Verbose -Force -ErrorAction SilentlyContinue
    Uninstall-Module -Name kbupdate -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
    Remove-Module kbupdate-library -Verbose -Force -ErrorAction SilentlyContinue
    Uninstall-Module -Name kbupdate-library -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
    Remove-Module PSSQLite -Verbose -Force -ErrorAction SilentlyContinue
    Uninstall-Module -Name kbupdate-library -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
    Uninstall-Module -Name PSSQLite -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Create a ZIP file ##################################################################################################################################
########################################################################################################################################################

$scriptStep = "CREATE ZIP"
try {
    Get-ChildItem -Path "$downloadPath\*" -Recurse | Unblock-File -Verbose
    $session = New-PSSession -Name CreateZip -ComputerName $env:COMPUTERNAME -EnableNetworkAccess
    Write-CustomVerbose -Message "Packaging files into a single ZIP file"
    Invoke-Command -Session $session -ArgumentList $downloadPath, $AzSPoCFilePath -ScriptBlock {
        $zipPath = "$Using:downloadPath\AzSPoCfiles.zip"
        Install-Module -Name 7Zip4PowerShell -Verbose -Force
        Compress-7Zip -CompressionLevel None -Path "$Using:AzSPoCFilePath" -ArchiveFileName $zipPath -Format Zip;
        Remove-Module -Name 7Zip4PowerShell -Verbose -Force
    }
    Remove-PSSession -Name CreateZip -Confirm:$false -ErrorAction SilentlyContinue -Verbose
    Remove-Variable -Name session -Force -ErrorAction SilentlyContinue -Verbose
    Uninstall-Module -Name 7Zip4PowerShell -Force -Confirm:$false -Verbose
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Final Steps #########################################################################################################################################
#########################################################################################################################################################

$scriptStep = "FINAL STEPS"
# Calculate completion time
$endTime = Get-Date -Format g
$sw.Stop()
$Hrs = $sw.Elapsed.Hours
$Mins = $sw.Elapsed.Minutes
$Secs = $sw.Elapsed.Seconds
$difference = '{0:00}h:{1:00}m:{2:00}s' -f $Hrs, $Mins, $Secs

Set-Location $ScriptLocation -ErrorAction SilentlyContinue
Write-Output "Azure Stack POC Configurator offline downloader completed successfully, taking $difference." -ErrorAction SilentlyContinue
Write-Output "You started the at $startTime." -ErrorAction SilentlyContinue
Write-Output "The process completed at $endTime." -ErrorAction SilentlyContinue
Stop-Transcript -ErrorAction SilentlyContinue