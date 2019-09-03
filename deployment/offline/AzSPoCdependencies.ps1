<#
.SYNOPSYS

    The purpose of this script is to automate the download of all files and scripts required for installing all services on an Azure Stack system, that are to be
    configured by the Azure Stack POC Configurator.

.VERSION

    1908  Latest version, to align with current Azure Stack POC Configurator version.

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
        # Ubuntu Server 16.04 ZIP
        #$row = $table.NewRow(); $row.Uri = "https://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"
        #hard coding to a known working VHD
        $row = $table.NewRow(); $row.Uri = "https://cloud-images.ubuntu.com/releases/16.04/release-20190628/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"
        $row.filename = "UbuntuServer1.0.0.zip"; $row.path = "$ubuntuPath"; $row.productName = "Ubuntu Server 16.04 LTS zip file"; $Table.Rows.Add($row)
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
        # MySQL RP
        $row = $table.NewRow(); $row.Uri = "https://aka.ms/azurestackmysqlrp11330"
        $row.filename = "MySQL.zip"; $row.path = "$dbPath"; $row.productName = "MySQL Resource Provider Files"; $Table.Rows.Add($row)
        # MySQL RP Helper MSI
        $row = $table.NewRow(); $row.Uri = "https://dev.mysql.com/get/Download/sConnector-Net/mysql-connector-net-6.10.5.msi"
        $row.filename = "mysql-connector-net-6.10.5.msi"; $row.path = "$dbPath"; $row.productName = "MySQL Resource Provider Files Offline Connector"; $Table.Rows.Add($row)
        # SQL RP
        $row = $table.NewRow(); $row.Uri = "https://aka.ms/azurestacksqlrp11330"
        $row.filename = "SQLServer.zip"; $row.path = "$dbPath"; $row.productName = "SQL Server Resource Provider Files"; $Table.Rows.Add($row)
        # MySQL 5.7 Install Script
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/scripts/install_MySQL_Offline.sh"
        $row.filename = "install_MySQL.sh"; $row.path = "$scriptPath"; $row.productName = "MySQL install script"; $Table.Rows.Add($row)
        # MySQL 8 Install Script
        $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/scripts/install_MySQL8_Offline.sh"
        $row.filename = "install_MySQL8.sh"; $row.path = "$scriptPath"; $row.productName = "MySQL 8 install script"; $Table.Rows.Add($row)

        ### Grab the MySQL Offline Binaries - used when Azure Stack system is deployed in a completely offline mode
        ### The MySQL script would usually install MySQL via apt-get, however in an offline mode, this isn't possible, hence
        ### we download them here, and upload them to local Azure Stack storage as part of the Azure Stack POC Configurator

        # MySQL 5.7 & 8 Offline Dependency #1
        $WebResponse = Invoke-WebRequest "http://mirrors.edge.kernel.org/ubuntu/pool/main/liba/libaio/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "libaio*amd64.deb") -and ($_.href -notlike "*dev*amd64.deb") -and ($_.href -notlike "*dbg*amd64.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://mirrors.edge.kernel.org/ubuntu/pool/main/liba/libaio/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql-libaio.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL libaio dependency"; $Table.Rows.Add($row)

        # MySQL 5.7 & 8 Offline Dependency #2
        $WebResponse = Invoke-WebRequest "http://security.ubuntu.com/ubuntu/pool/main/libe/libevent/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "libevent-core*16*amd64.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://security.ubuntu.com/ubuntu/pool/main/libe/libevent/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql-libevent-core.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL libevent dependency"; $Table.Rows.Add($row)

        # MySQL 5.7 & 8 Offline Dependency #3
        $WebResponse = Invoke-WebRequest "http://mirrors.edge.kernel.org/ubuntu/pool/universe/m/mecab/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "libmecab*amd64.deb") -and ($_.href -notlike "*dev*amd64.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://mirrors.edge.kernel.org/ubuntu/pool/universe/m/mecab/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql-libmecab.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL libmecab dependency"; $Table.Rows.Add($row)

        # MySQL 5.7 Offline Dependency #4
        $WebResponse = Invoke-WebRequest "http://security.ubuntu.com/ubuntu/pool/main/m/mysql-5.7/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mysql-client*16*amd64.deb") -and ($_.href -notlike "*core*amd64.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://security.ubuntu.com/ubuntu/pool/main/m/mysql-5.7/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql-client.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL client dependency"; $Table.Rows.Add($row)

        # MySQL 5.7 Offline Dependency #5
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mysql-client-core*16*amd64.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://security.ubuntu.com/ubuntu/pool/main/m/mysql-5.7/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql-client-core.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL client core dependency"; $Table.Rows.Add($row)

        # MySQL 5.7 Offline Dependency #6
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mysql-common*.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://security.ubuntu.com/ubuntu/pool/main/m/mysql-5.7/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql-common.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL common dependency"; $Table.Rows.Add($row)

        # MySQL 5.7 Offline Dependency #7
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mysql-server-core*16*amd64.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://security.ubuntu.com/ubuntu/pool/main/m/mysql-5.7/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql-server-core.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL Server Core dependency"; $Table.Rows.Add($row)

        # MySQL 5.7 Offline Dependency #8
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mysql-server*16*amd64.deb") -and ($_.href -notlike "*core*amd64.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://security.ubuntu.com/ubuntu/pool/main/m/mysql-5.7/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql-server.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL Server dependency"; $Table.Rows.Add($row)

        # MySQL 8 Offline Dependency #9
        $WebResponse = Invoke-WebRequest "http://mirrors.edge.kernel.org/ubuntu/pool/universe/m/mecab/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mecab-utils*amd64.deb") -and ($_.href -notlike "*dev*amd64.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://mirrors.edge.kernel.org/ubuntu/pool/universe/m/mecab/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql-mecab-utils.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL mecab-utils dependency"; $Table.Rows.Add($row)

        # MySQL 8 Offline Dependency #10
        $WebResponse = Invoke-WebRequest "http://mirrors.edge.kernel.org/ubuntu/pool/universe/m/mecab-ipadic/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mecab-ipadic_*.deb") -and ($_.href -notlike "*dev*.deb") } | Sort-Object href | Select-Object -First 1).href.ToString()
        $downloadFileURL = "http://mirrors.edge.kernel.org/ubuntu/pool/universe/m/mecab-ipadic/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql-mecab-ipadic.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL mecab-ipadic dependency"; $Table.Rows.Add($row)

        # MySQL 8 Offline Dependency #11
        $WebResponse = Invoke-WebRequest "http://mirrors.edge.kernel.org/ubuntu/pool/universe/m/mecab-ipadic/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mecab-ipadic-utf*.deb") -and ($_.href -notlike "*dev*.deb") } | Sort-Object href | Select-Object -First 1).href.ToString()
        $downloadFileURL = "http://mirrors.edge.kernel.org/ubuntu/pool/universe/m/mecab-ipadic/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql-mecab-ipadic-utf.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL mecab-ipadic-utf dependency"; $Table.Rows.Add($row)

        # MySQL 8 Offline Dependency #12
        $WebResponse = Invoke-WebRequest "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mysql-common*ubuntu16.04_amd64.deb") -and ($_.href -notlike "*dmr*.deb") -and ($_.href -notlike "*rc*.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql8-common.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL 8 common dependency"; $Table.Rows.Add($row)

        # MySQL 8 Offline Dependency #13
        $WebResponse = Invoke-WebRequest "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mysql-community-client-core*ubuntu16.04_amd64.deb") -and ($_.href -notlike "*dmr*.deb") -and ($_.href -notlike "*rc*.deb") -and ($_.href -notlike "*dbgsym*.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql8-community-client-core.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL 8 community client core dependency"; $Table.Rows.Add($row)

        # MySQL 8 Offline Dependency #14
        $WebResponse = Invoke-WebRequest "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mysql-community-client_*ubuntu16.04_amd64.deb") -and ($_.href -notlike "*dmr*.deb") -and ($_.href -notlike "*rc*.deb") -and ($_.href -notlike "*dbgsym*.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql8-community-client.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL 8 community client dependency"; $Table.Rows.Add($row)

        # MySQL 8 Offline Dependency #15
        $WebResponse = Invoke-WebRequest "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mysql-client_*ubuntu16.04_amd64.deb") -and ($_.href -notlike "*dmr*.deb") -and ($_.href -notlike "*rc*.deb") -and ($_.href -notlike "*dbgsym*.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql8-client.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL 8 client dependency"; $Table.Rows.Add($row)

        # MySQL 8 Offline Dependency #16
        $WebResponse = Invoke-WebRequest "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mysql-community-server-core*ubuntu16.04_amd64.deb") -and ($_.href -notlike "*dmr*.deb") -and ($_.href -notlike "*rc*.deb") -and ($_.href -notlike "*dbgsym*.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql8-community-server-core.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL 8 community server core dependency"; $Table.Rows.Add($row)

        # MySQL 8 Offline Dependency #17
        $WebResponse = Invoke-WebRequest "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mysql-community-server_*ubuntu16.04_amd64.deb") -and ($_.href -notlike "*dmr*.deb") -and ($_.href -notlike "*rc*.deb") -and ($_.href -notlike "*dbgsym*.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql8-community-server.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL 8 community server dependency"; $Table.Rows.Add($row)

        # MySQL 8 Offline Dependency #17
        $WebResponse = Invoke-WebRequest "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/" -UseBasicParsing
        $fileToDownload = $($WebResponse.Links | Select-Object href | Where-Object { ($_.href -like "mysql-server_*ubuntu16.04_amd64.deb") -and ($_.href -notlike "*dmr*.deb") -and ($_.href -notlike "*rc*.deb") -and ($_.href -notlike "*dbgsym*.deb") } | Sort-Object href | Select-Object -Last 1).href.ToString()
        $downloadFileURL = "http://repo.mysql.com/apt/ubuntu/pool/mysql-8.0/m/mysql-community/$fileToDownload"
        $row = $table.NewRow(); $row.Uri = "$downloadFileURL"
        $row.filename = "mysql8-server.deb"; $row.path = "$binaryPath"; $row.productName = "MySQL 8 server dependency"; $Table.Rows.Add($row)

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
        #$row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/appservice/appservicehelper1.4.zip"
        $row.filename = "appservicehelper.zip"; $row.path = "$appServicePath"; $row.productName = "App Service Resource Provider Helper files"; $Table.Rows.Add($row)
        # App Service Installer
        $row = $table.NewRow(); $row.Uri = "https://aka.ms/appsvconmasinstaller"
        #$row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/appservice/appservice1.4.exe"
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
    Write-CustomVerbose -Message "Downloading PowerShell Modules for AzureRM, Azure Stack and SQL Server" -ErrorAction Stop
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name AzureRM -Path $psPath -Force -RequiredVersion 2.5.0 | Out-Null
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name AzureStack -Path $psPath -Force -RequiredVersion 1.7.2 | Out-Null
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name Azure.Storage -Path $psPath -Force -RequiredVersion 4.5.0 | Out-Null
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name AzureRm.Storage -Path $psPath -Force -RequiredVersion 5.0.4 | Out-Null
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name SQLServer -Path $psPath -Force | Out-Null
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
    $scriptArray = "AddAppServicePreReqs.ps1", "AddDBHosting.ps1", "AddDBSkuQuota.ps1", "AddGalleryItems.ps1", "AddImage.ps1", "AddVMExtensions.ps1", `
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
        if ($v -eq "2019") {
            $StartKB = 'https://support.microsoft.com/en-us/help/4464619'
        }
        else {
            $StartKB = 'https://support.microsoft.com/en-us/help/4000825'
        }
        $SearchString = 'Cumulative.*Server.*x64'
        # Define the arrays that will be used later
        $kbDownloads = @()
        $Urls = @()
    
        ### Firstly, check for build 14393, and if so, download the Servicing Stack Update or other MSUs will fail to apply.
        if ($buildVersion -eq "14393") {
            # Test for dynamically building the SSU array
            $rss = "https://support.microsoft.com/app/content/api/content/feeds/sap/en-us/6ae59d69-36fc-8e4d-23dd-631d98bf74a9/rss"
            $rssFeed = [xml](New-Object System.Net.WebClient).DownloadString($rss)
            $feed = $rssFeed.rss.channel.item | Where-Object { $_.title -like "*Servicing Stack Update*Windows 10*" }
            $feed = ($feed | Where-Object { $_.title -like "*1607*" } | Select-Object -Property Link | Sort-Object link)
            $ssuArray = @()
            foreach ($update in $feed) {
                # trim down the URL to just get the KB
                $ssuItem = ($update.link).Split('/')[4]
                $ssuArray += "$ssuItem"
            }
            # Old ssuArray accurate as of July 2019
            #$ssuArray = @("4132216", "4465659", "4485447", "4498947", "4503537")
            $updateArray = @("4091664")
            $ssuSearchString = 'Windows Server 2016'
            $flashSearchString = 'Security Update for Adobe Flash Player for Windows Server 2016 for x64-based Systems'
        }
        elseif ($buildVersion -eq "17763") {
            $rss = "https://support.microsoft.com/app/content/api/content/feeds/sap/en-us/6ae59d69-36fc-8e4d-23dd-631d98bf74a9/rss"
            $rssFeed = [xml](New-Object System.Net.WebClient).DownloadString($rss)
            $feed = $rssFeed.rss.channel.item | Where-Object { $_.title -like "*Servicing Stack Update*Windows 10*" }
            $feed = ($feed | Where-Object { $_.title -like "*1809*" } | Select-Object -Property Link | Sort-Object link)
            $ssuArray = @()
            foreach ($update in $feed) {
                # trim down the URL to just get the KB
                $ssuItem = ($update.link).Split('/')[4]
                $ssuArray += "$ssuItem"
            }
            # Old ssuArray accurate as of July 2019
            #$ssuArray = @("4470788", "4493510", "4499728", "4504369")
            $updateArray = @("4465065")
            $ssuSearchString = 'Windows Server 2019'
            $flashSearchString = 'Security Update for Adobe Flash Player for Windows Server 2019 for x64-based Systems'
        }

        foreach ($ssu in $ssuArray) {
            Write-Host "Build is $buildVersion - Need to download: KB$($ssu) to update Servicing Stack before adding future Cumulative Updates"
            $ssuKbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$ssu" -UseBasicParsing
            $ssuAvailable_kbIDs = $ssuKbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
            #$ssuAvailable_kbIDs | Out-String | Write-Host
            $ssuKbIDs = $ssuKbObj.Links | Where-Object ID -match '_link' | Where-Object innerText -match $ssuSearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $ssuAvailable_kbIDs }
    
            # If innerHTML is empty or does not exist, use outerHTML instead
            if (!$ssuKbIDs) {
                $ssuKbIDs = $ssuKbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $ssuSearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $ssuAvailable_kbIDs }
            }
            $kbDownloads += "$ssuKbIDs"
        }
                        
        foreach ($update in $updateArray) {
            Write-Host "Build is $buildVersion - Need to download: KB$($update) to ensure image is fully updated at first run"
            $updateKbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$update%20x64%20$v" -UseBasicParsing
            $updateAvailable_kbIDs = $updateKbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID | Select-Object -First 1
            #$updateAvailable_kbIDs | Out-String | Write-Host
            $kbDownloads += "$updateAvailable_kbIDs"
        }

        # Find the KB Article for the latest Adobe Flash Security Update
        Write-Host "Getting info for latest Adobe Flash Security Update"
        $flashKbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=$flashSearchString" -UseBasicParsing
        $Available_flashKbIDs = $flashKbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
        $flashKbIDs = $flashKbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $flashSearchString | Select-Object -First 1 | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_flashKbIDs }
        # Defined a KB array to hold the NETkbIDs
        $kbDownloads += "$flashKbIDs"
                        
        # Find the KB Article Number for the latest Windows Server Cumulative Update
        Write-Host "Accessing $StartKB to retrieve the list of updates."
        $kbID = (Invoke-WebRequest -Uri $StartKB -UseBasicParsing).RawContent -split "`n"
        $kbID = ($kbID | Where-Object { $_ -like "*heading*$buildVersion*" } | Select-Object -First 1)
        $kbID = ((($kbID -split "KB", 2)[1]) -split "\s", 2)[0]
    
        if (!$kbID) {
            Write-Host "No Windows Update KB found - this is an error. Your Windows Server images will be out of date"
        }
    
        # Get Download Link for the corresponding Cumulative Update
        Write-Host "Found latest Cumulative Update: KB$kbID"
        $kbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$kbID" -UseBasicParsing
        $Available_kbIDs = $kbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
        #$Available_kbIDs | Out-String | Write-Host
        $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object innerText -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }
    
        # If innerHTML is empty or does not exist, use outerHTML instead
        if (!$kbIDs) {
            $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }
        }
        # Defined a KB array to hold the kbIDs and if the build is 14393, add the corresponding KBID to it
        $kbDownloads += "$kbIDs"
    
        if ($v -eq "2019") {
            ## .NET CU Download ####
            # Find the KB Article Number for the latest .NET on Windows Server 2019 (Build 17763) Cumulative Update
            $ie = New-Object -ComObject "InternetExplorer.Application"
            $ie.silent = $true
            $ie.Navigate("https://support.microsoft.com/en-us/help/4466961")
            while ($ie.ReadyState -ne 4) { start-sleep -m 100 }
            $NETkbID = ($ie.Document.getElementsByTagName('A') | Where-Object { $_.textContent -like "*KB*" }).innerHTML | Select-Object -First 1
            $NETkbID = ((($NETkbID -split "KB", 2)[1]) -split "\s", 2)[0]
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($ie)
            Remove-Variable ie -ErrorAction SilentlyContinue
    
            if (!$NETkbID) {
                Write-Host "No Windows Update KB found - this is an error. Your Windows Server images will not have the latest .NET update"
            }
    
            # Get Download Link for the corresponding Cumulative Update
            Write-Host "Found latest .NET Framework update: KB$NETkbID"
            $kbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$NETkbID" -UseBasicParsing
            $Available_kbIDs = $kbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
            #$Available_kbIDs | Out-String | Write-Host
            $NETkbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }
            # Defined a KB array to hold the NETkbIDs
            $kbDownloads += "$NETkbIDs"
        }
                        
        foreach ( $kbID in $kbDownloads ) {
            Write-Host "Need to download the following update file with KB ID: $kbID"
            $Post = @{ size = 0; updateID = $kbID; uidInfo = $kbID } | ConvertTo-Json -Compress
            $PostBody = @{ updateIDs = "[$Post]" } 
            $Urls += Invoke-WebRequest -Uri 'http://www.catalog.update.microsoft.com/DownloadDialog.aspx' -UseBasicParsing -Method Post -Body $postBody | Select-Object -ExpandProperty Content | Select-String -AllMatches -Pattern "(http[s]?\://download\.windowsupdate\.com\/[^\'\""]*)" | ForEach-Object { $_.matches.value }
        }
    
        # Download the corresponding Windows Server Cumulative Update (and possibly, Servicing Stack Updates)
        foreach ( $Url in $Urls ) {
            $filename = (($Url.Substring($Url.LastIndexOf("/") + 1)).Split("-", 2)[1])
            $filename = $filename -replace "_.*\.", "."
            $target = "$((Get-Item $azsPath).FullName)\images\$v\$filename"
            if (!(Test-Path -Path $target)) {
                foreach ($ssu in $ssuArray) {
                    if ((Test-Path -Path "$((Get-Item $azsPath).FullName)\images\$v\$($buildVersion)_ssu_kb$($ssu).msu")) {
                        Remove-Item -Path "$((Get-Item $azsPath).FullName)\images\$v\$($buildVersion)_ssu_kb$($ssu).msu" -Force -Verbose -ErrorAction Stop
                    }
                }
                Write-Host "Update will be stored at $target"
                Write-Host "These can be larger than 1GB, so may take a few minutes."
                DownloadWithRetry -downloadURI "$Url" -downloadLocation "$target" -retries 10
            }
            else {
                Write-Host "File exists: $target. Skipping download."
            }
        }
    
        # Rename the .msu for the servicing stack update, to ensure it gets applied in the correct order when patching the WIM file.
        foreach ($ssu in $ssuArray) {
            if ((Test-Path -Path "$((Get-Item $azsPath).FullName)\images\$v\$($buildVersion)_ssu_kb$($ssu).msu")) {
                Write-Host "The $buildVersion Servicing Stack Update already exists within the target folder"
            }
            else {
                Write-Host "Renaming the Servicing Stack Update to ensure it is applied in the correct order"
                Get-ChildItem -Path "$azsPath\images\$v\" -Filter *.msu | Where-Object { $_.FullName -like "*$($ssu)*" } | Rename-Item -NewName "$($buildVersion)_ssu_kb$($ssu).msu" -Force -ErrorAction Stop -Verbose
            }
        }
        # All updates should now be downloaded - time to distribute them into correct folders.
        New-Item -ItemType Directory -Path "$azsPath\images\$v\SSU" -Force | Out-Null
        New-Item -ItemType Directory -Path "$azsPath\images\$v\CU" -Force | Out-Null
        Get-ChildItem -Path "$azsPath\images\$v\" -Filter *.msu -ErrorAction SilentlyContinue | Where-Object { $_.FullName -like "*ssu*" } | Move-Item -Destination "$azsPath\images\$v\SSU" -Force -ErrorAction Stop -Verbose
        Get-ChildItem -Path "$azsPath\images\$v\" -Filter *.msu -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike "*ssu*" } | Move-Item -Destination "$azsPath\images\$v\CU" -Force -ErrorAction Stop -Verbose
    }
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