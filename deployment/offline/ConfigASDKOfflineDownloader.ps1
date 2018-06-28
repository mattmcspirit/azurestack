<#

.SYNOPSYS

    The purpose of this script is to automate the download of all files and scripts required for installing all services on ASDK, that are to be
    configured by the ASDK Configurator.
    This includes:
        * Validates all input parameters
        * Ensures password for VMs meets complexity required for App Service installation
        * Updated password expiration (180 days)
        * Disable Windows Update on all infrastructures VMs and ASDK host (To avoid the temptation to apply the patches...)
        * Tools installation (Azure Stack Tools)
        * Registration of the ASDK to Azure (Optional - enables Marketplace Syndication)

.VERSION

    1805.2  Initial version, to align with current ASDK Configurator version.

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
    [String]$ISOPath
)

$VerbosePreference = "Continue"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {Stop-Transcript | Out-Null} catch {}

### CUSTOM VERBOSE FUNCTION #################################################################################################################################
#############################################################################################################################################################
function Write-CustomVerbose {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string]$Message = ''
    )
    begin {}
    process {
        $verboseTime = (Get-Date).ToShortTimeString()
        # Function for displaying formatted log messages.  Also displays time in minutes since the script was started
        Write-Verbose -Message "[$verboseTime]::[$scriptStep]:: $Message"
    }
    end {}
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

Write-CustomVerbose -Message "Validating if running under Admin Privileges"
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-CustomVerbose -Message "User is not administrator - please ensure you're running as Administrator (right-click, Run as administrator)" 
    exit
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

### Validate path to ISO File ###
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

### Start Logging ###
$logTime = $(Get-Date).ToString("MMdd-HHmmss")
$logStart = Start-Transcript -Path "$downloadPath\ConfigASDKLog$logTime.txt" -Append
Write-CustomVerbose -Message $logStart

### DOWNLOAD TOOLS #####################################################################################################################################
########################################################################################################################################################

### Create root ConfigASDKfiles FOLDER and sub folder structure ###

$configASDKFilePathExists = [System.IO.Directory]::Exists("$downloadPath\ConfigASDKfiles")
if ($configASDKFilePathExists -eq $true) {
    $configASDKFilePath = "$downloadPath\ConfigASDKfiles"
    Write-CustomVerbose -Message "ASDK folder exists at $downloadPath - no need to create it."
    Write-CustomVerbose -Message "Download files will be placed in $downloadPath\ConfigASDKfiles"
    $i = 0 
    While ($i -le 3) {
        Remove-Item "$configASDKFilePath\*" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue -Verbose
        $i++
    }
}
elseif ($configASDKFilePathExists -eq $false) {
    # Create the ASDK folder.
    Write-CustomVerbose -Message "ASDK folder doesn't exist within $downloadPath, creating it"
    $configASDKFilePath = mkdir "$downloadPath\ConfigASDKfiles" -Force
}

$ASDKpath = mkdir "$configASDKFilePath\ASDK" -Force
$packagePath = mkdir "$ASDKpath\packages" -Force
$templatePath = mkdir "$ASDKpath\templates" -Force

try {
    ### DOWNLOAD TOOLS ###
    # Download the tools archive using a function incase the download fails or is interrupted.
    $toolsURI = "https://github.com/Azure/AzureStack-Tools/archive/master.zip"
    $toolsDownloadLocation = "$ASDKpath\master.zip"
    Write-CustomVerbose -Message "Downloading Azure Stack Tools to ensure you have the latest versions. This may take a few minutes, depending on your connection speed."
    Write-CustomVerbose -Message "The download will be stored in $ASDKpath."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    DownloadWithRetry -downloadURI "$toolsURI" -downloadLocation "$toolsDownloadLocation" -retries 10
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Download Ubuntu Zip & Gallery Item ##################################################################################################################
#########################################################################################################################################################

try {
    ### DOWNLOAD UBUNTU ZIP ###
    $ubuntuDownloadLocation = "$ASDKpath\UbuntuServer.1.0.0.zip"
    $ubuntuURI = "https://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"
    Write-CustomVerbose -Message "Downloading latest Ubuntu Server 16.04 image (ZIP). This may take a few minutes, depending on your connection speed."
    Write-CustomVerbose -Message "The download will be stored in $ubuntuDownloadLocation."
    DownloadWithRetry -downloadURI "$ubuntuURI" -downloadLocation "$ubuntuDownloadLocation" -retries 10
    ### DOWNLOAD UBUNTU GALLERY ITEM ###
    $ubuntuAzpkgDownloadLocation = "$packagePath\Canonical.UbuntuServer1604LTS-ARM.1.0.0.azpkg"
    $galleryItemUri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/Ubuntu/Canonical.UbuntuServer1604LTS-ARM.1.0.0.azpkg"
    Write-CustomVerbose -Message "Downloading latest Ubuntu Server 16.04 gallery item from GitHub. This may take a few minutes, depending on your connection speed."
    Write-CustomVerbose -Message "The download will be stored in $ubuntuAzpkgDownloadLocation."
    DownloadWithRetry -downloadURI "$galleryItemUri" -downloadLocation "$ubuntuAzpkgDownloadLocation" -retries 10
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Copy Windows Server ISO & Download Updates ##########################################################################################################
#########################################################################################################################################################

### Copy ISO file to $downloadPath ###
try {
    Write-CustomVerbose -Message "Copying Windows Server 2016 ISO image to $configASDKFilePath" -ErrorAction Stop
    $ISOFile = Split-Path $ISOPath -leaf
    $ISOinDownloadPath = [System.IO.File]::Exists("$configASDKFilePath\$ISOFile")
    if (!$ISOinDownloadPath) {
        Copy-Item "$ISOPath" -Destination "$configASDKFilePath" -Force -Verbose
    }
    else {
        Write-CustomVerbose -Message "Windows Server 2016 ISO image exists within $configASDKFilePath." -ErrorAction Stop
        Write-CustomVerbose -Message "Full path is "$configASDKFilePath\$ISOFile"." -ErrorAction Stop
    }
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Get appropriate update packages and store in $ASDKpath ###
try {
    # Mount the ISO, check the image for the version, then dismount
    Remove-Variable -Name buildVersion -ErrorAction SilentlyContinue
    $isoMountForVersion = Mount-DiskImage -ImagePath $ISOPath -StorageType ISO -PassThru
    $isoDriveLetterForVersion = ($isoMountForVersion | Get-Volume).DriveLetter
    $wimPath = "$IsoDriveLetterForVersion`:\sources\install.wim"
    $buildVersion = (dism.exe /Get-WimInfo /WimFile:$wimPath /index:1 | Select-String "Version ").ToString().Split(".")[2].Trim()
    Dismount-DiskImage -ImagePath $ISOPath

    Write-CustomVerbose -Message "You're missing at least one of the Windows Server 2016 Datacenter images, so we'll first download the latest Cumulative Update."
    # Define parameters
    $StartKB = 'https://support.microsoft.com/app/content/api/content/asset/en-us/4000816'
    $SearchString = 'Cumulative.*Server.*x64'

    ### Firstly, check for build 14393, and if so, download the Servicing Stack Update or other MSUs will fail to apply.    
    if ($buildVersion -eq "14393") {
        $servicingStackKB = "4132216"
        $ServicingSearchString = 'Windows Server 2016'
        Write-CustomVerbose -Message "Build is $buildVersion - Need to download: KB$($servicingStackKB) to update Servicing Stack before adding future Cumulative Updates"
        $servicingKbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$servicingStackKB" -UseBasicParsing
        $servicingAvailable_kbIDs = $servicingKbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
        $servicingAvailable_kbIDs | Out-String | Write-Verbose
        $servicingKbIDs = $servicingKbObj.Links | Where-Object ID -match '_link' | Where-Object innerText -match $ServicingSearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $servicingAvailable_kbIDs }

        # If innerHTML is empty or does not exist, use outerHTML instead
        if ($servicingKbIDs -eq $Null) {
            $servicingKbIDs = $servicingKbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $ServicingSearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $servicingAvailable_kbIDs }
        }
    }

    # Find the KB Article Number for the latest Windows Server 2016 (Build 14393) Cumulative Update
    Write-CustomVerbose -Message "Downloading $StartKB to retrieve the list of updates."
    $kbID = (Invoke-WebRequest -Uri $StartKB -UseBasicParsing).Content | ConvertFrom-Json | Select-Object -ExpandProperty Links | Where-Object level -eq 2 | Where-Object text -match $buildVersion | Select-Object -First 1

    # Get Download Link for the corresponding Cumulative Update
    Write-CustomVerbose -Message "Found ID: KB$($kbID.articleID)"
    $kbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$($kbID.articleID)" -UseBasicParsing
    $Available_kbIDs = $kbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
    $Available_kbIDs | Out-String | Write-Verbose
    $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object innerText -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }

    # If innerHTML is empty or does not exist, use outerHTML instead
    If ($kbIDs -eq $Null) {
        $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }
    }

    # Defined a KB array to hold the kbIDs and if the build is 14393, add the corresponding KBID to it
    $kbDownloads = @()
    if ($buildVersion -eq "14393") {
        $kbDownloads += "$servicingKbIDs"
    }
    $kbDownloads += "$kbIDs"
    $Urls = @()

    foreach ( $kbID in $kbDownloads ) {
        Write-CustomVerbose -Message "KB ID: $kbID"
        $Post = @{ size = 0; updateID = $kbID; uidInfo = $kbID } | ConvertTo-Json -Compress
        $PostBody = @{ updateIDs = "[$Post]" } 
        $Urls += Invoke-WebRequest -Uri 'http://www.catalog.update.microsoft.com/DownloadDialog.aspx' -UseBasicParsing -Method Post -Body $postBody | Select-Object -ExpandProperty Content | Select-String -AllMatches -Pattern "(http[s]?\://download\.windowsupdate\.com\/[^\'\""]*)" | ForEach-Object { $_.matches.value }
    }

    # Download the corresponding Windows Server 2016 Cumulative Update (and possibly, Servicing Stack Update)
    foreach ( $Url in $Urls ) {
        $filename = $Url.Substring($Url.LastIndexOf("/") + 1)
        $target = "$((Get-Item $ASDKpath).FullName)\$filename"
        Write-CustomVerbose -Message "Update will be stored at $target"
        Write-CustomVerbose -Message "These can be larger than 1GB, so may take a few minutes."
        if (!(Test-Path -Path $target)) {
            DownloadWithRetry -downloadURI "$Url" -downloadLocation "$target" -retries 10
        }
        else {
            Write-CustomVerbose -Message "File exists: $target. Skipping download."
        }
    }

    # If this is for Build 14393, rename the .msu for the servicing stack update, to ensure it gets applied first when patching the WIM file.
    if ($buildVersion -eq "14393") {
        Write-CustomVerbose -Message "Renaming the Servicing Stack Update to ensure it is applied first"
        Get-ChildItem -Path $ASDKpath -Filter *.msu | Sort-Object Length | Select-Object -First 1 | Rename-Item -NewName "14393UpdateServicingStack.msu" -Force -Verbose
        $target = $ASDKpath
    }

}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

try {
    # Download Convert-WindowsImage.ps1
    $convertWindowsURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/scripts/Convert-WindowsImage.ps1"
    $convertWindowsDownloadLocation = "$ASDKpath\Convert-WindowsImage.ps1"
    Write-CustomVerbose -Message "Downloading Convert-WindowsImage.ps1"
    Write-CustomVerbose -Message "The download will be stored in $ASDKpath."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    DownloadWithRetry -downloadURI "$convertWindowsURI" -downloadLocation "$convertWindowsDownloadLocation" -retries 10
    Set-Location $ASDKpath
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Download Windows Server packages from GitHub ###
try {
    $packageArray = @()
    $packageArray.Clear()
    $packageArray = "*Microsoft.WindowsServer2016Datacenter-ARM*", "*Microsoft.WindowsServer2016DatacenterServerCore-ARM*"

    foreach ($package in $packageArray) {
        $wsPackage = $null
        $wsPackage = $package -replace '[*]', ''
        $wsAzpkgDownloadLocation = "$packagePath\$wsPackage.1.0.0.azpkg"
        Write-CustomVerbose -Message "Downloading Windows Server 2016 AZPKG files from GitHub."
        Write-CustomVerbose -Message "The download will be stored in $wsAzpkgDownloadLocation."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $galleryItemUri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/WindowsServer/$wsPackage.1.0.0.azpkg"
        DownloadWithRetry -downloadURI "$galleryItemUri" -downloadLocation "$wsAzpkgDownloadLocation" -retries 10
    }
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### DOWNLOAD SCALE SET GALLERY ITEM ##########################################################################################################################
##############################################################################################################################################################

try {
    $vmssAzpkgDownloadLocation = "$packagePath\microsoft.vmss.1.3.6.azpkg"
    Write-CustomVerbose -Message "Downloading Virtual Machine Scale Set AZPKG file from GitHub."
    Write-CustomVerbose -Message "The download will be stored in $vmssAzpkgDownloadLocation."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $galleryItemUri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/VMSS/microsoft.vmss.1.3.6.azpkg"
    DownloadWithRetry -downloadURI "$galleryItemUri" -downloadLocation "$vmssAzpkgDownloadLocation" -retries 10
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### DOWNLOAD MYSQL GALLERY ITEM ##########################################################################################################################
##############################################################################################################################################################

try {
    $mySQLAzpkgDownloadLocation = "$packagePath\ASDK.MySQL.1.0.0"
    Write-CustomVerbose -Message "Downloading MySQL 5.7 on Ubuntu Server AZPKG file from GitHub."
    Write-CustomVerbose -Message "The download will be stored in $mySQLAzpkgDownloadLocation."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $galleryItemUri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/MySQL/ASDK.MySQL.1.0.0.azpkg"
    DownloadWithRetry -downloadURI "$galleryItemUri" -downloadLocation "$mySQLAzpkgDownloadLocation" -retries 10
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### DOWNLOAD SQL GALLERY ITEM ##########################################################################################################################
##############################################################################################################################################################

try {
    $sqlAzpkgDownloadLocation = "$packagePath\ASDK.MSSQL.1.0.0"
    Write-CustomVerbose -Message "Downloading SQL Server 2017 on Ubuntu Server AZPKG file from GitHub."
    Write-CustomVerbose -Message "The download will be stored in $sqlAzpkgDownloadLocation."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $galleryItemUri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/MSSQL/ASDK.MSSQL.1.0.0.azpkg"
    DownloadWithRetry -downloadURI "$galleryItemUri" -downloadLocation "$sqlAzpkgDownloadLocation" -retries 10
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### DOWNLOAD MySQL RP ########################################################################################################################################
##############################################################################################################################################################

try {
    $mySqlRpURI = "https://aka.ms/azurestackmysqlrp"
    $mySqlRpDownloadLocation = "$ASDKpath\MySQL.zip"
    Write-CustomVerbose -Message "Downloading MySQL Resource Provider files."
    Write-CustomVerbose -Message "The download will be stored in $mySqlRpDownloadLocation."
    DownloadWithRetry -downloadURI "$mySqlRpURI" -downloadLocation "$mySqlRpDownloadLocation" -retries 10
    Set-Location $ASDKpath
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### DOWNLOAD SQL RP ##########################################################################################################################################
##############################################################################################################################################################

try {
    $sqlRpURI = "https://aka.ms/azurestacksqlrp"
    $sqlRpDownloadLocation = "$ASDKpath\SQL.zip"
    Write-CustomVerbose -Message "Downloading SQL Resource Provider files."
    Write-CustomVerbose -Message "The download will be stored in $sqlRpDownloadLocation."
    DownloadWithRetry -downloadURI "$sqlRpURI" -downloadLocation "$sqlRpDownloadLocation" -retries 10
    Set-Location $ASDKpath
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Download Database & File Server Templates ##############################################################################################################################
##############################################################################################################################################################

try {
    # MySQL VM
    $mySQLTemplateURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/packages/MySQL/ASDK.MySQL/DeploymentTemplates/mainTemplate.json"
    $mySQLTemplateLocation = "$templatePath\mySqlTemplate.json"
    Write-CustomVerbose -Message "Downloading MySQL template for deployment."
    Write-CustomVerbose -Message "The download will be stored in $mySQLTemplateLocation."
    DownloadWithRetry -downloadURI "$mySQLTemplateURI" -downloadLocation "$mySQLTemplateLocation" -retries 10
    # SQL VM
    $sqlTemplateURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/packages/MSSQL/ASDK.MSSQL/DeploymentTemplates/mainTemplate.json"
    $sqlTemplateLocation = "$templatePath\SqlTemplate.json"
    Write-CustomVerbose -Message "Downloading SQL template for deployment."
    Write-CustomVerbose -Message "The download will be stored in $sqlTemplateLocation."
    DownloadWithRetry -downloadURI "$sqlTemplateURI" -downloadLocation "$sqlTemplateLocation" -retries 10
    # MySQL Hosting
    $mySQLHostingTemplateURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/MySQLHosting/azuredeploy.json"
    $mySQLHostingTemplateLocation = "$templatePath\mySqlHostingTemplate.json"
    Write-CustomVerbose -Message "Downloading MySQL Hosting Server template for deployment."
    Write-CustomVerbose -Message "The download will be stored in $mySQLHostingTemplateLocation."
    DownloadWithRetry -downloadURI "$mySQLHostingTemplateURI" -downloadLocation "$mySQLHostingTemplateLocation" -retries 10
    # SQL Hosting
    $sqlHostingTemplateURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/SQLHosting/azuredeploy.json"
    $sqlHostingTemplateLocation = "$templatePath\SqlHostingTemplate.json"
    Write-CustomVerbose -Message "Downloading SQL Hosting Server template for deployment."
    Write-CustomVerbose -Message "The download will be stored in $sqlHostingTemplateLocation."
    DownloadWithRetry -downloadURI "$sqlHostingTemplateURI" -downloadLocation "$sqlHostingTemplateLocation" -retries 10
    # File Server
    $fileServerTemplateURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/SQLHosting/azuredeploy.json"
    $fileServerTemplateLocation = "$templatePath\FileServerTemplate.json"
    Write-CustomVerbose -Message "Downloading File Server template for deployment."
    Write-CustomVerbose -Message "The download will be stored in $fileServerTemplateLocation."
    DownloadWithRetry -downloadURI "$fileServerTemplateURI" -downloadLocation "$fileServerTemplateLocation" -retries 10
    Set-Location $ASDKpath
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Download App Service #####################################################################################################################################
##############################################################################################################################################################

try {
    $appServiceHelperURI = "https://aka.ms/appsvconmashelpers"
    $appServiceHelperDownloadLocation = "$ASDKpath\appservicehelper.zip"
    Write-CustomVerbose -Message "Downloading App Service Resource Provider Helper files."
    Write-CustomVerbose -Message "The download will be stored in $appServiceHelperDownloadLocation."
    DownloadWithRetry -downloadURI "$appServiceHelperURI" -downloadLocation "$appServiceHelperDownloadLocation" -retries 10
    $appServiceExeURI = "https://aka.ms/appsvconmasinstaller"
    $appServiceExeDownloadLocation = "$ASDKpath\appservice.exe"
    Write-CustomVerbose -Message "Downloading App Service Installer."
    Write-CustomVerbose -Message "The download will be stored in $appServiceHelperDownloadLocation."
    DownloadWithRetry -downloadURI "$appServiceExeURI" -downloadLocation "$appServiceExeDownloadLocation" -retries 10
    $appServicePreJson = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/appservice/AppServiceDeploymentSettings.json"
    $appServicePreJsonDownloadLocation = "$ASDKpath\AppServiceDeploymentSettings.json"
    Write-CustomVerbose -Message "Downloading App Service Pre-Deployment JSON Configuration."
    Write-CustomVerbose -Message "The download will be stored in $appServicePreJsonDownloadLocation."
    DownloadWithRetry -downloadURI "$appServicePreJson" -downloadLocation "$appServicePreJsonDownloadLocation" -retries 10
    Set-Location $ASDKpath
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Create a ZIP file ########################################################################################################################################
##############################################################################################################################################################

try {
    Write-CustomVerbose -Message "Creating zip file" -ErrorAction Stop
    Compress-Archive -Path "$configASDKFilePath\*" -CompressionLevel Optimal -DestinationPath "$downloadPath\ConfigASDKfiles" -Force -Verbose -ErrorAction Stop
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Final Steps ##############################################################################################################################################
##############################################################################################################################################################

# Calculate completion time
$endTime = Get-Date -Format g
$sw.Stop()
$Hrs = $sw.Elapsed.Hours
$Mins = $sw.Elapsed.Minutes
$Secs = $sw.Elapsed.Seconds
$difference = '{0:00}h:{1:00}m:{2:00}s' -f $Hrs, $Mins, $Secs

Set-Location $ScriptLocation -ErrorAction SilentlyContinue
Write-Output "ASDK Configurator offline downloader completed successfully, taking $difference." -ErrorAction SilentlyContinue
Write-Output "You started the at $startTime." -ErrorAction SilentlyContinue
Write-Output "The process completed at $endTime." -ErrorAction SilentlyContinue
Stop-Transcript -ErrorAction SilentlyContinue