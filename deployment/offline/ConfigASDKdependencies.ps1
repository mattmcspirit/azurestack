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
$scriptStep = ""
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

$scriptStep = "VALIDATION"
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
$logStart = Start-Transcript -Path "$downloadPath\ConfigASDKDependencyLog$logTime.txt" -Append
Write-CustomVerbose -Message $logStart

### Create Folder Structure ############################################################################################################################
########################################################################################################################################################

$scriptStep = "CREATE FOLDERS"
### Create root ConfigASDKfiles FOLDER and sub folder structure ###
$configASDKFilePathExists = [System.IO.Directory]::Exists("$downloadPath\ConfigASDKfiles")
if ($configASDKFilePathExists -eq $true) {
    $configASDKFilePath = "$downloadPath\ConfigASDKfiles"
    Write-CustomVerbose -Message "ASDK folder exists at $downloadPath - no need to create it."
    Write-CustomVerbose -Message "Download files will be placed in $downloadPath\ConfigASDKfiles"
    $i = 0 
    While ($i -le 3) {
        Remove-Item "$configASDKFilePath\*" -Exclude "*.iso" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue -Verbose
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
$psPath = mkdir "$ASDKpath\powershell" -Force
$dbPath = mkdir "$ASDKpath\databases" -Force
$imagesPath = mkdir "$ASDKpath\images" -Force
$appServicePath = mkdir "$ASDKpath\appservice" -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


### Create Download Table ##############################################################################################################################
########################################################################################################################################################
$scriptStep = "CREATE TABLE"
try {
    Write-CustomVerbose -Message "Creating table to store list of downloads" -ErrorAction Stop
    $table = New-Object System.Data.DataTable
    $table.Clear()
    $table.Columns.Add("productName", "string") | Out-Null
    $table.Columns.Add("filename", "string") | Out-Null
    $table.Columns.Add("path", "string") | Out-Null
    $table.Columns.Add("Uri", "string") | Out-Null

    # ConfigASDK.ps1 Script
    $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/ConfigASDK.ps1"
    $row.filename = "ConfigASDK.ps1"; $row.path = "$downloadPath"; $row.productName = "ASDK Configurator Script"; $Table.Rows.Add($row)
    # Azure Stack Tools
    $row = $table.NewRow(); $row.Uri = "https://github.com/Azure/AzureStack-Tools/archive/master.zip"
    $row.filename = "Master.zip"; $row.path = "$ASDKpath"; $row.productName = "Azure Stack Tools"; $Table.Rows.Add($row)
    # Ubuntu Server 16.04 ZIP
    $row = $table.NewRow(); $row.Uri = "https://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"
    $row.filename = "UbuntuServer.1.0.0.zip"; $row.path = "$imagesPath"; $row.productName = "Ubuntu Server 16.04 LTS zip file"; $Table.Rows.Add($row)
    # Ubuntu Server AZPKG
    $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/Ubuntu/Canonical.UbuntuServer1604LTS-ARM.1.0.0.azpkg"
    $row.filename = "Canonical.UbuntuServer1604LTS-ARM.1.0.0.azpkg"; $row.path = "$packagePath"; $row.productName = "Ubuntu Server Marketplace Package"; $Table.Rows.Add($row)
    # Convert-WindowsImage.ps1 Script
    $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/scripts/Convert-WindowsImage.ps1"
    $row.filename = "Convert-WindowsImage.ps1"; $row.path = "$imagesPath"; $row.productName = "Convert-WindowsImage.ps1 VHD Creation Tool"; $Table.Rows.Add($row)
    # Windows Server DC AZPKG
    $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/WindowsServer/Microsoft.WindowsServer2016Datacenter-ARM.1.0.0.azpkg"
    $row.filename = "Microsoft.WindowsServer2016Datacenter-ARM.1.0.0.azpkg"; $row.path = "$packagePath"; $row.productName = "Windows Server 2016 Datacenter Marketplace Package"; $Table.Rows.Add($row)
    # Windows Server DC Core AZPKG
    $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/WindowsServer/Microsoft.WindowsServer2016DatacenterServerCore-ARM.1.0.0.azpkg"
    $row.filename = "Microsoft.WindowsServer2016DatacenterServerCore-ARM.1.0.0.azpkg"; $row.path = "$packagePath"; $row.productName = "Windows Server 2016 Datacenter Core Marketplace Package"; $Table.Rows.Add($row)
    # VMSS AZPKG
    $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/VMSS/microsoft.vmss.1.3.6.azpkg"
    $row.filename = "microsoft.vmss.1.3.6.azpkg"; $row.path = "$packagePath"; $row.productName = "Virtual Machine Scale Set Marketplace Package"; $Table.Rows.Add($row)
    # MYSQL AZPKG
    $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/MySQL/ASDK.MySQL.1.0.0.azpkg"
    $row.filename = "ASDK.MySQL.1.0.0.azpkg"; $row.path = "$packagePath"; $row.productName = "MySQL Marketplace Package"; $Table.Rows.Add($row)
    # SQL AZPKG
    $row = $table.NewRow(); $row.Uri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/MSSQL/ASDK.MSSQL.1.0.0.azpkg"
    $row.filename = "ASDK.MSSQL.1.0.0.azpkg"; $row.path = "$packagePath"; $row.productName = "SQL Server Marketplace Package"; $Table.Rows.Add($row)
    # MySQL RP
    $row = $table.NewRow(); $row.Uri = "https://aka.ms/azurestackmysqlrp"
    $row.filename = "MySQL.zip"; $row.path = "$dbPath"; $row.productName = "MySQL Resource Provider Files"; $Table.Rows.Add($row)
    # MySQL RP Helper MSI
    $row = $table.NewRow(); $row.Uri = "https://dev.mysql.com/get/Download/sConnector-Net/mysql-connector-net-6.10.5.msi"
    $row.filename = "mysql-connector-net-6.10.5.msi"; $row.path = "$dbPath"; $row.productName = "MySQL Resource Provider Files Offline Connector"; $Table.Rows.Add($row)
    # SQL RP
    $row = $table.NewRow(); $row.Uri = "https://aka.ms/azurestacksqlrp"
    $row.filename = "SQL.zip"; $row.path = "$dbPath"; $row.productName = "SQL Server Resource Provider Files"; $Table.Rows.Add($row)
    # MySQL VM Template
    $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/packages/MySQL/ASDK.MySQL/DeploymentTemplates/mainTemplate.json"
    $row.filename = "mySqlTemplate.json"; $row.path = "$templatePath"; $row.productName = "MySQL template for deployment"; $Table.Rows.Add($row)
    # SQL VM Template
    $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/packages/MSSQL/ASDK.MSSQL/DeploymentTemplates/mainTemplate.json"
    $row.filename = "sqlTemplate.json"; $row.path = "$templatePath"; $row.productName = "SQL Server template for deployment"; $Table.Rows.Add($row)
    # Add MySQL Hosting Server Template
    $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/MySQLHosting/azuredeploy.json"
    $row.filename = "mySqlHostingTemplate.json"; $row.path = "$templatePath"; $row.productName = "Add MySQL Hosting Server template for deployment"; $Table.Rows.Add($row)
    # Add SQL Hosting Server Template
    $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/SQLHosting/azuredeploy.json"
    $row.filename = "sqlHostingTemplate.json"; $row.path = "$templatePath"; $row.productName = "Add SQL Server Hosting Server template for deployment"; $Table.Rows.Add($row)
    # File Server Template
    $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/FileServer/azuredeploy.json"
    $row.filename = "FileServerTemplate.json"; $row.path = "$templatePath"; $row.productName = "File Server template for deployment"; $Table.Rows.Add($row)
    # App Service Helper Scripts
    $row = $table.NewRow(); $row.Uri = "https://aka.ms/appsvconmashelpers"
    $row.filename = "appservicehelper.zip"; $row.path = "$appServicePath"; $row.productName = "App Service Resource Provider Helper files"; $Table.Rows.Add($row)
    # App Service Installer
    $row = $table.NewRow(); $row.Uri = "https://aka.ms/appsvconmasinstaller"
    $row.filename = "appservice.exe"; $row.path = "$appServicePath"; $row.productName = "App Service installer"; $Table.Rows.Add($row)
    # App Service PreDeployment JSON
    $row = $table.NewRow(); $row.Uri = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/appservice/AppServiceDeploymentSettings.json"
    $row.filename = "AppServiceDeploymentSettings.json"; $row.path = "$appServicePath"; $row.productName = "App Service Pre-Deployment JSON Configuration"; $Table.Rows.Add($row)
    Write-CustomVerbose -Message "The following files will be downloaded:"
    $table | Format-Table -AutoSize
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
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

### Download PowerShell ################################################################################################################################
########################################################################################################################################################

$scriptStep = "POWERSHELL"
try {
    Write-CustomVerbose -Message "Downloading PowerShell Modules for AzureRM and Azure Stack" -ErrorAction Stop
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name AzureRM -Path $psPath -Force -RequiredVersion 1.2.11 | Out-Null
    Save-Package -ProviderName NuGet -Source https://www.powershellgallery.com/api/v2 -Name AzureStack -Path $psPath -Force -RequiredVersion 1.3.0 | Out-Null
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Copy Windows Server ISO & Download Updates ##########################################################################################################
#########################################################################################################################################################

$scriptStep = "WINDOWS"
### Copy ISO file to $downloadPath ###
try {
    Write-CustomVerbose -Message "Copying Windows Server 2016 ISO image to $configASDKFilePath" -ErrorAction Stop
    $ISOFile = Split-Path $ISOPath -leaf
    $ISOinDownloadPath = [System.IO.File]::Exists("$configASDKFilePath\$ISOFile")
    if (!$ISOinDownloadPath) {
        Copy-Item "$ISOPath" -Destination "$configASDKFilePath" -Force -Verbose
        $ISOPath = "$configASDKFilePath\$ISOFile"
    }
    else {
        Write-CustomVerbose -Message "Windows Server 2016 ISO image exists within $configASDKFilePath." -ErrorAction Stop
        Write-CustomVerbose -Message "Full path is $configASDKFilePath\$ISOFile" -ErrorAction Stop
        $ISOPath = "$configASDKFilePath\$ISOFile"
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
        $target = "$((Get-Item $imagesPath).FullName)\$filename"
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
        Get-ChildItem -Path $imagesPath -Filter *.msu | Sort-Object Length | Select-Object -First 1 | Rename-Item -NewName "14393UpdateServicingStack.msu" -Force -Verbose
        $target = $imagesPath
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
    $session = New-PSSession -Name CreateZip
    Write-CustomVerbose -Message "Packaging files into a single ZIP file"
    Invoke-Command -Session $session -ArgumentList $downloadPath, $configASDKFilePath -ScriptBlock {
        $zipPath = "$Using:downloadPath\ConfigASDKfiles.zip"
        Install-Module -Name 7Zip4PowerShell -Verbose -Force
        Compress-7Zip -CompressionLevel None -Path "$Using:configASDKFilePath" -ArchiveFileName $zipPath -Format Zip;
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
Write-Output "ASDK Configurator offline downloader completed successfully, taking $difference." -ErrorAction SilentlyContinue
Write-Output "You started the at $startTime." -ErrorAction SilentlyContinue
Write-Output "The process completed at $endTime." -ErrorAction SilentlyContinue
Stop-Transcript -ErrorAction SilentlyContinue