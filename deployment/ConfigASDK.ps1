<#

.SYNOPSYS

    The purpose of this script is to automate as much as possible post deployment tasks in Azure Stack Development Kit
    This includes:
    * Validates all input parameters
    * Installs Azure Stack PowerShell and AzureRM modules
    * Ensures password for VMs meets complexity required for App Service installation
    * Updated password expiration (180 days)
    * Disable Windows Update on all infrastructures VMs and ASDK host (To avoid the temptation to apply the patches...)
    * Tools installation (Azure Stack Tools)
    * Registration of the ASDK to Azure (Optional - enables Marketplace Syndication)
    * Windows Server 2016 Datacenter Evaluation (Full + Core) images added to the Platform Image Repository
    * Ubuntu Server 16.04-LTS image added to the Platform Image Repository
    * Corresponding gallery items created in the Marketplace for the Windows Server and Ubuntu Server images
    * Gallery item created for MySQL 5.7 and SQL Server 2017 (both on Ubuntu Server 16.04 LTS)
    * Automates adding of Microsoft VM Extensions to Gallery from Marketplace (for registered ASDKs)
    * MySQL Resource Provider installation
    * SQL Server Resource Provider installation
    * Deployment of a MySQL 5.7 hosting server on Ubuntu Server 16.04 LTS
    * Deployment of a SQL Server 2017 hosting server on Ubuntu Server 16.04 LTS
    * Adding SQL Server & MySQL hosting servers to Resource Providers including SKU/Quotas
    * App Service prerequisites installation (SQL Server PowerShell, SQL Server DB VM and Standalone File Server)
    * App Service Resource Provider sources download and certificates generation
    * App Service Service Principal Created (for Azure AD and ADFS)
    * Grants App Service Service Principal Admin Consent (for Azure AD)
    * Automates deployment of the latest App Service release using dynamically constructed JSON
    * Set new default Quotas for MySQL, SQL Server, Compute, Network, Storage and Key Vault
    * Creates a Base Plan and Offer containing all deployed services
    * Creates a user subscription for the logged in tenant, and activates all resource providers
    * Installs a selection of useful apps via Chocolatey (Putty, Chrome, VS Code, WinDirStat, WinSCP, Python3)
    * Configures Python & Azure CLI for usage with ASDK
    * MySQL, SQL, App Service and Host Customization can be optionally skipped
    * Cleans up download folder to ensure clean future runs
    * Transcript Log for errors and troubleshooting
    * Progress Tracking and rerun reliability with ConfigASDK database hosted on SqlLocalDB (2017)
    * Stores script output in a ConfigASDKOutput.txt, for future reference
    * Supports usage in offline/disconnected environments

.VERSION
    1811.2  New -serialMode to deploy VMs one at a time - useful for older, lower performance hardware
    1811.1  Updated to support Azure Stack PowerShell 1.6.0
            Adding v1.9.1 of Custom Script Extension when not registering to allow App Service install
            Bug fixes
    1811    Updated to support 1.1811.0.101
            Updated Windows Server image updates with dynamically obtaining Servicing Stack Update
            Increased App Service VM Image size - More reliable
            Bug fixes
    1809.3  Adjusted VM sizes for Resource Providers to use less resources
            Added host memory check to avoid running out of memory
    1809.2  App Service SQL DB Cleanup for reruns
            Cleans up App Service Resource Group in case of previous run failure - ensures fresh next attempt
            Adjusted Windows Update download to grab KB from different source web page - old one not being updated
    1809.1  Support for Database RPs 1.1.30.0
            Support for App Service 1.4 (Update 4)
            Handling of Azure AD tenants without associated subscription
    1809    Updated to support ASDK 1.1809.0.90
            Support for PS 1.5.0, and new AzureRM Profile 2018-03-01-hybrid
            Use of SqlLocalDB 2017 instead of CSV file to track progress
            Parallel job processing through PowerShell background jobs
            Support for host customization step in offline mode
    1808.1  Added fix for BITS issues with MySQL/SQL RP installations
    1808    No longer adds VMSS gallery item as this is built in.
            Updated to support ASDK build 1.1808.0.97
    1807.1  Updated to support automatic downloading of Microsoft VM Extensions for registered ASDKs
            Added SQL Server PowerShell installation to configure App Service SQL Server VM with Contained DB Authentication
    1807    Updated to provide support for offline deployments, using zip file containing pre-downloaded binaries, tools and scripts along with PS 1.4.0 support
            Also added support for Azure CLI and Python configuration
    1805.2  Update to Windows Image creation to handle adding of KB4132216 to update Servicing Stack (for build 14393) for future updates
            (<https://support.microsoft.com/en-us/help/4132216>)
    1805.1  Updates to handling Azure subscriptions with multiple Azure AD tenants, and error handling for random Add-AzureRmVhd pipeline error,
            added automated App Service quota to base plan, created user subscription and activated RPs for that subscription.
    1805    Updated with improvements to Azure account verification, ability to skip RP deployment, run counters and bug fixes
    1804    Updated with support for ASDK 1804 and PowerShell 1.3.0, bug fixes, reduced number of modules imported from GitHub tools repo
    3.1     Update added App Service automation, bug fixes, MySQL Root account fix.
    3.0     Major update for ASDK release 20180329.1
    2.0     Update for release 1.0.280917.3 
    1.0:    Small bug fixes and adding quotas/plan/offer creation
    0.5:    Add SQL 2014 VM deployment
    0.4:    Add Windows update disable
    0.3:    Bug fix (SQL Provider prompting for tenantdirectoryID)
    0.2:    Bug Fix (AZStools download)

.AUTHOR

    Matt McSpirit
    Blog: http://www.mattmcspirit.com
    Email: matt.mcspirit@microsoft.com 
    Twitter: @mattmcspirit

.CREDITS

    Jon LaBelle - https://jonlabelle.com/snippets/view/powershell/download-remote-file-with-retry-support
    Alain Vetier - https://github.com/esache/Azure-Stack
    Ned Ballavance - https://github.com/ned1313/AzureStack-VM-PoC
    Rik Hepworth - https://github.com/rikhepworth/azurestack

.GUIDANCE

    Please refer to the Readme.md (https://github.com/mattmcspirit/azurestack/blob/master/deployment/README.md) for recommended
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
    [Parameter(Mandatory = $false)]
    [String] $azureDirectoryTenantName,

    [Parameter(Mandatory = $true)]
    [ValidateSet("AzureAd", "ADFS")]
    [String] $authenticationType,

    # Path to store downloaded files
    [parameter(Mandatory = $true)]
    [String]$downloadPath,

    # Path to Windows Server 2016 Datacenter Evaluation ISO file
    [parameter(Mandatory = $false)]
    [String]$ISOPath,

    # Password used for deployment of the ASDK.
    [parameter(Mandatory = $false)]
    [String]$azureStackAdminPwd,

    # Provide Local Administrator password for App Service, MySQL and SQL VMs.
    [parameter(Mandatory = $false)]
    [String]$VMpwd,

    # Username for Azure AD Login - username@<directoryname>.onmicrosoft.com
    [parameter(Mandatory = $false)]
    [string]$azureAdUsername,

    # Password for Azure AD login
    [parameter(Mandatory = $false)]
    [string]$azureAdPwd,

    # If you want the script to register the ASDK for you, use this flag
    [switch]$registerASDK,

    # If you want to use the same Azure AD creds that you used to deploy Azure Stack, to register it, set this flag
    [switch]$useAzureCredsForRegistration,

    # Username for Azure Subscription Login for registering Azure Stack - username@<directoryname>.onmicrosoft.com
    [parameter(Mandatory = $false)]
    [string]$azureRegUsername,
    
    # Password for Azure Subscription Login for registering Azure Stack
    [parameter(Mandatory = $false)]
    [string]$azureRegPwd,

    # Azure Subscription to be used for registering Azure Stack 
    [parameter(Mandatory = $false)]
    [string]$azureRegSubId,

    # If you don't want to install the MySQL Resource Provider and Hosting Server set this flag
    [switch]$skipMySQL,

    # If you don't want to install the SQL Server Resource Provider and Hosting Server set this flag
    [switch]$skipMSSQL,

    # If you don't want to install the App Service and pre-requisites set this flag
    [switch]$skipAppService,

    # If you don't want to customize the ASDK host with useful apps such as Chrome, Azure CLI, VS Code etc. set this flag
    [switch]$skipCustomizeHost,

    # Offline installation package path for all key components
    [parameter(Mandatory = $false)]
    [string]$configAsdkOfflineZipPath,

    # This is used mainly for testing, when you want to run against a specific GitHub branch. Master should be used for all non-testing scenarios.
    [Parameter(Mandatory = $false)]
    [String] $branch,

    # If you have older hardware that can't handle concurrent VM deployments, use this flag
    [switch]$serialMode
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'
try {Stop-Transcript | Out-Null} catch {}
$scriptStep = ""

### DOWNLOADER FUNCTION #####################################################################################################################################
#############################################################################################################################################################
function DownloadWithRetry([string] $downloadURI, [string] $downloadLocation, [int] $retries) {
    while ($true) {
        try {
            Write-Host "Downloading: $downloadURI"
            (New-Object System.Net.WebClient).DownloadFile($downloadURI, $downloadLocation)
            break
        }
        catch {
            $exceptionMessage = $_.Exception.Message
            Write-Host "Failed to download '$downloadURI': $exceptionMessage"
            if ($retries -gt 0) {
                $retries--
                Write-Host "Waiting 10 seconds before retrying. Retries left: $retries"
                Start-Sleep -Seconds 10
            }
            else {
                $exception = $_.Exception
                throw $exception
            }
        }
    }
}

### OFFLINE AZPKG FUNCTION ##################################################################################################################################
#############################################################################################################################################################

function AddOfflineAZPKG {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string]$azpkgPackageName
    )
    #### Need to upload to blob storage first from extracted ZIP ####
    $azpkgFullPath = $null
    $azpkgFileName = $null
    $azpkgFullPath = Get-ChildItem -Path "$ASDKpath\packages" -Recurse -Include *$azpkgPackageName*.azpkg | ForEach-Object { $_.FullName }
    $azpkgFileName = Get-ChildItem -Path "$ASDKpath\packages" -Recurse -Include *$azpkgPackageName*.azpkg | ForEach-Object { $_.Name }
                                
    # Check there's not a gallery item already uploaded to storage
    if ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $azpkgFileName -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue)) {
        Write-Verbose -Message "You already have an upload of $azpkgFileName within your Storage Account. No need to re-upload."
        Write-Verbose -Message "Gallery path = $((Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $azpkgFileName -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue).ICloudBlob.StorageUri.PrimaryUri.AbsoluteUri)"
    }
    else {
        $uploadAzpkgAttempt = 1
        while (!$(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $azpkgFileName -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and ($uploadAzpkgAttempt -le 3)) {
            try {
                # Log back into Azure Stack to ensure login hasn't timed out
                Write-Verbose -Message "No existing gallery item found. Upload Attempt: $uploadAzpkgAttempt"
                Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                Set-AzureStorageBlobContent -File "$azpkgFullPath" -Container $asdkImagesContainerName -Blob "$azpkgFileName" -Context $asdkStorageAccount.Context -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Verbose -Message "Upload failed."
                Write-Verbose -Message "$_.Exception.Message"
                $uploadAzpkgAttempt++
            }
        }
    }
    $azpkgURI = '{0}{1}/{2}' -f $asdkStorageAccount.PrimaryEndpoints.Blob, $asdkImagesContainerName, $azpkgFileName
    Write-Verbose -Message "Uploading $azpkgFileName from $azpkgURI"
    return [string]$azpkgURI
}

### CUSTOM VERBOSE FUNCTION #################################################################################################################################
#############################################################################################################################################################
function Write-CustomVerbose {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string] $Message
    )
    $verboseTime = (Get-Date).ToShortTimeString()
    # Function for displaying formatted log messages.  Also displays time in minutes since the script was started
    Write-Host "[$verboseTime]::[$scriptStep]:: $Message"
}

### JOB LAUNCHER FUNCTION ###################################################################################################################################
#############################################################################################################################################################

function JobLauncher {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string] $jobName,

        [parameter(Mandatory = $true)]
        [System.Object] $jobToExecute
    )
    try {
        if ($null -ne (Get-Job -Name $jobName -ErrorAction SilentlyContinue)) {
            if (Get-Job -Name $jobName -ErrorAction SilentlyContinue | Where-Object { $_.state -eq "Running" } ) {
                Write-Host "$jobName is already running, no need to run this job"
            }
            elseif (Get-Job -Name $jobName -ErrorAction SilentlyContinue | Where-Object { $_.state -eq "Completed" } ) {
                Write-Host "$jobName already completed, no need to run this job"
            }
            elseif (Get-Job -Name $jobName -ErrorAction SilentlyContinue | Where-Object { $_.state -eq "Failed" } ) {
                Write-Host "$jobName previously failed - cleaning up and rerunning"
                Get-Job -Name $jobName -ErrorAction SilentlyContinue | Remove-Job
                & $jobToExecute;
            }
        }
        else {
            Write-Host "$jobName not found, and hasn't previously completed or failed - Starting $jobName job"
            & $jobToExecute;
        }
    }
    catch {
        $exception = $_.Exception
        throw $exception
    }
}

### PROGRESS FUNCTIONS ######################################################################################################################################
#############################################################################################################################################################
function CheckProgress {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string] $progressStage
    )
    # Grab the latest data from the database, store it as $progressCheck, and display it
    $progressCheck = (Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" `
            -TableName "$tableName" -ColumnName $progressStage -ErrorAction SilentlyContinue -Verbose:$false).Item(0)
    return $progressCheck
}
function StageComplete {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string] $progressStage
    )
    # Update the ConfigASDK Progress database with successful completion then display updated table
    Write-Host "ASDK Configurator Stage: $progressStage successfully completed. Updating ConfigASDK Progress database"
    Invoke-Sqlcmd -Server $sqlServerInstance -Query "USE $databaseName UPDATE Progress SET $progressStage = 'Complete';" -Verbose:$false -ErrorAction Stop
    Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" -TableName "$tableName" -Verbose:$false -ErrorAction Stop
}
function StageSkipped {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string] $progressStage
    )
    # Update the ConfigASDK Progress database with skipped status then display updated table
    Write-Host "ASDK Configurator Stage: $progressStage skipped. Updating ConfigASDK Progress database"
    Invoke-Sqlcmd -Server $sqlServerInstance -Query "USE $databaseName UPDATE Progress SET $progressStage = 'Skipped';" -Verbose:$false -ErrorAction Stop
    Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" -TableName "$tableName" -Verbose:$false -ErrorAction Stop
}
function StageFailed {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string] $progressStage
    )
    # Update the ConfigASDK Progress database with failed completion then display updated table, with failure message
    Write-Host "ASDK Configurator Stage: $progressStage failed. Updating ConfigASDK Progress database"
    Invoke-Sqlcmd -Server $sqlServerInstance -Query "USE $databaseName UPDATE Progress SET $progressStage = 'Failed';" -Verbose:$false -ErrorAction Stop
    Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" -TableName "$tableName" -Verbose:$false -ErrorAction Stop
    Write-Host "$_.Exception.Message" -ErrorAction Stop
}
function StageReset {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string] $progressStage
    )
    # Reset the ConfigASDK Progress database from previously being skipped, to incomplete
    Write-Host "The $progressStage stage was either previously skipped, or failed - Updating ConfigASDK Progress database to Incomplete."
    Invoke-Sqlcmd -Server $sqlServerInstance -Query "USE $databaseName UPDATE Progress SET $progressStage = 'Incomplete';" -Verbose:$false -ErrorAction Stop
    Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" -TableName "$tableName" -Verbose:$false -ErrorAction Stop
}

### HOST APP INSTALLER FUNCTION #############################################################################################################################
#############################################################################################################################################################
function HostAppInstaller {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string] $localInstallPath,

        [parameter(Mandatory = $true)]
        [string] $arguments,

        [parameter(Mandatory = $true)]
        [string] $appName,

        [parameter(Mandatory = $true)]
        [string] $fileName,

        [parameter(Mandatory = $true)]
        [ValidateSet("MSI", "EXE")]
        [string] $appType
    )
    if ($fileName -eq "azurecli.msi") {
        if ([System.IO.Directory]::Exists("$localInstallPath")) {
            Write-Host "$appName already appears to be available here: $LocalInstallPath. No need to reinstall"
            $appExists = $true
        }
    }
    else {
        if ([System.IO.File]::Exists("$localInstallPath")) {
            Write-Host "$appName already appears to be available here: $LocalInstallPath. No need to reinstall"
            $appExists = $true
        }
    }
    if (!$appExists) {
        if ($appType -eq "MSI") { $filePath = "msiexec" }
        elseif ($appType -eq "EXE") { $filePath = "$fileName" }
        Write-Host "Installing $appName"
        $installHostApp = Start-Process -FilePath "$filePath" -ArgumentList $arguments -Wait -PassThru -Verbose
        if ($installHostApp.ExitCode -ne 0) {
            throw "Installation of $appName returned error code: $($installHostApp.ExitCode)"
        }
        if ($installHostApp.ExitCode -eq 0) {
            Write-Host "Installation of $appName completed successfully"
        }
    }
}

$export_functions = [scriptblock]::Create(@"
  Function DownloadWithRetry { $function:DownloadWithRetry }
  Function AddOfflineAZPKG { $function:AddOfflineAZPKG }
  Function JobLauncher { $function:JobLauncher }
  Function CheckProgress { $function:CheckProgress }
  Function StageComplete { $function:StageComplete }
  Function StageSkipped { $function:StageSkipped }
  Function StageFailed { $function:StageFailed }
  Function StageReset { $function:StageReset }
"@)

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

### SET ERCS IP Address - same for all default ASDKs ###
$ERCSip = "AzS-ERCS01"

# Define Regex for Password Complexity - needs to be at least 12 characters, with at least 1 upper case, 1 lower case, 1 number and 1 special character
$regex = @"
(?=^.{12,123}$)((?=.*\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[^A-Za-z0-9])(?=.*[a-z])|(?=.*[^A-Za-z0-9])(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9]))^.*
"@

$emailRegex = @"
(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])
"@

### SET LOG LOCATION ###
$logDate = Get-Date -Format FileDate
New-Item -ItemType Directory -Path "$ScriptLocation\Logs\$logDate\" -Force | Out-Null
$logPath = "$ScriptLocation\Logs\$logDate"
Write-CustomVerbose -Message "Log folder full path is $logPath"

### START LOGGING ###
$runTime = $(Get-Date).ToString("MMddyy-HHmmss")
$fullLogPath = "$logPath\ConfigASDKLog$runTime.txt"
$logStart = Start-Transcript -Path "$fullLogPath" -Append
Write-CustomVerbose -Message $logStart

### INTERNET CONNECTION TEST #################################################################################################################################
##############################################################################################################################################################

try {
    Write-CustomVerbose -Message "Testing internet connectivity to various internet resources:"
    $azureNetTest = Test-NetConnection portal.azure.com -CommonTCPPort HTTP -InformationLevel Quiet
    $gitHubNetTest = Test-NetConnection github.com -CommonTCPPort HTTP -InformationLevel Quiet
    $ubuntuNetTest = Test-NetConnection cloud-images.ubuntu.com -CommonTCPPort HTTP -InformationLevel Quiet
    $catalogNetTest = Test-NetConnection www.catalog.update.microsoft.com -CommonTCPPort HTTP -InformationLevel Quiet
    $microsoftNetTest = Test-NetConnection microsoft.com -CommonTCPPort HTTP -InformationLevel Quiet
    $chocolateyNetTest = Test-NetConnection chocolatey.org -CommonTCPPort HTTP -InformationLevel Quiet
    Write-CustomVerbose -Message "Connection to Azure: $azureNetTest"
    Write-CustomVerbose -Message "Connection to Microsoft.com: $microsoftNetTest"
    Write-CustomVerbose -Message "Connection to Microsoft Update Catalog: $catalogNetTest"
    Write-CustomVerbose -Message "Connection to GitHub: $gitHubNetTest"
    Write-CustomVerbose -Message "Connection to Ubuntu's Image Repo: $ubuntuNetTest"
    Write-CustomVerbose -Message "Connection to Chocolatey: $chocolateyNetTest"

    if ($azureNetTest -and $gitHubNetTest -and $ubuntuNetTest -and $catalogNetTest -and $microsoftNetTest -and $chocolateyNetTest) {
        Write-CustomVerbose -Message "All internet connectivity tests passed"
        $validOnlineInstall = $true
    }
    else {
        Write-CustomVerbose -Message "One or more internet connectivity tests failed"
        $validOnlineInstall = $false
        if ($configAsdkOfflineZipPath) {
            Write-CustomVerbose -Message "However, offline zip path has been provided so installation can continue"
            if ($registerASDK) {
                Write-CustomVerbose -Message "You have selected to register your ASDK, which requires internet connectivity."
            }
        }
        else {
            $exception = "No offline zip path provided, and one or more connectivity tests failed. Check your network or provide an offline zip of the dependencies, and try again."
            throw $exception 
        }
    }
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### HOST MEMORY CHECK ###############################################################################################################################################
##############################################################################################################################################################

Write-CustomVerbose -Message "Validating ASDK host memory to ensure you can deploy the additional resource providers on this system"
Write-CustomVerbose -Message "Calculating ASDK host memory"
[INT]$totalPhysicalMemory = Get-CimInstance win32_ComputerSystem -Verbose:$false | ForEach-Object {[math]::round($_.TotalPhysicalMemory / 1GB)}
Write-CustomVerbose -Message "Total physical memory in the ASDK host = $([INT]$totalPhysicalMemory)GB"
[INT]$totalRPMemoryRequired = "0"
if (!$skipMySQL) {
    Write-CustomVerbose -Message "You've chosen to deploy the MySQL Resource Provider. This requires 5.5GB RAM"
    [INT]$totalRPMemoryRequired = [INT]$totalRPMemoryRequired + 5.5
}
if (!$skipMSSQL) {
    Write-CustomVerbose -Message "You've chosen to deploy the SQL Server Resource Provider. This requires 5.5GB RAM"
    [INT]$totalRPMemoryRequired = [INT]$totalRPMemoryRequired + 5.5
}
if (!$skipAppService) {
    Write-CustomVerbose -Message "You've chosen to deploy the App Service Resource Provider. This requires 23GB RAM"
    [INT]$totalRPMemoryRequired = [INT]$totalRPMemoryRequired + 23
}
if ([INT]$totalRPMemoryRequired -gt 0) {
    Write-CustomVerbose -Message "Based on your resource provider selections, you need a total of $([INT]$totalRPMemoryRequired)GB to install the Resource Providers"
    Write-CustomVerbose -Message "Calculating total current Azure Stack VM memory usage"
    $azureStackVMs = Get-VM | Where-Object {$_.VMName -like "*Azs*"}
    $azureStackVMs | Format-Table Name, State, @{n = "Memory"; e = {$_.memoryassigned / 1MB}} -AutoSize
    Remove-Variable -Name totalVmMemory -Force -ErrorAction SilentlyContinue
    $totalVmMemory = $azureStackVMs | Measure-Object memoryassigned –sum
    $totalVmMemory = [math]::round($totalVmMemory.sum / 1GB)
    [INT]$totalVmMemory = $totalVmMemory
    Write-CustomVerbose -Message "Total physical memory in the ASDK host = $([INT]$totalPhysicalMemory)GB"
    Write-CustomVerbose -Message "Total memory currently assigned to Azure Stack VMs on the ASDK host = $([INT]$totalVmMemory)GB"
    Write-CustomVerbose -Message "Total memory required by your selected resource provider VMs on the ASDK host = $([INT]$totalRPMemoryRequired)GB"
    [INT]$memoryAvailable = [INT]$totalPhysicalMemory - [INT]$totalVmMemory
    if ([INT]$memoryAvailable -gt [INT]$totalRPMemoryRequired) {
        Write-CustomVerbose -Message "You have $([INT]$memoryAvailable)GB memory available on your host, which is enough to run your chosen resource providers"
        Remove-Variable -Name totalFreeMemory -Force -ErrorAction SilentlyContinue
        [INT]$totalFreeMemory = Get-CimInstance Win32_OperatingSystem -Verbose:$false | ForEach-Object {[math]::round($_.FreePhysicalMemory / 1MB)}
        Write-CustomVerbose -Message "However, the ASDK host OS is reporting a total of $([INT]$totalFreeMemory)GB free physical memory"
        [INT]$memoryDifference = ([INT]$totalPhysicalMemory - [INT]$totalFreeMemory) - [INT]$totalVmMemory
        Write-CustomVerbose -Message "This is a difference of $([INT]$memoryDifference)GB on top of the Azure Stack VM usage, and is most likely consumed by system processes and overheads."
        Write-CustomVerbose -Message "If you run out of memory, this may cause the ASDK Configurator to fail."
        Start-Sleep 10
    }
    else {
        throw "Your ASDK host only has $([INT]$memoryAvailable)GB memory remaining, which is less than the required $([INT]$totalRPMemoryRequired)GB for your chosen resource providers.`
    Add more memory or reduce the number of resource providers that you wish to deploy"
    }
}
else {
    Write-CustomVerbose -Message "It appears you've chosen to deploy none of the Resource Providers. No need for further host memory checks"
}

### VALIDATION ###############################################################################################################################################
##############################################################################################################################################################

### Validate parameter combinations to determine deployment type - Online (fully internet connected)
### PartialOnline (internet connected, but using offline zip), and Offline (ADFS with offline zip)

try {
    if (($authenticationType.ToString() -like "AzureAd") -and $validOnlineInstall -and !$configAsdkOfflineZipPath) {
        $deploymentMode = "Online"
    }
    elseif (($authenticationType.ToString() -like "AzureAd") -and $validOnlineInstall -and $configAsdkOfflineZipPath) {
        $deploymentMode = "PartialOnline"
    }
    elseif (($authenticationType.ToString() -like "AzureAd") -and !$validOnlineInstall) {
        $exception = "Azure AD is the selected authentication model, but you failed internet connectivity tests. Check your internet connectivity, then retry."
        throw $exception
    }
    elseif (($authenticationType.ToString() -like "ADFS") -and $validOnlineInstall -and !$configAsdkOfflineZipPath) {
        $deploymentMode = "Online"
    }
    elseif (($authenticationType.ToString() -like "ADFS") -and $validOnlineInstall -and $configAsdkOfflineZipPath) {
        $deploymentMode = "PartialOnline"
    }
    elseif (($authenticationType.ToString() -like "ADFS") -and !$validOnlineInstall -and $configAsdkOfflineZipPath) {
        $deploymentMode = "Offline"
    }
    elseif (($authenticationType.ToString() -like "ADFS") -and !$validOnlineInstall -and !$configAsdkOfflineZipPath) {
        $exception = "ADFS is your selected authentication model, but you failed internet connectivity tests and didn't provide an offline zip path."
        throw $exception
    }
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### Validate offline Zip Path ###
try {
    if ($configAsdkOfflineZipPath) {
        Write-CustomVerbose -Message "Validating offline zip path."
        $validZipPath = [System.IO.File]::Exists("$configAsdkOfflineZipPath")
        $validZipfile = [System.IO.Path]::GetExtension("$configAsdkOfflineZipPath")

        if ($validZipPath -eq $true -and $validZipfile -eq ".zip") {
            Write-CustomVerbose -Message "Found path to valid zip file" 
            $configAsdkOfflineZipPath = [System.IO.Path]::GetFullPath($configAsdkOfflineZipPath)
            Write-CustomVerbose -Message "The zip path found at $configAsdkOfflineZipPath will be used"
            $offlineZipIsValid = $true
        }
        elseif ($validZipPath -eq $false -or $validZipfile -ne ".zip") {
            $configAsdkOfflineZipPath = Read-Host "Zip path is invalid - please enter a valid path to the offline zip file"
            $validZipPath = [System.IO.File]::Exists("$configAsdkOfflineZipPath")
            $validZipfile = [System.IO.Path]::GetExtension("$configAsdkOfflineZipPath")
            if ($validZipPath -eq $false -or $validZipfile -ne ".zip") {
                $offlineZipIsValid = $false
                Write-CustomVerbose -Message "No valid path to a zip file was entered again. Exiting process..." -ErrorAction Stop
                Set-Location $ScriptLocation
                return
            }
            elseif ($validZipPath -eq $true -and $validZipfile -eq ".zip") {
                Write-CustomVerbose -Message "Found path to valid zip file" 
                $configAsdkOfflineZipPath = [System.IO.Path]::GetFullPath($configAsdkOfflineZipPath)
                Write-CustomVerbose -Message "The zip file found at $configAsdkOfflineZipPath will be used"
                $offlineZipIsValid = $true
            }
        }
    }
    ### Validate path to ISO File ###
    # If both the ConfigASDKfiles.zip file exists AND the $ISOPath has been provided by the user, set the $ISOPath to $null as it will be defined later
    if (([System.IO.File]::Exists($configAsdkOfflineZipPath)) -and ([System.IO.File]::Exists($ISOPath))) { 
        $ISOPath = $null
    }
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

if (!$branch) {
    $branch = "master"
}

# Validate Github branch exists - usually reserved for testing purposes
if ($deploymentMode -eq "Online") {
    try {
        $urlToTest = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/README.md"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $statusCode = Invoke-WebRequest "$urlToTest" -UseBasicParsing -ErrorAction SilentlyContinue | ForEach-Object {$_.StatusCode} -ErrorAction SilentlyContinue
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
}

### Validate Download Path ###
Write-CustomVerbose -Message "Validating download path."
$validDownloadPath = [System.IO.Directory]::Exists($downloadPath)
If ($validDownloadPath -eq $true) {
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

Write-CustomVerbose -Message "Selected identity provider is $authenticationType"

### VALIDATE CREDS ##########################################################################################################################################
#############################################################################################################################################################

### Validate Virtual Machine (To be created) Password ###

if ([string]::IsNullOrEmpty($VMpwd)) {
    Write-CustomVerbose -Message "You didn't enter a password for the virtual machines that the ASDK configurator will create." 
    $secureVMpwd = Read-Host "Please enter a password for the virtual machines that will be created during this process" -AsSecureString -ErrorAction Stop
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureVMpwd)            
    $VMpwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
}

Write-CustomVerbose -Message "Checking to see if Virtual Machine password is strong..."

if ($VMpwd -cmatch $regex -eq $true) {
    Write-CustomVerbose -Message "Virtual Machine password meets desired complexity level" 
    # Convert plain text password to a secure string
    $secureVMpwd = ConvertTo-SecureString -AsPlainText $VMpwd -Force
}

elseif ($VMpwd -cmatch $regex -eq $false) {
    Write-CustomVerbose -Message "Virtual Machine password doesn't meet complexity requirements, it needs to be at least 12 characters in length."
    Write-CustomVerbose -Message "Your password should also have at least 3 of the following 4 options: 1 upper case, 1 lower case, 1 number, 1 special character."
    Write-CustomVerbose -Message 'The App Service installation requires a password of this strength. An Example would be p@ssw0rd123!'
    # Obtain new password and store as a secure string
    $secureVMpwd = Read-Host -AsSecureString "Enter VM password again"
    # Convert to plain text to test regex complexity
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureVMpwd)            
    $VMpwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
    if ($VMpwd -cmatch $regex -eq $true) {
        Write-CustomVerbose -Message "Virtual Machine password matches desired complexity" 
        # Convert plain text password to a secure string
        $secureVMpwd = ConvertTo-SecureString -AsPlainText $VMpwd -Force
    }
    else {
        Write-CustomVerbose -Message "No valid password was entered again. Exiting process..." -ErrorAction Stop 
        Set-Location $ScriptLocation
        return
    }
}

### Validate Azure Stack Development Kit Deployment Credentials ###
if ([string]::IsNullOrEmpty($azureStackAdminPwd)) {
    Write-CustomVerbose -Message "You didn't enter the Azure Stack Development Kit Deployment password." 
    $secureAzureStackAdminPwd = Read-Host "Please enter the password used for the Azure Stack Development Kit Deployment, for account AzureStack\AzureStackAdmin" -AsSecureString -ErrorAction Stop
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureStackAdminPwd)            
    $azureStackAdminPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
}

Write-CustomVerbose -Message "Checking to see Azure Stack Admin password is strong..."

$azureStackAdminUsername = "AzureStack\AzureStackAdmin"
if ($azureStackAdminPwd -cmatch $regex -eq $true) {
    Write-CustomVerbose -Message "Azure Stack Development Kit Deployment password for AzureStack\AzureStackAdmin, meets desired complexity level" 
    # Convert plain text password to a secure string
    $secureAzureStackAdminPwd = ConvertTo-SecureString -AsPlainText $azureStackAdminPwd -Force
    $azureStackAdminCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $azureStackAdminUsername, $secureAzureStackAdminPwd -ErrorAction Stop
}

elseif ($azureStackAdminPwd -cmatch $regex -eq $false) {
    Write-Host "`r`nAzure Stack Admin (AzureStack\AzureStackAdmin) password is not a strong password.`nIt should ideally be at least 8 characters, with at least 1 upper case, 1 lower case, and 1 special character.`nPlease consider a stronger password in the future.`r`n" -ForegroundColor Cyan
    Start-Sleep -Seconds 10
    # Convert plain text password to a secure string
    $secureAzureStackAdminPwd = ConvertTo-SecureString -AsPlainText $azureStackAdminPwd -Force
    $azureStackAdminCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $azureStackAdminUsername, $secureAzureStackAdminPwd -ErrorAction Stop
}

### Credentials Recap ###
# $azureStackAdminUsername = "AzureStack\AzureStackAdmin" | Used to log into the local ASDK Host
# azureStackAdminPwd (and $secureAzureStackAdminPwd) | Used to log into the local ASDK Host
# $azureStackAdminCreds | Used to log into the local ASDK Host

### Validate Azure Stack Development Kit Service Administrator Credentials (AZURE AD ONLY) ###

if ($authenticationType.ToString() -like "AzureAd") {

    ### Validate Azure AD Service Administrator Username (Used for ASDK Deployment) ###

    if ([string]::IsNullOrEmpty($azureAdUsername)) {
        Write-CustomVerbose -Message "You didn't enter a username for the Azure AD login." 
        $azureAdUsername = Read-Host "Please enter a username in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" -ErrorAction Stop
    }

    Write-CustomVerbose -Message "Checking to see if Azure AD Service Administrator (Used for ASDK Deployment) username is correctly formatted..."

    if ($azureAdUsername.ToLower() -cmatch $emailRegex -eq $true) {
        Write-CustomVerbose -Message "Azure AD Service Administrator username (Used for ASDK Deployment) is correctly formatted."
        $azureAdUsername = $azureAdUsername.ToLower()
        Write-CustomVerbose -Message "$azureAdUsername will be used to connect to Azure." 
    }

    elseif ($azureAdUsername.ToLower() -cmatch $emailRegex -eq $false) {
        Write-CustomVerbose -Message "Azure AD Service Administrator Username (Used for ASDK Deployment) isn't correctly formatted. It should be entered in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" 
        # Obtain new username
        $azureAdUsername = Read-Host "Enter Azure AD Service Administrator Username (Used for ASDK Deployment) again" -ErrorAction Stop
        if ($azureAdUsername.ToLower() -cmatch $emailRegex -eq $true) {
            $azureAdUsername = $azureAdUsername.ToLower()
            Write-CustomVerbose -Message "Azure AD Service Administrator Username (Used for ASDK Deployment) is correctly formatted." 
            Write-CustomVerbose -Message "$azureAdUsername will be used to connect to Azure." 
        }
        else {
            Write-CustomVerbose -Message "No valid Azure AD Service Administrator Username (Used for ASDK Deployment) was entered again. Exiting process..." -ErrorAction Stop 
            Set-Location $ScriptLocation
            return
        }
    }

    ### Validate Azure AD Service Administrator (Used for ASDK Deployment) Password ###

    if ([string]::IsNullOrEmpty($azureAdPwd)) {
        Write-CustomVerbose -Message "You didn't enter the Azure AD Service Administrator account (Used for ASDK Deployment) password." 
        $secureAzureAdPwd = Read-Host "Please enter the password for the Azure AD Service Administrator account used to deploy the ASDK. It should be at least 8 characters, with at least 1 upper case and 1 special character." -AsSecureString -ErrorAction Stop
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureAdPwd)            
        $azureAdPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
    }

    Write-CustomVerbose -Message "Checking to see if password for the Azure AD Service Administrator used to deploy the ASDK, is strong..."

    if ($azureAdPwd -cmatch $regex -eq $true) {
        Write-CustomVerbose -Message "Password for the Azure AD Service Administrator account used to deploy the ASDK meets desired complexity level" 
        # Convert plain text password to a secure string
        $secureAzureAdPwd = ConvertTo-SecureString -AsPlainText $azureAdPwd -Force
        $azureAdCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureAdUsername, $secureAzureAdPwd) -ErrorAction Stop
    }

    elseif ($azureAdPwd -cmatch $regex -eq $false) {
        Write-Host "`r`nAzure AD Service Administrator account password is not a strong password.`nIt should ideally be at least 8 characters, with at least 1 upper case, 1 lower case, and 1 special character.`nPlease consider a stronger password in the future.`r`n" -ForegroundColor Cyan
        Start-Sleep -Seconds 10
        $secureAzureAdPwd = ConvertTo-SecureString -AsPlainText $azureAdPwd -Force
        $azureAdCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureAdUsername, $secureAzureAdPwd) -ErrorAction Stop
    }

    $asdkCreds = $azureAdCreds

    ### Credentials Recap ###
    # $azureAdUsername | Used for Azure AD athentication to log into Azure/Azure Stack portals
    # $azureAdPwd (and $secureAzureAdPwd) | Used to log into Azure/Azure Stack portals
    # $azureAdCreds | Combined credentials, used to log into Azure/Azure Stack portals
    # $asdkCreds | New variable to represent the $azureAdCreds (if Azure AD) or the $azureStackAdminCreds (if ADFS)

    if ($useAzureCredsForRegistration -and $registerASDK) {
        $azureRegCreds = $azureAdCreds
    }

    elseif (!$useAzureCredsForRegistration -and $registerASDK) {
        
        if ([string]::IsNullOrEmpty($azureRegUsername)) {
            Write-CustomVerbose -Message "You didn't enter a username for Azure account you'll use to register the Azure Stack to." 
            $azureRegUsername = Read-Host "Please enter a username in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" -ErrorAction Stop
        }
    
        Write-CustomVerbose -Message "Checking to see if the Azure AD username is correctly formatted..."
    
        if ($azureRegUsername -cmatch $emailRegex -eq $true) {
            Write-CustomVerbose -Message "Azure AD username is correctly formatted." 
            Write-CustomVerbose -Message "$azureRegUsername will be used to connect to Azure."
        }
    
        elseif ($azureRegUsername -cmatch $emailRegex -eq $false) {
            Write-CustomVerbose -Message "Azure AD username isn't correctly formatted. It should be entered in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" 
            # Obtain new username
            $azureRegUsername = Read-Host "Enter Azure AD username again"
            if ($azureRegUsername -cmatch $emailRegex -eq $true) {
                Write-CustomVerbose -Message "Azure AD username is correctly formatted." 
                Write-CustomVerbose -Message "$azureRegUsername will be used to connect to Azure." 
            }
            else {
                Write-CustomVerbose -Message "No valid Azure AD username was entered again. Exiting process..." -ErrorAction Stop 
                Set-Location $ScriptLocation
                return
            }
        }
    
        ### Validate Azure AD Registration Password ###
    
        if ([string]::IsNullOrEmpty($azureRegPwd)) {
            Write-CustomVerbose -Message "You didn't enter the Azure AD password that you want to use for registration." 
            $secureAzureRegPwd = Read-Host "Please enter the Azure AD password you wish to use for registration. It should ideally be at least 8 characters, with at least 1 upper case and 1 special character." -AsSecureString -ErrorAction Stop
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureRegPwd)            
            $azureRegPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
        }
    
        Write-CustomVerbose -Message "Checking to see if Azure AD password is strong..."
    
        if ($azureRegPwd -cmatch $regex -eq $true) {
            Write-CustomVerbose -Message "Azure AD password meets desired complexity level" 
            # Convert plain text password to a secure string
            $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
            $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
        }
    
        elseif ($azureRegPwd -cmatch $regex -eq $false) {
            Write-Host "`r`nAzure AD password for registration is not a strong password.`nIt should ideally be at least 8 characters, with at least 1 upper case, 1 lower case, and 1 special character.`nPlease consider a stronger password in the future.`r`n" -ForegroundColor Cyan
            Start-Sleep -Seconds 10
            $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
            $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
        }
    }
}

### Create Cloud Admin Creds ###
$cloudAdminUsername = "azurestack\cloudadmin"
$cloudAdminCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $cloudAdminUsername, $secureAzureStackAdminPwd -ErrorAction Stop

### Credentials Recap ###
# $azureRegUsername | Used for Azure AD authentication to register the ASDK if NOT using same Azure AD Creds as deployment
# $azureRegPwd (and $secureAzureRegPwd) | Used for Azure AD authentication to register the ASDK if NOT using same Azure AD Creds as deployment
# $azureRegCreds | Combined credentials, used for Azure AD authentication to register the ASDK if NOT using same Azure AD Creds as deployment
# $cloudAdminCreds | Used for ADFS login (azurestackadmin not used) and also MySQL/SQL RP deployment

if ($authenticationType.ToString() -like "ADFS") {
    $asdkCreds = $cloudAdminCreds
}

### Credentials Recap ###
# $asdkCreds | If deployment is using ADFS, $asdkCreds will be set to match $azureStackAdminCreds, which should be azurestack\azurestackadmin and accompanying password

if ($authenticationType.ToString() -like "ADFS" -and $registerASDK) {

    # If the user has chosen ADFS authentication, they will need to be prompted to provide some additional Azure credentials to register the ASDK.
    # This If statement captures those credentials

    Remove-Variable -Name azureAdPwd -Force -ErrorAction SilentlyContinue
    Remove-Variable -Name azureAdUsername -Force -ErrorAction SilentlyContinue

    Write-CustomVerbose -Message "Checking for an Azure AD username - this account will be used to register the ADFS-based ASDK to Azure..."
            
    if ([string]::IsNullOrEmpty($azureRegUsername)) {
        Write-CustomVerbose -Message "You didn't enter a username for Azure account you'll use to register the Azure Stack to." 
        $azureRegUsername = Read-Host "Please enter a username in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" -ErrorAction Stop
    }
    else {
        Write-CustomVerbose -Message "Found an Azure AD username that will be used for registering this ADFS-based Azure Stack to Azure" 
        Write-CustomVerbose -Message "Account username is $azureRegUsername"
    }
        
    Write-CustomVerbose -Message "Checking to see if the Azure AD username, that will be used for Azure Stack registration to Azure, is correctly formatted..."
        
    if ($azureRegUsername -cmatch $emailRegex -eq $true) {
        Write-CustomVerbose -Message "Azure AD username is correctly formatted."
        Write-CustomVerbose -Message "$azureRegUsername will be used to register this ADFS-based Azure Stack to Azure."
    }
        
    elseif ($azureRegUsername -cmatch $emailRegex -eq $false) {
        Write-CustomVerbose -Message "Azure AD username isn't correctly formatted. It should be entered in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" 
        # Obtain new username
        $azureRegUsername = Read-Host "Enter Azure AD username again"
        if ($azureRegUsername -cmatch $emailRegex -eq $true) {
            Write-CustomVerbose -Message "Azure AD username is correctly formatted."
            Write-CustomVerbose -Message "$azureRegUsername will be used to register this ADFS-based Azure Stack to Azure."
        }
        else {
            Write-CustomVerbose -Message "No valid Azure AD username was entered again. Exiting process..." -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
        
    ### Validate Azure AD Registration Password ADFS-based Azure Stack ###

    Write-CustomVerbose -Message "Checking for an Azure AD password - this account will be used to register the ADFS-based ASDK to Azure..."
        
    if ([string]::IsNullOrEmpty($azureRegPwd)) {
        Write-CustomVerbose -Message "You didn't enter the Azure AD password that you want to use for registration." 
        $secureAzureRegPwd = Read-Host "Please enter the Azure AD password you wish to use for registration. It should ideally be at least 8 characters, with at least 1 upper case and 1 special character." -AsSecureString -ErrorAction Stop
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureRegPwd)            
        $azureRegPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
    }

    Write-CustomVerbose -Message "Checking to see if Azure AD password for registration is strong..."

    if ($azureRegPwd -cmatch $regex -eq $true) {
        Write-CustomVerbose -Message "Azure AD password meets desired complexity level" 
        # Convert plain text password to a secure string
        $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
        $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
    }

    elseif ($azureRegPwd -cmatch $regex -eq $false) {
        Write-Host "`r`nAzure AD password for registration is not a strong password.`nIt should ideally be at least 8 characters, with at least 1 upper case, 1 lower case, and 1 special character.`nPlease consider a stronger password in the future.`r`n" -ForegroundColor Cyan
        Start-Sleep -Seconds 10
        $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
        $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
    }
}

if ($registerASDK) {

    Write-CustomVerbose -Message "Checking for a valid Azure subscription ID that will be used to register the Azure Stack to Azure"
    ### Validate Azure Subscription ID for Registration ###
    if ([string]::IsNullOrEmpty($azureRegSubId)) {
        Write-CustomVerbose -Message "You didn't enter a subscription ID for registering your Azure Stack in Azure."
        $azureRegSubId = Read-Host "Please enter a valid Azure subscription ID" -ErrorAction Stop
    }      
    if ($azureRegSubId) {
        Write-CustomVerbose -Message "Azure subscription ID has been provided."
        Write-CustomVerbose -Message "$azureRegSubId will be used to register this Azure Stack with Azure."

    }   
    elseif ([string]::IsNullOrEmpty($azureRegSubId)) {
        Write-CustomVerbose -Message "No valid Azure subscription ID was entered again. Exiting process..." -ErrorAction Stop
        Set-Location $ScriptLocation
        return    
    }
}

### EXTRACT ZIP (OPTIONAL) ##################################################################################################################################
#############################################################################################################################################################

$zipExtractedRunFlag = "$ScriptLocation\ZipExtractedRunFlag.txt"
$zipExtracted = [System.IO.File]::Exists($zipExtractedRunFlag)
if (($configAsdkOfflineZipPath) -and ($offlineZipIsValid = $true)) {
    if (!$zipExtracted) {
        try {
            Write-CustomVerbose -Message "ASDK Configurator dependency files located at: $configAsdkOfflineZipPath"
            Write-CustomVerbose -Message "Starting extraction to $downloadPath"
            ### Extract the Zip file, move contents to appropriate place
            Expand-Archive -Path $configAsdkOfflineZipPath -DestinationPath $downloadPath -Force -Verbose -ErrorAction Stop
            New-Item $zipExtractedRunFlag -ItemType file -Force
        }
        catch {
            Set-Location $ScriptLocation
            $exception = $_.Exception
            throw $exception
        }
    }
    elseif ($zipExtracted -eq $true) {
        Write-CustomVerbose -Message "ConfigASDKfiles has been previously extracted successfully"
    }
}
elseif (!$configAsdkOfflineZipPath) {
    Write-CustomVerbose -Message "Skipping zip extraction - this is a 100% online deployment`r`n"
}

### CREATE ASDK FOLDER ######################################################################################################################################
#############################################################################################################################################################

$ConfigAsdkRunFlag = "$ScriptLocation\ConfigASDKRunFlag.txt"
$isRerun = [System.IO.File]::Exists($ConfigAsdkRunFlag)
### CREATE ASDK FOLDER ###
$ASDKpath = [System.IO.Directory]::Exists("$downloadPath\ASDK")
if ($ASDKpath -eq $true) {
    $ASDKpath = "$downloadPath\ASDK"
    Write-CustomVerbose -Message "ASDK folder exists at $downloadPath - no need to create it."
    Write-CustomVerbose -Message "Download files will be placed in $downloadPath\ASDK"
    Write-CustomVerbose -Message "ASDK folder full path is $ASDKpath"
    if ((!$isRerun) -and ($deploymentMode -eq "Online")) {
        # If this is a fresh run, the $asdkPath should be empty to avoid any conflicts.
        # It may exist from a previous successful run
        Write-CustomVerbose -Message "Cleaning up an old ASDK Folder from a previous completed run"
        # Will attempt multiple times as sometimes it fails
        $i = 0 
        While ($i -le 3) {
            Remove-Item "$ASDKpath\*" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue -Verbose
            $i++
        }
    }
    New-Item $ConfigAsdkRunFlag -ItemType file -Force
}
elseif ($ASDKpath -eq $false) {
    # Create the ASDK folder.
    Write-CustomVerbose -Message "ASDK folder doesn't exist within $downloadPath, creating it"
    mkdir "$downloadPath\ASDK" -Force | Out-Null
    $ASDKpath = "$downloadPath\ASDK"
    Write-CustomVerbose -Message "ASDK folder full path is $ASDKpath"
    # Create txt file to act as flag that this is a rerun in future
    New-Item $ConfigAsdkRunFlag -ItemType file -Force
}

### DOWNLOAD SQLLOCALDB #####################################################################################################################################
#############################################################################################################################################################

# Check for existence of directory for SqlLocalDB and creating if it doesn't exist
if (![System.IO.Directory]::Exists("$asdkPath\SqlLocalDB")) {
    mkdir "$asdkPath\SqlLocalDB" -Force | Out-Null
    $sqlLocalDBpath = "$asdkPath\SqlLocalDB"
}
else {
    $sqlLocalDBpath = "$asdkPath\SqlLocalDB"
}

# If there isn't already a copy of the MSI locally, pull it down
$sqlLocalDBUri = "https://download.microsoft.com/download/E/F/2/EF23C21D-7860-4F05-88CE-39AA114B014B/SqlLocalDB.msi"
$sqlLocalDBMSIPath = "$sqlLocalDBpath\SqlLocalDB.msi"
if (![System.IO.File]::Exists($sqlLocalDBMSIPath)) {
    DownloadWithRetry -downloadURI $sqlLocalDBUri -downloadLocation $sqlLocalDBMSIPath -retries 10
}

### INSTALL SQLLOCALDB ######################################################################################################################################
#############################################################################################################################################################

# Install SqlLocalDB from MSI
$sqlLocalInstallPath = "C:\Program Files\Microsoft SQL Server\140\Tools\Binn\"
HostAppInstaller -localInstallPath "$sqlLocalInstallPath\SqlLocalDB.exe" -appName SqlLocalDB `
    -arguments "/i `"$sqlLocalDBpath\SqlLocalDB.msi`" /qn IACCEPTSQLLOCALDBLICENSETERMS=YES /l*v `"$sqlLocalDBpath\SqlLocalDB.log`"" `
    -fileName "SqlLocalDB.msi" -appType "MSI"

# Add SqlLocalDB to $env:Path
$testEnvPath = $Env:path
if (!($testEnvPath -contains "C:\Program Files\Microsoft SQL Server\140\Tools\Binn\")) {
    $Env:path = $env:path + ";C:\Program Files\Microsoft SQL Server\140\Tools\Binn\"
}

### INSTALL SQL SERVER POWERSHELL ###########################################################################################################################
#############################################################################################################################################################

if ($deploymentMode -eq "Online") {
    # Install SQL Server Module from Online PSrepository
    Register-PsRepository -Default -Verbose:$false -ErrorAction SilentlyContinue
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -Verbose:$false -ErrorAction SilentlyContinue
    if (!(Get-InstalledModule -Name SqlServer -ErrorAction SilentlyContinue -Verbose)) {
        Install-Module SqlServer -Force -Confirm:$false -AllowClobber -Verbose -ErrorAction Stop
    }
}
elseif (($deploymentMode -ne "Online")) {
    $SourceLocation = "$downloadPath\ASDK\PowerShell"
    $RepoName = "ConfigASDKRepo"
    if (!(Get-InstalledModule -Name SqlServer -ErrorAction SilentlyContinue -Verbose)) {
        # Need to grab module from the ConfigASDKfiles.zip
        if (!(Get-PSRepository -Name $RepoName -ErrorAction SilentlyContinue)) {
            Register-PSRepository -Name $RepoName -SourceLocation $SourceLocation -InstallationPolicy Trusted
        }                
        Install-Module SqlServer -Repository $RepoName -Force -Confirm:$false -Verbose -ErrorAction Stop
    }
}

### CUSTOMIZE SQLLOCALDB ####################################################################################################################################
#############################################################################################################################################################

# Check if the instance is running and start it, if it isn't.
$testDBStatus = SqlLocalDB.exe info "MSSQLLocalDB" | Out-String
while ($testDBStatus -notlike "*Running*") {
    SqlLocalDB.exe start "MSSQLLocalDB"
    $testDBStatus = SqlLocalDB.exe info "MSSQLLocalDB" | Out-String
    $testDBStatus
}

# Set the advanced properties for the MSSqlLocalDB instance
$sqlServerInstance = '(localdb)\MSSQLLocalDB'
Invoke-Sqlcmd -Server $sqlServerInstance -Query "sp_configure 'show advanced options', 1; RECONFIGURE;" -Verbose -ErrorAction Stop
Invoke-Sqlcmd -Server $sqlServerInstance -Query "sp_configure 'user instance timeout', 600; RECONFIGURE;" -Verbose -ErrorAction Stop

### CREATE DB ###############################################################################################################################################
#############################################################################################################################################################

# Need to check if ConfigASDK Database exists and if not, create it, storing the files in the default location for other base DBs (master etc)
$databaseName = "ConfigASDK"
$instancePath = "$env:LOCALAPPDATA\Microsoft\Microsoft SQL Server Local DB\Instances\MSSQLLocalDB"
$configAsdkDatabaseExists = Invoke-Sqlcmd -Server $sqlServerInstance -Query "SELECT NAME FROM sys.databases WHERE name IN ('ConfigASDK')" | Out-String
if (!$configAsdkDatabaseExists) {
    $createQuery = "CREATE DATABASE $databaseName ON PRIMARY (NAME=[ConfigASDKdata], FILENAME = '$instancePath\ConfigASDKdata.mdf') LOG ON (NAME=[ConfigASDKlog], FILENAME = '$instancePath\ConfigASDKlog.ldf');"
    Invoke-Sqlcmd -Server $sqlServerInstance -Query $createQuery -Verbose -ErrorAction Stop
}
else {
    Write-Host "The ConfigASDK Database already exists. No need to recreate."
}

# Need to check if the logins are present
$configAsdkSqlLoginExists = Get-SqlLogin -ServerInstance $sqlServerInstance -LoginName "asdkadmin" -ErrorAction SilentlyContinue | Out-String
if (!$configAsdkSqlLoginExists) {
    $sqlLocalDbAdmin = "asdkadmin"
    $sqlLocalDbCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $sqlLocalDbAdmin, $secureVMpwd -ErrorAction Stop
    Add-SqlLogin -ServerInstance $sqlServerInstance -LoginName "asdkadmin" -LoginPSCredential $sqlLocalDbCreds -LoginType SqlLogin -DefaultDatabase "ConfigASDK" -Enable -GrantConnectSql -ErrorAction SilentlyContinue -Verbose:$false
}
else {
    Write-Host "The ConfigASDK Admin Login already exists. No need to recreate."
}

# Need to check if a table is present
$tableName = "Progress"
$configAsdkSqlTableExists = Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" -TableName "$tableName" -ErrorAction SilentlyContinue | Out-String
if (!$configAsdkSqlTableExists) {
    # Need to populate a PowerShell Hash Table that contains all of the stages of the ConfigASDK Script
    $progressHashTable = [ordered]@{
        GetScripts           = "Incomplete";
        CheckPowerShell      = "Incomplete";
        InstallPowerShell    = "Incomplete";
        DownloadTools        = "Incomplete";
        HostConfiguration    = "Incomplete";
        Registration         = "Incomplete";
        UbuntuServerImage    = "Incomplete";
        WindowsUpdates       = "Incomplete";
        ServerCoreImage      = "Incomplete";
        ServerFullImage      = "Incomplete";
        MySQLGalleryItem     = "Incomplete";
        SQLServerGalleryItem = "Incomplete";
        AddVMExtensions      = "Incomplete";
        MySQLRP              = "Incomplete";
        SQLServerRP          = "Incomplete";
        MySQLSKUQuota        = "Incomplete";
        SQLServerSKUQuota    = "Incomplete";
        UploadScripts        = "Incomplete";
        MySQLDBVM            = "Incomplete";
        SQLServerDBVM        = "Incomplete";
        MySQLAddHosting      = "Incomplete";
        SQLServerAddHosting  = "Incomplete";
        AppServiceFileServer = "Incomplete";
        AppServiceSQLServer  = "Incomplete";
        DownloadAppService   = "Incomplete";
        AddAppServicePreReqs = "Incomplete";
        DeployAppService     = "Incomplete";
        RegisterNewRPs       = "Incomplete";
        CreatePlansOffers    = "Incomplete";
        InstallHostApps      = "Incomplete";
        CreateOutput         = "Incomplete";
    }

    # Convert the hash tables to PSCustomObjects before storing the information in the database
    # Data seems more natural in the database and the results of a simple database query are cleaner
    $progressHashTable.ForEach( {$_.ForEach( {[PSCustomObject]$_})}) | Format-Table
    $progressHashTable.ForEach( {$_.ForEach( {[PSCustomObject]$_})}) | Get-Member

    # The SQL Server database already exists, but not the table. The Force parameter creates the table automatically:
    $progressHashTable.ForEach( {$_.ForEach( {[PSCustomObject]$_}) | Write-SqlTableData -ServerInstance $sqlServerInstance `
                -DatabaseName $databaseName -SchemaName dbo -TableName $tableName -Force -ErrorAction Stop -Verbose})

    $configAsdkSqlTable = Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" -TableName "$tableName" -ErrorAction SilentlyContinue | Out-String
    $configAsdkSqlTable
}
else {
    Write-Host "The ConfigASDK Progress Table already exists. No need to recreate."
    $configAsdkSqlTableExists
}

### VALIDATE ISO ############################################################################################################################################
#############################################################################################################################################################

$scriptStep = "VALIDATE ISO"
try {
    Write-CustomVerbose -Message "Validating ISO path"
    # If this deployment is PartialOnline/Offline and using the Zip, we need to search for the ISO
    if (($configAsdkOfflineZipPath) -and ($offlineZipIsValid = $true)) {
        $ISOPath = Get-ChildItem -Path "$downloadPath\*" -Recurse -Include *.iso -ErrorAction Stop | ForEach-Object { $_.FullName }
    }
    $validISOPath = [System.IO.File]::Exists($ISOPath)
    $validISOfile = [System.IO.Path]::GetExtension("$ISOPath")
    if ($validISOPath -eq $true -and $validISOfile -eq ".iso") {
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
}
catch {
    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
    Set-Location $ScriptLocation
    return
}

### VALIDATE PS SCRIPTS LOCATION ############################################################################################################################
#############################################################################################################################################################

$progressStage = "GetScripts"
$progressCheck = CheckProgress -progressStage $progressStage
$scriptStep = $progressStage.ToUpper()

if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
    try {
        $scriptPath = [System.IO.Directory]::Exists("$ScriptLocation\Scripts")
        if ($scriptPath -eq $true) {
            $scriptPath = "$ScriptLocation\Scripts"
            Write-CustomVerbose -Message "Scripts folder exists at $scriptPath - no need to create it."
            Write-CustomVerbose -Message "PowerShell scripts will be placed in $scriptPath"
        }
        elseif ($scriptPath -eq $false) {
            # Create the ASDK folder.
            Write-CustomVerbose -Message "Scripts folder doesn't exist within $ScriptLocation, creating it"
            mkdir "$ScriptLocation\Scripts" -Force | Out-Null
            $scriptPath = "$ScriptLocation\Scripts"
            Write-CustomVerbose -Message "PowerShell scripts will be placed in $scriptPath"
        }
        $scriptArray = @()
        $scriptArray.Clear()
        $scriptArray = "AddAppServicePreReqs.ps1", "AddDBHosting.ps1", "AddDBSkuQuota.ps1", "AddGalleryItems.ps1", "AddImage.ps1", "AddVMExtensions.ps1", `
            "DeployAppService.ps1", "DeployDBRP.ps1", "DeployVM.ps1", "DownloadAppService.ps1", "DownloadWinUpdates.ps1", "GetJobStatus.ps1", "UploadScripts.ps1"

        if ($deploymentMode -eq "Online") {
            # If this is an online deployment, pull down the PowerShell scripts from GitHub
            foreach ($script in $scriptArray) {
                $scriptBaseURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/powershell"
                $scriptDownloadPath = "$scriptPath\$script"
                DownloadWithRetry -downloadURI "$scriptBaseURI/$script" -downloadLocation $scriptDownloadPath -retries 10
            }
        }
        elseif ($deploymentMode -ne "Online") {
            # If this is a PartialOnline or Offline deployment, pull from the extracted zip file
            $SourceLocation = "$downloadPath\ASDK\PowerShell\Scripts"
            Copy-Item -Path "$SourceLocation\*" -Destination "$scriptPath" -Include "*.ps1" -Verbose -ErrorAction Stop
        }
        Get-ChildItem -Path "$scriptPath\*" -Recurse | Unblock-File -Verbose
        # Update the ConfigASDK Progress database with successful completion
        StageComplete -progressStage $progressStage
    }
    catch {
        StageFailed -progressStage $progressStage
        Set-Location $ScriptLocation
        return        
    }
}
elseif ($progressCheck -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configurator Stage: $progressStage previously completed successfully"
}

### POWERSHELL CHECK #########################################################################################################################################
##############################################################################################################################################################

$progressStage = "CheckPowerShell"
$progressCheck = CheckProgress -progressStage $progressStage
$scriptStep = $progressStage.ToUpper()

if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
    try {
        Clear-Host
        Write-CustomVerbose -Message "Checking for a previous installation of PowerShell. If found, to ensure full compatibility with the ConfigASDK, this will be cleaned up...please wait..."
        $cleanupRequired = $false
        $psRepositoryName = "PSGallery"
        $psRepositoryInstallPolicy = "Trusted"
        $psRepositorySourceLocation = "https://www.powershellgallery.com/api/v2"
        $psRepository = Get-PSRepository -ErrorAction SilentlyContinue | Where-Object {($_.Name -eq "$psRepositoryName") -and ($_.InstallationPolicy -eq "$psRepositoryInstallPolicy") -and ($_.SourceLocation -eq "$psRepositorySourceLocation")}
        if ($psRepository) {
            $cleanupRequired = $false
        }
        else {
            $cleanupRequired = $true
        }
        try {
            $psRmProfle = Get-AzureRmProfile -ErrorAction Ignore | Where-Object {($_.ProfileName -eq "2018-03-01-hybrid") -or ($_.ProfileName -eq "2017-03-09-profile")}
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            $error.Clear()
        }
        if ($psRmProfle) {
            $cleanupRequired = $true
        }
        $psAzureModuleCheck = Get-Module -Name Azure* -ListAvailable
        $psAzsModuleCheck = Get-Module -Name Azs.* -ListAvailable
        if (($psAzureModuleCheck) -or ($psAzsModuleCheck) ) {
            $cleanupRequired = $true
        }

        if ($cleanupRequired -eq $true) {
            Write-CustomVerbose -Message "A previous installation of PowerShell has been detected. To ensure full compatibility with the ConfigASDK, this will be cleaned up"
            Write-CustomVerbose -Message "Cleaning...."
            try {
                if ($(Get-AzureRmProfile -ErrorAction SilentlyContinue | Where-Object {($_.ProfileName -eq "2018-03-01-hybrid")})) {
                    Uninstall-AzureRmProfile -Profile '2018-03-01-hybrid' -Force -ErrorAction SilentlyContinue | Out-Null
                }
                if ($(Get-AzureRmProfile -ErrorAction SilentlyContinue | Where-Object {($_.ProfileName -eq "2017-03-09-profile")})) {
                    Uninstall-AzureRmProfile -Profile '2017-03-09-profile' -Force -ErrorAction SilentlyContinue | Out-Null
                }
                if ($(Get-AzureRmProfile -ErrorAction SilentlyContinue | Where-Object {($_.ProfileName -eq "latest")})) {
                    Uninstall-AzureRmProfile -Profile 'latest' -Force -ErrorAction SilentlyContinue | Out-Null
                }
            }
            catch [System.Management.Automation.CommandNotFoundException] {
                $error.Clear()
            }
            Get-Module -Name Azs.* -ListAvailable | Uninstall-Module -Force -ErrorAction SilentlyContinue -Verbose
            Get-Module -Name Azure* -ListAvailable | Uninstall-Module -Force -ErrorAction SilentlyContinue -Verbose
            if (!(Get-PSRepository -ErrorAction SilentlyContinue | Where-Object {($_.Name -eq "$psRepositoryName") -and ($_.InstallationPolicy -eq "$psRepositoryInstallPolicy") -and ($_.SourceLocation -eq "$psRepositorySourceLocation")})) {
                Get-PSRepository | Where-Object {($_.Name -ne "$psRepositoryName") -and ($_.InstallationPolicy -ne "$psRepositoryInstallPolicy") -and ($_.SourceLocation -ne "$psRepositorySourceLocation")} | Unregister-PSRepository -ErrorAction SilentlyContinue
            }
            Get-ChildItem -Path $Env:ProgramFiles\WindowsPowerShell\Modules\Azure* -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Get-ChildItem -Path $Env:ProgramFiles\WindowsPowerShell\Modules\Azs* -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
        else {
            Write-CustomVerbose -Message "No existing PowerShell installation detected - proceeding without cleanup."
        }
        StageComplete -progressStage $progressStage
        if ($cleanupRequired -eq $true) {
            Write-CustomVerbose -Message "A previous installation of PowerShell has been removed from this system."
            Write-CustomVerbose -Message "Once you have closed this PowerShell session, delete all the folders that start with 'Azure' from the $Env:ProgramFiles\WindowsPowerShell\Modules"
            Write-CustomVerbose -Message "Once deleted, rerun the ConfigASDK script. This will reinstall PowerShell for you."
            BREAK
        }
    }
    catch {
        StageFailed -progressStage $progressStage
        Set-Location $ScriptLocation
        return  
    }
}
elseif ($progressCheck -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configurator Stage: $progressStage previously completed successfully"
}

### INSTALL POWERSHELL ######################################################################################################################################
#############################################################################################################################################################

$progressStage = "InstallPowerShell"
$progressCheck = CheckProgress -progressStage $progressStage
$scriptStep = $progressStage.ToUpper()

if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
    try {
        Import-Module -Name PowerShellGet -ErrorAction Stop
        Import-Module -Name PackageManagement -ErrorAction Stop
        Write-CustomVerbose -Message "Uninstalling previously existing Azure Stack modules"
        Uninstall-Module AzureRM.AzureStackAdmin -Force -ErrorAction SilentlyContinue
        Uninstall-Module AzureRM.AzureStackStorage -Force -ErrorAction SilentlyContinue
        Uninstall-Module -Name AzureStack -Force -ErrorAction SilentlyContinue
        Get-Module Azs.* -ListAvailable | Uninstall-Module -Force -ErrorAction SilentlyContinue
        if ($deploymentMode -eq "Online") {
            # If this is an online deployment, pull down the PowerShell modules from the Internet
            Write-CustomVerbose -Message "Configuring the PSGallery Repo for Azure Stack PowerShell Modules"
            Unregister-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
            Register-PsRepository -Default
            Get-PSRepository -Name "PSGallery"
            Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
            Get-PSRepository -Name "PSGallery"
            Install-Module -Name AzureRm.BootStrapper -Force -ErrorAction Stop
            Use-AzureRmProfile -Profile 2018-03-01-hybrid -Force -ErrorAction Stop
            Install-Module -Name AzureStack -RequiredVersion 1.6.0 -Force -ErrorAction Stop
            # Install the Azure.Storage module version 4.5.0
            Install-Module -Name Azure.Storage -RequiredVersion 4.5.0 -Force -AllowClobber -Verbose
            # Install the AzureRm.Storage module version 5.0.4
            Install-Module -Name AzureRM.Storage -RequiredVersion 5.0.4 -Force -AllowClobber -Verbose
            # Remove incompatible storage module installed by AzureRM.Storage
            Uninstall-Module Azure.Storage -RequiredVersion 4.6.1 -Force -Verbose
        }
        elseif ($deploymentMode -ne "Online") {
            $SourceLocation = "$downloadPath\ASDK\PowerShell"
            $RepoName = "ConfigASDKRepo"
            if (!(Get-PSRepository -Name $RepoName -ErrorAction SilentlyContinue)) {
                Register-PSRepository -Name $RepoName -SourceLocation $SourceLocation -InstallationPolicy Trusted
            }
            # If this is a PartialOnline or Offline deployment, pull from the extracted zip file
            Install-Module AzureRM -Repository $RepoName -Force -AllowClobber -ErrorAction Stop -Verbose
            Install-Module AzureStack -Repository $RepoName -Force -AllowClobber -ErrorAction Stop -Verbose
            Install-Module Azure.Storage -Repository $RepoName -RequiredVersion 4.5.0 -Force -AllowClobber -ErrorAction Stop -Verbose
            Install-Module AzureRM.Storage -Repository $RepoName -RequiredVersion 5.0.4 -Force -AllowClobber -ErrorAction Stop -Verbose
            Uninstall-Module Azure.Storage -RequiredVersion 4.6.1 -Force -Verbose
        }
        StageComplete -progressStage $progressStage
    }
    catch {
        StageFailed -progressStage $progressStage
        Set-Location $ScriptLocation
        return        
    }
}
elseif ($progressCheck -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configurator Stage: $progressStage previously completed successfully"
}

# Load the Storage PowerShell modules explicitly specifying the versions
Import-Module -Name Azure.Storage -RequiredVersion 4.5.0 -Verbose
Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4 -Verbose

### TEST ALL LOGINS #########################################################################################################################################
#############################################################################################################################################################

$scriptStep = "TEST LOGINS"
# Register an AzureRM environment that targets your administrative Azure Stack instance
Write-CustomVerbose -Message "ASDK Configurator will now test all logins"
$ArmEndpoint = "https://adminmanagement.local.azurestack.external"
Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
$ADauth = (Get-AzureRmEnvironment -Name "AzureStackAdmin").ActiveDirectoryAuthority.TrimEnd('/')

if ($authenticationType.ToString() -like "AzureAd") {
    try {
        ### TEST AZURE LOGIN - Login to Azure Cloud
        Write-CustomVerbose -Message "Testing Azure login with Azure Active Directory`r`n"
        $tenantId = (Invoke-RestMethod "$($ADauth)/$($azureDirectoryTenantName)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
        $testAzureSub = Add-AzureRmAccount -EnvironmentName "AzureCloud" -TenantId $tenantId -Credential $asdkCreds -ErrorAction Stop
        $testAzureSub = $testAzureSub | Out-String
        Write-CustomVerbose -Message "Selected Azure Subscription is:"
        Write-Output $testAzureSub
        Start-Sleep -Seconds 5

        ### TEST AZURE STACK LOGIN - Login to Azure Stack
        Write-CustomVerbose -Message "Testing Azure Stack login with Azure Active Directory"
        Write-CustomVerbose -Message "Logging into the Default Provider Subscription with your Azure Stack Administrator Account used with Azure Active Directory"
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        $testAzureSub = Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Subscription "Default Provider Subscription" -Credential $asdkCreds -ErrorAction Stop
        $testAzureSub = $testAzureSub | Out-String
        Write-CustomVerbose -Message "Selected Azure Stack Subscription is:"
        Write-Output $testAzureSub
        Start-Sleep -Seconds 5
    }
    catch {
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($authenticationType.ToString() -like "ADFS") {
    try {
        ### TEST AZURE STACK LOGIN with ADFS - Login to Azure Stack
        Write-CustomVerbose -Message "Testing Azure Stack login with ADFS"
        Write-CustomVerbose -Message "Getting Tenant ID for Login to Azure Stack"
        $tenantId = (invoke-restmethod "$($ADauth)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
        Write-CustomVerbose -Message "Logging in with your Azure Stack Administrator Account used with ADFS"
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        $testAzureSub = Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Subscription "Default Provider Subscription" -Credential $asdkCreds -ErrorAction Stop
        $testAzureSub = $testAzureSub | Out-String
        Write-CustomVerbose -Message "Selected Azure Stack Subscription is:"
        Write-Output $testAzureSub
    }
    catch {
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
if ($registerASDK -and ($deploymentMode -ne "Offline")) {
    try {
        ### OPTIONAL - TEST AZURE REGISTRATION CREDS
        Write-CustomVerbose -Message "Testing Azure login for registration with Azure Active Directory"
        $testAzureRegSub = Add-AzureRmAccount -EnvironmentName "AzureCloud" -SubscriptionId $azureRegSubId -Credential $azureRegCreds -ErrorAction Stop
        $testAzureRegSubString = $testAzureRegSub | Out-String
        Write-CustomVerbose -Message "Selected Azure Subscription used for registration is:"
        Write-Output $testAzureRegSubString
        Write-CustomVerbose -Message "TenantID for this registration subscription is:"
        $azureRegTenantID = $testAzureRegSub.Context.Tenant.Id
        Write-Output $azureRegTenantID
        Start-Sleep -Seconds 5
    }
    catch {
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif (!$registerASDK) {
    Write-CustomVerbose -Message "User has chosen to not register the ASDK with Azure"
    Write-CustomVerbose -Message "No need to test login for registration"
    $azureRegTenantID = $null
    $azureRegSubId = $null
    $azureRegCreds = $null
}

### CLEAN LOGINS #######################################################################################################################################
########################################################################################################################################################

Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
Clear-AzureRmContext -Scope CurrentUser -Force
Disable-AzureRMContextAutosave -Scope CurrentUser

### Run Counter #############################################################################################################################################
#############################################################################################################################################################

# Once logins have been successfully tested, increment run counter to track usage
# This is used to understand how many times the ConfigASDK.ps1 script has been run
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {Invoke-WebRequest "http://bit.ly/asdkcounter" -UseBasicParsing -DisableKeepAlive | Out-Null } catch {$_.Exception.Response.StatusCode.Value__}

### DOWNLOAD TOOLS #####################################################################################################################################
########################################################################################################################################################

$progressStage = "DownloadTools"
$progressCheck = CheckProgress -progressStage $progressStage
$scriptStep = $progressStage.ToUpper()

if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {

    try {
        ### DOWNLOAD & EXTRACT TOOLS ###
        if ($deploymentMode -eq "Online") {
            # Download the tools archive using a function incase the download fails or is interrupted.
            $toolsURI = "https://github.com/Azure/AzureStack-Tools/archive/master.zip"
            $toolsDownloadLocation = "$ASDKpath\master.zip"
            Write-CustomVerbose -Message "Downloading Azure Stack Tools to ensure you have the latest versions. This may take a few minutes, depending on your connection speed."
            Write-CustomVerbose -Message "The download will be stored in $ASDKpath."
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            DownloadWithRetry -downloadURI "$toolsURI" -downloadLocation "$toolsDownloadLocation" -retries 10
        }
        elseif ($deploymentMode -ne "Online") {
            $toolsDownloadLocation = "$ASDKpath\master.zip"
        }
        # Expand the downloaded files
        Write-CustomVerbose -Message "Expanding Archive"
        Expand-Archive "$toolsDownloadLocation" -DestinationPath "C:\" -Force
        if ($deploymentMode -eq "Online") {
            Write-CustomVerbose -Message "Archive expanded. Cleaning up."
            Remove-Item "$toolsDownloadLocation" -Force -ErrorAction Stop
        }
        StageComplete -progressStage $progressStage
    }
    catch {
        StageFailed -progressStage $progressStage
        Set-Location $ScriptLocation
        return        
    }
}
elseif ($progressCheck -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configurator Stage: $progressStage previously completed successfully"
}

# Change to the tools directory
Write-CustomVerbose -Message "Changing Directory"
$modulePath = "C:\AzureStack-Tools-master"
Get-ChildItem -Path "$modulePath\*" -Recurse | Unblock-File -Verbose
Set-Location $modulePath
Disable-AzureRmDataCollection -WarningAction SilentlyContinue

### CONFIGURE THE AZURE STACK HOST & INFRA VIRTUAL MACHINES ############################################################################################
########################################################################################################################################################

$progressStage = "HostConfiguration"
$progressCheck = CheckProgress -progressStage $progressStage
$scriptStep = $progressStage.ToUpper()

if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
    try {
        # Set password expiration to 180 days
        Write-CustomVerbose -Message "Configuring password expiration policy"
        Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 180.00:00:00 -Identity azurestack.local
        Get-ADDefaultDomainPasswordPolicy

        # Set Power Policy
        Write-CustomVerbose -Message "Optimizing power policy for high performance"
        POWERCFG.EXE /S SCHEME_MIN

        # Disable Windows Update on infrastructure VMs
        Write-CustomVerbose -Message "Disabling Windows Update on Infrastructure VMs and ASDK Host`r`n"
        $AZSvms = Get-VM -Name AZS*
        $scriptblock = {
            Get-Service -Name wuauserv | Stop-Service -Force -PassThru | Set-Service -StartupType disabled -Confirm:$false
        }
        foreach ($vm in $AZSvms) {
            Invoke-Command -VMName $vm.name -ScriptBlock $scriptblock -Credential $azureStackAdminCreds
        }

        # Disable Windows Update and DNS Server on Host - using foreach loop as ASDK on Azure solution doesn't have DNS Server.
        $serviceArray = @()
        $serviceArray.Clear()
        $serviceArray = "wuauserv", "DNS"
        foreach ($service in $serviceArray) {
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                Write-CustomVerbose -Message "Stopping Service: $service"
                Stop-Service -Name $service -Force -PassThru
                Write-CustomVerbose -Message "Disabling Service: $service at startup"
                Set-Service -Name $service -StartupType disabled -Confirm:$false
            }
            else {
                Write-CustomVerbose -Message "Service: $service not found, continuing process..."
            }
        }
        StageComplete -progressStage $progressStage
    }
    Catch {
        StageFailed -progressStage $progressStage
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progressCheck -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configurator Stage: $progressStage previously completed successfully"
}

### REGISTER AZURE STACK TO AZURE ############################################################################################################################
##############################################################################################################################################################

$progressStage = "Registration"
$progressCheck = CheckProgress -progressStage $progressStage
$scriptStep = $progressStage.ToUpper()
if ($registerASDK -and ($deploymentMode -ne "Offline")) {
    if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
        try {
            Write-CustomVerbose -Message "Starting Azure Stack registration to Azure"
            # Add the Azure cloud subscription environment name. Supported environment names are AzureCloud or, if using a China Azure Subscription, AzureChinaCloud.
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            $ADauth = (Get-AzureRmEnvironment -Name "AzureStackAdmin").ActiveDirectoryAuthority.TrimEnd('/')
            $tenantId = (Invoke-RestMethod "$($ADauth)/$($azureDirectoryTenantName)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Subscription "Default Provider Subscription" -Credential $asdkCreds -ErrorAction Stop
            Add-AzureRmAccount -EnvironmentName "AzureCloud" -SubscriptionId $azureRegSubId -TenantId $azureRegTenantID -Credential $azureRegCreds -ErrorAction Stop | Out-Null
            # Register the Azure Stack resource provider in your Azure subscription
            Register-AzureRmResourceProvider -ProviderNamespace Microsoft.AzureStack
            # Import the registration module that was downloaded with the GitHub tools
            Import-Module $modulePath\Registration\RegisterWithAzure.psm1 -Force -Verbose
            #Register Azure Stack
            $asdkHostName = ($env:computername).ToLower()
            $asdkRegName = "asdkreg-$asdkHostName-$runTime"
            Set-AzsRegistration -PrivilegedEndpointCredential $cloudAdminCreds -PrivilegedEndpoint AzS-ERCS01 -RegistrationName "$asdkRegName" -BillingModel Development -ErrorAction Stop
            # Create Cleanup Doc - First Create File
            $CleanUpRegPS1Path = "$downloadPath\ASDKRegCleanUp.ps1"
            Remove-Item -Path $CleanUpRegPS1Path -Confirm:$false -Force -ErrorAction SilentlyContinue -Verbose
            New-Item "$CleanUpRegPS1Path" -ItemType file -Force
            # Populate file with key parameters
            Write-Output "# This script should be used to remove a registration resource from Azure, prior to redeploying your ASDK on this hardware`n" -Verbose -ErrorAction Stop | Out-File -FilePath "$CleanUpRegPS1Path" -Force -Verbose -Append
            Write-Output "# Populate key parameters" -Verbose -ErrorAction Stop | Out-File -FilePath "$CleanUpRegPS1Path" -Force -Verbose -Append
            Write-Output "`$modulePath = `"$modulePath`"" -Verbose -ErrorAction Stop | Out-File -FilePath "$CleanUpRegPS1Path" -Force -Verbose -Append
            Write-Output 'Import-Module "$modulePath\Registration\RegisterWithAzure.psm1" -Force -Verbose' -Verbose -ErrorAction Stop | Out-File -FilePath "$CleanUpRegPS1Path" -Force -Verbose -Append
            Write-Output "`$asdkRegName = `"$asdkRegName`"" -Verbose -ErrorAction Stop | Out-File -FilePath "$CleanUpRegPS1Path" -Force -Verbose -Append
            # Populate AAD Registration Information
            Write-Output "`n# Populate AAD Registration Information" -Verbose -ErrorAction Stop | Out-File -FilePath "$CleanUpRegPS1Path" -Force -Verbose -Append
            Write-Output "`$azureRegCreds = Get-Credential -UserName `"$azureRegUsername`" -Message `"Enter the credentials you used to register this ASDK for username:$azureRegUsername.`"" -Verbose -ErrorAction Stop | Out-File -FilePath "$CleanUpRegPS1Path" -Force -Verbose -Append
            Write-Output "`$azureRegSubId = `"$azureRegSubId`"" -Verbose -ErrorAction Stop | Out-File -FilePath "$CleanUpRegPS1Path" -Force -Verbose -Append
            Write-Output "`$azureRegSub = Add-AzureRmAccount -EnvironmentName `"AzureCloud`" -SubscriptionId `"$azureRegSubId`" -Credential `$azureRegCreds" -ErrorAction Stop | Out-File -FilePath "$CleanUpRegPS1Path" -Force -Verbose -Append
            # Get ASDK Privileged Endpoint Creds
            Write-Output "`n# Get ASDK Privileged Endpoint Creds" -Verbose -ErrorAction Stop | Out-File -FilePath "$CleanUpRegPS1Path" -Force -Verbose -Append
            Write-Output '$cloudAdminCreds = Get-Credential -UserName "azurestack\cloudadmin" -Message "Enter the credentials to access the privileged endpoint."' -Verbose -ErrorAction Stop | Out-File -FilePath "$CleanUpRegPS1Path" -Force -Verbose -Append
            # Perform Removal
            Write-Output 'Remove-AzsRegistration -PrivilegedEndpoint "Azs-ERCS01" -PrivilegedEndpointCredential $cloudAdminCreds -RegistrationName "$asdkRegName"' -Verbose -ErrorAction Stop | Out-File -FilePath "$CleanUpRegPS1Path" -Force -Verbose -Append
            StageComplete -progressStage $progressStage
        }
        catch {
            StageFailed -progressStage $progressStage
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progressCheck -eq "Complete") {
        Write-CustomVerbose -Message "ASDK Configurator Stage: $progressStage previously completed successfully"
    }
}
elseif (!$registerASDK) {
    Write-CustomVerbose -Message "Skipping Azure Stack registration to Azure"
    StageSkipped -progressStage $progressStage
}

### CONNECT TO AZURE STACK #############################################################################################################################
########################################################################################################################################################

$scriptStep = "CONNECTING"
# Add GraphEndpointResourceId value for Azure AD or ADFS and obtain Tenant ID, then login to Azure Stack
if ($authenticationType.ToString() -like "AzureAd") {
    # Clear old Azure login
    Write-CustomVerbose -Message "Azure Active Directory selected by Administrator"
    Write-CustomVerbose -Message "Logging into the Default Provider Subscription with your Azure Stack Administrator Account used with Azure Active Directory"
    $ADauth = (Get-AzureRmEnvironment -Name "AzureStackAdmin").ActiveDirectoryAuthority.TrimEnd('/')
    $tenantId = (Invoke-RestMethod "$($ADauth)/$($azureDirectoryTenantName)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
    $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
    Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
    Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Subscription "Default Provider Subscription" -Credential $asdkCreds -ErrorAction Stop
}
elseif ($authenticationType.ToString() -like "ADFS") {
    # Clear old Azure login
    Write-CustomVerbose -Message "Active Directory Federation Services selected by Administrator"
    $ADauth = (Get-AzureRmEnvironment -Name "AzureStackAdmin").ActiveDirectoryAuthority.TrimEnd('/')
    $tenantId = (Invoke-RestMethod "$($ADauth)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
    Write-CustomVerbose -Message "Logging in with your Azure Stack Administrator Account used with ADFS"
    $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
    Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
    Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Subscription "Default Provider Subscription" -Credential $asdkCreds -ErrorAction Stop
}
else {
    Write-CustomVerbose -Message ("No valid authentication types specified - please use AzureAd or ADFS")  -ErrorAction Stop
}

# Get Azure Stack location
$azsLocation = (Get-AzsLocation).Name

### ADD VM IMAGES - JOB SETUP ################################################################################################################################
##############################################################################################################################################################

# This section now includes 4 key steps - Ubuntu Image, Windows Updates, Server Core Image and Server Full Image
# They will execute serially or in parallel, depending on host capacity

$scriptStep = "LAUNCHJOBS"
# Get current free space on the drive used to hold the Azure Stack images
Write-CustomVerbose -Message "Calculating free disk space on Cluster Shared Volume, to plan image upload concurrency"
Start-Sleep 5
$freeCSVSpace = [int](((Get-ClusterSharedVolume | Select-Object -Property Name -ExpandProperty SharedVolumeInfo).Partition.FreeSpace) / 1GB)
Write-CustomVerbose -Message "Free space on Cluster Shared Volume = $($freeCSVSpace)GB"
Start-Sleep 3

if ($freeCSVSpace -lt 45) {
    Write-CustomVerbose -Message "Free space is less than 45GB - you don't have enough room on the drive to create the Windows Server image with updates"
    throw "You need additional space to create a Windows Server image. Minimum required free space is 45GB"
}
elseif ($freeCSVSpace -ge 45 -and $freeCSVSpace -lt 82) {
    Write-CustomVerbose -Message "Free space is less than 82GB - you don't have enough room on the drive to create all Ubuntu Server and Windows Server images in parallel"
    Write-CustomVerbose -Message "Your Ubuntu Server and Windows Server images will be created serially.  This could take some time."
    # Create images: 1. Ubuntu + Windows Update in parallel 2. Windows Server Core 3. Windows Server Full
    $runMode = "serial"
}
elseif ($freeCSVSpace -ge 82 -and $freeCSVSpace -lt 115) {
    Write-CustomVerbose -Message "Free space is less than 115GB - you don't have enough room on the drive to create all Ubuntu Server and Windows Server images in parallel"
    Write-CustomVerbose -Message "Your Ubuntu Server will be created first, then Windows Server images will be created in parallel.  This could take some time."
    # Create images: 1. Ubuntu + Windows Update in parallel 2. Windows Server Core and Windows Server Full in parallel after both prior jobs have finished.
    $runMode = "partialParallel"
}
elseif ($freeCSVSpace -ge 115) {
    Write-CustomVerbose -Message "Free space is more than 115GB - you have enough room on the drive to create all Ubuntu Server and Windows Server images in parallel"
    Write-CustomVerbose -Message "This is the fastest way to populate the Azure Stack Platform Image Repository."
    # Create images: 1. Ubuntu + Windows Update in parallel 2. Windows Server Core and Windows Server Full in parallel after Windows Update job is finished.
    $runMode = "parallel"
}

# Define the image jobs
$jobName = "AddUbuntuImage"
$AddUbuntuImage = {
    Start-Job -Name AddUbuntuImage -InitializationScript $export_functions -ArgumentList $ISOpath, $ASDKpath, $azsLocation, $registerASDK, $deploymentMode, $modulePath, `
        $azureRegSubId, $azureRegTenantID, $tenantID, $azureRegCreds, $asdkCreds, $ScriptLocation, $branch, $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\AddImage.ps1 -ASDKpath $Using:ASDKpath `
            -azsLocation $Using:azsLocation -registerASDK $Using:registerASDK -deploymentMode $Using:deploymentMode -modulePath $Using:modulePath `
            -azureRegSubId $Using:azureRegSubId -azureRegTenantID $Using:azureRegTenantID -tenantID $Using:TenantID -azureRegCreds $Using:azureRegCreds `
            -asdkCreds $Using:asdkCreds -ScriptLocation $Using:ScriptLocation -ISOpath $Using:ISOpath -image "UbuntuServer" -branch $Using:branch -runMode $Using:runMode `
            -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $AddUbuntuImage -Verbose

$jobName = "DownloadWindowsUpdates"
$DownloadWindowsUpdates = {
    Start-Job -Name DownloadWindowsUpdates -InitializationScript $export_functions -ArgumentList $ISOpath, $ASDKpath, $azsLocation, `
        $deploymentMode, $tenantID, $asdkCreds, $ScriptLocation, $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\DownloadWinUpdates.ps1 -ISOpath $Using:ISOpath -ASDKpath $Using:ASDKpath `
            -azsLocation $Using:azsLocation -deploymentMode $Using:deploymentMode -tenantID $Using:TenantID -asdkCreds $Using:asdkCreds `
            -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName -ScriptLocation $Using:ScriptLocation
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $DownloadWindowsUpdates -Verbose

$jobName = "AddServerCoreImage"
$AddServerCoreImage = {
    Start-Job -Name AddServerCoreImage -InitializationScript $export_functions -ArgumentList $ASDKpath, $azsLocation, $registerASDK, $deploymentMode, `
        $modulePath, $azureRegSubId, $azureRegTenantID, $tenantID, $azureRegCreds, $asdkCreds, $ScriptLocation, $runMode, $ISOpath, $branch, `
        $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\AddImage.ps1 -ASDKpath $Using:ASDKpath -azsLocation $Using:azsLocation -registerASDK $Using:registerASDK `
            -deploymentMode $Using:deploymentMode -modulePath $Using:modulePath -azureRegSubId $Using:azureRegSubId -azureRegTenantID $Using:azureRegTenantID `
            -tenantID $Using:TenantID -azureRegCreds $Using:azureRegCreds -asdkCreds $Using:asdkCreds -ScriptLocation $Using:ScriptLocation -ISOpath $Using:ISOpath `
            -image "ServerCore" -branch $Using:branch -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName -runMode $Using:runMode
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $AddServerCoreImage -Verbose

$jobName = "AddServerFullImage"
$AddServerFullImage = {
    Start-Job -Name AddServerFullImage -InitializationScript $export_functions -ArgumentList $ASDKpath, $azsLocation, `
        $registerASDK, $deploymentMode, $modulePath, $azureRegSubId, $azureRegTenantID, $tenantID, $azureRegCreds, $asdkCreds, $ScriptLocation, `
        $runMode, $ISOpath, $branch, $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\AddImage.ps1 -ASDKpath $Using:ASDKpath `
            -azsLocation $Using:azsLocation -registerASDK $Using:registerASDK -deploymentMode $Using:deploymentMode -modulePath $Using:modulePath `
            -azureRegSubId $Using:azureRegSubId -azureRegTenantID $Using:azureRegTenantID -tenantID $Using:TenantID -azureRegCreds $Using:azureRegCreds `
            -asdkCreds $Using:asdkCreds -ScriptLocation $Using:ScriptLocation -ISOpath $Using:ISOpath -image "ServerFull" -branch $Using:branch `
            -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName -runMode $Using:runMode
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $AddServerFullImage -Verbose

### ADD DB GALLERY ITEMS - JOB SETUP #########################################################################################################################
##############################################################################################################################################################

# Define the DB Gallery Item jobs
$jobName = "AddMySQLAzpkg"
$AddMySQLAzpkg = {
    Start-Job -Name AddMySQLAzpkg -InitializationScript $export_functions -ArgumentList $ASDKpath, $azsLocation, $deploymentMode, $tenantID, $asdkCreds, $ScriptLocation, `
        $branch, $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\AddGalleryItems.ps1 -ASDKpath $Using:ASDKpath -azsLocation $Using:azsLocation `
            -deploymentMode $Using:deploymentMode -tenantID $Using:TenantID -asdkCreds $Using:asdkCreds -ScriptLocation $Using:ScriptLocation -branch $Using:branch `
            -azpkg "MySQL" -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $AddMySQLAzpkg -Verbose

$jobName = "AddSQLServerAzpkg"
$AddSQLServerAzpkg = {
    Start-Job -Name AddSQLServerAzpkg -InitializationScript $export_functions -ArgumentList $ASDKpath, $azsLocation, $deploymentMode, $tenantID, $asdkCreds, $ScriptLocation, `
        $branch, $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\AddGalleryItems.ps1 -ASDKpath $Using:ASDKpath -azsLocation $Using:azsLocation `
            -deploymentMode $Using:deploymentMode -tenantID $Using:TenantID -asdkCreds $Using:asdkCreds -ScriptLocation $Using:ScriptLocation -branch $Using:branch `
            -azpkg "SQLServer" -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $AddSQLServerAzpkg -Verbose

### ADD VM EXTENSIONS - JOB SETUP ############################################################################################################################
##############################################################################################################################################################

$jobName = "AddVMExtensions"
$AddVMExtensions = {
    Start-Job -Name AddVMExtensions -InitializationScript $export_functions -ArgumentList $deploymentMode, $tenantID, $asdkCreds, $ScriptLocation, $registerASDK, `
        $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\AddVMExtensions.ps1 -deploymentMode $Using:deploymentMode -tenantID $Using:TenantID -asdkCreds $Using:asdkCreds `
            -ScriptLocation $Using:ScriptLocation -registerASDK $Using:registerASDK -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName `
            -tableName $Using:tableName
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $AddVMExtensions -Verbose

### ADD DB RPS - JOB SETUP ###################################################################################################################################
##############################################################################################################################################################

$jobName = "AddMySQLRP"
$AddMySQLRP = {
    Start-Job -Name AddMySQLRP -InitializationScript $export_functions -ArgumentList $ASDKpath, $secureVMpwd, $deploymentMode, $serialMode, `
        $tenantID, $asdkCreds, $ScriptLocation, $skipMySQL, $skipMSSQL, $ERCSip, $cloudAdminCreds, $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\DeployDBRP.ps1 -ASDKpath $Using:ASDKpath -deploymentMode $Using:deploymentMode -tenantID $Using:TenantID `
            -asdkCreds $Using:asdkCreds -ScriptLocation $Using:ScriptLocation -dbrp "MySQL" -ERCSip $Using:ERCSip -cloudAdminCreds $Using:cloudAdminCreds `
            -skipMySQL $Using:skipMySQL -skipMSSQL $Using:skipMSSQL -secureVMpwd $Using:secureVMpwd -sqlServerInstance $Using:sqlServerInstance `
            -databaseName $Using:databaseName -tableName $Using:tableName -serialMode $Using:serialMode
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $AddMySQLRP -Verbose

$jobName = "AddSQLServerRP"
$AddSQLServerRP = {
    Start-Job -Name AddSQLServerRP -InitializationScript $export_functions -ArgumentList $ASDKpath, $secureVMpwd, $deploymentMode, $serialMode, `
        $tenantID, $asdkCreds, $ScriptLocation, $skipMySQL, $skipMSSQL, $ERCSip, $cloudAdminCreds, $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\DeployDBRP.ps1 -ASDKpath $Using:ASDKpath -deploymentMode $Using:deploymentMode -tenantID $Using:TenantID `
            -asdkCreds $Using:asdkCreds -ScriptLocation $Using:ScriptLocation -dbrp "SQLServer" -ERCSip $Using:ERCSip -cloudAdminCreds $Using:cloudAdminCreds `
            -skipMySQL $Using:skipMySQL -skipMSSQL $Using:skipMSSQL -secureVMpwd $Using:secureVMpwd -sqlServerInstance $Using:sqlServerInstance `
            -databaseName $Using:databaseName -tableName $Using:tableName -serialMode $Using:serialMode
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $AddSQLServerRP -Verbose

### ADD DB SKUs - JOB SETUP ##################################################################################################################################
##############################################################################################################################################################

$jobName = "AddMySQLSku"
$AddMySQLSku = {
    Start-Job -Name AddMySQLSku -InitializationScript $export_functions -ArgumentList $tenantID, $asdkCreds, $ScriptLocation, $azsLocation, $skipMySQL, $skipMSSQL, `
        $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\AddDBSkuQuota.ps1 -tenantID $Using:TenantID -asdkCreds $Using:asdkCreds -ScriptLocation $Using:ScriptLocation `
            -azsLocation $Using:azsLocation -dbsku "MySQL" -skipMySQL $Using:skipMySQL -skipMSSQL $Using:skipMSSQL -sqlServerInstance $Using:sqlServerInstance `
            -databaseName $Using:databaseName -tableName $Using:tableName
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $AddMySQLSku -Verbose

$jobName = "AddSQLServerSku"
$AddSQLServerSku = {
    Start-Job -Name AddSQLServerSku -InitializationScript $export_functions -ArgumentList $tenantID, $asdkCreds, $ScriptLocation, $azsLocation, $skipMySQL, $skipMSSQL, `
        $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\AddDBSkuQuota.ps1 -tenantID $Using:TenantID -asdkCreds $Using:asdkCreds -ScriptLocation $Using:ScriptLocation `
            -azsLocation $Using:azsLocation -dbsku "SQLServer" -skipMySQL $Using:skipMySQL -skipMSSQL $Using:skipMSSQL -sqlServerInstance $Using:sqlServerInstance `
            -databaseName $Using:databaseName -tableName $Using:tableName
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $AddSQLServerSku -Verbose

### UPLOAD SCRIPTS - JOB SETUP ###############################################################################################################################
##############################################################################################################################################################

$jobName = "UploadScripts"
$UploadScripts = {
    Start-Job -Name UploadScripts -InitializationScript $export_functions -ArgumentList $ASDKpath, $tenantID, $asdkCreds, $deploymentMode, $azsLocation, $ScriptLocation, `
        $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\UploadScripts.ps1 -ASDKpath $Using:ASDKpath -tenantID $Using:TenantID -asdkCreds $Using:asdkCreds `
            -deploymentMode $Using:deploymentMode -azsLocation $Using:azsLocation -ScriptLocation $Using:ScriptLocation -sqlServerInstance $Using:sqlServerInstance `
            -databaseName $Using:databaseName -tableName $Using:tableName
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $UploadScripts -Verbose

### DEPLOY DB VMs - JOB SETUP ################################################################################################################################
##############################################################################################################################################################

$jobName = "DeployMySQLHost"
$DeployMySQLHost = {
    Start-Job -Name DeployMySQLHost -InitializationScript $export_functions -ArgumentList $ASDKpath, $downloadPath, $deploymentMode, $tenantID, $secureVMpwd, $VMpwd, `
        $asdkCreds, $ScriptLocation, $azsLocation, $skipMySQL, $skipMSSQL, $skipAppService, $branch, $sqlServerInstance, $databaseName, $tableName, $serialMode -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\DeployVM.ps1 -ASDKpath $Using:ASDKpath `
            -downloadPath $Using:downloadPath -deploymentMode $Using:deploymentMode -vmType "MySQL" -tenantID $Using:TenantID `
            -secureVMpwd $Using:secureVMpwd -VMpwd $Using:VMpwd -asdkCreds $Using:asdkCreds -ScriptLocation $Using:ScriptLocation -azsLocation $Using:azsLocation `
            -skipMySQL $Using:skipMySQL -skipMSSQL $Using:skipMSSQL -skipAppService $Using:skipAppService -branch $Using:branch -sqlServerInstance $Using:sqlServerInstance `
            -databaseName $Using:databaseName -tableName $Using:tableName -serialMode $Using:serialMode
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $DeployMySQLHost -Verbose

$jobName = "DeploySQLServerHost"
$DeploySQLServerHost = {
    Start-Job -Name DeploySQLServerHost -InitializationScript $export_functions -ArgumentList $ASDKpath, $downloadPath, $deploymentMode, $tenantID, $secureVMpwd, $VMpwd, `
        $asdkCreds, $ScriptLocation, $azsLocation, $skipMySQL, $skipMSSQL, $skipAppService, $branch, $sqlServerInstance, $databaseName, $tableName, $serialMode -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\DeployVM.ps1 -ASDKpath $Using:ASDKpath -downloadPath $Using:downloadPath -deploymentMode $Using:deploymentMode `
            -vmType "SQLServer" -tenantID $Using:TenantID -secureVMpwd $Using:secureVMpwd -VMpwd $Using:VMpwd -asdkCreds $Using:asdkCreds `
            -ScriptLocation $Using:ScriptLocation -azsLocation $Using:azsLocation -skipMySQL $Using:skipMySQL -skipMSSQL $Using:skipMSSQL `
            -skipAppService $Using:skipAppService -branch $Using:branch -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName -serialMode $Using:serialMode
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $DeploySQLServerHost -Verbose

### ADD HOSTING SERVERS - JOB SETUP ##########################################################################################################################
##############################################################################################################################################################

$jobName = "AddMySQLHosting"
$AddMySQLHosting = {
    Start-Job -Name AddMySQLHosting -InitializationScript $export_functions -ArgumentList $ASDKpath, $deploymentMode, $tenantID, $secureVMpwd, `
        $asdkCreds, $ScriptLocation, $skipMySQL, $skipMSSQL, $branch, $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\AddDBHosting.ps1 -ASDKpath $Using:ASDKpath -deploymentMode $Using:deploymentMode -dbHost "MySQL" `
            -tenantID $Using:TenantID -secureVMpwd $Using:secureVMpwd -asdkCreds $Using:asdkCreds -ScriptLocation $Using:ScriptLocation -skipMySQL $Using:skipMySQL `
            -skipMSSQL $Using:skipMSSQL -branch $Using:branch -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $AddMySQLHosting -Verbose

$jobName = "AddSQLHosting"
$AddSQLHosting = {
    Start-Job -Name AddSQLHosting -InitializationScript $export_functions -ArgumentList $ASDKpath, $deploymentMode, $tenantID, $secureVMpwd, `
        $asdkCreds, $ScriptLocation, $skipMySQL, $skipMSSQL, $branch, $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\AddDBHosting.ps1 -ASDKpath $Using:ASDKpath -deploymentMode $Using:deploymentMode -dbHost "SQLServer" `
            -tenantID $Using:TenantID -secureVMpwd $Using:secureVMpwd -asdkCreds $Using:asdkCreds -ScriptLocation $Using:ScriptLocation -skipMySQL $Using:skipMySQL `
            -skipMSSQL $Using:skipMSSQL -branch $Using:branch -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $AddSQLHosting -Verbose

### APP SERVICE - JOB SETUP ##################################################################################################################################
##############################################################################################################################################################

$jobName = "DeployAppServiceFS"
$DeployAppServiceFS = {
    Start-Job -Name DeployAppServiceFS -InitializationScript $export_functions -ArgumentList $ASDKpath, $downloadPath, $deploymentMode, $tenantID, $secureVMpwd, $VMpwd, `
        $asdkCreds, $ScriptLocation, $azsLocation, $skipMySQL, $skipMSSQL, $skipAppService, $branch, $sqlServerInstance, $databaseName, $tableName, $serialMode -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\DeployVM.ps1 -ASDKpath $Using:ASDKpath -downloadPath $Using:downloadPath -deploymentMode $Using:deploymentMode `
            -vmType "AppServiceFS" -tenantID $Using:TenantID -secureVMpwd $Using:secureVMpwd -VMpwd $Using:VMpwd -asdkCreds $Using:asdkCreds `
            -ScriptLocation $Using:ScriptLocation -azsLocation $Using:azsLocation -skipMySQL $Using:skipMySQL -skipMSSQL $Using:skipMSSQL -skipAppService $Using:skipAppService `
            -branch $Using:branch -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName -serialMode $Using:serialMode
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $DeployAppServiceFS -Verbose

$jobName = "DeployAppServiceDB"
$DeployAppServiceDB = {
    Start-Job -Name DeployAppServiceDB -InitializationScript $export_functions -ArgumentList $ASDKpath, $downloadPath, $deploymentMode, $tenantID, $secureVMpwd, $VMpwd, `
        $asdkCreds, $ScriptLocation, $azsLocation, $skipMySQL, $skipMSSQL, $skipAppService, $branch, $sqlServerInstance, $databaseName, $tableName, $serialMode -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\DeployVM.ps1 -ASDKpath $Using:ASDKpath -downloadPath $Using:downloadPath -deploymentMode $Using:deploymentMode `
            -vmType "AppServiceDB" -tenantID $Using:TenantID -secureVMpwd $Using:secureVMpwd -VMpwd $Using:VMpwd -asdkCreds $Using:asdkCreds `
            -ScriptLocation $Using:ScriptLocation -azsLocation $Using:azsLocation -skipMySQL $Using:skipMySQL -skipMSSQL $Using:skipMSSQL -skipAppService $Using:skipAppService `
            -branch $Using:branch -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName -serialMode $Using:serialMode
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $DeployAppServiceDB -Verbose

$jobName = "DownloadAppService"
$DownloadAppService = {
    Start-Job -Name DownloadAppService -InitializationScript $export_functions -ArgumentList $ASDKpath, $deploymentMode, $ScriptLocation, $skipAppService, `
        $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\DownloadAppService.ps1 -ASDKpath $Using:ASDKpath -deploymentMode $Using:deploymentMode -ScriptLocation $Using:ScriptLocation `
            -skipAppService $Using:skipAppService -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $DownloadAppService -Verbose

$jobName = "AddAppServicePreReqs"
$AddAppServicePreReqs = {
    Start-Job -Name AddAppServicePreReqs -InitializationScript $export_functions -ArgumentList $ASDKpath, $downloadPath, $deploymentMode, $authenticationType, `
        $azureDirectoryTenantName, $tenantID, $secureVMpwd, $ERCSip, $branch, $asdkCreds, $cloudAdminCreds, $ScriptLocation, $skipAppService, `
        $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\AddAppServicePreReqs.ps1 -ASDKpath $Using:ASDKpath `
            -downloadPath $Using:downloadPath -deploymentMode $Using:deploymentMode -authenticationType $Using:authenticationType `
            -azureDirectoryTenantName $Using:azureDirectoryTenantName -tenantID $Using:tenantID -secureVMpwd $Using:secureVMpwd -ERCSip $Using:ERCSip -branch $Using:branch `
            -asdkCreds $Using:asdkCreds -cloudAdminCreds $Using:cloudAdminCreds -ScriptLocation $Using:ScriptLocation -skipAppService $Using:skipAppService `
            -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $AddAppServicePreReqs -Verbose

$jobName = "DeployAppService"
$DeployAppService = {
    Start-Job -Name DeployAppService -InitializationScript $export_functions -ArgumentList $ASDKpath, $downloadPath, $deploymentMode, $authenticationType, `
        $azureDirectoryTenantName, $tenantID, $VMpwd, $asdkCreds, $ScriptLocation, $skipAppService, $branch, $sqlServerInstance, $databaseName, $tableName -ScriptBlock {
        Set-Location $Using:ScriptLocation; .\Scripts\DeployAppService.ps1 -ASDKpath $Using:ASDKpath -downloadPath $Using:downloadPath -deploymentMode $Using:deploymentMode `
            -authenticationType $Using:authenticationType -azureDirectoryTenantName $Using:azureDirectoryTenantName -tenantID $Using:tenantID -VMpwd $Using:VMpwd `
            -asdkCreds $Using:asdkCreds -ScriptLocation $Using:ScriptLocation -skipAppService $Using:skipAppService -branch $Using:branch `
            -sqlServerInstance $Using:sqlServerInstance -databaseName $Using:databaseName -tableName $Using:tableName
    } -Verbose -ErrorAction Stop
}
JobLauncher -jobName $jobName -jobToExecute $DeployAppService -Verbose

### JOB LAUNCHER & TRACKER ###################################################################################################################################
##############################################################################################################################################################

# Get all the running jobs
Set-Location $ScriptLocation
Clear-Host
.\Scripts\GetJobStatus.ps1

#### REGISTER NEW RESOURCE PROVIDERS #########################################################################################################################
##############################################################################################################################################################

$progressStage = "RegisterNewRPs"
$progressCheck = CheckProgress -progressStage $progressStage
$scriptStep = $progressStage.ToUpper()
if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
    try {
        # Register resource providers
        foreach ($s in (Get-AzureRmSubscription)) {
            Select-AzureRmSubscription -SubscriptionId $s.SubscriptionId | Out-Null
            Write-Progress $($s.SubscriptionId + " : " + $s.SubscriptionName)
            Get-AzureRmResourceProvider -ListAvailable | Register-AzureRmResourceProvider
        }
        StageComplete -progressStage $progressStage
    }
    catch {
        StageFailed -progressStage $progressStage
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progressCheck -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configurator Stage: $progressStage previously completed successfully"
}

#### CREATE BASIC BASE PLANS AND OFFERS ######################################################################################################################
##############################################################################################################################################################

$progressStage = "CreatePlansOffers"
$progressCheck = CheckProgress -progressStage $progressStage
$scriptStep = $progressStage.ToUpper()
if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
    try {
        # Configure a simple base plan and offer for IaaS
        Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
        Clear-AzureRmContext -Scope CurrentUser -Force
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        $sub = Get-AzureRmSubscription | Where-Object {$_.Name -eq "Default Provider Subscription"}
        $azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
        $subID = $azureContext.Subscription.Id

        # Default quotas, plan, and offer
        $PlanName = "BasePlan"
        $OfferName = "BaseOffer"
        $RGName = "azurestack-plansandoffers"

        $computeParams = $null
        $computeParams = @{
            Name                 = "compute_default"
            CoresCount           = 200
            AvailabilitySetCount = 20
            VirtualMachineCount  = 100
            VmScaleSetCount      = 20
            Location             = $azsLocation
        }

        $netParams = $null
        $netParams = @{
            Name                                               = "network_default"
            MaxPublicIpsPerSubscription                        = 500
            MaxVNetsPerSubscription                            = 500
            MaxVirtualNetworkGatewaysPerSubscription           = 10
            MaxVirtualNetworkGatewayConnectionsPerSubscription = 20
            MaxLoadBalancersPerSubscription                    = 500
            MaxNicsPerSubscription                             = 1000
            MaxSecurityGroupsPerSubscription                   = 500
            Location                                           = $azsLocation
        }

        $storageParams = $null
        $storageParams = @{
            Name                    = "storage_default"
            NumberOfStorageAccounts = 200
            CapacityInGB            = 2048
            Location                = $azsLocation
        }

        $kvParams = $null
        $kvParams = @{
            Location = $azsLocation
        }

        $quotaIDs = $null
        $quotaIDs = @()
        while (!$(Get-AzsNetworkQuota -Name ($netParams.Name) -Location $azsLocation -ErrorAction SilentlyContinue -Verbose)) {
            New-AzsNetworkQuota @netParams
        }
        if ($(Get-AzsNetworkQuota -Name ($netParams.Name) -Location $azsLocation -ErrorAction Stop -Verbose)) {
            $quotaIDs += (Get-AzsNetworkQuota -Name ($netParams.Name) -Location $azsLocation).ID
        }
        while (!$(Get-AzsComputeQuota -Name ($computeParams.Name) -Location $azsLocation -ErrorAction SilentlyContinue -Verbose)) {
            New-AzsComputeQuota @computeParams -ErrorAction Stop -Verbose
        }
        if ($(Get-AzsComputeQuota -Name ($computeParams.Name) -Location $azsLocation -ErrorAction Stop -Verbose)) {
            $quotaIDs += (Get-AzsComputeQuota -Name ($computeParams.Name) -Location $azsLocation).ID
        }
        while (!$(Get-AzsStorageQuota -Name ($storageParams.Name) -Location $azsLocation -ErrorAction SilentlyContinue -Verbose)) {
            New-AzsStorageQuota @storageParams -ErrorAction Stop -Verbose
        }
        if ($(Get-AzsStorageQuota -Name ($storageParams.Name) -Location $azsLocation -ErrorAction Stop -Verbose)) {
            $quotaIDs += (Get-AzsStorageQuota -Name ($storageParams.Name) -Location $azsLocation).ID
        }
        $quotaIDs += (Get-AzsKeyVaultQuota @kvParams -ErrorAction Stop -Verbose).ID

        # If MySQL, MSSQL and App Service haven't been skipped, add them to the Base Plan too
        if (!$skipMySQL) {
            $mySqlDatabaseAdapterNamespace = "Microsoft.MySQLAdapter.Admin"
            $mySqlLocation = "$azsLocation"
            $mySqlQuotaName = "mysqldefault"
            $mySQLQuotaId = '/subscriptions/{0}/providers/{1}/locations/{2}/quotas/{3}' -f $subID, $mySqlDatabaseAdapterNamespace, $mySqlLocation, $mySqlQuotaName
            $quotaIDs += $mySQLQuotaId
        }
        if (!$skipMSSQL) {
            $sqlDatabaseAdapterNamespace = "Microsoft.SQLAdapter.Admin"
            $sqlLocation = "$azsLocation"
            $sqlQuotaName = "sqldefault"
            $sqlQuotaId = '/subscriptions/{0}/providers/{1}/locations/{2}/quotas/{3}' -f $subID, $sqlDatabaseAdapterNamespace, $sqlLocation, $sqlQuotaName
            $quotaIDs += $sqlQuotaId
        }
        if (!$skipAppService) {
            $appServiceNamespace = "Microsoft.Web.Admin"
            $appServiceLocation = "$azsLocation"
            $appServiceQuotaName = "Default"
            $appServiceQuotaId = '/subscriptions/{0}/providers/{1}/locations/{2}/quotas/{3}' -f $subID, $appServiceNamespace, $appServiceLocation, $appServiceQuotaName
            $quotaIDs += $appServiceQuotaId
        }
        # Create the Plan and Offer
        New-AzureRmResourceGroup -Name $RGName -Location $azsLocation
        $plan = New-AzsPlan -Name $PlanName -DisplayName $PlanName -Location $azsLocation -ResourceGroupName $RGName -QuotaIds $QuotaIDs
        New-AzsOffer -Name $OfferName -DisplayName $OfferName -State Private -BasePlanIds $plan.Id -ResourceGroupName $RGName -Location $azsLocation
        Set-AzsOffer -Name $OfferName -DisplayName $OfferName -State Public -BasePlanIds $plan.Id -ResourceGroupName $RGName -Location $azsLocation

        # Create a new subscription for that offer, for the currently logged in user
        $Offer = Get-AzsManagedOffer | Where-Object name -eq "BaseOffer"
        $subUserName = (Get-AzureRmContext).Account.Id
        New-AzsUserSubscription -Owner $subUserName -OfferId $Offer.Id -DisplayName "ASDK Subscription"

        # Log the user out of the "AzureStackAdmin" environment
        Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
        Clear-AzureRmContext -Scope CurrentUser -Force

        # Log the user into the "AzureStackUser" environment
        Add-AzureRMEnvironment -Name "AzureStackUser" -ArmEndpoint "https://management.local.azurestack.external"
        Add-AzureRmAccount -EnvironmentName "AzureStackUser" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

        # Register all the RPs for that user
        foreach ($s in (Get-AzureRmSubscription)) {
            Select-AzureRmSubscription -SubscriptionId $s.SubscriptionId | Out-Null
            Write-Progress $($s.SubscriptionId + " : " + $s.SubscriptionName)
            Get-AzureRmResourceProvider -ListAvailable | Register-AzureRmResourceProvider
        }
        StageComplete -progressStage $progressStage
    }
    catch {
        StageFailed -progressStage $progressStage
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progressCheck -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configurator Stage: $progressStage previously completed successfully"
}

#### CUSTOMIZE ASDK HOST #####################################################################################################################################
##############################################################################################################################################################

$progressStage = "InstallHostApps"
$progressCheck = CheckProgress -progressStage $progressStage
$scriptStep = $progressStage.ToUpper()

if ($progressCheck -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configurator Stage: $progressStage previously completed successfully"
}
elseif (!$skipCustomizeHost -and ($progressCheck -ne "Complete")) {
    # We first need to check if in a previous run, this section was skipped, but now, the user wants to add this, so we need to reset the progress.
    if ($progressCheck -eq "Skipped") {
        StageReset
    }
    if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
        try {
            if ($deploymentMode -eq "Online") {
                # Install useful ASDK Host Apps via Chocolatey
                Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                # Enable Choco Global Confirmation
                Write-CustomVerbose -Message "Enabling global confirmation to streamline installs"
                choco feature enable -n allowGlobalConfirmation
                # Add Choco to default path
                $testEnvPath = $Env:path
                if (!($testEnvPath -contains "$env:ProgramData\chocolatey\bin")) {
                    $Env:path = $env:path + ";$env:ProgramData\chocolatey\bin"
                }
                # Visual Studio Code
                Write-CustomVerbose -Message "Installing VS Code with Chocolatey"
                choco install vscode
                # Putty
                Write-CustomVerbose -Message "Installing Putty with Chocolatey"
                choco install putty.install
                # WinSCP
                Write-CustomVerbose -Message "Installing WinSCP with Chocolatey"
                choco install winscp.install
                # Chrome
                Write-CustomVerbose -Message "Installing Chrome with Chocolatey"
                choco install googlechrome
                # WinDirStat
                Write-CustomVerbose -Message "Installing WinDirStat with Chocolatey"
                choco install windirstat
                # Python
                Write-CustomVerbose -Message "Installing latest version of Python for Windows"
                choco install python3 --params "/InstallDir:C:\Python"
                refreshenv
                # Set Environment Variables
                [System.Environment]::SetEnvironmentVariable("PATH", "$env:Path;C:\Python;C:\Python\Scripts", "Machine")
                [System.Environment]::SetEnvironmentVariable("PATH", "$env:Path;C:\Python;C:\Python\Scripts", "User")
                # Set Current Session Variable
                $testEnvPath = $Env:path
                if (!($testEnvPath -contains "C:\Python;C:\Python\Scripts")) {
                    $Env:path = $env:path + ";C:\Python;C:\Python\Scripts"
                }
                Write-CustomVerbose -Message "Upgrading pip"
                python -m ensurepip --default-pip
                python -m pip install -U pip
                refreshenv
                Write-CustomVerbose -Message "Installing certifi"
                pip install certifi
                refreshenv
                # Azure CLI
                Write-CustomVerbose -Message "Installing latest version of Azure CLI with Chocolatey"
                choco install azure-cli
                refreshenv
            }
            elseif ($deploymentMode -ne "Online") {
                $hostAppsPath = "$ASDKpath\hostapps"
                Set-Location $hostAppsPath
                # Visual Studio Code
                HostAppInstaller -localInstallPath "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe" -appName VSCode `
                    -arguments '/SP /VERYSILENT /SUPPRESSMSGBOXES /LOG="vscode.log" /NOCANCEL /NORESTART /MERGETASKS=!runcode,addtopath,associatewithfiles,addcontextmenufolders,addcontextmenufiles,quicklaunchicon,desktopicon' `
                    -fileName "vscode.exe" -appType "EXE"
                # Putty
                HostAppInstaller -localInstallPath "$env:ProgramFiles\PuTTY\putty.exe" -appName Putty `
                    -arguments '/i putty.msi /qn /l*v "putty.log" ADDLOCAL=FilesFeature,DesktopFeature,PathFeature,PPKFeature' -fileName "putty.msi" -appType "MSI"
                # WinSCP
                HostAppInstaller -localInstallPath "$env:ProgramFiles\WinSCP\WinSCP.exe" -appName WinSCP `
                    -arguments '/SP /VERYSILENT /SUPPRESSMSGBOXES /LOG="WinSCP.log" /NOCANCEL /NORESTART' -fileName "WinSCP.exe" -appType "EXE"
                # Chrome
                HostAppInstaller -localInstallPath "${Env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe" -appName "Google Chrome" `
                    -arguments '/i googlechrome.msi /qn /l*v "googlechrome.log"' -fileName "googlechrome.msi" -appType "MSI"
                # WinDirStat
                HostAppInstaller -localInstallPath "${Env:ProgramFiles(x86)}\WinDirStat\WinDirStat.exe" -appName WinDirStat `
                    -arguments '/S /VERYSILENT /SUPPRESSMSGBOXES /LOG="WinDirStat.log" /NOCANCEL /NORESTART' `
                    -fileName "windirstat.exe" -appType "EXE"
                # Python
                HostAppInstaller -localInstallPath "C:\Python\Python.exe" -appName Python `
                    -arguments '/quiet InstallAllUsers=1 PrependPath=1 TargetDir=c:\Python' -fileName "python3.exe" -appType "EXE"
                # Set Environment Variables
                [System.Environment]::SetEnvironmentVariable("PATH", "$env:Path;C:\Python;C:\Python\Scripts", "Machine")
                [System.Environment]::SetEnvironmentVariable("PATH", "$env:Path;C:\Python;C:\Python\Scripts", "User")
                # Set Current Session Variable
                $testEnvPath = $Env:path
                if (!($testEnvPath -contains "C:\Python;C:\Python\Scripts")) {
                    $Env:path = $env:path + ";C:\Python;C:\Python\Scripts"
                }
                Write-CustomVerbose -Message "Upgrading pip"
                $pipWhl = (Get-ChildItem -Path .\* -Include "pip*.whl" -Force -Verbose -ErrorAction Stop).Name
                python -m pip install --no-index $pipWhl
                python -m ensurepip --default-pip
                Write-CustomVerbose -Message "Installing certifi"
                # pip install certifi
                $certifiWhl = (Get-ChildItem -Path .\* -Include "certifi*.whl" -Force -Verbose -ErrorAction Stop).Name
                pip install --no-index $certifiWhl
                # Azure CLI
                HostAppInstaller -localInstallPath "${Env:ProgramFiles(x86)}\Microsoft SDKs\Azure\CLI2\wbin" -appName "Azure CLI" `
                    -arguments '/i azurecli.msi /qn /norestart /l*v "azurecli.log"' -fileName "azurecli.msi" -appType "MSI"
            }
            # Configure Python & Azure CLI Certs
            Write-CustomVerbose -Message "Retrieving Azure Stack Root Authority certificate..." -Verbose
            $label = "AzureStackSelfSignedRootCert"
            $cert = Get-ChildItem Cert:\CurrentUser\Root | Where-Object Subject -eq "CN=$label" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($cert) {
                try {
                    New-Item -Path "$env:userprofile\desktop\Certs" -ItemType Directory -Force | Out-Null
                    $certFileName = "$env:computername" + "-CA.cer"
                    $certFilePath = "$env:userprofile\desktop\Certs\$certFileName"
                    Write-CustomVerbose -Message "Saving Azure Stack Root certificate in $certFilePath..." -Verbose
                    Export-Certificate -Cert $cert -FilePath $certFilePath -Force | Out-Null
                    Write-CustomVerbose -Message "Converting certificate to PEM format"
                    Set-Location "$env:userprofile\desktop\Certs"
                    $pemFileName = $certFileName -replace ".cer", ".pem"
                    certutil.exe -encode $certFileName $pemFileName
                    $pemFilePath = "$env:userprofile\desktop\Certs\$pemFileName"
                    $root = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $root.Import($pemFilePath)
                    Write-CustomVerbose -Message "Extracting required information from the cert file"
                    $md5Hash = (Get-FileHash -Path $pemFilePath -Algorithm MD5).Hash.ToLower()
                    $sha1Hash = (Get-FileHash -Path $pemFilePath -Algorithm SHA1).Hash.ToLower()
                    $sha256Hash = (Get-FileHash -Path $pemFilePath -Algorithm SHA256).Hash.ToLower()
                    $issuerEntry = [string]::Format("# Issuer: {0}", $root.Issuer)
                    $subjectEntry = [string]::Format("# Subject: {0}", $root.Subject)
                    $labelEntry = [string]::Format("# Label: {0}", $root.Subject.Split('=')[-1])
                    $serialEntry = [string]::Format("# Serial: {0}", $root.GetSerialNumberString().ToLower())
                    $md5Entry = [string]::Format("# MD5 Fingerprint: {0}", $md5Hash)
                    $sha1Entry = [string]::Format("# SHA1 Finterprint: {0}", $sha1Hash)
                    $sha256Entry = [string]::Format("# SHA256 Fingerprint: {0}", $sha256Hash)
                    $certText = (Get-Content -Path $pemFilePath -Raw).ToString().Replace("`r`n", "`n")
                    $rootCertEntry = "`n" + $issuerEntry + "`n" + $subjectEntry + "`n" + $labelEntry + "`n" + `
                        $serialEntry + "`n" + $md5Entry + "`n" + $sha1Entry + "`n" + $sha256Entry + "`n" + $certText
                    Write-CustomVerbose -Message "Adding the certificate content to Python Cert store"
                    Add-Content "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\CLI2\Lib\site-packages\certifi\cacert.pem" $rootCertEntry -Force -ErrorAction SilentlyContinue
                    $certifiPath = python -c "import certifi; print(certifi.where())"
                    Add-Content "$certifiPath" $rootCertEntry
                    Write-CustomVerbose -Message "Python Cert store was updated for allowing the Azure Stack CA root certificate"
                    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User") 
                    # Set up the VM alias Endpoint for Azure CLI & Python
                    if ($deploymentMode -eq "Online") {
                        $vmAliasEndpoint = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/packages/Aliases/aliases.json"
                    }
                    elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                        $item = Get-ChildItem -Path "$ASDKpath\images" -Recurse -Include ("aliases.json") -ErrorAction Stop
                        $itemName = $item.Name
                        $itemFullPath = $item.FullName
                        $uploadItemAttempt = 1
                        while (!$(Get-AzureStorageBlob -Container $asdkOfflineContainerName -Blob $itemName -Context $asdkOfflineStorageAccount.Context -ErrorAction SilentlyContinue) -and ($uploadItemAttempt -le 3)) {
                            try {
                                # Log back into Azure Stack to ensure login hasn't timed out
                                Write-CustomVerbose -Message "$itemName not found. Upload Attempt: $uploadItemAttempt"
                                $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
                                Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
                                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                                Set-AzureStorageBlobContent -File "$itemFullPath" -Container $asdkOfflineContainerName -Blob $itemName -Context $asdkOfflineStorageAccount.Context -ErrorAction Stop | Out-Null
                            }
                            catch {
                                Write-CustomVerbose -Message "Upload failed."
                                Write-CustomVerbose -Message "$_.Exception.Message"
                                $uploadItemAttempt++
                            }
                        }
                        $vmAliasEndpoint = ('{0}{1}/{2}' -f $asdkOfflineStorageAccount.PrimaryEndpoints.Blob, $asdkOfflineContainerName, $itemName) -replace "https", "http"
                    }
                    Write-CustomVerbose -Message "Virtual Machine Alias Endpoint for your ASDK = $vmAliasEndpoint"
                    Write-CustomVerbose -Message "Configuring your Azure CLI environment on the ASDK host, for Admin and User"
                    # Register AZ CLI environment for Admin
                    Write-CustomVerbose -Message "Configuring for AzureStackAdmin"
                    az cloud register -n AzureStackAdmin --endpoint-resource-manager "https://adminmanagement.local.azurestack.external" --suffix-storage-endpoint "local.azurestack.external" --suffix-keyvault-dns ".adminvault.local.azurestack.external" --endpoint-vm-image-alias-doc $vmAliasEndpoint
                    Write-CustomVerbose -Message "Configuring for AzureStackUser"
                    az cloud register -n AzureStackUser --endpoint-resource-manager "https://management.local.azurestack.external" --suffix-storage-endpoint "local.azurestack.external" --suffix-keyvault-dns ".vault.local.azurestack.external" --endpoint-vm-image-alias-doc $vmAliasEndpoint
                    Write-CustomVerbose -Message "Setting Azure CLI active environment to AzureStackAdmin"
                    # Set the active environment
                    az cloud set -n AzureStackAdmin
                    Write-CustomVerbose -Message "Updating profile for Azure CLI"
                    # Update the profile
                    az cloud update --profile 2018-03-01-hybrid
                }
                catch {
                    Write-CustomVerbose -Message "Something went wrong configuring Azure CLI and Python. Please follow the Azure Stack docs to configure for your ASDK"
                }
            }
            else {
                Write-CustomVerbose -Message "Certificate has not been retrieved - Azure CLI and Python configuration cannot continue and will be skipped."
            }
            StageComplete -progressStage $progressStage
        }
        catch {
            StageFailed -progressStage $progressStage
            Set-Location $ScriptLocation
            return
        }
    }
}
elseif ($skipCustomizeHost -and ($progressCheck -ne "Complete")) {
    StageSkipped -progressStage $progressStage
}

#### GENERATE OUTPUT #########################################################################################################################################
##############################################################################################################################################################

$progressStage = "CreateOutput"
$progressCheck = CheckProgress -progressStage $progressStage
$scriptStep = $progressStage.ToUpper()
try {
    ### Create Output Document ###
    $txtPath = "$downloadPath\ConfigASDKOutput.txt"
    Remove-Item -Path $txtPath -Confirm:$false -Force -ErrorAction SilentlyContinue -Verbose
    New-Item "$txtPath" -ItemType file -Force
    Write-Output "`r`nThis document contains useful information about your deployment" > $txtPath
    Write-Output "`r`nYour chosen authentication type was: $authenticationType" >> $txtPath
    if ($authenticationType.ToString() -like "ADFS") {
        Write-Output "Your ASDK admin account and the Azure Stack portal use the following account for login: $azureStackAdminUsername" >> $txtPath
    }
    elseif ($authenticationType.ToString() -like "AzureAD") {
        Write-Output "Use the following username to login to your ASDK host: $azureStackAdminUsername" >> $txtPath
        Write-Output "Use the following username to login to the Azure Stack portal: $azureAdUsername" >> $txtPath
    }
    Write-Output "`r`nASDK has been registered to Azure: $($registerASDK.IsPresent)" >> $txtPath
    if ($registerASDK) {
        Write-Output "Your Azure Stack was registered to this Azure subscription: $azureRegSubId" >> $txtPath
    }
    if ($useAzureCredsForRegistration -and $registerASDK) {
        Write-Output "Your Azure Stack was registered to Azure with the following username: $azureAdUsername" >> $txtPath
    }
    elseif ($authenticationType.ToString() -like "AzureAd" -and !$useAzureCredsForRegistration -and $registerASDK) {
        Write-Output "Your Azure Stack was registered to Azure with the following username: $azureRegUsername" >> $txtPath
    }
    if ($authenticationType.ToString() -like "ADFS" -and $registerASDK) {
        Write-Output "Your Azure Stack was registered to Azure with the following username: $azureRegUsername" >> $txtPath
    }
    Write-Output "`r`nThe Azure Stack PowerShell tools have been downloaded to: $modulePath" >> $txtPath
    Write-Output "All other downloads have been stored here: $ASDKpath" >> $txtPath
    Write-Output "`r`nSQL & MySQL Resource Provider Information:" >> $txtPath
    if (!$skipMySQL) {
        Write-Output "MySQL Resource Provider VM Credentials = mysqlrpadmin | $VMpwd" >> $txtPath
        Write-Output "MySQL Database Hosting VM FQDN: $mySqlFqdn" >> $txtPath
        Write-Output "MySQL Database Hosting VM Credentials = mysqladmin | $VMpwd" >> $txtPath
    }
    if (!$skipMSSQL) {
        Write-Output "SQL Server Resource Provider VM Credentials = sqlrpadmin | $VMpwd" >> $txtPath
        Write-Output "SQL Server Database Hosting VM FQDN: $sqlFqdn" >> $txtPath
        Write-Output "SQL Server Database Hosting VM Credentials = sqladmin | $VMpwd" >> $txtPath
    }
    if (!$skipAppService) {
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        $fileServerFqdn = (Get-AzureRmPublicIpAddress -Name "fileserver_ip" -ResourceGroupName "appservice-fileshare").DnsSettings.Fqdn
        $sqlAppServerFqdn = (Get-AzureRmPublicIpAddress -Name "sqlapp_ip" -ResourceGroupName "appservice-sql").DnsSettings.Fqdn
        $identityApplicationID = Get-Content -Path "$downloadPath\ApplicationIDBackup.txt" -ErrorAction SilentlyContinue
        $AppServicePath = "$ASDKpath\appservice"
        Write-Output "`r`nApp Service Resource Provider Information:" >> $txtPath
        Write-Output "App Service File Server VM FQDN: $fileServerFqdn" >> $txtPath
        Write-Output "App Service File Server VM Credentials = fileshareowner or fileshareuser | $VMpwd" >> $txtPath
        Write-Output "App Service SQL Server VM FQDN: $sqlAppServerFqdn" >> $txtPath
        Write-Output "App Service SQL Server VM Credentials = sqladmin | $VMpwd" >> $txtPath
        Write-Output "App Service SQL Server SA Credentials = sa | $VMpwd" >> $txtPath
        Write-Output "App Service Application Id: $identityApplicationID" >> $txtPath
        Write-Output "`r`nOther useful information for reference:" >> $txtPath
        Write-Output "`r`nAzure Stack Admin ARM Endpoint: adminmanagement.local.azurestack.external" >> $txtPath
        Write-Output "Azure Stack Tenant ARM Endpoint: management.local.azurestack.external" >> $txtPath
        Write-Output "Azure Directory Tenant Name: $azureDirectoryTenantName" >> $txtPath
        Write-Output "File Share UNC Path: \\appservicefileshare.local.cloudapp.azurestack.external\websites" >> $txtPath
        Write-Output "File Share Owner: fileshareowner" >> $txtPath
        Write-Output "File Share Owner Password: $VMpwd" >> $txtPath
        Write-Output "File Share User: fileshareuser" >> $txtPath
        Write-Output "File Share User Password: $VMpwd" >> $txtPath
        Write-Output "Identity Application ID: $identityApplicationID" >> $txtPath
        Write-Output "Identity Application Certificate file (*.pfx): $AppServicePath\sso.appservice.local.azurestack.external.pfx" >> $txtPath
        Write-Output "Identity Application Certificate (*.pfx) password: $VMpwd" >> $txtPath
        Write-Output "Azure Resource Manager (ARM) root certificate file (*.cer): $AppServicePath\AzureStackCertificationAuthority.cer" >> $txtPath
        Write-Output "App Service default SSL certificate file (*.pfx): $AppServicePath\_.appservice.local.AzureStack.external.pfx" >> $txtPath
        Write-Output "App Service default SSL certificate (*.pfx) password: $VMpwd" >> $txtPath
        Write-Output "App Service API SSL certificate file (*.pfx): $AppServicePath\api.appservice.local.AzureStack.external.pfx" >> $txtPath
        Write-Output "App Service API SSL certificate (*.pfx) password: $VMpwd" >> $txtPath
        Write-Output "App Service Publisher SSL certificate file (*.pfx): $AppServicePath\ftp.appservice.local.AzureStack.external.pfx" >> $txtPath
        Write-Output "App Service Publisher SSL certificate (*.pfx) password: $VMpwd" >> $txtPath
        Write-Output "SQL Server Name: $sqlAppServerFqdn" >> $txtPath
        Write-Output "SQL sysadmin login: sa" >> $txtPath
        Write-Output "SQL sysadmin password: $VMpwd" >> $txtPath
        Write-Output "Worker Role Virtual Machine(s) Admin: workeradmin" >> $txtPath
        Write-Output "Worker Role Virtual Machine(s) Password: $VMpwd" >> $txtPath
        Write-Output "Confirm Password: $VMpwd" >> $txtPath
        Write-Output "Other Roles Virtual Machine(s) Admin: roleadmin" >> $txtPath
        Write-Output "Other Roles Virtual Machine(s) Password: $VMpwd" >> $txtPath
        Write-Output "Confirm Password: $VMpwd" >> $txtPath
    }
    StageComplete -progressStage $progressStage
}
catch {
    StageFailed -progressStage $progressStage
    Set-Location $ScriptLocation
    return
}

#### FINAL STEPS #############################################################################################################################################
##############################################################################################################################################################

### Clean Up ASDK Folder ###
$scriptStep = "CLEANUP"

# Need to check whole Progress database table for Incomplete or Failed status.
$finalStatusCheck = Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" -TableName "$tableName" -ErrorAction Stop | Out-String
if (($finalStatusCheck -contains "Incomplete") -or ($finalStatusCheck -contains "Failed")) {
    $scriptSuccess = $false
}
else {
    $scriptSuccess = $true
}

if ($scriptSuccess) {
    Write-CustomVerbose -Message "Congratulations - all steps completed successfully:`r`n"
    Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" -TableName "$tableName" -ErrorAction Stop

    if ([bool](Get-ChildItem -Path $downloadPath\* -Include "*.txt", "*.ps1" -ErrorAction SilentlyContinue -Verbose)) {
        # Move log files and cleanup files to Completed folder - first check for 'Completed' folder, and create if not existing
        if (!$([System.IO.Directory]::Exists("$downloadPath\Completed"))) {
            New-Item -Path "$downloadPath\Completed" -ItemType Directory -Force -ErrorAction SilentlyContinue -Verbose | Out-Null
        }
        # Then create the folder that corresponds to this completed run using the time the script was started as the folder name
        $completedPath = "$downloadPath\Completed\$runTime"
        New-Item -Path "$completedPath" -ItemType Directory -Force -ErrorAction SilentlyContinue -Verbose | Out-Null
        # Then move the files to this folder
        Get-ChildItem -Path "$downloadPath\*" -Include "*.txt", "*.ps1" -ErrorAction SilentlyContinue -Verbose | ForEach-Object { Copy-Item -Path $_ -Destination "$completedPath" -Force -ErrorAction SilentlyContinue -Verbose }
    }

    Write-CustomVerbose -Message "Retaining App Service Certs for potential App Service updates in the future"
    if (!$([System.IO.Directory]::Exists("$completedPath\AppServiceCerts"))) {
        New-Item -Path "$completedPath\AppServiceCerts" -ItemType Directory -Force -ErrorAction SilentlyContinue -Verbose | Out-Null
    }
    if ([bool](Get-ChildItem -Path "$AppServicePath\*" -Include "*.cer", "*.pfx" -ErrorAction SilentlyContinue -Verbose)) {
        Get-ChildItem -Path "$AppServicePath\*" -Include "*.cer", "*.pfx" -ErrorAction SilentlyContinue -Verbose | ForEach-Object { Copy-Item -Path $_ "$completedPath\AppServiceCerts" -Force -ErrorAction SilentlyContinue -Verbose }
    }

    Write-CustomVerbose -Message "Cleaning up ASDK Folder"
    # Will attempt multiple times as sometimes it fails
    $i = 1
    While ($i -le 5) {
        Write-CustomVerbose -Message "Cleanup Attempt: $i"
        if ($([System.IO.Directory]::Exists("$ASDKpath"))) {
            Remove-Item "$ASDKpath\*" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue -Verbose
            Remove-Item -Path "$ASDKpath" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
        }
        if ($([System.IO.Directory]::Exists("$AppServicePath"))) {
            Remove-Item -Path "$AppServicePath\*" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue -Verbose
            Remove-Item "$AppServicePath" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue -Verbose
        }
        $csvPath = "C:\ClusterStorage\Volume1\images"
        if ($([System.IO.Directory]::Exists("$csvPath"))) {
            Remove-Item -Path "$csvPath\*" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue -Verbose
            Remove-Item "$csvPath" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue -Verbose
        }
        $i++
    }
    Write-CustomVerbose -Message "Cleaning up Resource Group used for Image Upload"
    $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
    Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
    Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
    $asdkImagesRGName = "azurestack-images"
    Get-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -ErrorAction SilentlyContinue | Remove-AzureRmResourceGroup -Force -ErrorAction SilentlyContinue

    # Create desktop icons
    $shortcut_name = "Azure Stack Admin Portal" 
    $shortcut_target = "https://adminportal.local.azurestack.external" 
    $sh = new-object -com "WScript.Shell" 
    $p = $sh.SpecialFolders.item("AllUsersDesktop") 
    $lnk = $sh.CreateShortcut( (join-path $p $shortcut_name) + ".lnk" ) 
    $lnk.TargetPath = $shortcut_target 
    $lnk.IconLocation = "$env:WINDIR\system32\imageres.dll,220"
    $lnk.Save()
    
    $shortcut_name = "Azure Stack User Portal" 
    $shortcut_target = "https://portal.local.azurestack.external" 
    $sh = new-object -com "WScript.Shell" 
    $p = $sh.SpecialFolders.item("AllUsersDesktop") 
    $lnk = $sh.CreateShortcut( (join-path $p $shortcut_name) + ".lnk" ) 
    $lnk.TargetPath = $shortcut_target 
    $lnk.IconLocation = "$env:WINDIR\system32\imageres.dll,220"
    $lnk.Save()
    
    # Increment run counter to track successful run
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {Invoke-WebRequest "http://bit.ly/asdksuccessrun" -UseBasicParsing -DisableKeepAlive | Out-Null } catch {$_.Exception.Response.StatusCode.Value__}

    # Final Cleanup
    while (Get-ChildItem -Path "$downloadPath\*" -Include "*.txt" -ErrorAction SilentlyContinue -Verbose) {
        Get-ChildItem -Path "$downloadPath\*" -Include "*.txt" -ErrorAction SilentlyContinue -Verbose | Remove-Item -Force -Verbose -ErrorAction SilentlyContinue
    }

    # Take a copy of the log file at this point
    Write-CustomVerbose -Message "Copying log file for future reference"
    Copy-Item "$fullLogPath" -Destination "$completedPath" -Force -ErrorAction SilentlyContinue -Verbose
}
else {
    Write-CustomVerbose -Message "Script hasn't completed successfully"
    Write-CustomVerbose -Message "Please rerun the script to complete the process"
    Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" -TableName "$tableName" -ErrorAction Stop
}

Write-CustomVerbose -Message "Setting Execution Policy back to RemoteSigned"
Set-ExecutionPolicy RemoteSigned -Confirm:$false -Force | Out-Null

# Calculate completion time
$endTime = Get-Date -Format g
$sw.Stop()
$Hrs = $sw.Elapsed.Hours
$Mins = $sw.Elapsed.Minutes
$Secs = $sw.Elapsed.Seconds
$difference = '{0:00}h:{1:00}m:{2:00}s' -f $Hrs, $Mins, $Secs

Set-Location $ScriptLocation -ErrorAction SilentlyContinue
Write-Host "ASDK Configurator setup completed successfully, taking $difference." -ErrorAction SilentlyContinue
Write-Host "You started the ASDK Configurator deployment at $startTime." -ErrorAction SilentlyContinue
Write-Host "ASDK Configurator deployment completed at $endTime." -ErrorAction SilentlyContinue
Stop-Transcript -ErrorAction SilentlyContinue