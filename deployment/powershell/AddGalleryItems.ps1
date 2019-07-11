[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $customDomainSuffix,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [Parameter(Mandatory = $true)]
    [ValidateSet("MySQL", "SQLServer")]
    [String] $azpkg,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

    [Parameter(Mandatory = $true)]
    [String] $branch,

    [Parameter(Mandatory = $true)]
    [String] $sqlServerInstance,

    [Parameter(Mandatory = $true)]
    [String] $databaseName,

    [Parameter(Mandatory = $true)]
    [String] $tableName
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

$logFolder = "$($azpkg)GalleryItem"
$logName = $logFolder
$progressName = $logFolder

### SET LOG LOCATION ###
$logDate = Get-Date -Format FileDate
New-Item -ItemType Directory -Path "$ScriptLocation\Logs\$logDate\$logFolder" -Force | Out-Null
$logPath = "$ScriptLocation\Logs\$logDate\$logFolder"
$azCopyLogPath = "$logPath\AzCopy$logDate.log"
$journalPath = "$logPath\Journal"
New-Item -ItemType Directory -Path "$journalPath" -Force | Out-Null

### START LOGGING ###
$runTime = $(Get-Date).ToString("MMdd-HHmmss")
$fullLogPath = "$logPath\$($logName)$runTime.txt"
Start-Transcript -Path "$fullLogPath" -Append
Write-Host "Creating log folder"
Write-Host "Log folder has been created at $logPath"
Write-Host "Log file stored at $fullLogPath"
Write-Host "Starting logging"
Write-Host "Log started at $runTime"

$progressStage = $progressName
$progressCheck = CheckProgress -progressStage $progressStage

if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
    try {
        if ($progressCheck -eq "Failed") {
            # Update the ConfigASDK database back to incomplete status if previously failed
            StageReset -progressStage $progressStage
            $progressCheck = CheckProgress -progressStage $progressStage
            Write-Host "Clearing up any failed attempts to deploy the gallery items"
            Get-AzsGalleryItem | Where-Object { $_.Name -like "*ASDK*" } | Remove-AzsGalleryItem -Force -ErrorAction SilentlyContinue
        }
        Write-Host "Clearing previous Azure/Azure Stack logins"
        Get-AzureRmContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzureRmAccount | Out-Null
        Clear-AzureRmContext -Scope CurrentUser -Force
        Disable-AzureRMContextAutosave -Scope CurrentUser

        <#Write-Host "Importing Azure.Storage and AzureRM.Storage modules"
        Import-Module -Name Azure.Storage -RequiredVersion 4.5.0
        Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4
        #>

        ### Login to Azure Stack, then confirm if the MySQL Gallery Item is already present ###
        Write-Host "Logging into Azure Stack"
        $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        # Set Storage Variables
        Write-Host "Setting storage variables for resource group, storage account and container"
        $asdkImagesRGName = "azurestack-adminimages"
        $asdkImagesStorageAccountName = "asdkimagesstor"
        $asdkImagesContainerName = "asdkimagescontainer"
        $azsLocation = (Get-AzureRmLocation).DisplayName
        Write-Host "Resource Group = $asdkImagesRGName, Storage Account = $asdkImagesStorageAccountName and Container = $asdkImagesContainerName"
        Write-Host "Setting AZPKG Package Name"
        if ($azpkg -eq "MySQL") {
            $azpkgPackageName = "ASDKConfigurator.MySQL.1.0.0"
        }
        elseif ($azpkg -eq "SQLServer") {
            $azpkgPackageName = "ASDKConfigurator.MSSQL.1.0.0"
            Start-Sleep -Seconds 30
        }
        Write-Host "AZPKG Package Name = $azpkgPackageName"
        Write-Host "Starting a 120 second delay to avoid conflict with image creation stage"
        # Delay to avoid conflict with Image creation.
        Start-Sleep -Seconds 120

        # Test/Create RG
        if (-not (Get-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -ErrorAction SilentlyContinue)) {
            Write-Host "Creating the resource group: $asdkImagesRGName"
            New-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop 
        }
        # Test/Create Storage
        $asdkStorageAccount = Get-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName -ErrorAction SilentlyContinue
        if (-not ($asdkStorageAccount)) {
            Write-Host "Creating the storage account: $asdkImagesStorageAccountName"
            $asdkStorageAccount = New-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -Location $azsLocation -ResourceGroupName $asdkImagesRGName -Type Standard_LRS -ErrorAction Stop
        }
        Write-Host "Setting the storage context"
        Set-AzureRmCurrentStorageAccount -StorageAccountName $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName | Out-Null
        # Test/Create Container
        $asdkContainer = Get-AzureStorageContainer -Name $asdkImagesContainerName -ErrorAction SilentlyContinue
        if (-not ($asdkContainer)) {
            Write-Host "Creating the storage container: $asdkImagesContainerName"
            $asdkContainer = New-AzureStorageContainer -Name $asdkImagesContainerName -Permission Blob -Context $asdkStorageAccount.Context -ErrorAction Stop
        }
        
        Write-Host "Checking for the $azpkg gallery item"
        if (Get-AzsGalleryItem | Where-Object { $_.Name -like "*$azpkgPackageName*" }) {
            Write-Host "Found a suitable $azpkg Gallery Item in your Azure Stack Marketplace. No need to upload a new one"
        }
        else {
            Write-Host "Didn't find this package: $azpkgPackageName"
            Write-Host "Will need to side load it in to the gallery"

            if ($deploymentMode -eq "Online") {
                Write-Host "Uploading $azpkgPackageName"
                if ($azpkg -eq "MySQL") {
                    $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/MySQL/ASDKConfigurator.MySQL.1.0.0.azpkg"
                }
                elseif ($azpkg -eq "SQLServer") {
                    $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/MSSQL/ASDKConfigurator.MSSQL.1.0.0.azpkg"
                }  
            }
            # If this isn't an online deployment, use the extracted zip file, and upload to a storage account
            elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                Write-Host "Uploading $azpkgPackageName to a storage account before it's side-loaded into the gallery"
                $azpkgPackageURL = AddOfflineAZPKG -azpkgPackageName $azpkgPackageName -azCopyLogPath $azCopyLogPath -Verbose
            }
            $Retries = 0
            # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
            while (!$(Get-AzsGalleryItem | Where-Object { $_.name -like "*$azpkgPackageName*" }) -and ($Retries++ -lt 20)) {
                try {
                    Write-Host "$azpkgPackageName doesn't exist in the gallery. Upload Attempt #$Retries"
                    Write-Host "Uploading $azpkgPackageName from $azpkgPackageURL"
                    Add-AzsGalleryItem -GalleryItemUri $azpkgPackageURL -Force -Confirm:$false -ErrorAction Stop
                }
                catch {
                    Write-Host "Upload wasn't successful. Waiting 5 seconds before retrying."
                    Write-Host "$_.Exception.Message"
                    if ("$_.Exception.Message" -like "*NoContent*") {
                        Write-Host "The error suggests that you cannot reach the AZPKG URL: $azpkgPackageURL - please confirm you can reach this URL otherwise this step will fail."
                    }
                    Start-Sleep -Seconds 5
                }
            }
            if (!$(Get-AzsGalleryItem | Where-Object { $_.name -like "*$azpkgPackageName*" }) -and ($Retries -ge 20)) {
                throw "Uploading gallery item failed after $Retries attempts. Exiting process."
                Set-Location $ScriptLocation
                return
            }
        }
        # Update the ConfigASDK database with successful completion
        $progressStage = $progressName
        StageComplete -progressStage $progressStage
    }
    catch {
        StageFailed -progressStage $progressStage
        Set-Location $ScriptLocation
        throw $_.Exception.Message
        return
    }
}
elseif ($progressCheck -eq "Complete") {
    Write-Host "ASDK Configurator Stage: $progressStage previously completed successfully"
}
Set-Location $ScriptLocation
$endTime = $(Get-Date).ToString("MMdd-HHmmss")
Write-Host "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue