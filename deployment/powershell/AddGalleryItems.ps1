[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $azsLocation,

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

### START LOGGING ###
$runTime = $(Get-Date).ToString("MMdd-HHmmss")
$fullLogPath = "$logPath\$($logName)$runTime.txt"
Start-Transcript -Path "$fullLogPath" -Append -IncludeInvocationHeader

$progressStage = $progressName
$progressCheck = CheckProgress -progressStage $progressStage

if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
    try {
        if ($progressCheck -eq "Failed") {
            # Update the ConfigASDK database back to incomplete status if previously failed
            StageReset -progressStage $progressStage
            $progressCheck = CheckProgress -progressStage $progressStage
        }

        Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
        Clear-AzureRmContext -Scope CurrentUser -Force
        Disable-AzureRMContextAutosave -Scope CurrentUser

        Import-Module -Name Azure.Storage -RequiredVersion 4.5.0 -Verbose
        Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4 -Verbose

        ### Login to Azure Stack, then confirm if the MySQL Gallery Item is already present ###
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        # Set Storage Variables
        $asdkImagesRGName = "azurestack-images"
        $asdkImagesStorageAccountName = "asdkimagesstor"
        $asdkImagesContainerName = "asdkimagescontainer"

        if ($azpkg -eq "MySQL") {
            $azpkgPackageName = "ASDK.MySQL.1.0.0"
        }
        elseif ($azpkg -eq "SQLServer") {
            $azpkgPackageName = "ASDK.MSSQL.1.0.0"
            Start-Sleep -Seconds 30
        }

        # Delay to avoid conflict with Image creation.
        Start-Sleep -Seconds 120

        # Test/Create RG
        if (-not (Get-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -ErrorAction SilentlyContinue)) { 
            New-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop 
        }
        # Test/Create Storage
        $asdkStorageAccount = Get-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName -ErrorAction SilentlyContinue
        if (-not ($asdkStorageAccount)) { 
            $asdkStorageAccount = New-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -Location $azsLocation -ResourceGroupName $asdkImagesRGName -Type Standard_LRS -ErrorAction Stop
        }
        Set-AzureRmCurrentStorageAccount -StorageAccountName $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName | Out-Null
        # Test/Create Container
        $asdkContainer = Get-AzureStorageContainer -Name $asdkImagesContainerName -ErrorAction SilentlyContinue
        if (-not ($asdkContainer)) { 
            $asdkContainer = New-AzureStorageContainer -Name $asdkImagesContainerName -Permission Blob -Context $asdkStorageAccount.Context -ErrorAction Stop
        }
        
        Write-Host "Checking for the $azpkg gallery item"
        if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$azpkgPackageName*"}) {
            Write-Host "Found a suitable $azpkg Gallery Item in your Azure Stack Marketplace. No need to upload a new one"
        }
        else {
            Write-Host "Didn't find this package: $azpkgPackageName"
            Write-Host "Will need to side load it in to the gallery"

            if ($deploymentMode -eq "Online") {
                Write-Host "Uploading $azpkgPackageName"
                if ($azpkg -eq "MySQL") {
                    $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/MySQL/ASDK.MySQL.1.0.0.azpkg"
                }
                elseif ($azpkg -eq "SQLServer") {
                    $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/MSSQL/ASDK.MSSQL.1.0.0.azpkg"
                }  
            }
            # If this isn't an online deployment, use the extracted zip file, and upload to a storage account
            elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                $azpkgPackageURL = AddOfflineAZPKG -azpkgPackageName $azpkgPackageName -Verbose
            }
            $Retries = 0
            # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
            while (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "*$azpkgPackageName*"}) -and ($Retries++ -lt 20)) {
                try {
                    Write-Host "$azpkgPackageName doesn't exist in the gallery. Upload Attempt #$Retries"
                    Write-Host "Uploading $azpkgPackageName from $azpkgPackageURL"
                    Add-AzsGalleryItem -GalleryItemUri $azpkgPackageURL -Force -Confirm:$false -ErrorAction Ignore
                }
                catch {
                    Write-Host "Upload wasn't successful. Waiting 5 seconds before retrying."
                    Write-Host "$_.Exception.Message"
                    Start-Sleep -Seconds 5
                }
            }
            if (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "*$azpkgPackageName*"}) -and ($Retries++ -ge 20)) {
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
Stop-Transcript -ErrorAction SilentlyContinue