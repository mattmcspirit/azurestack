﻿[CmdletBinding()]
param (
    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $azsLocation,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

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

$logFolder = "UploadScripts"
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

if ($progressCheck -eq "Complete") {
    Write-Host "ASDK Configurator Stage: $progressStage previously completed successfully"
}
elseif ((($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) -and (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed"))) {
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

        # Firstly create the appropriate RG, storage account and container
        # Scan the $asdkPath\scripts folder and retrieve both files, add to an array, then upload to the storage account
        # Save URI of the container to a variable to use later
        $asdkOfflineRGName = "azurestack-offline"
        $asdkOfflineStorageAccountName = "offlinestor"
        $asdkOfflineContainerName = "offlinecontainer"
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        if (-not (Get-AzureRmResourceGroup -Name $asdkOfflineRGName -Location $azsLocation -ErrorAction SilentlyContinue)) {
            New-AzureRmResourceGroup -Name $asdkOfflineRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
        }
        # Test/Create Storage
        $asdkOfflineStorageAccount = Get-AzureRmStorageAccount -Name $asdkOfflineStorageAccountName -ResourceGroupName $asdkOfflineRGName -ErrorAction SilentlyContinue
        if (-not ($asdkOfflineStorageAccount)) {
            $asdkOfflineStorageAccount = New-AzureRmStorageAccount -Name $asdkOfflineStorageAccountName -Location $azsLocation -ResourceGroupName $asdkOfflineRGName -Type Standard_LRS -ErrorAction Stop
        }
        Set-AzureRmCurrentStorageAccount -StorageAccountName $asdkOfflineStorageAccountName -ResourceGroupName $asdkOfflineRGName
        # Test/Create Container
        $asdkOfflineContainer = Get-AzureStorageContainer -Name $asdkOfflineContainerName -ErrorAction SilentlyContinue
        if (-not ($asdkOfflineContainer)) {
            $asdkOfflineContainer = New-AzureStorageContainer -Name $asdkOfflineContainerName -Permission Blob -Context $asdkOfflineStorageAccount.Context -ErrorAction Stop
        }
        $offlineArray = @()
        $offlineArray.Clear()
        $offlineArray = Get-ChildItem -Path "$ASDKpath\scripts" -Recurse -Include ("*.sh", "*.cr.zip", "*FileServer.ps1") -ErrorAction Stop
        $offlineArray += Get-ChildItem -Path "$ASDKpath\binaries" -Recurse -Include "*.deb" -ErrorAction Stop
        foreach ($item in $offlineArray) {
            $itemName = $item.Name
            $itemFullPath = $item.FullName
            $uploadItemAttempt = 1
            while (!$(Get-AzureStorageBlob -Container $asdkOfflineContainerName -Blob $itemName -Context $asdkOfflineStorageAccount.Context -ErrorAction SilentlyContinue) -and ($uploadItemAttempt -le 3)) {
                try {
                    # Log back into Azure Stack to ensure login hasn't timed out
                    Write-Host "$itemName not found. Upload Attempt: $uploadItemAttempt"
                    Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    Set-AzureStorageBlobContent -File "$itemFullPath" -Container $asdkOfflineContainerName -Blob "$itemName" -Context $asdkOfflineStorageAccount.Context -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-Host "Upload failed."
                    Write-Host "$_.Exception.Message"
                    $uploadItemAttempt++
                }
            }
        }
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
elseif ($deploymentMode -eq "Online") {
    Write-Host "This is not an offline deployment, skipping step`r`n"
    # Update the ConfigASDK database with skip status
    $progressStage = $progressName
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue