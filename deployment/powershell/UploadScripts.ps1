[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ConfigASDKProgressLogPath,

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
    [String] $ScriptLocation
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

$progress = Import-Csv -Path $ConfigASDKProgressLogPath
$RowIndex = [array]::IndexOf($progress.Stage, "$progressName")

if ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}
elseif ((($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) -and (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed"))) {
    try {
        # Firstly create the appropriate RG, storage account and container
        # Scan the $asdkPath\scripts folder and retrieve both files, add to an array, then upload to the storage account
        # Save URI of the container to a variable to use later
        $asdkOfflineRGName = "azurestack-offline"
        $asdkOfflineStorageAccountName = "offlinestor"
        $asdkOfflineContainerName = "offlinecontainer"
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
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
                    Write-Verbose -Message "$itemName not found. Upload Attempt: $uploadItemAttempt"
                    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    Set-AzureStorageBlobContent -File "$itemFullPath" -Container $asdkOfflineContainerName -Blob "$itemName" -Context $asdkOfflineStorageAccount.Context -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-Verbose -Message "Upload failed."
                    Write-Verbose -Message "$_.Exception.Message"
                    $uploadItemAttempt++
                }
            }
        }
        Write-Verbose "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
        $progress = Import-Csv -Path $ConfigASDKProgressLogPath
        $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
        $progress = Import-Csv -Path $ConfigASDKProgressLogPath
        $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        Set-Location $ScriptLocation
        throw $_.Exception.Message
        return
    }
}
elseif ($deploymentMode -eq "Online") {
    Write-Verbose -Message "This is not an offline deployent, skipping step`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress = Import-Csv -Path $ConfigASDKProgressLogPath
    $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}
Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue