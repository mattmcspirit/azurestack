[CmdletBinding()]
param (
    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [pscredential] $azsCreds,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [Parameter(Mandatory = $true)]
    [String] $azsPath,

    [Parameter(Mandatory = $true)]
    [String] $customDomainSuffix,
    
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
$azCopyLogPath = "$logPath\AzCopy$logDate.log"
$journalPath = "$logPath\Journal"
New-Item -ItemType Directory -Path "$journalPath" -Force | Out-Null

# Add AzCopy to $env:Path
$testEnvPath = $Env:path
if (!($testEnvPath -contains "C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\")) {
    $Env:path = $env:path + ";C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\"
}

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

if ($progressCheck -eq "Complete") {
    Write-Host "Azure Stack POC Configurator Stage: $progressStage previously completed successfully"
}
elseif (($deploymentMode -eq "Offline") -and (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed"))) {
    try {
        if ($progressCheck -eq "Failed") {
            # Update the AzSPoC database back to incomplete status if previously failed
            Write-Host "Resuming this previously failed step. Updating AzSPoC database."
            StageReset -progressStage $progressStage
            $progressCheck = CheckProgress -progressStage $progressStage
        }

        $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
        Add-AzEnvironment -Name "AzureStackAdmin" -ARMEndpoint "$ArmEndpoint" -ErrorAction Stop
        Add-AzEnvironment -Name "AzureStackUser" -ARMEndpoint "https://management.$customDomainSuffix" -ErrorAction Stop

        Write-Host "Clearing previous Azure logins for this session"
        Get-AzContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzContext -Force | Out-Null
        Clear-AzContext -Scope CurrentUser -Force
        Disable-AzContextAutosave -Scope CurrentUser

        # Firstly create the appropriate RG, storage account and container
        # Scan the $azsPath\scripts folder and retrieve both files, add to an array, then upload to the storage account
        # Save URI of the container to a variable to use later
        $azsOfflineRGName = "azurestack-offlinescripts"
        $azsOfflineStorageAccountName = "offlinestor"
        $azsOfflineContainerName = "offlinecontainer"
        
        # Log the user into the "AzureStackUser" environment
        Connect-AzAccount -Environment "AzureStackUser" -TenantId $tenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
        Write-Host "Selecting the *ADMIN OFFLINE SCRIPTS subscription"
        $sub = Get-AzSubscription | Where-Object { $_.Name -eq '*ADMIN OFFLINE SCRIPTS' }
        Set-AzContext -Subscription $sub.SubscriptionId -NAME $sub.Name -Force | Out-Null
        $subID = $sub.SubscriptionId
        Write-Host "Current subscription ID is: $subID"

        $azsLocation = (Get-AzLocation).DisplayName

        # Create Resource Group
        if (-not (Get-AzResourceGroup -Name $azsOfflineRGName -Location $azsLocation -ErrorAction SilentlyContinue)) {
            Write-Host "Creating resource group for storing scripts"
            New-AzResourceGroup -Name $azsOfflineRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
        }
        # Test/Create Storage
        $azsOfflineStorageAccount = Get-AzStorageAccount -Name $azsOfflineStorageAccountName -ResourceGroupName $azsOfflineRGName -ErrorAction SilentlyContinue
        $createAttempt = 1
        while (-not ($azsOfflineStorageAccount) -and ($createAttempt -lt 6)) {
            Write-Host "Creating storage account for storing scripts. This is attempt $createAttempt."
            $createAttempt++
            $azsOfflineStorageAccount = New-AzStorageAccount -Name $azsOfflineStorageAccountName -Location $azsLocation -ResourceGroupName $azsOfflineRGName -Type Standard_LRS -ErrorAction SilentlyContinue
            if ($azsOfflineStorageAccount) {
                Write-Host "Storage account has been created"
            }
            else {
                Write-Host "Storage account creation failed. Waiting 30 seconds before retry"
                Start-Sleep 30
            }
        }
        $azsOfflineStorageAccount = Get-AzStorageAccount -Name $azsOfflineStorageAccountName -ResourceGroupName $azsOfflineRGName -ErrorAction SilentlyContinue
        if (-not ($azsOfflineStorageAccount)) {
            Write-Host "Storage account creation failed after $createAttempt attempts."
            throw "Storage account creation failed after $createAttempt attempts. Check the logs and rerun the script."
        }
        Write-Host "Setting current storage account for storing scripts"
        Set-AzCurrentStorageAccount -StorageAccountName $azsOfflineStorageAccountName -ResourceGroupName $azsOfflineRGName
        
        # Test/Create Container
        $azsOfflineContainer = Get-AzStorageContainer -Name $azsOfflineContainerName -ErrorAction SilentlyContinue
        if (-not ($azsOfflineContainer)) {
            Write-Host "Creating storage container for storing scripts"
            $azsOfflineContainer = New-AzStorageContainer -Name $azsOfflineContainerName -Permission Blob -Context $azsOfflineStorageAccount.Context -ErrorAction Stop
            Write-Host "Storage container has been created"
        }
        Write-Host "Building array of scripts"
        $offlineArray = @()
        $offlineArray.Clear()
        $offlineArray = Get-ChildItem -Path "$azsPath\scripts" -Recurse -Include ("*.sh", "*.cr.zip", "*FileServer.ps1") -ErrorAction Stop
        $offlineArray += Get-ChildItem -Path "$azsPath\binaries" -Recurse -Include "*.deb" -ErrorAction Stop
        Write-Host "Beginning upload of scripts to storage account"
        foreach ($item in $offlineArray) {
            $itemName = $item.Name
            #$itemFullPath = $item.FullName
            $itemDirectory = $item.DirectoryName
            $uploadItemAttempt = 1
            $uploadFailed = $false
            while (!$(Get-AzStorageBlob -Container $azsOfflineContainerName -Blob $itemName -Context $azsOfflineStorageAccount.Context -ErrorAction SilentlyContinue) -and ($uploadItemAttempt -le 3)) {
                try {
                    # Log back into Azure Stack to ensure login hasn't timed out
                    Write-Host "$itemName not found. Upload Attempt: $uploadItemAttempt"
                    #Add-AzAccount -EnvironmentName "AzureStackUser" -TenantId $TenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
                    #$sub = Get-AzSubscription | Where-Object { $_.Name -eq '*ADMIN OFFLINE SCRIPTS' }
                    #$azureContext = Get-AzSubscription -SubscriptionID $sub.SubscriptionId | Select-AzSubscription
                    #$subID = $azureContext.Subscription.Id
                    #Write-Host "Current subscription ID is: $subID"
                    #Set-AzureStorageBlobContent -File "$itemFullPath" -Container $azsOfflineContainerName -Blob "$itemName" -Context $azsOfflineStorageAccount.Context -ErrorAction Stop | Out-Null
                    ################## AzCopy Testing ##############################################
                    $containerDestination = '{0}{1}' -f $azsOfflineStorageAccount.PrimaryEndpoints.Blob, $azsOfflineContainerName
                    Write-Host "Container destination is: $containerDestination"
                    $azCopyPath = "C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\AzCopy.exe"
                    $storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $azsOfflineRGName -Name $azsOfflineStorageAccountName).Value[0]
                    $azCopyCmd = [string]::Format("""{0}"" /source:""{1}"" /dest:""{2}"" /destkey:""{3}"" /Pattern:""{4}"" /Y /V:""{5}"" /Z:""{6}""", $azCopyPath, $itemDirectory, $containerDestination, $storageAccountKey, $itemName, $azCopyLogPath, $journalPath)
                    Write-Host "Executing the following command:`n'n$azCopyCmd"
                    $result = cmd /c $azCopyCmd
                    foreach ($s in $result) {
                        Write-Host $s 
                    }
                    if ($LASTEXITCODE -ne 0) {
                        Throw "Upload file failed: $itemName. Check logs at $azCopyLogPath";
                        break;
                    }
                    ################## AzCopy Testing ##############################################
                }
                catch {
                    Write-Host "Upload failed."
                    Write-Host "$_.Exception.Message"
                    $uploadItemAttempt++
                }
                if ($uploadItemAttempt -gt 3) {
                    $uploadFailed = $true
                }
            }
            if ($uploadFailed -eq $true) {
                throw "At least one of the files failed to upload. Check the logs for further info."
                Break
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
    Write-Host "This is an online deployment, skipping step`r`n"
    # Update the AzSPoC database with skip status
    $progressStage = $progressName
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
$endTime = $(Get-Date).ToString("MMdd-HHmmss")
Write-Host "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue