[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [Parameter(Mandatory = $true)]
    [String] $customDomainSuffix,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [pscredential] $azsCreds,

    [Parameter(Mandatory = $false)]
    [String] $registerAzS,
    
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

$logFolder = "AddVMExtensions"
$logName = $logFolder
$progressName = $logFolder

### SET LOG LOCATION ###
$logDate = Get-Date -Format FileDate
New-Item -ItemType Directory -Path "$ScriptLocation\Logs\$logDate\$logFolder" -Force | Out-Null
$logPath = "$ScriptLocation\Logs\$logDate\$logFolder"

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

if (($registerAzS -eq $true) -and ($deploymentMode -ne "Offline")) {
    if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
        try {
            if ($progressCheck -eq "Failed") {
                StageReset -progressStage $progressStage
            }

            Write-Host "Clearing previous Azure/Azure Stack logins"
            Get-AzContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzContext -Force | Out-Null
            Clear-AzContext -Scope CurrentUser -Force
            Disable-AzContextAutosave -Scope CurrentUser
            # Currently an infinite loop bug exists in Azs.AzureBridge.Admin 0.1.1 - this section fixes it by editing the Get-TaskResult.ps1 file
            if (!(Get-Module -Name Azs.AzureBridge.Admin)) {
                Import-Module Azs.AzureBridge.Admin -Force
            }
            if ((((Get-Module -Name Azs.AzureBridge*).Version).ToString()) -eq "0.1.1") {
                $taskResult = (Get-ChildItem -Path "$((Get-Module -Name Azs.AzureBridge*).ModuleBase)" -Recurse -Include "Get-TaskResult.ps1" -ErrorAction Stop).FullName
                foreach ($task in $taskResult) {
                    $old = 'Write-Debug -Message "$($result | Out-String)"'
                    $new = '#Write-Debug -Message "$($result | Out-String)"'
                    $pattern1 = [RegEx]::Escape($old)
                    $pattern2 = [RegEx]::Escape($new)
                    if (!((Get-Content $taskResult) | Select-String $pattern2)) {
                        if ((Get-Content $taskResult) | Select-String $pattern1) {
                            Write-Host "Known issue with Azs.AzureBridge.Admin Module Version 0.1.1 - editing Get-TaskResult.ps1"
                            Write-Host "Removing module before editing file"
                            Remove-Module Azs.AzureBridge.Admin -Force -Confirm:$false -Verbose
                            Write-Host "Editing file"
                            (Get-Content $taskResult) | ForEach-Object { $_ -replace $pattern1, $new } -Verbose -ErrorAction Stop | Set-Content $taskResult -Verbose -ErrorAction Stop
                            Write-Host "Editing completed. Reimporting module"
                            Import-Module Azs.AzureBridge.Admin -Force
                        }
                    }
                }
            }
            Write-Host "Logging into Azure Stack"
            $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
            Add-AzEnvironment -Name "AzureStackAdmin" -ARMEndpoint "$ArmEndpoint" -ErrorAction Stop
            Connect-AzAccount -Environment "AzureStackAdmin" -Tenant $tenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
            $sub = Get-AzSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
            Get-AzSubscription -SubscriptionID $sub.SubscriptionId | Set-AzContext
            $activationName = "default"
            $activationRG = "azurestack-activation"
            Write-Host "Checking if Azure Stack is activated and successfully registered"
            if ($(Get-AzsAzureBridgeActivation -Name $activationName -ResourceGroupName $activationRG -ErrorAction SilentlyContinue -Verbose)) {
                Write-Host "Adding Microsoft VM Extensions from the from the Azure Stack Marketplace"
                $getExtensions = (Get-AzsAzureBridgeProduct -ActivationName $activationName -ResourceGroupName $activationRG -ErrorAction SilentlyContinue -Verbose | Where-Object { ($_.ProductKind -eq "virtualMachineExtension") -and ($_.Name -like "*microsoft*") }).DisplayName | Sort-Object -Descending -Unique
                $newExtensionList = @()
                foreach ($ext in $getExtensions) {
                    $newExtensionList += ((Get-AzsAzureBridgeProduct -ActivationName $activationName -ResourceGroupName $activationRG -ErrorAction SilentlyContinue -Verbose | Where-Object { ($_.ProductKind -eq "virtualMachineExtension") -and ($_.DisplayName -like "*$ext*") }).Name) -replace "default/", "" | Sort-Object -Descending | Select-Object -First 1
                }
                #$getExtensions = ((Get-AzsAzureBridgeProduct -ActivationName $activationName -ResourceGroupName $activationRG -ErrorAction SilentlyContinue -Verbose | Where-Object { ($_.ProductKind -eq "virtualMachineExtension") -and ($_.Name -like "*microsoft*") }).Name) -replace "default/", ""
                foreach ($extension in $newExtensionList) {
                    while (!$(Get-AzsAzureBridgeDownloadedProduct -Name $extension -ActivationName $activationName -ResourceGroupName $activationRG -ErrorAction SilentlyContinue -Verbose)) {
                        Write-Host "Didn't find $extension in your gallery. Downloading from the Azure Stack Marketplace"
                        Invoke-AzsAzureBridgeProductDownload -ActivationName $activationName -Name $extension -ResourceGroupName $activationRG -Confirm:$false -Verbose
                        Connect-AzAccount -Environment "AzureStackAdmin" -Tenant $tenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
                        $sub = Get-AzSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
                        Get-AzSubscription -SubscriptionID $sub.SubscriptionId | Set-AzContext
                    }
                }
                $getDownloads = (Get-AzsAzureBridgeDownloadedProduct -ActivationName $activationName -ResourceGroupName $activationRG -ErrorAction SilentlyContinue -Verbose | Where-Object { ($_.ProductKind -eq "virtualMachineExtension") -and ($_.Name -like "*microsoft*") })
                Write-Host "Your Azure Stack gallery now has the following Microsoft VM Extensions for enhancing your deployments:`r`n"
                foreach ($download in $getDownloads) {
                    Write-Host "$($download.DisplayName) | Version: $($download.ProductProperties)"
                }
                # Update the AzSPoC database with successful completion
                StageComplete -progressStage $progressStage
            }
            else {
                # No Azure Bridge Activation Record found - Skip rather than fail
                Write-Host "Skipping Microsoft VM Extension download, no Azure Bridge Activation Object called $activationName could be found within the resource group $activationRG on your Azure Stack"
                Write-Host "Assuming registration of this Azure Stack POC was successful, you should be able to manually download the VM extensions from Marketplace Management in the admin portal`r`n"
                # Update the AzSPoC database with skip status
                StageSkipped -progressStage $progressStage
            }
        }
        catch {
            StageFailed -progressStage $progressStage
            Set-Location $ScriptLocation
            throw $_.Exception.Message
            return
        }
    }
    elseif ($progressCheck -eq "Skipped") {
        Write-Host "Azure Stack POC Configurator Stage: $progressStage previously skipped"
    }
    elseif ($progressCheck -eq "Complete") {
        Write-Host "Azure Stack POC Configurator Stage: $progressStage previously completed successfully"
    }
}
elseif ($registerAzS -eq $false) {
    Write-Host "Skipping VM Extension download, as Azure Stack has not been registered`r`n"
    # Update the AzSPoC database with skip status
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
$endTime = $(Get-Date).ToString("MMdd-HHmmss")
Write-Host "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue