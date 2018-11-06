[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,

    [Parameter(Mandatory = $false)]
    [String] $registerASDK,
    
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
Start-Transcript -Path "$fullLogPath" -Append -IncludeInvocationHeader

$progressStage = $progressName
$progressCheck = CheckProgress -progressStage $progressStage

if (($registerASDK -eq $true) -and ($deploymentMode -ne "Offline")) {
    if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
        try {
            if ($progressCheck -eq "Failed") {
                StageReset -progressStage $progressStage
            }

            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force
            Disable-AzureRMContextAutosave -Scope CurrentUser

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
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRmEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            $activationName = "default"
            $activationRG = "azurestack-activation"
            if ($(Get-AzsAzureBridgeActivation -Name $activationName -ResourceGroupName $activationRG -ErrorAction SilentlyContinue -Verbose)) {
                Write-Host "Adding Microsoft VM Extensions from the from the Azure Stack Marketplace"
                $getExtensions = ((Get-AzsAzureBridgeProduct -ActivationName $activationName -ResourceGroupName $activationRG -ErrorAction SilentlyContinue -Verbose | Where-Object {($_.ProductKind -eq "virtualMachineExtension") -and ($_.Name -like "*microsoft*")}).Name) -replace "default/", ""
                foreach ($extension in $getExtensions) {
                    while (!$(Get-AzsAzureBridgeDownloadedProduct -Name $extension -ActivationName $activationName -ResourceGroupName $activationRG -ErrorAction SilentlyContinue -Verbose)) {
                        Write-Host "Didn't find $extension in your gallery. Downloading from the Azure Stack Marketplace"
                        Invoke-AzsAzureBridgeProductDownload -ActivationName $activationName -Name $extension -ResourceGroupName $activationRG -Force -Confirm:$false -Verbose
                        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    }
                }
                $getDownloads = (Get-AzsAzureBridgeDownloadedProduct -ActivationName $activationName -ResourceGroupName $activationRG -ErrorAction SilentlyContinue -Verbose | Where-Object {($_.ProductKind -eq "virtualMachineExtension") -and ($_.Name -like "*microsoft*")})
                Write-Host "Your Azure Stack gallery now has the following Microsoft VM Extensions for enhancing your deployments:`r`n"
                foreach ($download in $getDownloads) {
                    Write-Host "$($download.DisplayName) | Version: $($download.ProductProperties.Version)"
                }
                # Update the ConfigASDK database with successful completion
                StageComplete -progressStage $progressStage
            }
            else {
                # No Azure Bridge Activation Record found - Skip rather than fail
                Write-Host "Skipping Microsoft VM Extension download, no Azure Bridge Activation Object called $activationName could be found within the resource group $activationRG on your Azure Stack"
                Write-Host "Assuming registration of this ASDK was successful, you should be able to manually download the VM extensions from Marketplace Management in the admin portal`r`n"
                # Update the ConfigASDK database with skip status
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
        Write-Host "ASDK Configurator Stage: $progressStage previously skipped"
    }
    elseif ($progressCheck -eq "Complete") {
        Write-Host "ASDK Configurator Stage: $progressStage previously completed successfully"
    }
}
elseif ($registerASDK -eq $false) {
    Write-Host "Skipping VM Extension download, as Azure Stack has not been registered`r`n"
    # Update the ConfigASDK database with skip status
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue