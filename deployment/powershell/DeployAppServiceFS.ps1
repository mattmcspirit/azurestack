[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ConfigASDKProgressLogPath,

    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [securestring] $secureVMpwd,

    [parameter(Mandatory = $true)]
    [String] $VMpwd,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

    [Parameter(Mandatory = $true)]
    [String] $azsLocation,

    [parameter(Mandatory = $false)]
    [String] $skipAppService
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

$logFolder = "AppServiceFileServer"
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
elseif (($skipAppService -eq $false) -and ($progress[$RowIndex].Status -ne "Complete")) {
    # We first need to check if in a previous run, this section was skipped, but now, the user wants to add this, so we need to reset the progress.
    if ($progress[$RowIndex].Status -eq "Skipped") {
        Write-Verbose -Message "Operator previously skipped this step, but now wants to perform this step. Updating ConfigASDKProgressLog.csv file to Incomplete."
        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress = Import-Csv -Path $ConfigASDKProgressLogPath
        $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
        $progress[$RowIndex].Status = "Incomplete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
    }
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Need to ensure this stage doesn't start before the Windows Server Full have been put into the PIR and the Offline Scripts have been uploaded
            $progress = Import-Csv -Path $ConfigASDKProgressLogPath
            $serverFullJobCheck = [array]::IndexOf($progress.Stage, "ServerFullImage")
            while (($progress[$serverFullJobCheck].Status -ne "Complete")) {
                Write-Verbose -Message "The ServerFullImage stage of the process has not yet completed. Checking again in 10 seconds"
                Start-Sleep -Seconds 10
                if ($progress[$serverFullJobCheck].Status -eq "Failed") {
                    throw "The ServerFullImage stage of the process has failed. This should fully complete before the Windows Server full image is created. Check the UbuntuServerImage log, ensure that step is completed first, and rerun."
                }
                $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                $serverFullJobCheck = [array]::IndexOf($progress.Stage, "ServerFullImage")
            }
            
            # Need to check if the UploadScripts stage has finished (for an partial/offline deployment)
            if (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                $uploadScriptsJobCheck = [array]::IndexOf($progress.Stage, "UploadScripts")
                while (($progress[$uploadScriptsJobCheck].Status -ne "Complete") -or ($progress[$uploadScriptsJobCheck].Status -ne "Skipped")) {
                    Write-Verbose -Message "The UploadScripts stage of the process has not yet completed. Checking again in 10 seconds"
                    Start-Sleep -Seconds 10
                    if ($progress[$uploadScriptsJobCheck].Status -eq "Failed") {
                        throw "The UploadScripts stage of the process has failed. This should fully complete before the database VMs can be deployed. Check the UploadScripts log, ensure that step is completed first, and rerun."
                    }
                    $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                    $uploadScriptsJobCheck = [array]::IndexOf($progress.Stage, "UploadScripts")
                }
            }

            ### Login to Azure Stack ###
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

            Write-Verbose -Message "Deploying Windows Server 2016 File Server"
            $appServiceRG = "appservice-fileshare"
            
            if (-not (Get-AzureRmResourceGroup -Name $appServiceRG -Location $azsLocation -ErrorAction SilentlyContinue)) {
                New-AzureRmResourceGroup -Name $appServiceRG -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
            }

            if ($deploymentMode -eq "Online") {
                $templateURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/FileServer/azuredeploy.json"
                New-AzureRmResourceGroupDeployment -Name "fileshareserver" -ResourceGroupName $appServiceRG -vmName "fileserver" -TemplateUri $templateURI `
                    -adminPassword $secureVMpwd -fileShareOwnerPassword $secureVMpwd -fileShareUserPassword $secureVMpwd -Mode Incremental -Verbose -ErrorAction Stop
            }
            elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                $templateFile = "FileServerTemplate.json"
                $templateURI = Get-ChildItem -Path "$ASDKpath\templates" -Recurse -Include "$templateFile" | ForEach-Object { $_.FullName }
                $asdkOfflineRGName = "azurestack-offline"
                $asdkOfflineStorageAccountName = "offlinestor"
                $asdkOfflineContainerName = "offlinecontainer"
                $asdkOfflineStorageAccount = Get-AzureRmStorageAccount -Name $asdkOfflineStorageAccountName -ResourceGroupName $asdkOfflineRGName -ErrorAction SilentlyContinue
                $configFilesURI = ('{0}{1}/' -f $asdkOfflineStorageAccount.PrimaryEndpoints.Blob.AbsoluteUri, $asdkOfflineContainerName) -replace "https", "http"
                New-AzureRmResourceGroupDeployment -Name "fileshareserver" -ResourceGroupName $appServiceRG -vmName "fileserver" -TemplateUri $templateURI `
                    -adminPassword $secureVMpwd -fileShareOwnerPassword $secureVMpwd -fileShareUserPassword $secureVMpwd -vmExtensionScriptLocation $configFilesURI -Mode Incremental -Verbose -ErrorAction Stop
            }
            # Update the ConfigASDKProgressLog.csv file with successful completion
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
}
elseif (($skipAppService) -and ($progress[$RowIndex].Status -ne "Complete")) {
    Write-Verbose -Message "Operator chose to skip Resource Provider Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress = Import-Csv -Path $ConfigASDKProgressLogPath
    $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}
Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue