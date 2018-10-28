[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [parameter(Mandatory = $true)]
    [String]$downloadPath,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [Parameter(Mandatory = $true)]
    [ValidateSet("AzureAd", "ADFS")]
    [String] $authenticationType,

    [Parameter(Mandatory = $true)]
    [String] $azureDirectoryTenantName,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,

    [parameter(Mandatory = $true)]
    [String] $VMpwd,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

    [parameter(Mandatory = $false)]
    [String] $skipAppService,

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

$logFolder = "DeployAppService"
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
    Write-Verbose -Message "ASDK Configurator Stage: $progressStage previously completed successfully"
}
elseif (($skipAppService -eq $false) -and ($progressCheck -ne "Complete")) {
    # We first need to check if in a previous run, this section was skipped, but now, the user wants to add this, so we need to reset the progress.
    if ($progressCheck -eq "Skipped") {
        Write-Verbose -Message "Operator previously skipped this step, but now wants to perform this step. Updating ConfigASDK database to Incomplete."
        # Update the ConfigASDK database back to incomplete
        StageReset -progressStage $progressStage
        $progressCheck = CheckProgress -progressStage $progressStage
    }
    if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
        try {
            if ($progressCheck -eq "Failed") {
                # Update the ConfigASDK database back to incomplete status if previously failed
                StageReset -progressStage $progressStage
                $progressCheck = CheckProgress -progressStage $progressStage
            }
            # Need to ensure this stage doesn't start before the App Service components have been downloaded
            $appServicePreReqJobCheck = CheckProgress -progressStage "AddAppServicePreReqs"
            while ($appServicePreReqJobCheck -ne "Complete") {
                Write-Verbose -Message "The AddAppServicePreReqs stage of the process has not yet completed. Checking again in 20 seconds"
                Start-Sleep -Seconds 20
                $appServicePreReqJobCheck = CheckProgress -progressStage "AddAppServicePreReqs"
                if ($appServicePreReqJobCheck -eq "Failed") {
                    throw "The AddAppServicePreReqs stage of the process has failed. This should fully complete before the App Service deployment can be started. Check the AddAppServicePreReqs log, ensure that step is completed first, and rerun."
                }
            }
            # Need to ensure this stage doesn't start before the App Service File Server has been deployed
            $appServiceFSJobCheck = CheckProgress -progressStage "AppServiceFileServer"
            while ($appServiceFSJobCheck -ne "Complete") {
                Write-Verbose -Message "The AppServiceFileServer stage of the process has not yet completed. Checking again in 20 seconds"
                Start-Sleep -Seconds 20
                $appServiceFSJobCheck = CheckProgress -progressStage "AppServiceFileServer"
                if ($appServiceFSJobCheck -eq "Failed") {
                    throw "The AppServiceFileServer stage of the process has failed. This should fully complete before the App Service deployment can be started. Check the AppServiceFileServer log, ensure that step is completed first, and rerun."
                }
            }
            # Need to ensure this stage doesn't start before the App Service SQL Server has been deployed
            $appServiceSQLJobCheck = CheckProgress -progressStage "AppServiceSQLServer"
            while ($appServiceSQLJobCheck -ne "Complete") {
                Write-Verbose -Message "The AppServiceSQLServer stage of the process has not yet completed. Checking again in 20 seconds"
                Start-Sleep -Seconds 20
                $appServiceSQLJobCheck = CheckProgress -progressStage "AppServiceSQLServer"
                if ($appServiceSQLJobCheck -eq "Failed") {
                    throw "The AppServiceSQLServer stage of the process has failed. This should fully complete before the App Service deployment can be started. Check the AppServiceSQLServer log, ensure that step is completed first, and rerun."
                }
            }
            # Login to Azure Stack to grab FQDNs and also Identity App ID locally
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            $fileServerFqdn = (Get-AzureRmPublicIpAddress -Name "fileserver_ip" -ResourceGroupName "appservice-fileshare").DnsSettings.Fqdn
            $sqlAppServerFqdn = (Get-AzureRmPublicIpAddress -Name "sqlapp_ip" -ResourceGroupName "appservice-sql").DnsSettings.Fqdn
            $identityApplicationID = Get-Content -Path "$downloadPath\ApplicationIDBackup.txt" -ErrorAction SilentlyContinue

            Write-Verbose -Message "Checking variables are present before creating JSON"
            # Check Variables #
            if (($authenticationType.ToString() -like "AzureAd") -and ($azureDirectoryTenantName)) {
                Write-Verbose -Message "Azure Directory Tenant Name is present: $azureDirectoryTenantName"
            }
            elseif ($authenticationType.ToString() -like "ADFS") {
                Write-Verbose -Message "ADFS deployment, no need for Azure Directory Tenant Name"
            }
            elseif (($authenticationType.ToString() -like "AzureAd") -and ($azureDirectoryTenantName)) {
                throw "Missing Azure Directory Tenant Name - Exiting process"
            }
            if ($fileServerFqdn) { 
                Write-Verbose -Message "File Server FQDN is present: $fileServerFqdn"
            }
            else {
                throw "Missing File Server FQDN - Exiting process"
            }
            if ($VMpwd) {
                Write-Verbose -Message "Virtual Machine password is present: $VMpwd"
            }
            else {
                throw "Missing Virtual Machine password - Exiting process"
            }
            if ($sqlAppServerFqdn) {
                Write-Verbose -Message "SQL Server FQDN is present: $sqlAppServerFqdn"
            }
            else {
                throw "Missing SQL Server FQDN - Exiting process"
            }
            if ($identityApplicationID) {
                Write-Verbose -Message "Identity Application ID present: $identityApplicationID"
            }
            else {
                throw "Missing Identity Application ID - Exiting process"
            }

            $AppServicePath = "$ASDKpath\appservice"
            Set-Location "$AppServicePath"

            # Pull the pre-deployment JSON file from online, or the local zip file.
            if ($deploymentMode -eq "Online") {
                $appServiceJsonURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/appservice/AppServiceDeploymentSettings.json"
                $appServiceJsonDownloadLocation = "$AppServicePath\AppServicePreDeploymentSettings.json"
                DownloadWithRetry -downloadURI "$appServiceJsonURI" -downloadLocation "$appServiceJsonDownloadLocation" -retries 10
            }
            elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                if ([System.IO.File]::Exists("$ASDKpath\appservice\AppServicePreDeploymentSettings.json")) {
                    Write-Verbose -Message "Located AppServicePreDeploymentSettings.json file"
                }
                if (-not [System.IO.File]::Exists("$ASDKpath\appservice\AppServicePreDeploymentSettings.json")) {
                    throw "Missing AppServicePreDeploymentSettings.json file in extracted app service dependencies folder. Please ensure this exists at $ASDKpath\appservice\ - Exiting process"
                }
            }
            $JsonConfig = Get-Content -Path "$AppServicePath\AppServicePreDeploymentSettings.json"
            # Edit the JSON from deployment

            if ($authenticationType.ToString() -like "AzureAd") {
                $JsonConfig = $JsonConfig.Replace("<<AzureDirectoryTenantName>>", $azureDirectoryTenantName)
            }
            elseif ($authenticationType.ToString() -like "ADFS") {
                $JsonConfig = $JsonConfig.Replace("<<AzureDirectoryTenantName>>", "adfs")
            }
            $JsonConfig = $JsonConfig.Replace("<<FileServerDNSLabel>>", $fileServerFqdn)
            $JsonConfig = $JsonConfig.Replace("<<Password>>", $VMpwd)
            $CertPathDoubleSlash = $AppServicePath.Replace("\", "\\")
            $JsonConfig = $JsonConfig.Replace("<<CertPathDoubleSlash>>", $CertPathDoubleSlash)
            $JsonConfig = $JsonConfig.Replace("<<SQLServerName>>", $sqlAppServerFqdn)
            $SQLServerUser = "sa"
            $JsonConfig = $JsonConfig.Replace("<<SQLServerUser>>", $SQLServerUser)
            $JsonConfig = $JsonConfig.Replace("<<IdentityApplicationId>>", $identityApplicationID)
            Out-File -FilePath "$AppServicePath\AppServiceDeploymentSettings.json" -InputObject $JsonConfig

            # Deploy App Service EXE
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($asdkCreds.Password)
            $appServiceInstallPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            $appServiceLogTime = $(Get-Date).ToString("MMdd-HHmmss")
            $appServiceLogPath = "$AppServicePath\AppServiceLog$appServiceLogTime.txt"
            Set-Location "$AppServicePath"
            Write-Verbose -Message "Starting deployment of the App Service"

            if ($deploymentMode -eq "Online") {
                Start-Process -FilePath .\AppService.exe -ArgumentList "/quiet /log $appServiceLogPath Deploy UserName=$($asdkCreds.UserName) Password=$appServiceInstallPwd ParamFile=$AppServicePath\AppServiceDeploymentSettings.json" -PassThru
            }
            elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                Start-Process -FilePath .\AppService.exe -ArgumentList "/quiet /log $appServiceLogPath Deploy OfflineInstallationPackageFile=$AppServicePath\appserviceoffline.zip UserName=$($asdkCreds.UserName) Password=$appServiceInstallPwd ParamFile=$AppServicePath\AppServiceDeploymentSettings.json" -PassThru
            }

            while ((Get-Process AppService -ErrorAction SilentlyContinue).Responding) {
                Write-Verbose -Message "App Service is deploying. Checking in 20 seconds"
                Start-Sleep -Seconds 20
            }
            if (!(Get-Process AppService -ErrorAction SilentlyContinue).Responding) {
                Write-Verbose -Message "App Service deployment has finished executing."
            }

            $appServiceErrorCode = "Exit code: 0xffffffff"
            Write-Verbose -Message "Checking App Service log file for issues"
            if ($(Select-String -Path $appServiceLogPath -Pattern "$appServiceErrorCode" -SimpleMatch -Quiet) -eq "True") {
                Write-Verbose -Message "App Service install failed with $appServiceErrorCode"
                Write-Verbose -Message "An error has occurred during deployment. Please check the App Service logs at $appServiceLogPath"
                throw "App Service install failed with $appServiceErrorCode. Please check the App Service logs at $appServiceLogPath"
            }
            else {
                Write-Verbose -Message "App Service log file indicates successful deployment"
            }
            Write-Verbose -Message "Checking App Service resource group for successful deployment"
            # Ensure logged into Azure Stack
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            $appServiceRgCheck = (Get-AzureRmResourceGroupDeployment -ResourceGroupName "appservice-infra" -Name "AppService.DeployCloud" -ErrorAction SilentlyContinue)
            if ($appServiceRgCheck.ProvisioningState -ne 'Succeeded') {
                Write-Verbose -Message "An error has occurred during deployment. Please check the App Service logs at $appServiceLogPath"
                throw "$($appServiceRgCheck.DeploymentName) has $($appServiceRgCheck.ProvisioningState). Please check the App Service logs at $appServiceLogPath"
            }
            else {
                Write-Verbose -Message "App Service deployment with name: $($appServiceRgCheck.DeploymentName) has $($appServiceRgCheck.ProvisioningState)"
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
}
elseif ($skipAppService -and ($progressCheck -ne "Complete")) {
    Write-Verbose -Message "Operator chose to skip App Service Deployment`r`n"
    # Update the ConfigASDK database with skip status
    $progressStage = $progressName
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue