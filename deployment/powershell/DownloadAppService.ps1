[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

    [parameter(Mandatory = $false)]
    [String] $skipAppService,

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

$logFolder = "DownloadAppService"
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

if ($progressCheck -eq "Complete") {
    Write-Host "ASDK Configurator Stage: $progressStage previously completed successfully"
}
elseif (($skipAppService -eq $false) -and ($progressCheck -ne "Complete")) {
    # We first need to check if in a previous run, this section was skipped, but now, the user wants to add this, so we need to reset the progress.
    if ($progressCheck -eq "Skipped") {
        Write-Host "Operator previously skipped this step, but now wants to perform this step. Updating ConfigASDK database to Incomplete."
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

            Write-Host "Clearing previous Azure/Azure Stack logins"
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force
            Disable-AzureRMContextAutosave -Scope CurrentUser

            if ($deploymentMode -eq "Online") {
                if (!$([System.IO.Directory]::Exists("$ASDKpath\appservice"))) {
                    New-Item -Path "$ASDKpath\appservice" -ItemType Directory -Force | Out-Null
                }
                if (!$([System.IO.Directory]::Exists("$ASDKpath\appservice\extension"))) {
                    New-Item -Path "$ASDKpath\appservice\extension" -ItemType Directory -Force | Out-Null
                }
                # Install App Service To be added
                Write-Host "Downloading App Service Installer"
                Set-Location "$ASDKpath\appservice"
                # Clean up old App Service Path if it exists
                Write-Host "Cleaning up old App Service if it exists"
                Remove-Item "$asdkPath\appservice\" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                Write-Host "Downloading App Service files"
                $appServiceHelperURI = "https://aka.ms/appsvconmashelpers"
                $appServiceHelperDownloadLocation = "$ASDKpath\appservice\appservicehelper.zip"
                DownloadWithRetry -downloadURI "$appServiceHelperURI" -downloadLocation "$appServiceHelperDownloadLocation" -retries 10
                $appServiceExeURI = "https://aka.ms/appsvconmasinstaller"
                $appServiceExeDownloadLocation = "$ASDKpath\appservice\appservice.exe"
                DownloadWithRetry -downloadURI "$appServiceExeURI" -downloadLocation "$appServiceExeDownloadLocation" -retries 10
            }
            elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                if (-not [System.IO.File]::Exists("$ASDKpath\appservice\appservicehelper.zip")) {
                    throw "Missing appservice.zip file in extracted app service dependencies folder. Please ensure this exists at $ASDKpath\appservice\appservicehelper.zip - Exiting process"
                }
                if (-not [System.IO.File]::Exists("$ASDKpath\appservice\appservice.exe")) {
                    throw "Missing appservice.exe file in extracted app service dependencies folder. Please ensure this exists at $ASDKpath\appservice\appservice.exe - Exiting process"
                }
            }
            Expand-Archive "$ASDKpath\appservice\appservicehelper.zip" -DestinationPath "$ASDKpath\appservice" -Force -Verbose
            Get-ChildItem -Path "$ASDKpath\appservice\*" -Recurse | Unblock-File -Verbose
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
    # Update the ConfigASDK database with skip status
    $progressStage = $progressName
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
Write-Host "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue