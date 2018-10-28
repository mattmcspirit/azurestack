﻿[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [Parameter(Mandatory = $true)]
    [ValidateSet("MySQL", "SQLServer")]
    [String] $dbrp,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [securestring] $secureVMpwd,

    [parameter(Mandatory = $true)]
    [String] $ERCSip,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,

    [parameter(Mandatory = $true)]
    [pscredential] $cloudAdminCreds,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

    [parameter(Mandatory = $false)]
    [String] $skipMySQL,

    [parameter(Mandatory = $false)]
    [String] $skipMSSQL,

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

$logFolder = "$($dbrp)RP"
$logName = $logFolder
$progressName = $logFolder
$skipRP = $false

if ($dbrp -eq "MySQL") {
    $vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("mysqlrpadmin", $secureVMpwd)
    $rp = "mysql"
    if ($skipMySQL -eq $true) {
        $skipRP = $true
    }
}
elseif ($dbrp -eq "SQLServer") {
    $vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("sqlrpadmin", $secureVMpwd)
    $rp = "sql"
    if ($skipMSSQL -eq $true) {
        $skipRP = $true
    }
}

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
elseif (($skipRP -eq $false) -and ($progressCheck -ne "Complete")) {
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
            # Need to ensure this stage doesn't start before the Windows Server images have been put into the PIR
            $serverCoreJobCheck = CheckProgress -progressStage "ServerCoreImage"
            while ($serverCoreJobCheck -ne "Complete") {
                Write-Verbose -Message "The ServerCoreImage stage of the process has not yet completed. Checking again in 20 seconds"
                Start-Sleep -Seconds 20
                $serverCoreJobCheck = CheckProgress -progressStage "ServerCoreImage"
                if ($serverCoreJobCheck -eq "Failed") {
                    throw "The ServerCoreImage stage of the process has failed. This should fully complete before the Windows Server full image is created. Check the UbuntuServerImage log, ensure that step is completed first, and rerun."
                }
            }

            ### Login to Azure Stack ###
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

            # Get Azure Stack location
            $azsLocation = (Get-AzsLocation).Name
            # Need to 100% confirm that the ServerCoreImage is ready as it seems that starting the MySQL/SQL RP deployment immediately is causing an issue
            Write-Verbose -Message "Need to confirm that the Windows Server 2016 Core image is available in the gallery and ready"
            $azsPlatformImageExists = (Get-AzsPlatformImage -Location "$azsLocation" -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter-Server-Core" -Version "1.0.0" -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded'
            $azureRmVmPlatformImageExists = (Get-AzureRmVMImage -Location "$azsLocation" -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter-Server-Core" -Version "1.0.0" -ErrorAction SilentlyContinue).StatusCode -eq 'OK'
            Write-Verbose -Message "Check #1 - Using Get-AzsPlatformImage to check for Windows Server 2016 Core image"
            if ($azsPlatformImageExists) {
                Write-Verbose -Message "Get-AzsPlatformImage, successfully located an appropriate image with the following details:"
                Write-Verbose -Message "Publisher: MicrosoftWindowsServer | Offer: WindowsServer | Sku: 2016-Datacenter-Server-Core"
            }
            While (!$(Get-AzsPlatformImage -Location "$azsLocation" -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter-Server-Core" -Version "1.0.0" -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
                Write-Verbose -Message "Using Get-AzsPlatformImage, ServerCoreImage is not ready yet. Delaying by 20 seconds"
                Start-Sleep -Seconds 20
            }
            Write-Verbose -Message "Check #2 - Using Get-AzureRmVMImage to check for Windows Server 2016 Core image"
            if ($azureRmVmPlatformImageExists) {
                Write-Verbose -Message "Using Get-AzureRmVMImage, successfully located an appropriate image with the following details:"
                Write-Verbose -Message "Publisher: MicrosoftWindowsServer | Offer: WindowsServer | Sku: 2016-Datacenter-Server-Core"
            }
            While (!$(Get-AzureRmVMImage -Location "$azsLocation" -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter-Server-Core" -Version "1.0.0" -ErrorAction SilentlyContinue).StatusCode -eq 'OK') {
                Write-Verbose -Message "Using Get-AzureRmVMImage to test, ServerCoreImage is not ready yet. Delaying by 20 seconds"
                Start-Sleep -Seconds 20
            }

            # For an extra safety net, add an extra delay to ensure the image is fully ready in the PIR, otherwise it seems to cause a failure.
            Write-Verbose -Message "Delaying for a further 4 minutes to account for random failure with MySQL/SQL RP to detect platform image immediately after upload"
            Start-Sleep -Seconds 240

            # Need to confirm that both deployments don't operate at exactly the same time, or there may be a conflict with creating DNS records at the end of the RP deployment
            if ($dbrp -eq "SQLServer") {
                if (($skipMySQL -eq $false) -and ($skipMSSQL -eq $false)) {
                    $mySQLProgressCheck = CheckProgress -progressStage "MySQLRP"
                    if ($mySQLProgressCheck -ne "Complete") {
                        Write-Verbose -Message "To avoid deployment conflicts with the MySQL RP, delaying the SQL Server RP deployment by 2 minutes"
                        Start-Sleep -Seconds 120
                    }
                }
            }
            # Login to Azure Stack
            Write-Verbose -Message "Downloading and installing $dbrp Resource Provider"
            if (!$([System.IO.Directory]::Exists("$ASDKpath\databases"))) {
                New-Item -Path "$ASDKpath\databases" -ItemType Directory -Force | Out-Null
            }
            if ($deploymentMode -eq "Online") {
                # Cleanup old folder
                Remove-Item "$asdkPath\databases\$dbrp" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                Remove-Item "$ASDKpath\databases\$($dbrp).zip" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                # Download and Expand the RP files
                $rpURI = "https://aka.ms/azurestack$($rp)rp"
                $rpDownloadLocation = "$ASDKpath\databases\$($dbrp).zip"
                DownloadWithRetry -downloadURI "$rpURI" -downloadLocation "$rpDownloadLocation" -retries 10
            }
            elseif ($deploymentMode -ne "Online") {
                if (-not [System.IO.File]::Exists("$ASDKpath\databases\$($dbrp).zip")) {
                    throw "Missing Zip file in extracted dependencies folder. Please ensure this exists at $ASDKpath\databases\$($dbrp).zip - Exiting process"
                }
            }
            Set-Location "$ASDKpath\databases"
            Expand-Archive "$ASDKpath\databases\$($dbrp).zip" -DestinationPath .\$dbrp -Force -ErrorAction Stop
            Set-Location "$ASDKpath\databases\$($dbrp)"
            if ($dbrp -eq "MySQL") {
                if ($deploymentMode -eq "Online") {
                    .\DeployMySQLProvider.ps1 -AzCredential $asdkCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $cloudAdminCreds -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureVMpwd -AcceptLicense
                }
                elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                    $dependencyFilePath = New-Item -ItemType Directory -Path "$ASDKpath\databases\$dbrp\Dependencies" -Force | ForEach-Object { $_.FullName }
                    $MySQLMSI = Get-ChildItem -Path "$ASDKpath\databases\*" -Recurse -Include "*connector*.msi" -ErrorAction Stop | ForEach-Object { $_.FullName }
                    Copy-Item $MySQLMSI -Destination $dependencyFilePath -Force -Verbose
                    .\DeployMySQLProvider.ps1 -AzCredential $asdkCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $cloudAdminCreds -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureVMpwd -DependencyFilesLocalPath $dependencyFilePath -AcceptLicense
                }
            }
            elseif ($dbrp -eq "SQLServer") {
                .\DeploySQLProvider.ps1 -AzCredential $asdkCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $cloudAdminCreds -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureVMpwd
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
elseif (($skipRP) -and ($progressCheck -ne "Complete")) {
    Write-Verbose -Message "Operator chose to skip Resource Provider Deployment"
    # Update the ConfigASDK database with skip status
    $progressStage = $progressName
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue