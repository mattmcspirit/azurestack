[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $azsPath,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [Parameter(Mandatory = $true)]
    [String] $customDomainSuffix,

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
    [pscredential] $azsCreds,

    [parameter(Mandatory = $true)]
    [pscredential] $pepAdminCreds,
    
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
    [String] $tableName,

    [Parameter(Mandatory = $false)]
    [String] $serialMode,

    [Parameter(Mandatory = $false)]
    [String] $certPath,

    [parameter(Mandatory = $true)]
    [securestring] $secureCertPwd,

    [Parameter(Mandatory = $false)]
    [String] $multiNode
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
elseif (($skipRP -eq $false) -and ($progressCheck -ne "Complete")) {
    # We first need to check if in a previous run, this section was skipped, but now, the user wants to add this, so we need to reset the progress.
    if ($progressCheck -eq "Skipped") {
        Write-Host "Operator previously skipped this step, but now wants to perform this step. Updating AzSPoC database to Incomplete."
        # Update the AzSPoC database back to incomplete
        StageReset -progressStage $progressStage
        $progressCheck = CheckProgress -progressStage $progressStage
    }
    $rpAttempt = 0
    $rpSuccess = $false
    while ((($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) -and ($rpAttempt -lt 3)) {
        $rpAttempt++ # Increment the attempt
        $dbrpPath = "$($dbrp)$rpAttempt"
        Write-Host "This is deployment attempt $rpAttempt for the deployment of the $dbrp Resource Provider."
        # Try the deployment of the RP a maximum of 3 times
        if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
            try {
                # Update the AzSPoC database back to incomplete status if previously failed
                StageReset -progressStage $progressStage
                $progressCheck = CheckProgress -progressStage $progressStage
                Write-Host "Logging into Azure Stack"
                $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
                Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
                # Get Azure Stack location
                $azsLocation = (Get-AzureRmLocation).DisplayName
                # Perform a cleanup of the failed deployment - RG, Files
                Write-Host "Checking for a previously failed deployemnt and cleaning up."
                $rgName = "system.$azslocation.$($rp)adapter"
                if (Get-AzureRmResourceGroup -Name "$rgName" -Location $azsLocation -ErrorAction SilentlyContinue) {
                    Remove-AzureRmResourceGroup -Name $rgName -Force -ErrorAction Stop -Verbose
                }

                Write-Host "Clearing previous Azure/Azure Stack logins"
                Get-AzureRmContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzureRmAccount | Out-Null
                Clear-AzureRmContext -Scope CurrentUser -Force
                Disable-AzureRMContextAutosave -Scope CurrentUser

                # Need to ensure this stage doesn't start before the Windows Server images have been put into the PIR
                $serverCore2016JobCheck = CheckProgress -progressStage "ServerCore2016Image"
                while ($serverCore2016JobCheck -ne "Complete") {
                    Write-Host "The ServerCore2016Image stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 20
                    $serverCore2016JobCheck = CheckProgress -progressStage "ServerCore2016Image"
                    if ($serverCore2016JobCheck -eq "Failed") {
                        throw "The ServerCore2016Image stage of the process has failed. This should fully complete before the Windows Server core image is created. Check the Windows Server image log, ensure that step is completed first, and rerun."
                    }
                }

                ### Login to Azure Stack ###
                Write-Host "Logging into Azure Stack"
                $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
                Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $azsCreds -ErrorAction Stop | Out-Null

                # Get Azure Stack location
                $azsLocation = (Get-AzureRmLocation).DisplayName
                # Need to 100% confirm that the ServerCoreImage is ready as it seems that starting the MySQL/SQL RP deployment immediately is causing an issue
                Write-Host "Need to confirm that the Windows Server 2016 Core image is available in the gallery and ready"
                $azsPlatformImageExists = (Get-AzsPlatformImage -Location $azsLocation -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter-Server-Core" -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded'
                $azureRmVmPlatformImageExists = (Get-AzureRmVMImage -Location $azsLocation -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter-Server-Core" -ErrorAction SilentlyContinue).StatusCode -eq 'OK'
                Write-Host "Check #1 - Using Get-AzsPlatformImage to check for Windows Server 2016 Core image"
                if ($azsPlatformImageExists) {
                    Write-Host "Get-AzsPlatformImage, successfully located an appropriate image with the following details:"
                    Write-Host "Publisher: MicrosoftWindowsServer | Offer: WindowsServer | Sku: 2016-Datacenter-Server-Core"
                }
                While (!$(Get-AzsPlatformImage -Location $azsLocation -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter-Server-Core" -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
                    Write-Host "Using Get-AzsPlatformImage, ServerCoreImage is not ready yet. Delaying by 20 seconds"
                    Start-Sleep -Seconds 20
                }
                Write-Host "Check #2 - Using Get-AzureRmVMImage to check for Windows Server 2016 Core image"
                if ($azureRmVmPlatformImageExists) {
                    Write-Host "Using Get-AzureRmVMImage, successfully located an appropriate image with the following details:"
                    Write-Host "Publisher: MicrosoftWindowsServer | Offer: WindowsServer | Sku: 2016-Datacenter-Server-Core"
                }
                While (!$(Get-AzureRmVMImage -Location $azsLocation -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter-Server-Core" -ErrorAction SilentlyContinue).StatusCode -eq 'OK') {
                    Write-Host "Using Get-AzureRmVMImage to test, ServerCoreImage is not ready yet. Delaying by 20 seconds"
                    Start-Sleep -Seconds 20
                }

                # For an extra safety net, add an extra delay to ensure the image is fully ready in the PIR, otherwise it seems to cause a failure.
                Write-Host "Delaying for a further 4 minutes to account for random failure with MySQL/SQL RP to detect platform image immediately after upload"
                Start-Sleep -Seconds 240

                # Need to confirm that both deployments don't operate at exactly the same time, or there may be a conflict with creating DNS records at the end of the RP deployment
                if ($serialMode -eq $true) {
                    if ($dbrp -eq "SQLServer") {
                        if (($skipMySQL -eq $false) -and ($skipMSSQL -eq $false)) {
                            $mySQLProgressCheck = CheckProgress -progressStage "MySQLRP"
                            while ($mySQLProgressCheck -eq "Incomplete") {
                                Write-Host "The MySQLRP stage of the process has not yet completed. This should complete first in a serialMode deployment. Checking again in 60 seconds"
                                Start-Sleep -Seconds 60
                                $mySQLProgressCheck = CheckProgress -progressStage "MySQLRP"
                                if ($mySQLProgressCheck -eq "Failed") {
                                    Write-Host "MySQLRP deployment seems to have failed, but this doesn't affect the SQL Server RP Deployment. Process can continue."
                                    BREAK
                                }
                            }
                        }
                    }
                    elseif ($dbrp -eq "MySQL") {
                        $appDBProgressCheck = CheckProgress -progressStage "AppServiceSQLServer"
                        while ($appDBProgressCheck -eq "Incomplete") {
                            Write-Host "The AppServiceSQLServer stage of the process has not yet completed. This should complete first in a serialMode deployment. Checking again in 60 seconds"
                            Start-Sleep -Seconds 60
                            $appDBProgressCheck = CheckProgress -progressStage "AppServiceSQLServer"
                            if ($appDBProgressCheck -eq "Failed") {
                                Write-Host "AppServiceSQLServer deployment seems to have failed, but this doesn't affect the Database RP Deployment. Process can continue."
                                BREAK
                            }
                        }
                    }
                }
                elseif ($serialMode -eq $false) {
                    if ($dbrp -eq "SQLServer") {
                        if (($skipMySQL -eq $false) -and ($skipMSSQL -eq $false)) {
                            $mySQLProgressCheck = CheckProgress -progressStage "MySQLRP"
                            if ($mySQLProgressCheck -eq "Incomplete") {
                                Write-Host "To avoid deployment conflicts with the MySQL RP, delaying the SQL Server RP deployment by 2 minutes"
                                Start-Sleep -Seconds 120
                            }
                        }
                    }
                }

                # Login to Azure Stack
                Write-Host "Downloading and installing $dbrp Resource Provider"
                if (!$([System.IO.Directory]::Exists("$azsPath\databases"))) {
                    New-Item -Path "$azsPath\databases" -ItemType Directory -Force | Out-Null
                }
                if ($deploymentMode -eq "Online") {
                    # Cleanup old folder
                    Write-Host "Cleaning up old deployment"
                    if ($([System.IO.Directory]::Exists("$azsPath\databases\$dbrpPath"))) {
                        Remove-Item "$azsPath\databases\$dbrpPath" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                    }
                    if ($([System.IO.File]::Exists("$azsPath\databases\$($dbrp).zip"))) {
                        Remove-Item "$azsPath\databases\$($dbrp).zip" -Recurse -Force -Confirm:$false -ErrorAction Stop
                    }
                    # Download and Expand the RP files
                    Write-Host "Downloading the database RP files"
                    $rpURI = "https://aka.ms/azurestack$($rp)rp11330"
                    $rpDownloadLocation = "$azsPath\databases\$($dbrp).zip"
                    DownloadWithRetry -downloadURI "$rpURI" -downloadLocation "$rpDownloadLocation" -retries 10
                }
                elseif ($deploymentMode -ne "Online") {
                    if (-not [System.IO.File]::Exists("$azsPath\databases\$($dbrp).zip")) {
                        throw "Missing Zip file in extracted dependencies folder. Please ensure this exists at $azsPath\databases\$($dbrp).zip - Exiting process"
                    }
                }
                Set-Location "$azsPath\databases"
                Expand-Archive "$azsPath\databases\$($dbrp).zip" -DestinationPath ".\$dbrpPath" -Force -ErrorAction Stop
                Set-Location "$azsPath\databases\$dbrpPath"
                Get-ChildItem -Path "$azsPath\databases\$dbrpPath\*" -Recurse | Unblock-File -Verbose

                ############################################################################################################################################################################
                # Temporary Workaround to installing DB RP with PS 1.7.0 and newer AzureRM 2.4.0
                $getCommonModule = (Get-ChildItem -Path "$azsPath\databases\$dbrpPath\Prerequisites\Common" -Recurse -Include "Common.psm1" -ErrorAction Stop).FullName
                $old = 'elseif (($azureRMModule.Version.Major -eq "2") -and ($azureRMModule.Version.Minor -eq "3") -and ($azureRMModule.Version.Build -ge "0"))'
                $new = 'elseif (($azureRMModule.Version.Major -eq "2") -and ($azureRMModule.Version.Minor -ge "3") -and ($azureRMModule.Version.Build -ge "0"))'
                $pattern1 = [RegEx]::Escape($old)
                $pattern2 = [RegEx]::Escape($new)
                if (!((Get-Content $getCommonModule) | Select-String $pattern2)) {
                    if ((Get-Content $getCommonModule) | Select-String $pattern1) {
                        Write-Host "Known issue with AzureRM 2.4.0 and DB RPs - editing Common.psm1"
                        Write-Host "Editing file"
                        (Get-Content $getCommonModule) | ForEach-Object { $_ -replace $pattern1, $new } -Verbose -ErrorAction Stop | Set-Content $getCommonModule -Verbose -ErrorAction Stop
                        Write-Host "Editing completed."
                    }
                }
                # End of Temporary Workaround
                ############################################################################################################################################################################

                Write-Host "Starting deployment of $dbrp Resource Provider"
                if ($dbrp -eq "MySQL") {
                    if ($deploymentMode -eq "Online") {
                        if ($multinode -eq $true) {
                            $dependencyFilePath = New-Item -ItemType Directory -Path "$azsPath\databases\$dbrp\Dependencies" -Force | ForEach-Object { $_.FullName }
                            $dbCert = Get-ChildItem -Path "$certPath\*" -Recurse -Include "_.dbadapter*.pfx" -ErrorAction Stop | ForEach-Object { $_.FullName }
                            Copy-Item $dbCert -Destination $dependencyFilePath -Force -Verbose
                            .\DeployMySQLProvider.ps1 -AzCredential $azsCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $pepAdminCreds -PrivilegedEndpoint $ERCSip -DependencyFilesLocalPath $dependencyFilePath -DefaultSSLCertificatePassword $secureCertPwd -AcceptLicense
                        }
                        else {
                            .\DeployMySQLProvider.ps1 -AzCredential $azsCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $pepAdminCreds -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureCertPwd -AcceptLicense
                        }
                    }
                    elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                        $dependencyFilePath = New-Item -ItemType Directory -Path "$azsPath\databases\$dbrp\Dependencies" -Force | ForEach-Object { $_.FullName }
                        $MySQLMSI = Get-ChildItem -Path "$azsPath\databases\*" -Recurse -Include "*connector*.msi" -ErrorAction Stop | ForEach-Object { $_.FullName }
                        Copy-Item $MySQLMSI -Destination $dependencyFilePath -Force -Verbose
                        .\DeployMySQLProvider.ps1 -AzCredential $azsCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $pepAdminCreds -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureCertPwd -DependencyFilesLocalPath $dependencyFilePath -AcceptLicense
                    }
                }
                elseif ($dbrp -eq "SQLServer") {
                    if ($multinode -eq $true) {
                        $dependencyFilePath = New-Item -ItemType Directory -Path "$azsPath\databases\$dbrp\Dependencies" -Force | ForEach-Object { $_.FullName }
                        $dbCert = Get-ChildItem -Path "$certPath\*" -Recurse -Include "_.dbadapter*.pfx" -ErrorAction Stop | ForEach-Object { $_.FullName }
                        Copy-Item $dbCert -Destination $dependencyFilePath -Force -Verbose
                        .\DeploySQLProvider.ps1 -AzCredential $azsCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $pepAdminCreds -PrivilegedEndpoint $ERCSip -DependencyFilesLocalPath $dependencyFilePath -DefaultSSLCertificatePassword $secureCertPwd
                    }
                    else {
                        .\DeploySQLProvider.ps1 -AzCredential $azsCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $pepAdminCreds -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureCertPwd
                    }
                    }
                # Update the AzSPoC database with successful completion
                $progressCheck = CheckProgress -progressStage $progressStage
                StageComplete -progressStage $progressStage
                $progressCheck = CheckProgress -progressStage $progressStage
                $rpSuccess = $true
            }
            catch {
                Write-Host "Attempt #$rpAttempt failed with the following error: $_.Exception.Message"
                Write-Host "This will be retried a maximum of 3 times"
                Set-Location $ScriptLocation
            }
        }
    }
    if (($rpSuccess -eq $false) -and ($rpAttempt -ge 3)) {
        Write-Host "Deploying the $dbrp Resource Provider failed after 3 attempts. Cleanup manually and rerun the script"
        $progressStage = $progressName
        StageFailed -progressStage $progressStage
        $progressCheck = CheckProgress -progressStage $progressStage
        Set-Location $ScriptLocation
        throw $_.Exception.Message
    }
}
elseif (($skipRP) -and ($progressCheck -ne "Complete")) {
    Write-Host "Operator chose to skip Resource Provider Deployment"
    # Update the AzSPoC database with skip status
    $progressStage = $progressName
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
$endTime = $(Get-Date).ToString("MMdd-HHmmss")
Write-Host "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue