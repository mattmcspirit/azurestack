[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $azsPath,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [Parameter(Mandatory = $false)]
    [String] $registerAzS,

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
    [String] $multiNode,

    [Parameter(Mandatory = $true)]
    [ValidateSet("AzureChinaCloud", "AzureCloud", "AzureGermanCloud", "AzureUSGovernment")]
    [String] $azureEnvironment
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
    $rpAdapter = "MySQLAdapter"
    if ($skipMySQL -eq $true) {
        $skipRP = $true
    }
}
elseif ($dbrp -eq "SQLServer") {
    $vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("sqlrpadmin", $secureVMpwd)
    $rp = "sql"
    $rpAdapter = "SQLAdapter"
    if ($skipMSSQL -eq $true) {
        $skipRP = $true
    }
}

if (($registerAzS -eq $true) -and ($deploymentMode -ne "Offline")) {
    if (($dbrp -eq "SQLServer") -and ($authenticationType -eq "ADFS")) {
        $dbRpVersion = "Old"
        $imageProgressCheck = "ServerCore2016Image"
        $publisher = "MicrosoftWindowsServer"
        $offer = "windowsserver"
        $sku = "2016-Datacenter-Server-Core"
    }
    $dbRpVersion = "New"
    $imageProgressCheck = "AddDBRPImage"
    $publisher = "Microsoft"
    $offer = "AddOnRP"
    $sku = "WindowsServer"
}
else {
    $dbRpVersion = "Old"
    $imageProgressCheck = "ServerCore2016Image"
    $publisher = "MicrosoftWindowsServer"
    $offer = "windowsserver"
    $sku = "2016-Datacenter-Server-Core"
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
                Add-AzEnvironment -Name "AzureStackAdmin" -ARMEndpoint "$ArmEndpoint" -ErrorAction Stop
                Connect-AzAccount -Environment "AzureStackAdmin" -Tenant $tenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
                $sub = Get-AzSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
                Get-AzSubscription -SubscriptionID $sub.SubscriptionId | Set-AzContext
                # Get Azure Stack location
                $azsLocation = (Get-AzLocation).DisplayName
                # Perform a cleanup of the failed deployment - RG, Files
                Write-Host "Checking for a previously failed deployemnt and cleaning up."
                $rgName = "system.$azslocation.$($rp)adapter"
                if (Get-AzResourceGroup -Name "$rgName" -Location $azsLocation -ErrorAction SilentlyContinue) {
                    Remove-AzResourceGroup -Name $rgName -Force -ErrorAction Stop -Verbose
                }

                Write-Host "Clearing previous Azure/Azure Stack logins"
                Get-AzContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzContext -Force | Out-Null
                Clear-AzContext -Scope CurrentUser -Force
                Disable-AzContextAutosave -Scope CurrentUser

                # Need to ensure this stage doesn't start before the VM extensions have been updated, or there could be a conflict
                if ($registerAzS -eq $true) {
                    $AddVmExtensionsJobCheck = CheckProgress -progressStage "AddVMExtensions"
                    while ($AddVmExtensionsJobCheck -ne "Complete") {
                        Write-Host "The AddVMExtensions stage of the process has not yet completed. Checking again in 20 seconds"
                        Start-Sleep -Seconds 20
                        $AddVmExtensionsJobCheck = CheckProgress -progressStage "AddVMExtensions"
                        if ($AddVmExtensionsJobCheck -eq "Skipped") {
                            Write-Host "The AddVMExtensions stage of the process was skipped"
                            BREAK
                        }
                        elseif ($AddVmExtensionsJobCheck -eq "Failed") {
                            Write-Host "The AddVMExtensions stage of the process failed"
                            BREAK
                        }
                    }
                }

                # Need to ensure this stage doesn't start before the Windows Server images have been put into the PIR
                $dbrpImageJobCheck = CheckProgress -progressStage "$imageProgressCheck"
                while ($dbrpImageJobCheck -ne "Complete") {
                    Write-Host "The $imageProgressCheck stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 20
                    $dbrpImageJobCheck = CheckProgress -progressStage "$imageProgressCheck"
                    if ($dbrpImageJobCheck -eq "Failed") {
                        throw "The $imageProgressCheck stage of the process has failed. This should fully complete before the Database RPs can be deployed. Check the $imageProgressCheck image log, ensure that step is completed first, and rerun."
                    }
                }

                ### Login to Azure Stack ###
                Write-Host "Logging into Azure Stack"
                $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
                Add-AzEnvironment -Name "AzureStackAdmin" -ARMEndpoint "$ArmEndpoint" -ErrorAction Stop
                Connect-AzAccount -Environment "AzureStackAdmin" -Tenant $tenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
                $sub = Get-AzSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
                Get-AzSubscription -SubscriptionID $sub.SubscriptionId | Set-AzContext
                # Get Azure Stack location
                $azsLocation = (Get-AzLocation).DisplayName
                # Need to 100% confirm that the required platform image is ready as it seems that starting the MySQL/SQL RP deployment immediately is causing an issue
                Write-Host "Need to confirm that the required platform image is available in the gallery and ready"
                
                $azsPlatformImageExists = (Get-AzsPlatformImage | Where-Object { $_.Id -like "*$azsLocation*$publisher*$offer*$sku*" } -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded'
                Write-Host "Check #1 - Using Get-AzsPlatformImage to check for correct platform image"
                if ($azsPlatformImageExists) {
                    Write-Host "Get-AzsPlatformImage, successfully located an appropriate image with the following details:"
                    Write-Host "Publisher: $publisher | Offer: $offer | Sku: $sku"
                }
                While (!$(Get-AzsPlatformImage | Where-Object { $_.Id -like "*$azsLocation*$publisher*$offer*$sku*" } -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
                    Write-Host "Using Get-AzsPlatformImage, $imageProgressCheck is not ready yet. Delaying by 20 seconds"
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
                    if ($([System.IO.File]::Exists("$azsPath\databases\$($dbrp).exe"))) {
                        Remove-Item "$azsPath\databases\$($dbrp).exe" -Recurse -Force -Confirm:$false -ErrorAction Stop
                    }
                    # Download and Expand the RP files
                    Write-Host "Downloading the database RP files"
                    if ($dbRpVersion -eq "New") {
                        $rpURI = "https://aka.ms/azsh$($rp)rp11931"
                    }
                    elseif ($dbRpVersion -eq "Old") {
                        $rpURI = "https://aka.ms/azurestack$($rp)rp11470"
                    }
                    $rpDownloadLocation = "$azsPath\databases\$($dbrp).exe"
                    DownloadWithRetry -downloadURI "$rpURI" -downloadLocation "$rpDownloadLocation" -retries 10
                }
                elseif ($deploymentMode -ne "Online") {
                    Get-ChildItem -Path "$azsPath\databases\" -Filter "*$($dbrp)$($dbRpVersion).exe" | Rename-Item -NewName "$dbrp.exe" -Force
                    if (-not [System.IO.File]::Exists("$azsPath\databases\$($dbrp).exe")) {
                        throw "Missing Exe file in extracted dependencies folder. Please ensure this exists at $azsPath\databases\$($dbrp).exe - Exiting process"
                    }
                }
                if (!$([System.IO.Directory]::Exists("$azsPath\databases\$dbrpPath"))) {
                    New-Item -Path "$azsPath\databases\$dbrpPath" -ItemType Directory -Force | Out-Null
                }
                Set-Location "$azsPath\databases\$dbrpPath"
                $finalDbPath = "$azsPath\databases\$dbrpPath"
                Start-Process -FilePath "$azsPath\databases\$($dbrp).exe" -Argumentlist '/s' -Wait
                Get-ChildItem -Path "$finalDbPath\*" -Recurse | Unblock-File -Verbose

                ############################################################################################################################################################################
                # Temporary Workaround to installing DB RP - separating PowerShell install locations
                Write-Host "Editing the Common Module file to ensure process completes..."
                $getCommonModule = (Get-ChildItem -Path "$azsPath\databases\$dbrpPath\Prerequisites\Common" -Recurse -Include "Common.psm1" -ErrorAction Stop).FullName
                $old1 = '$AzPshInstallFolder = "SqlMySqlPsh"'
                if ($dbrp -eq "SQLServer") {
                    $new1 = '$AzPshInstallFolder = "SQLServerPsh"'
                }                
                elseif ($dbrp -eq "MySQL") {
                    $new1 = '$AzPshInstallFolder = "MySQLPsh"'
                }
                $pattern1 = [RegEx]::Escape($old1)
                $pattern2 = [RegEx]::Escape($new1)
                if (!((Get-Content $getCommonModule) | Select-String $pattern2)) {
                    if ((Get-Content $getCommonModule) | Select-String $pattern1) {
                        Write-Host "Known issues with Azure PowerShell and DB RPs - editing Common.psm1"
                        Write-Host "Editing Azure PowerShell Module Path"
                        (Get-Content $getCommonModule) | ForEach-Object { $_ -replace $pattern1, $new1 } -Verbose -ErrorAction Stop | Set-Content $getCommonModule -Verbose -ErrorAction Stop
                        Write-Host "Editing completed."
                    }
                }
                
                # End of Temporary Workaround
                ############################################################################################################################################################################

                ############################################################################################################################################################################
                # Temporary Workaround to installing old DB RP on ASDK 2008 with longer RP Timeout

                if ($dbRpVersion -eq "Old") {
                    Write-Host "Editing the Deploy_X_Provider.ps1 file to ensure process completes..."
                    $getProviderFile = (Get-ChildItem -Path "$azsPath\databases\$dbrpPath\" -Recurse -Include "Deploy*SQLProvider.ps1" -ErrorAction Stop).FullName
                    $old1 = 'MaxRetryCount 10'
                    $new1 = 'MaxRetryCount 24'
                    $old2 = 'RetryDuration 60'
                    $new2 = 'RetryDuration 300'
                    $pattern1 = [RegEx]::Escape($old1)
                    $pattern2 = [RegEx]::Escape($new1)
                    $pattern3 = [RegEx]::Escape($old2)
                    $pattern4 = [RegEx]::Escape($new2)
                    if (!((Get-Content $getProviderFile) | Select-String $pattern2)) {
                        if ((Get-Content $getProviderFile) | Select-String $pattern1) {
                            Write-Host "Known issues with Azure PowerShell and DB RPs - editing Provider file"
                            Write-Host "Editing MaxRetryCount"
                            (Get-Content $getProviderFile) | ForEach-Object { $_ -replace $pattern1, $new1 } -Verbose -ErrorAction Stop | Set-Content $getProviderFile -Verbose -ErrorAction Stop
                            Write-Host "Editing completed."
                        }
                    }
                    if (!((Get-Content $getProviderFile) | Select-String $pattern4)) {
                        if ((Get-Content $getProviderFile) | Select-String $pattern3) {
                            Write-Host "Known issues with Azure PowerShell and DB RPs - editing Provider file"
                            Write-Host "Editing RetryDuration"
                            (Get-Content $getProviderFile) | ForEach-Object { $_ -replace $pattern3, $new2 } -Verbose -ErrorAction Stop | Set-Content $getProviderFile -Verbose -ErrorAction Stop
                            Write-Host "Editing completed."
                        }
                    }
                }
                # End of Temporary Workaround
                ############################################################################################################################################################################
                
                Write-Host "Starting deployment of $dbrp Resource Provider"
                if ($dbrp -eq "MySQL") {
                    if ($deploymentMode -eq "Online") {
                        if ($multinode -eq $true) {
                            $dependencyFilePath = New-Item -ItemType Directory -Path "$azsPath\databases\$dbrppath\Dependencies" -Force | ForEach-Object { $_.FullName }
                            $dbCert = Get-ChildItem -Path "$certPath\*" -Recurse -Include "_.dbadapter*.pfx" -ErrorAction Stop | ForEach-Object { $_.FullName }
                            Copy-Item $dbCert -Destination $dependencyFilePath -Force -Verbose
                            # Need to deploy in a fresh PSSession due to needing fresh PowerShell modules
                            $mySQLsession = New-PSSession -Name mySQLsession -ComputerName $env:COMPUTERNAME -EnableNetworkAccess
                            Invoke-Command -Session $mySQLsession -ArgumentList $finalDbPath, $azsCreds, $vmLocalAdminCreds, $pepAdminCreds, $ERCSip, $dependencyFilePath, $secureCertPwd, $azureEnvironment -ScriptBlock {
                                Set-Location $Using:finalDbPath
                                .\DeployMySQLProvider.ps1 -AzCredential $Using:azsCreds -VMLocalCredential $Using:vmLocalAdminCreds -CloudAdminCredential $Using:pepAdminCreds `
                                    -PrivilegedEndpoint $Using:ERCSip -DependencyFilesLocalPath $Using:dependencyFilePath -DefaultSSLCertificatePassword $Using:secureCertPwd `
                                    -AzureEnvironment $Using:azureEnvironment -AcceptLicense
                            }
                            Remove-PSSession -Name mySQLsession -Confirm:$false -ErrorAction SilentlyContinue -Verbose
                            Remove-Variable -Name mySQLsession -Force -ErrorAction SilentlyContinue -Verbose
                            <# .\DeployMySQLProvider.ps1 -AzCredential $azsCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $pepAdminCreds `
                                -PrivilegedEndpoint $ERCSip -DependencyFilesLocalPath $dependencyFilePath -DefaultSSLCertificatePassword $secureCertPwd `
                                -AzureEnvironment $azureEnvironment -AcceptLicense #>
                        }
                        else {
                            # Need to deploy in a fresh PSSession due to needing fresh PowerShell modules
                            $mySQLsession = New-PSSession -Name mySQLsession -ComputerName $env:COMPUTERNAME -EnableNetworkAccess
                            Invoke-Command -Session $mySQLsession -ArgumentList $finalDbPath, $azsCreds, $vmLocalAdminCreds, $pepAdminCreds, $ERCSip, $secureCertPwd, $azureEnvironment -ScriptBlock {
                                Set-Location $Using:finalDbPath
                                .\DeployMySQLProvider.ps1 -AzCredential $Using:azsCreds -VMLocalCredential $Using:vmLocalAdminCreds -CloudAdminCredential $Using:pepAdminCreds `
                                    -PrivilegedEndpoint $Using:ERCSip -DefaultSSLCertificatePassword $Using:secureCertPwd `
                                    -AzureEnvironment $Using:azureEnvironment -AcceptLicense
                            }
                            Remove-PSSession -Name mySQLsession -Confirm:$false -ErrorAction SilentlyContinue -Verbose
                            Remove-Variable -Name mySQLsession -Force -ErrorAction SilentlyContinue -Verbose
                            <# .\DeployMySQLProvider.ps1 -AzCredential $azsCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $pepAdminCreds `
                                -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureCertPwd -AzureEnvironment $azureEnvironment -AcceptLicense #>
                        }
                    }
                    elseif ($deploymentMode -ne "Online") {
                        $dependencyFilePath = New-Item -ItemType Directory -Path "$azsPath\databases\$dbrppath\Dependencies" -Force | ForEach-Object { $_.FullName }
                        $MySQLMSI = Get-ChildItem -Path "$azsPath\databases\*" -Include "*connector*.msi" -ErrorAction Stop | ForEach-Object { $_.FullName }
                        Copy-Item $MySQLMSI -Destination $dependencyFilePath -Force -Verbose
                        # Need to deploy in a fresh PSSession due to needing fresh PowerShell modules
                        $mySQLsession = New-PSSession -Name mySQLsession -ComputerName $env:COMPUTERNAME -EnableNetworkAccess
                        Invoke-Command -Session $mySQLsession -ArgumentList $finalDbPath, $azsCreds, $vmLocalAdminCreds, $pepAdminCreds, $ERCSip, $dependencyFilePath, $secureCertPwd, $azureEnvironment -ScriptBlock {
                            Set-Location $Using:finalDbPath
                            Unregister-PSRepository -Name PSGallery -ErrorAction SilentlyContinue -Verbose
                            .\DeployMySQLProvider.ps1 -AzCredential $Using:azsCreds -VMLocalCredential $Using:vmLocalAdminCreds -CloudAdminCredential $Using:pepAdminCreds `
                                -PrivilegedEndpoint $Using:ERCSip -DefaultSSLCertificatePassword $Using:secureCertPwd -DependencyFilesLocalPath $Using:dependencyFilePath `
                                -AzureEnvironment $Using:azureEnvironment -AcceptLicense
                        }
                        Remove-PSSession -Name mySQLsession -Confirm:$false -ErrorAction SilentlyContinue -Verbose
                        Remove-Variable -Name mySQLsession -Force -ErrorAction SilentlyContinue -Verbose
                        <# .\DeployMySQLProvider.ps1 -AzCredential $azsCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $pepAdminCreds `
                            -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureCertPwd -DependencyFilesLocalPath $dependencyFilePath `
                            -AzureEnvironment $azureEnvironment -AcceptLicense #>
                    }
                }
                elseif ($dbrp -eq "SQLServer") {
                    if ($multinode -eq $true) {
                        $dependencyFilePath = New-Item -ItemType Directory -Path "$azsPath\databases\$dbrp\Dependencies" -Force | ForEach-Object { $_.FullName }
                        $dbCert = Get-ChildItem -Path "$certPath\*" -Recurse -Include "_.dbadapter*.pfx" -ErrorAction Stop | ForEach-Object { $_.FullName }
                        Copy-Item $dbCert -Destination $dependencyFilePath -Force -Verbose
                        # Need to deploy in a fresh PSSession due to needing fresh PowerShell modules
                        $SQLsession = New-PSSession -Name SQLsession -ComputerName $env:COMPUTERNAME -EnableNetworkAccess
                        Invoke-Command -Session $SQLsession -ArgumentList $finalDbPath, $azsCreds, $vmLocalAdminCreds, $pepAdminCreds, $ERCSip, $dependencyFilePath, $secureCertPwd, $azureEnvironment -ScriptBlock {
                            Set-Location $Using:finalDbPath
                            .\DeploySQLProvider.ps1 -AzCredential $Using:azsCreds -VMLocalCredential $Using:vmLocalAdminCreds -CloudAdminCredential $Using:pepAdminCreds `
                                -PrivilegedEndpoint $Using:ERCSip -DependencyFilesLocalPath $Using:dependencyFilePath -DefaultSSLCertificatePassword $Using:secureCertPwd `
                                -AzureEnvironment $Using:azureEnvironment
                        }
                        Remove-PSSession -Name SQLsession -Confirm:$false -ErrorAction SilentlyContinue -Verbose
                        Remove-Variable -Name SQLsession -Force -ErrorAction SilentlyContinue -Verbose
                        
                        <# .\DeploySQLProvider.ps1 -AzCredential $azsCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $pepAdminCreds `
                            -PrivilegedEndpoint $ERCSip -DependencyFilesLocalPath $dependencyFilePath -DefaultSSLCertificatePassword $secureCertPwd `
                            -AzureEnvironment $azureEnvironment #>
                    }
                    else {
                        # Need to deploy in a fresh PSSession due to needing fresh PowerShell modules
                        $SQLsession = New-PSSession -Name SQLsession -ComputerName $env:COMPUTERNAME -EnableNetworkAccess
                        Invoke-Command -Session $SQLsession -ArgumentList $deploymentMode, $finalDbPath, $azsCreds, $vmLocalAdminCreds, $pepAdminCreds, $ERCSip, $secureCertPwd, $azureEnvironment -ScriptBlock {
                            Set-Location $Using:finalDbPath
                            if ($Using:deploymentMode -ne "Online") {
                                Unregister-PSRepository -Name PSGallery -ErrorAction SilentlyContinue -Verbose
                            }
                            .\DeploySQLProvider.ps1 -AzCredential $Using:azsCreds -VMLocalCredential $Using:vmLocalAdminCreds -CloudAdminCredential $Using:pepAdminCreds `
                                -PrivilegedEndpoint $Using:ERCSip -DefaultSSLCertificatePassword $Using:secureCertPwd `
                                -AzureEnvironment $Using:azureEnvironment
                        }
                        Remove-PSSession -Name SQLsession -Confirm:$false -ErrorAction SilentlyContinue -Verbose
                        Remove-Variable -Name SQLsession -Force -ErrorAction SilentlyContinue -Verbose
                        <# .\DeploySQLProvider.ps1 -AzCredential $azsCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $pepAdminCreds `
                            -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureCertPwd -AzureEnvironment $azureEnvironment #>
                    }
                }

                # Need to check the log file to confirm successful deployment - only for PS Session Version
                Set-Location "$finalDbPath\Logs"
                # Get Log File
                $getLogFile = (Get-ChildItem -Path "$finalDbPath\Logs" -Recurse -Include "*.txt" -ErrorAction Stop).FullName
                $successString = "*$rpAdapter Installation was successful."
                $pattern1 = [RegEx]::Escape($successString)
                if ((Get-Content $getLogFile) | Select-String $pattern1) {
                    Write-Host "$rpAdapter log file shows a successful completion"
                }
                else {
                    throw "$rpAdapter log file shows a failure - review the log file in the $finalDbPath\Logs folder"
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