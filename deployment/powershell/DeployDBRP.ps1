[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ConfigASDKProgressLogPath,

    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $azsLocation,

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
    [String] $skipMSSQL
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

### DOWNLOADER FUNCTION #####################################################################################################################################
#############################################################################################################################################################
function DownloadWithRetry([string] $downloadURI, [string] $downloadLocation, [int] $retries) {
    while ($true) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            (New-Object System.Net.WebClient).DownloadFile($downloadURI, $downloadLocation)
            break
        }
        catch {
            $exceptionMessage = $_.Exception.Message
            Write-Verbose "Failed to download '$downloadURI': $exceptionMessage"
            if ($retries -gt 0) {
                $retries--
                Write-Verbose "Waiting 10 seconds before retrying. Retries left: $retries"
                Start-Sleep -Seconds 10
            }
            else {
                $exception = $_.Exception
                throw $exception
            }
        }
    }
}

$logFolder = "$($dbrp)RP"
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
    Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}
elseif ((!$skipMySQL) -and ($progress[$RowIndex].Status -ne "Complete")) {
    # We first need to check if in a previous run, this section was skipped, but now, the user wants to add this, so we need to reset the progress.
    if ($progress[$RowIndex].Status -eq "Skipped") {
        Write-CustomVerbose -Message "Operator previously skipped this step, but now wants to perform this step. Updating ConfigASDKProgressLog.csv file to Incomplete."
        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress = Import-Csv -Path $ConfigASDKProgressLogPath
        $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
        $progress[$RowIndex].Status = "Incomplete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
    }
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Need to ensure this stage doesn't start before the Windows Server images have been put into the PIR
            $progress = Import-Csv -Path $ConfigASDKProgressLogPath
            $serverCoreJobCheck = [array]::IndexOf($progress.Stage, "ServerCoreImage")
            while (($progress[$serverCoreJobCheck].Status -ne "Complete")) {
                Write-Verbose -Message "The ServerCoreImage stage of the process has not yet completed. Checking again in 10 seconds"
                Start-Sleep -Seconds 10
                if ($progress[$serverCoreJobCheck].Status -eq "Failed") {
                    throw "The ServerCoreImage stage of the process has failed. This should fully complete before the Windows Server full image is created. Check the UbuntuServerImage log, ensure that step is completed first, and rerun."
                }
                $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                $serverCoreJobCheck = [array]::IndexOf($progress.Stage, "ServerCoreImage")
            }
            # Need to confirm that both deployments don't operate at exactly the same time, or there may be a conflict with creating DNS records at the end of the RP deployment
            if ($dbrp -eq "SQLServer") {
                if (($skipMySQL -eq $null) -and ($skipMSSQL -eq $null)) {
                    $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                    $mySQLProgressCheck = [array]::IndexOf($progress.Stage, "MySQLRP")
                    if (($progress[$mySQLProgressCheck].Status -ne "Complete")) {
                        Write-Verbose -Message "To avoid deployment conflicts, delaying the SQL Server RP deployment by 2 minutes"
                        Start-Sleep -Seconds 120           
                    }
                }
            }
            # Login to Azure Stack
            Write-CustomVerbose -Message "Downloading and installing $dbrp Resource Provider"
            ### Login to Azure Stack ###
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

            if (!$([System.IO.Directory]::Exists("$ASDKpath\databases"))) {
                New-Item -Path "$ASDKpath\databases" -ItemType Directory -Force | Out-Null
            }
            if ($deploymentMode -eq "Online") {
                # Cleanup old folder
                Remove-Item "$asdkPath\databases\$dbrp" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                # Download and Expand the RP files
                $rpURI = "https://aka.ms/azurestack$($dbrp)rp"
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
            # Define the additional credentials for the local virtual machine username/password and certificates password
            if ($dbrp -eq "MySQL") {
                $vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("mysqlrpadmin", $secureVMpwd)
            }
            elseif ($dbrp -eq "SQLServer") {
                $vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("sqlrpadmin", $secureVMpwd)
            }

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
elseif (($skipMySQL) -and ($progress[$RowIndex].Status -ne "Complete")) {
    Write-CustomVerbose -Message "Operator chose to skip MySQL Resource Provider Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress = Import-Csv -Path $ConfigASDKProgressLogPath
    $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}
Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue