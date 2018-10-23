[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ConfigASDKProgressLogPath,

    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [Parameter(Mandatory = $true)]
    [ValidateSet("MySQL", "SQLServer")]
    [String] $dbHost,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [securestring] $secureVMpwd,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

    [parameter(Mandatory = $false)]
    [String] $skipMySQL,

    [parameter(Mandatory = $false)]
    [String] $skipMSSQL,

    [Parameter(Mandatory = $true)]
    [String] $branch
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

$logFolder = "$($dbHost)AddHosting"
$logName = $logFolder
$progressName = $logFolder

if (($skipMySQL -eq $true) -or ($skipMSSQL -eq $true) -or ($skipAppService -eq $true)) {
    $skipRP = $true
}
else {
    $skipRP = $false
}

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
elseif (($skipRP -eq $false) -and ($progress[$RowIndex].Status -ne "Complete")) {
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
            if ($progress[$RowIndex].Status -eq "Failed") {
                # Update the ConfigASDKProgressLog.csv file back to incomplete status if previously failed
                $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
                $progress[$RowIndex].Status = "Incomplete"
                $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            }
            # Need to ensure this stage doesn't start before the database SKU has been added
            $progress = Import-Csv -Path $ConfigASDKProgressLogPath
            $dbSkuJobCheck = [array]::IndexOf($progress.Stage, "$($dbHost)SKUQuota")
            while (($progress[$dbSkuJobCheck].Status -ne "Complete")) {
                Write-Verbose -Message "The $($dbHost)SKUQuota stage of the process has not yet completed. Checking again in 10 seconds"
                Start-Sleep -Seconds 10
                if ($progress[$dbSkuJobCheck].Status -eq "Failed") {
                    throw "The $($dbHost)SKUQuota stage of the process has failed. This should fully complete before the $dbHost database host has been deployed. Check the $($dbHost)SKUQuota log, ensure that step is completed first, and rerun."
                }
                $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                $dbSkuJobCheck = [array]::IndexOf($progress.Stage, "$($dbHost)SKUQuota")
            }
            # Need to ensure this stage doesn't start before the database host has finished deployment
            $progress = Import-Csv -Path $ConfigASDKProgressLogPath
            $dbHostJobCheck = [array]::IndexOf($progress.Stage, "$($dbHost)DBVM")
            while (($progress[$dbHostJobCheck].Status -ne "Complete")) {
                Write-Verbose -Message "The $($dbHost)DBVM stage of the process has not yet completed. Checking again in 10 seconds"
                Start-Sleep -Seconds 10
                if ($progress[$dbHostJobCheck].Status -eq "Failed") {
                    throw "The $($dbHost)DBVM stage of the process has failed. This should fully complete before the $dbHost database host has been deployed. Check the $($dbHost)DBVM log, ensure that step is completed first, and rerun."
                }
                $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                $dbHostJobCheck = [array]::IndexOf($progress.Stage, "$($dbHost)DBVM")
            }
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            $dbrg = "azurestack-dbhosting"
            if ($dbHost -eq "MySQL") {
                $hostingJobCheck = "MySQLDBVM"
                $hostingPath = "MySQLHosting"
                $hostingTemplate = "mySqlHostingTemplate.json"
                $dbFqdn = (Get-AzureRmPublicIpAddress -Name "mysql_ip" -ResourceGroupName $dbrg).DnsSettings.Fqdn
            }
            elseif ($dbHost -eq "SQLServer") {
                $hostingJobCheck = "SQLServerDBVM"
                $hostingPath = "SQLHosting"
                $hostingTemplate = "sqlHostingTemplate.json"
                $dbFqdn = (Get-AzureRmPublicIpAddress -Name "sql_ip" -ResourceGroupName $dbrg).DnsSettings.Fqdn
            }
            # Need to ensure this stage doesn't start before the Ubuntu Server images have been put into the PIR
            $progress = Import-Csv -Path $ConfigASDKProgressLogPath
            $addHostingJobCheck = [array]::IndexOf($progress.Stage, "$hostingJobCheck")
            while (($progress[$addHostingJobCheck].Status -ne "Complete")) {
                Write-Verbose -Message "The $hostingJobCheck stage of the process has not yet completed. Checking again in 10 seconds"
                Start-Sleep -Seconds 10
                if ($progress[$addHostingJobCheck].Status -eq "Failed") {
                    throw "The $hostingJobCheck stage of the process has failed. This should fully complete before the database VMs can be deployed. Check the $hostingJobCheck log, ensure that step is completed first, and rerun."
                }
                $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                $addHostingJobCheck = [array]::IndexOf($progress.Stage, "$hostingJobCheck")
            }
            # Add host server to MySQL RP
            Write-Verbose -Message "Attaching $dbHost hosting server to $dbHost resource provider"
            if ($deploymentMode -eq "Online") {
                $templateURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/templates/$hostingPath/azuredeploy.json"
            }
            elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                $templateURI = Get-ChildItem -Path "$ASDKpath\templates" -Recurse -Include "$hostingTemplate" | ForEach-Object { $_.FullName }
            }
            if ($dbHost -eq "MySQL") {
                New-AzureRmResourceGroupDeployment -Name AddMySQLHostingServer -ResourceGroupName $dbrg -TemplateUri $templateURI `
                    -username "root" -password $secureVMpwd -hostingServerName $dbFqdn -totalSpaceMB 20480 `
                    -skuName "MySQL57" -Mode Incremental -Verbose -ErrorAction Stop
            }
            elseif ($dbHost -eq "SQLServer") {
                New-AzureRmResourceGroupDeployment -Name AddSQLServerHostingServer -ResourceGroupName $dbrg -TemplateUri $templateURI `
                    -hostingServerName $dbFqdn -hostingServerSQLLoginName "sa" -hostingServerSQLLoginPassword $secureVMpwd -totalSpaceMB 20480 `
                    -skuName "MSSQL2017" -Mode Incremental -Verbose -ErrorAction Stop
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
            $progress = Import-Csv -Path $ConfigASDKProgressLogPath
            $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Set-Location $ScriptLocation
            Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            throw $_.Exception.Message
            return
        }
    }
}
elseif (($skipRP) -and ($progress[$RowIndex].Status -ne "Complete")) {
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