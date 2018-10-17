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
    [String] $dbhosting,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [ValidateSet("azurestack-dbhosting")]
    [String] $dbrg,

    [parameter(Mandatory = $true)]
    [securestring] $secureVMpwd,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,
    
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

$logFolder = "$($dbhosting)AddHosting"
$logName = $logFolder
$progressName = $logFolder
if ($dbhosting -eq "MySQL") {
    if ($skipMySQL -eq $true) {
        $skipRP = $true
    }
    else {
        $skipRP = $false
    }
}
elseif ($dbhosting -eq "SQLServer") {
    if ($skipMSSQL -eq $true) {
        $skipRP = $true
    }
    else {
        $skipRP = $false
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
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            if ($dbhosting -eq "MySQL") {
                $hostingJobCheck = "MySQLDBVM"
                $hostingPath = "MySQLHosting"
                $hostingTemplate = "mySqlHostingTemplate.json"
                $dbFqdn = (Get-AzureRmPublicIpAddress -Name "mysql_ip" -ResourceGroupName $dbrg).DnsSettings.Fqdn
            }
            elseif ($dbhosting -eq "SQLServer") {
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
            Write-Verbose -Message "Attaching $dbhosting hosting server to $dbhosting resource provider"
            if ($deploymentMode -eq "Online") {
                $templateURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/$hostingPath/azuredeploy.json"
            }
            elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                $templateURI = Get-ChildItem -Path "$ASDKpath\templates" -Recurse -Include "$hostingTemplate" | ForEach-Object { $_.FullName }
            }
            if ($dbhosting -eq "MySQL") {
            New-AzureRmResourceGroupDeployment -ResourceGroupName $dbrg -TemplateUri $templateURI `
                -username "root" -password $secureVMpwd -hostingServerName $dbFqdn -totalSpaceMB 20480 `
                -skuName "MySQL57" -Mode Incremental -Verbose -ErrorAction Stop
            }
            elseif ($dbhosting -eq "SQLServer") {
                New-AzureRmResourceGroupDeployment -ResourceGroupName $dbrg -TemplateUri $templateURI `
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