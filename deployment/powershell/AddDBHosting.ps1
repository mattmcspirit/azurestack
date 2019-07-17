[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,
    
    [Parameter(Mandatory = $true)]
    [String] $customDomainSuffix,

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

$logFolder = "$($dbHost)AddHosting"
$logName = $logFolder
$progressName = $logFolder
$skipRP = $false

if ($dbHost -eq "MySQL") {
    if ($skipMySQL -eq $true) {
        $skipRP = $true
    }
}
elseif ($dbHost -eq "SQLServer") {
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
    Write-Host "ASDK Configurator Stage: $progressStage previously completed successfully"
}
elseif (($skipRP -eq $false) -and ($progressCheck -ne "Complete")) {
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
            Get-AzureRmContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force
            Disable-AzureRMContextAutosave -Scope CurrentUser

            <#Write-Host "Importing Azure.Storage and AzureRM.Storage modules"
            Import-Module -Name Azure.Storage -RequiredVersion 4.5.0
            Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4
            #>

            # Need to ensure this stage doesn't start before the database SKU has been added
            $dbSkuJobCheck = $progressCheck = CheckProgress -progressStage "$($dbHost)SKUQuota"
            while ($dbSkuJobCheck -ne "Complete") {
                Write-Host "The $($dbHost)SKUQuota stage of the process has not yet completed. Checking again in 20 seconds"
                Start-Sleep -Seconds 20
                $dbSkuJobCheck = $progressCheck = CheckProgress -progressStage "$($dbHost)SKUQuota"
                if ($dbSkuJobCheck -eq "Failed") {
                    throw "The $($dbHost)SKUQuota stage of the process has failed. This should fully complete before the $dbHost database host has been deployed. Check the $($dbHost)SKUQuota log, ensure that step is completed first, and rerun."
                }
            }
            # Need to ensure this stage doesn't start before the database host has finished deployment
            $dbHostJobCheck = CheckProgress -progressStage "$($dbHost)DBVM"
            while ($dbHostJobCheck -ne "Complete") {
                Write-Host "The $($dbHost)DBVM stage of the process has not yet completed. Checking again in 20 seconds"
                Start-Sleep -Seconds 20
                $dbHostJobCheck = CheckProgress -progressStage "$($dbHost)DBVM"
                if ($dbHostJobCheck -eq "Failed") {
                    throw "The $($dbHost)DBVM stage of the process has failed. This should fully complete before the $dbHost database host has been deployed. Check the $($dbHost)DBVM log, ensure that step is completed first, and rerun."
                }
            }
            Write-Host "Logging into Azure Stack into the user space to get the FQDN of the Hosting Server"
            $ArmEndpoint = "https://management.$customDomainSuffix"
            Add-AzureRMEnvironment -Name "AzureStackUser" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Add-AzureRmAccount -EnvironmentName "AzureStackUser" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            Write-Host "Selecting the *ADMIN DB HOSTS subscription"
            $sub = Get-AzureRmSubscription | Where-Object { $_.Name -eq '*ADMIN DB HOSTS' }
            Set-AzureRMContext -Subscription $sub.SubscriptionId -NAME $sub.Name -Force | Out-Null
            $subID = $sub.SubscriptionId
            #$azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
            #$subID = $azureContext.Subscription.Id
            Write-Host "Current subscription ID is: $subID"
            
            Write-Host "Setting up Database Variables"
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
            $addHostingJobCheck = CheckProgress -progressStage "$hostingJobCheck"
            while ($addHostingJobCheck -ne "Complete") {
                Write-Host "The $hostingJobCheck stage of the process has not yet completed. Checking again in 20 seconds"
                Start-Sleep -Seconds 20
                $addHostingJobCheck = CheckProgress -progressStage "$hostingJobCheck"
                if ($addHostingJobCheck -eq "Failed") {
                    throw "The $hostingJobCheck stage of the process has failed. This should fully complete before the database VMs can be deployed. Check the $hostingJobCheck log, ensure that step is completed first, and rerun."
                }
            }

            Write-Host "Clearing previous Azure/Azure Stack logins"
            Get-AzureRmContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force

            Write-Host "Logging into Azure Stack into the admin space to complete the process"
            $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            $azsLocation = (Get-AzureRmLocation).DisplayName
            $adminDbRg = "azurestack-admindbhosting"

            # Create the RG to hold the assets in the admin space
            if (-not (Get-AzureRmResourceGroup -Name $adminDbRg -Location $azsLocation -ErrorAction SilentlyContinue)) {
                New-AzureRmResourceGroup -Name $adminDbRg -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
            }

            # Add host server to MySQL RP
            Write-Host "Attaching $dbHost hosting server to $dbHost resource provider"
            if ($deploymentMode -eq "Online") {
                $templateURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/templates/$hostingPath/azuredeploy.json"
            }
            elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                $templateURI = Get-ChildItem -Path "$ASDKpath\templates" -Recurse -Include "$hostingTemplate" | ForEach-Object { $_.FullName }
            }
            if ($dbHost -eq "MySQL") {
                New-AzureRmResourceGroupDeployment -Name AddMySQLHostingServer -ResourceGroupName $adminDbRg -TemplateUri $templateURI `
                    -username "root" -password $secureVMpwd -hostingServerName $dbFqdn -totalSpaceMB 20480 `
                    -skuName "MySQL57" -Mode Incremental -Verbose -ErrorAction Stop
            }
            elseif ($dbHost -eq "SQLServer") {
                New-AzureRmResourceGroupDeployment -Name AddSQLServerHostingServer -ResourceGroupName $adminDbRg -TemplateUri $templateURI `
                    -hostingServerName $dbFqdn -hostingServerSQLLoginName "sa" -hostingServerSQLLoginPassword $secureVMpwd -totalSpaceMB 20480 `
                    -skuName "MSSQL2017" -Mode Incremental -Verbose -ErrorAction Stop
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
    # Update the ConfigASDK database with skip status
    $progressStage = $progressName
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
$endTime = $(Get-Date).ToString("MMdd-HHmmss")
Write-Host "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue