[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ConfigASDKProgressLogPath,

    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $downloadPath,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [Parameter(Mandatory = $true)]
    [ValidateSet("MySQL", "SQLServer", "AppService")]
    [String] $dbvm,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [ValidateSet("azurestack-dbhosting", "appservice-sql")]
    [String] $dbrg,

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
    [String] $skipMySQL,

    [parameter(Mandatory = $false)]
    [String] $skipMSSQL
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

$logFolder = "$($dbvm)DBVM"
$logName = $logFolder
$progressName = $logFolder
if ($dbvm -eq "MySQL") {
    $azpkg = "MySQL"
    if ($skipMySQL -eq $true) {
        $skipRP = $true
    }
    else {
        $skipRP = $false
    }
}
elseif ($dbvm -eq "SQLServer") {
    $azpkg = "MSSQL"
    if ($skipMSSQL -eq $true) {
        $skipRP = $true
    }
    else {
        $skipRP = $false
    }
}
elseif ($dbvm -eq "AppService") { $azpkg = "MSSQL" }

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
            # Need to ensure this stage doesn't start before the Ubuntu Server images have been put into the PIR
            $progress = Import-Csv -Path $ConfigASDKProgressLogPath
            $ubuntuImageJobCheck = [array]::IndexOf($progress.Stage, "UbuntuServerImage")
            while (($progress[$ubuntuImageJobCheck].Status -ne "Complete")) {
                Write-Verbose -Message "The UbuntuServerImage stage of the process has not yet completed. Checking again in 10 seconds"
                Start-Sleep -Seconds 10
                if ($progress[$ubuntuImageJobCheck].Status -eq "Failed") {
                    throw "The UbuntuServerImage stage of the process has failed. This should fully complete before the database VMs can be deployed. Check the UbuntuServerImage log, ensure that step is completed first, and rerun."
                }
                $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                $ubuntuImageJobCheck = [array]::IndexOf($progress.Stage, "UbuntuServerImage")
            }
            if ($dbvm -eq "MySQL") {
                # Then need to confirm the gallery items are in place
                $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                $MySQLGalleryItemJobCheck = [array]::IndexOf($progress.Stage, "MySQLGalleryItem")
                while (($progress[$MySQLGalleryItemJobCheck].Status -ne "Complete")) {
                    Write-Verbose -Message "The MySQLGalleryItem stage of the process has not yet completed. Checking again in 10 seconds"
                    Start-Sleep -Seconds 10
                    if ($progress[$MySQLGalleryItemJobCheck].Status -eq "Failed") {
                        throw "The MySQLGalleryItem stage of the process has failed. This should fully complete before the database VMs can be deployed. Check the MySQLGalleryItem log, ensure that step is completed first, and rerun."
                    }
                    $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                    $MySQLGalleryItemJobCheck = [array]::IndexOf($progress.Stage, "MySQLGalleryItem")
                }
            }
            elseif ($dbvm -eq "SQLServer") {
                # Then need to confirm the gallery items are in place
                $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                $SQLServerGalleryItemJobCheck = [array]::IndexOf($progress.Stage, "SQLServerGalleryItem")
                while (($progress[$SQLServerGalleryItemJobCheck].Status -ne "Complete")) {
                    Write-Verbose -Message "The SQLServerGalleryItem stage of the process has not yet completed. Checking again in 10 seconds"
                    Start-Sleep -Seconds 10
                    if ($progress[$SQLServerGalleryItemJobCheck].Status -eq "Failed") {
                        throw "The SQLServerGalleryItem stage of the process has failed. This should fully complete before the database VMs can be deployed. Check the SQLServerGalleryItem log, ensure that step is completed first, and rerun."
                    }
                    $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                    $SQLServerGalleryItemJobCheck = [array]::IndexOf($progress.Stage, "SQLServerGalleryItem")
                }
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

            # Need to confirm that both DB Hosting VM deployments don't operate at exactly the same time, or there may be a conflict with creating the resource groups and other resources at the start of the deployment
            if ($dbvm -eq "SQLServer") {
                if (($skipMySQL -eq $false) -and ($skipMSSQL -eq $false)) {
                    $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                    $mySQLProgressCheck = [array]::IndexOf($progress.Stage, "MySQLDBVM")
                    if (($progress[$mySQLProgressCheck].Status -ne "Complete")) {
                        Write-Verbose -Message "To avoid deployment conflicts, delaying the SQL Server VM deployment by 2 minutes to allow initial resources to be created"
                        Start-Sleep -Seconds 120
                    }
                }
            }
            ### Login to Azure Stack ###
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

            Write-Verbose -Message "Creating a dedicated Resource Group for all database hosting assets"
            if (-not (Get-AzureRmResourceGroup -Name $dbrg -Location $azsLocation -ErrorAction SilentlyContinue)) {
                New-AzureRmResourceGroup -Name $dbrg -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
            }

            # Dynamically retrieve the mainTemplate.json URI from the Azure Stack Gallery to determine deployment base URI
            $mainTemplateURI = $(Get-AzsGalleryItem | Where-Object {$_.Name -like "ASDK.$azpkg*"}).DefinitionTemplates.DeploymentTemplateFileUris.Values | Where-Object {$_ -like "*mainTemplate.json"}

            if ($deploymentMode -eq "Online") {
                $dbScriptBaseURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/scripts/"
            }
            elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                $asdkOfflineRGName = "azurestack-offline"
                $asdkOfflineStorageAccountName = "offlinestor"
                $asdkOfflineContainerName = "offlinecontainer"
                $asdkOfflineStorageAccount = Get-AzureRmStorageAccount -Name $asdkOfflineStorageAccountName -ResourceGroupName $asdkOfflineRGName -ErrorAction SilentlyContinue
                $dbScriptBaseURI = ('{0}{1}/' -f $asdkOfflineStorageAccount.PrimaryEndpoints.Blob.AbsoluteUri, $asdkOfflineContainerName) -replace "https", "http"
                # This should pull from the internally accessible template files already added when the MySQL and SQL Server 2017 gallery packages were added
            }
            Write-Verbose -Message "Creating a dedicated $dbvm database VM running on Ubuntu Server 16.04 LTS for database hosting"

            if ($dbvm -eq "MySQL") {
                New-AzureRmResourceGroupDeployment -Name "MySQLHost" -ResourceGroupName $dbrg -TemplateUri $mainTemplateURI `
                    -vmName "mysqlhost" -adminUsername "mysqladmin" -adminPassword $secureVMpwd -mySQLPassword $secureVMpwd -allowRemoteConnections "Yes" `
                    -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "mysqlhost" `
                    -vmSize Standard_A3 -mode Incremental -scriptBaseUrl $dbScriptBaseURI -Verbose -ErrorAction Stop
            }
            elseif ($dbvm -eq "SQLServer") {
                if ($skipMySQL -eq $true) {
                    #if MySQL RP was skipped, DB hosting resources should be created here
                    New-AzureRmResourceGroupDeployment -Name "SQLHost" -ResourceGroupName $dbrg -TemplateUri $mainTemplateURI `
                        -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $dbScriptBaseURI `
                        -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "sqlhost" -vmSize Standard_A3 -mode Incremental -Verbose -ErrorAction Stop
                }
                else {
                    # Assume MySQL RP was deployed, and DB Hosting RG and networks were previously created
                    New-AzureRmResourceGroupDeployment -Name "SQLHost" -ResourceGroupName $dbrg -TemplateUri $mainTemplateURI `
                        -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $dbScriptBaseURI `
                        -virtualNetworkNewOrExisting "existing" -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "sqlhost" -vmSize Standard_A3 -mode Incremental -Verbose -ErrorAction Stop
                }
            }
            elseif ($dbvm -eq "AppService") {
                # Install SQL Server PowerShell on Host in order to configure 'Contained Database Authentication'
                if ($deploymentMode -eq "Online") {
                    # Install SQL Server Module from Online PSrepository
                    Install-Module SqlServer -Force -Confirm:$false -Verbose -ErrorAction Stop
                }
                elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                    # Need to grab module from the ConfigASDKfiles.zip
                    $SourceLocation = "$downloadPath\ASDK\PowerShell"
                    $RepoName = "MyNuGetSource"
                    if (!(Get-PSRepository -Name $RepoName -ErrorAction SilentlyContinue)) {
                        Register-PSRepository -Name $RepoName -SourceLocation $SourceLocation -InstallationPolicy Trusted
                    }                
                    Install-Module SqlServer -Repository $RepoName -Force -Confirm:$false -Verbose -ErrorAction Stop
                }
                New-AzureRmResourceGroupDeployment -Name "sqlapp" -ResourceGroupName $dbrg -TemplateUri $mainTemplateURI -scriptBaseUrl $dbScriptBaseURI `
                    -vmName "sqlapp" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -storageAccountName "sqlappstor" `
                    -publicIPAddressDomainNameLabel "sqlapp" -publicIPAddressName "sqlapp_ip" -vmSize Standard_A3 -mode Incremental -Verbose -ErrorAction Stop
            
                # Get the FQDN of the VM
                $sqlAppServerFqdn = (Get-AzureRmPublicIpAddress -Name "sqlapp_ip" -ResourceGroupName $dbrg).DnsSettings.Fqdn
                        
                # Invoke the SQL Server query to turn on contained database authentication
                $sqlQuery = "sp_configure 'contained database authentication', 1;RECONFIGURE;"
                Invoke-Sqlcmd -Query "$sqlQuery" -ServerInstance "$sqlAppServerFqdn" -Username sa -Password $VMpwd -Verbose -ErrorAction Stop
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