[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $downloadPath,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [Parameter(Mandatory = $true)]
    [ValidateSet("MySQL", "SQLServer", "AppServiceFS", "AppServiceDB")]
    [String] $vmType,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

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
    [String] $skipMSSQL,

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

if ($vmType -eq "MySQL") {
    $logFolder = "$($vmType)DBVM"
    $azpkg = "MySQL"
    $rg = "azurestack-dbhosting"
    $skipMSSQL = $null
    $skipAppService = $null
}
elseif ($vmType -eq "SQLServer") {
    $logFolder = "$($vmType)DBVM"
    $azpkg = "MSSQL"
    $rg = "azurestack-dbhosting"
    $skipMySQL = $null
    $skipAppService = $null
}
elseif ($vmType -eq "AppServiceFS") {
    $logFolder = "AppServiceFileServer"
    $rg = "appservice-fileshare"
    $skipMySQL = $null
    $skipMSSQL = $null
}
elseif ($vmType -eq "AppServiceDB") {
    $logFolder = "AppServiceSQLServer"
    $azpkg = "MSSQL"
    $rg = "appservice-sql"
    $skipMySQL = $null
    $skipMSSQL = $null
}

if (($skipMySQL -eq $true) -or ($skipMSSQL -eq $true) -or ($skipAppService -eq $true)) {
    $skipRP = $true
}
else {
    $skipRP = $false
}

### SET LOG LOCATION ###
$logName = $logFolder
$progressName = $logFolder
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
            if ($vmType -ne "AppServiceFS") {
                $ubuntuImageJobCheck = CheckProgress -progressStage "UbuntuServerImage"
                while ($ubuntuImageJobCheck -ne "Complete") {
                    Write-Verbose -Message "The UbuntuServerImage stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 20
                    $ubuntuImageJobCheck = CheckProgress -progressStage "UbuntuServerImage"
                    if ($ubuntuImageJobCheck -eq "Failed") {
                        throw "The UbuntuServerImage stage of the process has failed. This should fully complete before the database VMs can be deployed. Check the UbuntuServerImage log, ensure that step is completed first, and rerun."
                    }
                }
            }
            elseif ($vmType -eq "AppServiceFS") {
                $serverFullJobCheck = CheckProgress -progressStage "ServerFullImage"
                while ($serverFullJobCheck -ne "Complete") {
                    Write-Verbose -Message "The ServerFullImage stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 20
                    $serverFullJobCheck = CheckProgress -progressStage "ServerFullImage"
                    if ($serverFullJobCheck -eq "Failed") {
                        throw "The ServerFullImage stage of the process has failed. This should fully complete before the File Server can be deployed. Check the ServerFullImage log, ensure that step is completed first, and rerun."
                    }
                }
            }
            # Need to ensure this stage doesn't start before the Ubuntu Server images have been put into the PIR
            if ($vmType -eq "MySQL") {
                # Then need to confirm the gallery items are in place
                $MySQLGalleryItemJobCheck = CheckProgress -progressStage "MySQLGalleryItem"
                while ($MySQLGalleryItemJobCheck -ne "Complete") {
                    Write-Verbose -Message "The MySQLGalleryItem stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 20
                    $MySQLGalleryItemJobCheck = CheckProgress -progressStage "MySQLGalleryItem"
                    if ($MySQLGalleryItemJobCheck -eq "Failed") {
                        throw "The MySQLGalleryItem stage of the process has failed. This should fully complete before the database VMs can be deployed. Check the MySQLGalleryItem log, ensure that step is completed first, and rerun."
                    }
                }
            }
            elseif (($vmType -eq "SQLServer") -or ($vmType -eq "AppServiceDB")) {
                # Then need to confirm the gallery items are in place
                $SQLServerGalleryItemJobCheck = CheckProgress -progressStage "SQLServerGalleryItem"
                while ($SQLServerGalleryItemJobCheck -ne "Complete") {
                    Write-Verbose -Message "The SQLServerGalleryItem stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 20
                    $SQLServerGalleryItemJobCheck = CheckProgress -progressStage "SQLServerGalleryItem"
                    if ($SQLServerGalleryItemJobCheck -eq "Failed") {
                        throw "The SQLServerGalleryItem stage of the process has failed. This should fully complete before the database VMs can be deployed. Check the SQLServerGalleryItem log, ensure that step is completed first, and rerun."
                    }
                }
            }
            # Need to check if the UploadScripts stage has finished (for an partial/offline deployment)
            if (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                $uploadScriptsJobCheck = CheckProgress -progressStage "UploadScripts"
                while ($uploadScriptsJobCheck -ne "Complete") {
                    Write-Verbose -Message "The UploadScripts stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 20
                    $uploadScriptsJobCheck = CheckProgress -progressStage "UploadScripts"
                    if ($uploadScriptsJobCheck -eq "Skipped") {
                        return "The UploadScripts stage of the process has been skipped."
                    }
                    if ($uploadScriptsJobCheck -eq "Failed") {
                        throw "The UploadScripts stage of the process has failed. This should fully complete before the database VMs can be deployed. Check the UploadScripts log, ensure that step is completed first, and rerun."
                    }
                }
            }
            # Need to confirm that both DB Hosting VM deployments don't operate at exactly the same time, or there may be a conflict with creating the resource groups and other resources at the start of the deployment
            if ($vmType -eq "SQLServer") {
                if (($skipMySQL -eq $false) -and ($skipMSSQL -eq $false)) {
                    $mySQLProgressCheck = CheckProgress -progressStage "MySQLDBVM"
                    if ($mySQLProgressCheck -ne "Complete") {
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
            if (-not (Get-AzureRmResourceGroup -Name $rg -Location $azsLocation -ErrorAction SilentlyContinue)) {
                New-AzureRmResourceGroup -Name $rg -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
            }

            # Dynamically retrieve the mainTemplate.json URI from the Azure Stack Gallery to determine deployment base URI
            if ($deploymentMode -eq "Online") {
                if ($vmType -eq "AppServiceFS") {
                    $mainTemplateURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/templates/FileServer/azuredeploy.json"
                }
                else {
                    $mainTemplateURI = $(Get-AzsGalleryItem | Where-Object {$_.Name -like "ASDK.$azpkg*"}).DefinitionTemplates.DeploymentTemplateFileUris.Values | Where-Object {$_ -like "*mainTemplate.json"}
                    $scriptBaseURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/scripts/"
                }
            }
            elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                $asdkOfflineRGName = "azurestack-offline"
                $asdkOfflineStorageAccountName = "offlinestor"
                $asdkOfflineContainerName = "offlinecontainer"
                $asdkOfflineStorageAccount = Get-AzureRmStorageAccount -Name $asdkOfflineStorageAccountName -ResourceGroupName $asdkOfflineRGName -ErrorAction SilentlyContinue
                if ($vmType -eq "AppServiceFS") {
                    $templateFile = "FileServerTemplate.json"
                    $mainTemplateURI = Get-ChildItem -Path "$ASDKpath\templates" -Recurse -Include "$templateFile" | ForEach-Object { $_.FullName }
                }
                else {
                    $mainTemplateURI = $(Get-AzsGalleryItem | Where-Object {$_.Name -like "ASDK.$azpkg*"}).DefinitionTemplates.DeploymentTemplateFileUris.Values | Where-Object {$_ -like "*mainTemplate.json"}
                }
                $scriptBaseURI = ('{0}{1}/' -f $asdkOfflineStorageAccount.PrimaryEndpoints.Blob.AbsoluteUri, $asdkOfflineContainerName) -replace "https", "http"
            }

            if ($vmType -eq "MySQL") {
                Write-Verbose -Message "Creating a dedicated $vmType database VM running on Ubuntu Server 16.04 LTS for database hosting"
                New-AzureRmResourceGroupDeployment -Name "DeployMySQLHost" -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                    -vmName "mysqlhost" -adminUsername "mysqladmin" -adminPassword $secureVMpwd -mySQLPassword $secureVMpwd -allowRemoteConnections "Yes" `
                    -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "mysqlhost" `
                    -vmSize Standard_A2 -mode Incremental -scriptBaseUrl $scriptBaseURI -Verbose -ErrorAction Stop
            }
            elseif ($vmType -eq "SQLServer") {
                if ($skipMySQL -eq $true) {
                    Write-Verbose -Message "Creating a dedicated $vmType database VM running on Ubuntu Server 16.04 LTS for database hosting"
                    #if MySQL RP was skipped, DB hosting resources should be created here
                    New-AzureRmResourceGroupDeployment -Name "DeploySQLHost" -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                        -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $scriptBaseURI `
                        -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "sqlhost" `
                        -vmSize Standard_A2 -mode Incremental -Verbose -ErrorAction Stop
                }
                else {
                    Write-Verbose -Message "Creating a dedicated $vmType database VM running on Ubuntu Server 16.04 LTS for database hosting"
                    # Assume MySQL RP was deployed, and DB Hosting RG and networks were previously created
                    New-AzureRmResourceGroupDeployment -Name "DeploySQLHost" -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                        -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $scriptBaseURI `
                        -virtualNetworkNewOrExisting "existing" -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" `
                        -publicIPAddressDomainNameLabel "sqlhost" -vmSize Standard_A2 -mode Incremental -Verbose -ErrorAction Stop
                }
            }
            elseif ($vmType -eq "AppServiceFS") {
                Write-Verbose -Message "Creating a dedicated File Server on Windows Server 2016 for the App Service"
                if ($deploymentMode -eq "Online") {
                    New-AzureRmResourceGroupDeployment -Name "DeployAppServiceFileServer" -ResourceGroupName $rg -vmName "fileserver" -TemplateUri $mainTemplateURI `
                        -adminPassword $secureVMpwd -fileShareOwnerPassword $secureVMpwd -fileShareUserPassword $secureVMpwd -Mode Incremental -Verbose -ErrorAction Stop
                }
                elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                    New-AzureRmResourceGroupDeployment -Name "DeployAppServiceFileServer" -ResourceGroupName $rg -vmName "fileserver" -TemplateUri $mainTemplateURI `
                        -adminPassword $secureVMpwd -fileShareOwnerPassword $secureVMpwd -fileShareUserPassword $secureVMpwd `
                        -vmExtensionScriptLocation $scriptBaseURI -Mode Incremental -Verbose -ErrorAction Stop
                }
            }
            elseif ($vmType -eq "AppServiceDB") {
                New-AzureRmResourceGroupDeployment -Name "DeployAppServiceDB" -ResourceGroupName $rg -TemplateUri $mainTemplateURI -scriptBaseUrl $scriptBaseURI `
                    -vmName "sqlapp" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -storageAccountName "sqlappstor" `
                    -publicIPAddressDomainNameLabel "sqlapp" -publicIPAddressName "sqlapp_ip" -vmSize Standard_A2 -mode Incremental -Verbose -ErrorAction Stop
            
                # Get the FQDN of the VM
                $sqlAppServerFqdn = (Get-AzureRmPublicIpAddress -Name "sqlapp_ip" -ResourceGroupName $rg).DnsSettings.Fqdn
                        
                # Invoke the SQL Server query to turn on contained database authentication
                $sqlQuery = "sp_configure 'contained database authentication', 1;RECONFIGURE;"
                Invoke-Sqlcmd -Query "$sqlQuery" -ServerInstance "$sqlAppServerFqdn" -Username sa -Password $VMpwd -Verbose -ErrorAction Stop
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
Stop-Transcript -ErrorAction SilentlyContinue