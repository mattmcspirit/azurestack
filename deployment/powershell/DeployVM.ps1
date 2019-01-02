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
    [String] $tableName,

    [Parameter(Mandatory = $false)]
    [String] $serialMode
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

$skipRP = $false
if ($vmType -eq "MySQL") {
    $logFolder = "$($vmType)DBVM"
    $azpkg = "MySQL"
    $rg = "azurestack-dbhosting"
    if ($skipMySQL -eq $true) {
        $skipRP = $true
    }
}
elseif ($vmType -eq "SQLServer") {
    $logFolder = "$($vmType)DBVM"
    $azpkg = "MSSQL"
    $rg = "azurestack-dbhosting"
    if ($skipMSSQL -eq $true) {
        $skipRP = $true
    }
}
elseif ($vmType -eq "AppServiceFS") {
    $logFolder = "AppServiceFileServer"
    $rg = "appservice-fileshare"
    if ($skipAppService -eq $true) {
        $skipRP = $true
    }
}
elseif ($vmType -eq "AppServiceDB") {
    $logFolder = "AppServiceSQLServer"
    $azpkg = "MSSQL"
    $rg = "appservice-sql"
    if ($skipAppService -eq $true) {
        $skipRP = $true
    }
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

            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force
            Disable-AzureRMContextAutosave -Scope CurrentUser

            Import-Module -Name Azure.Storage -RequiredVersion 4.5.0 -Verbose
            Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4 -Verbose

            if ($vmType -ne "AppServiceFS") {
                $ubuntuImageJobCheck = CheckProgress -progressStage "UbuntuServerImage"
                while ($ubuntuImageJobCheck -ne "Complete") {
                    Write-Host "The UbuntuServerImage stage of the process has not yet completed. Checking again in 20 seconds"
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
                    Write-Host "The ServerFullImage stage of the process has not yet completed. Checking again in 20 seconds"
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
                    Write-Host "The MySQLGalleryItem stage of the process has not yet completed. Checking again in 20 seconds"
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
                    Write-Host "The SQLServerGalleryItem stage of the process has not yet completed. Checking again in 20 seconds"
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
                    Write-Host "The UploadScripts stage of the process has not yet completed. Checking again in 20 seconds"
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
                        Write-Host "To avoid deployment conflicts, delaying the SQL Server VM deployment by 2 minutes to allow initial resources to be created"
                        Start-Sleep -Seconds 120
                    }
                }
            }
            ### Login to Azure Stack ###
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

            Write-Host "Creating a dedicated Resource Group for all database hosting assets"
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
                $scriptBaseURI = ('{0}{1}/' -f $asdkOfflineStorageAccount.PrimaryEndpoints.Blob, $asdkOfflineContainerName) -replace "https", "http"
            }

            if ($vmType -eq "MySQL") {
                Write-Host "Creating a dedicated $vmType database VM running on Ubuntu Server for database hosting"
                if (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployMySQLHost" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Succeeded"}) {
                    Write-Host "$vmType database VM has already been deployed - Deployment completed successfully"
                }
                elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployMySQLHost" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Running"}) {
                    Write-Host "$vmType database VM is currently being deployed"
                    While (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployMySQLHost" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Running"}) {
                        Write-Host "Checking $vmType database VM deployment in 20 seconds"
                        Start-Sleep -Seconds 20
                    }
                }
                elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployMySQLHost" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Failed"}) {
                    Write-Host "Resource group currently in a failed state - cleaning up"
                    Get-AzureRmResource -ResourceGroupName "azurestack-dbhosting" | Where-Object {$_.Name -like "mysql*"} -ErrorAction SilentlyContinue | Remove-AzureRmResource -Force -Verbose
                    Remove-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployMySQLHost"
                    Start-Sleep -Seconds 30
                    Write-Host "Starting deployment again..."
                    New-AzureRmResourceGroupDeployment -Name "DeployMySQLHost" -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                        -vmName "mysqlhost" -adminUsername "mysqladmin" -adminPassword $secureVMpwd -mySQLPassword $secureVMpwd -allowRemoteConnections "Yes" `
                        -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "mysqlhost" `
                        -vmSize Standard_A1_v2 -mode Incremental -scriptBaseUrl $scriptBaseURI -Verbose -ErrorAction Stop
                }
                elseif (!(Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployMySQLHost" -ErrorAction SilentlyContinue)) {
                    Write-Host "No previous deployment found - starting deployment of $vmType database host"
                    New-AzureRmResourceGroupDeployment -Name "DeployMySQLHost" -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                        -vmName "mysqlhost" -adminUsername "mysqladmin" -adminPassword $secureVMpwd -mySQLPassword $secureVMpwd -allowRemoteConnections "Yes" `
                        -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "mysqlhost" `
                        -vmSize Standard_A1_v2 -mode Incremental -scriptBaseUrl $scriptBaseURI -Verbose -ErrorAction Stop
                }
            }
            elseif ($vmType -eq "SQLServer") {
                Write-Host "Creating a dedicated $vmType database VM running on Ubuntu Server for database hosting"
                if (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeploySQLHost" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Succeeded"}) {
                    Write-Host "$vmType database VM has already been deployed - Deployment completed successfully"
                }
                elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeploySQLHost" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Running"}) {
                    Write-Host "$vmType database VM is currently being deployed"
                    While (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeploySQLHost" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Running"}) {
                        Write-Host "Checking $vmType database VM deployment in 20 seconds"
                        Start-Sleep -Seconds 20
                    }
                }
                elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeploySQLHost" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Failed"}) {
                    Write-Host "Resource group currently in a failed state - cleaning up"
                    Get-AzureRmResource -ResourceGroupName "azurestack-dbhosting" | Where-Object {$_.Name -like "sql*"} -ErrorAction SilentlyContinue | Remove-AzureRmResource -Force -Verbose
                    Remove-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeploySQLHost"
                    Start-Sleep -Seconds 30
                    Write-Host "Starting deployment again..."
                    if ($skipMySQL -eq $true) {
                        #if MySQL RP was skipped, DB hosting resources should be created here
                        New-AzureRmResourceGroupDeployment -Name "DeploySQLHost" -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                            -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $scriptBaseURI `
                            -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "sqlhost" `
                            -vmSize Standard_A1_v2 -mode Incremental -Verbose -ErrorAction Stop
                    }
                    else {
                        # Assume MySQL RP was deployed, and DB Hosting RG and networks were previously created
                        New-AzureRmResourceGroupDeployment -Name "DeploySQLHost" -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                            -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $scriptBaseURI `
                            -virtualNetworkNewOrExisting "existing" -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" `
                            -publicIPAddressDomainNameLabel "sqlhost" -vmSize Standard_A1_v2 -mode Incremental -Verbose -ErrorAction Stop
                    }
                }
                elseif (!(Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeploySQLHost" -ErrorAction SilentlyContinue)) {
                    Write-Host "No previous deployment found - starting deployment of $vmType database host"
                    if ($skipMySQL -eq $true) {
                        #if MySQL RP was skipped, DB hosting resources should be created here
                        New-AzureRmResourceGroupDeployment -Name "DeploySQLHost" -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                            -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $scriptBaseURI `
                            -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "sqlhost" `
                            -vmSize Standard_A1_v2 -mode Incremental -Verbose -ErrorAction Stop
                    }
                    else {
                        # Assume MySQL RP was deployed, and DB Hosting RG and networks were previously created
                        New-AzureRmResourceGroupDeployment -Name "DeploySQLHost" -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                            -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $scriptBaseURI `
                            -virtualNetworkNewOrExisting "existing" -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" `
                            -publicIPAddressDomainNameLabel "sqlhost" -vmSize Standard_A1_v2 -mode Incremental -Verbose -ErrorAction Stop
                    }
                }
            }
            elseif ($vmType -eq "AppServiceFS") {
                Write-Host "Creating a dedicated File Server on Windows Server 2016 for the App Service"
                if (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployAppServiceFileServer" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Succeeded"}) {
                    Write-Host "File Server has already been deployed - Deployment completed successfully"
                }
                elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployAppServiceFileServer" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Running"}) {
                    Write-Host "File Server is currently being deployed"
                    While (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployAppServiceFileServer" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Running"}) {
                        Write-Host "Checking File Server deployment in 20 seconds"
                        Start-Sleep -Seconds 20
                    }
                }
                elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployAppServiceFileServer" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Failed"}) {
                    Write-Host "Resource group currently in a failed state - cleaning up"
                    Remove-AzureRmResourceGroup -Name $rg -Force
                    Start-Sleep -Seconds 30
                    Write-Host "Starting deployment again..."
                    if ($deploymentMode -eq "Online") {
                        New-AzureRmResourceGroupDeployment -Name "DeployAppServiceFileServer" -ResourceGroupName $rg -vmName "fileserver" -TemplateUri $mainTemplateURI `
                            -adminPassword $secureVMpwd -fileShareOwnerPassword $secureVMpwd -fileShareUserPassword $secureVMpwd -Mode Incremental -Verbose -ErrorAction Stop
                    }
                    elseif ($deploymentMode -ne "Online") {
                        New-AzureRmResourceGroupDeployment -Name "DeployAppServiceFileServer" -ResourceGroupName $rg -vmName "fileserver" -TemplateUri $mainTemplateURI `
                            -adminPassword $secureVMpwd -fileShareOwnerPassword $secureVMpwd -fileShareUserPassword $secureVMpwd `
                            -vmExtensionScriptLocation $scriptBaseURI -Mode Incremental -Verbose -ErrorAction Stop
                    }
                }
                elseif (!(Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployAppServiceFileServer" -ErrorAction SilentlyContinue)) {
                    Write-Host "No previous deployment found - starting deployment of File Server"
                    if ($deploymentMode -eq "Online") {
                        New-AzureRmResourceGroupDeployment -Name "DeployAppServiceFileServer" -ResourceGroupName $rg -vmName "fileserver" -TemplateUri $mainTemplateURI `
                            -adminPassword $secureVMpwd -fileShareOwnerPassword $secureVMpwd -fileShareUserPassword $secureVMpwd -Mode Incremental -Verbose -ErrorAction Stop
                    }
                    elseif ($deploymentMode -ne "Online") {
                        New-AzureRmResourceGroupDeployment -Name "DeployAppServiceFileServer" -ResourceGroupName $rg -vmName "fileserver" -TemplateUri $mainTemplateURI `
                            -adminPassword $secureVMpwd -fileShareOwnerPassword $secureVMpwd -fileShareUserPassword $secureVMpwd `
                            -vmExtensionScriptLocation $scriptBaseURI -Mode Incremental -Verbose -ErrorAction Stop
                    }
                }
            }
            elseif ($vmType -eq "AppServiceDB") {
                Write-Host "Creating a dedicated database host for the App Service"
                if (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployAppServiceDB" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Succeeded"}) {
                    Write-Host "App Service database host has already been deployed - Deployment completed successfully"
                }
                elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployAppServiceDB" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Running"}) {
                    Write-Host "App Service database host is currently being deployed"
                    While (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployAppServiceDB" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Running"}) {
                        Write-Host "Checking App Service database host deployment in 20 seconds"
                        Start-Sleep -Seconds 20
                    }
                }
                elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployAppServiceDB" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Failed"}) {
                    Write-Host "Resource group currently in a failed state - cleaning up"
                    Remove-AzureRmResourceGroup -Name $rg -Force
                    Start-Sleep -Seconds 30
                    Write-Host "Starting deployment again..."
                    New-AzureRmResourceGroupDeployment -Name "DeployAppServiceDB" -ResourceGroupName $rg -TemplateUri $mainTemplateURI -scriptBaseUrl $scriptBaseURI `
                        -vmName "sqlapp" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -storageAccountName "sqlappstor" `
                        -publicIPAddressDomainNameLabel "sqlapp" -publicIPAddressName "sqlapp_ip" -vmSize Standard_A1_v2 -mode Incremental -Verbose -ErrorAction Stop
                }
                elseif (!(Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "DeployAppServiceDB" -ErrorAction SilentlyContinue)) {
                    Write-Host "No previous deployment found - starting deployment of File Server"
                    New-AzureRmResourceGroupDeployment -Name "DeployAppServiceDB" -ResourceGroupName $rg -TemplateUri $mainTemplateURI -scriptBaseUrl $scriptBaseURI `
                        -vmName "sqlapp" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -storageAccountName "sqlappstor" `
                        -publicIPAddressDomainNameLabel "sqlapp" -publicIPAddressName "sqlapp_ip" -vmSize Standard_A1_v2 -mode Incremental -Verbose -ErrorAction Stop
                }
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