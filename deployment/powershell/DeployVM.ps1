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
    [String] $customDomainSuffix,

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
    $azpkg = "MySQL8"
    $deploymentName = "DeployMySQLHost"
    $rg = "azurestack-dbhosting"
    if ($skipMySQL -eq $true) {
        $skipRP = $true
    }
}
elseif ($vmType -eq "SQLServer") {
    $logFolder = "$($vmType)DBVM"
    $azpkg = "MSSQL"
    $deploymentName = "DeploySQLHost"
    $rg = "azurestack-dbhosting"
    if ($skipMSSQL -eq $true) {
        $skipRP = $true
    }
}
elseif ($vmType -eq "AppServiceFS") {
    $logFolder = "AppServiceFileServer"
    $deploymentName = "DeployAppServiceFileServer"
    $rg = "appservice-fileshare"
    if ($skipAppService -eq $true) {
        $skipRP = $true
    }
}
elseif ($vmType -eq "AppServiceDB") {
    $logFolder = "AppServiceSQLServer"
    $deploymentName = "DeployAppServiceDB"
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

            $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            $ArmEndpoint = "https://management.$customDomainSuffix"
            Add-AzureRMEnvironment -Name "AzureStackUser" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop

            <#Write-Host "Importing Azure.Storage and AzureRM.Storage modules"
            Import-Module -Name Azure.Storage -RequiredVersion 4.5.0
            Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4
            #>

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
                $serverCore2016JobCheck = CheckProgress -progressStage "ServerCore2016Image"
                while ($serverCore2016JobCheck -ne "Complete") {
                    Write-Host "The ServerCore2016Image stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 20
                    $serverCore2016JobCheck = CheckProgress -progressStage "ServerCore2016Image"
                    if ($serverCore2016JobCheck -eq "Failed") {
                        throw "The ServerCore2016Image stage of the process has failed. This should fully complete before the File Server can be deployed. Check the ServerFullImage log, ensure that step is completed first, and rerun."
                    }
                }
            }
            # Need to ensure this stage doesn't start before the Ubuntu Server images have been put into the PIR
            if ($vmType -eq "MySQL") {
                # Then need to confirm the gallery items are in place
                $MySQLGalleryItemJobCheck = CheckProgress -progressStage "MySQL80GalleryItem"
                while ($MySQLGalleryItemJobCheck -ne "Complete") {
                    Write-Host "The MySQL80GalleryItem stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 20
                    $MySQLGalleryItemJobCheck = CheckProgress -progressStage "MySQL80GalleryItem"
                    if ($MySQLGalleryItemJobCheck -eq "Failed") {
                        throw "The MySQL80GalleryItem stage of the process has failed. This should fully complete before the database VMs can be deployed. Check the MySQL80GalleryItem log, ensure that step is completed first, and rerun."
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
            if ($serialMode -eq $false) {
                if ($vmType -eq "SQLServer") {
                    if (($skipMySQL -eq $false) -and ($skipMSSQL -eq $false)) {
                        $mySQLProgressCheck = CheckProgress -progressStage "MySQLDBVM"
                        if ($mySQLProgressCheck -ne "Complete") {
                            ### Login to Azure Stack ###
                            Add-AzureRmAccount -EnvironmentName "AzureStackUser" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                            $sub = Get-AzureRmSubscription | Where-Object { $_.Name -eq '*ADMIN DB HOSTS' }
                            Set-AzureRMContext -Subscription $sub.SubscriptionId -NAME $sub.Name -Force | Out-Null
                            $subID = $sub.SubscriptionId
                            #$azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
                            #$subID = $azureContext.Subscription.Id
                            Write-Host "Current subscription ID is: $subID"
                            while (!$(Get-AzureRmVirtualNetwork -ResourceGroupName "azurestack-dbhosting" -Name "dbhosting_vnet" -ErrorAction SilentlyContinue | Get-AzureRmVirtualNetworkSubnetConfig).ProvisioningState -eq "Succeeded") {
                                Write-Host "Waiting for deployment of database virtual network and subnet before continuing with deployment of SQL Server for DB hosting. Checking again in 10 seconds."
                                Start-Sleep 10
                            }
                            Write-Host "To avoid deployment conflicts, delaying the SQL Server VM deployment by 2 minutes to allow initial resources to be created"
                            Start-Sleep -Seconds 120
                        }
                    }
                }
            }
            # If the user had chosen to deploy with SerialMode, this will stagger the VM deployments, one after another.
            if ($serialMode -eq $true) {
                if ($vmType -eq "SQLServer") {
                    $mySQLProgressCheck = CheckProgress -progressStage "MySQLDBVM"
                    while ($mySQLProgressCheck -eq "Incomplete") {
                        Write-Host "The MySQLDBVM stage of the process has not yet completed. This should complete first in a serialMode deployment. Checking again in 60 seconds"
                        Start-Sleep -Seconds 60
                        $mySQLProgressCheck = CheckProgress -progressStage "MySQLDBVM"
                        if ($mySQLProgressCheck -eq "Failed") {
                            Write-Host "MySQLDBVM deployment seems to have failed, but this doesn't affect the SQL Server VM Deployment. Process can continue."
                            BREAK
                        }
                    }
                }
                elseif ($vmType -eq "AppServiceDB") {
                    $msSQLProgressCheck = CheckProgress -progressStage "SQLServerDBVM"
                    while (($msSQLProgressCheck -eq "Incomplete")) {
                        Write-Host "The SQLServerDBVM stage of the process has not yet completed. This should complete first in a serialMode deployment. Checking again in 60 seconds"
                        Start-Sleep -Seconds 60
                        $msSQLProgressCheck = CheckProgress -progressStage "SQLServerDBVM"
                        if ($msSQLProgressCheck -eq "Failed") {
                            Write-Host "SQLServerDBVM deployment seems to have failed, but this doesn't affect the App Service DB VM Deployment. Process can continue."
                            BREAK
                        }
                    }
                }
                elseif ($vmType -eq "AppServiceFS") {
                    $sqlRPProgressCheck = CheckProgress -progressStage "SQLServerRP"
                    while (($sqlRPProgressCheck -eq "Incomplete")) {
                        Write-Host "The SQLServerRP stage of the process has not yet completed. This should complete first in a serialMode deployment. Checking again in 60 seconds"
                        Start-Sleep -Seconds 60
                        $sqlRPProgressCheck = CheckProgress -progressStage "SQLServerRP"
                        if ($sqlRPProgressCheck -eq "Failed") {
                            Write-Host "SQLServerRP deployment seems to have failed, but this doesn't affect the App Service File Server VM Deployment. Process can continue."
                            BREAK
                        }
                    }
                }
            }

            # Dynamically retrieve the mainTemplate.json URI from the Azure Stack Gallery to determine deployment base URI
            if ($deploymentMode -eq "Online") {
                if ($vmType -eq "AppServiceFS") {
                    Write-Host "Downloading the template required for the File Server"
                    $mainTemplateURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/templates/FileServer/azuredeploy.json"
                    $scriptBaseURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/templates/FileServer/scripts/"
                }
                else {
                    Write-Host "Getting the URIs for all AZPKG files for deployment of resources"
                    ### Login to Azure Stack ###
                    Write-Host "Logging into Azure Stack into the admin space, to grab information"
                    Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    $azsLocation = (Get-AzureRmLocation).DisplayName
                    $mainTemplateURI = $(Get-AzsGalleryItem | Where-Object { $_.Name -like "AzureStackPOC.$azpkg*" }).DefinitionTemplates.DeploymentTemplateFileUris.Values | Where-Object { $_ -like "*mainTemplate.json" }
                    $scriptBaseURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/scripts/"
                }
            }
            elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                Write-Host "Clearing previous Azure/Azure Stack logins"
                Get-AzureRmContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzureRmAccount | Out-Null
                Clear-AzureRmContext -Scope CurrentUser -Force
                Write-Host "Logging into Azure Stack into the user space, to grab the location of the scripts and packages"
                Add-AzureRmAccount -EnvironmentName "AzureStackUser" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                Write-Host "Selecting the *ADMIN OFFLINE SCRIPTS subscription"
                $sub = Get-AzureRmSubscription | Where-Object { $_.Name -eq '*ADMIN OFFLINE SCRIPTS' }
                Set-AzureRMContext -Subscription $sub.SubscriptionId -NAME $sub.Name -Force | Out-Null
                $subID = $sub.SubscriptionId
                #$azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
                #$subID = $azureContext.Subscription.Id
                Write-Host "Current subscription ID is: $subID"
                $asdkOfflineRGName = "azurestack-offlinescripts"
                $asdkOfflineStorageAccountName = "offlinestor"
                $asdkOfflineContainerName = "offlinecontainer"
                $asdkOfflineStorageAccount = Get-AzureRmStorageAccount -Name $asdkOfflineStorageAccountName -ResourceGroupName $asdkOfflineRGName -ErrorAction SilentlyContinue
                if ($vmType -eq "AppServiceFS") {
                    Write-Host "Downloading the template required for the File Server"
                    $templateFile = "FileServerTemplate.json"
                    $mainTemplateURI = Get-ChildItem -Path "$ASDKpath\templates" -Recurse -Include "$templateFile" | ForEach-Object { $_.FullName }
                }
                else {
                    Write-Host "Getting the URIs for all AZPKG files for deployment of resources"
                    Write-Host "Logging into Azure Stack into the admin space, to grab information"
                    Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    $mainTemplateURI = $(Get-AzsGalleryItem | Where-Object { $_.Name -like "AzureStackPOC.$azpkg*" }).DefinitionTemplates.DeploymentTemplateFileUris.Values | Where-Object { $_ -like "*mainTemplate.json" }
                }
                $scriptBaseURI = ('{0}{1}/' -f $asdkOfflineStorageAccount.PrimaryEndpoints.Blob, $asdkOfflineContainerName) -replace "https", "http"
            }
            ### Login to Azure Stack ###
            Write-Host "Clearing previous Azure/Azure Stack logins"
            Get-AzureRmContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force
            
            if (($vmType -eq "SQLServer") -or ($vmType -eq "MySQL")) {
                Write-Host "Logging into Azure Stack into the user space, to create the backend resources"
                Add-AzureRmAccount -EnvironmentName "AzureStackUser" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                $azsLocation = (Get-AzureRmLocation).DisplayName
                Write-Host "Selecting the *ADMIN DB HOSTS subscription"
                $sub = Get-AzureRmSubscription | Where-Object { $_.Name -eq '*ADMIN DB HOSTS' }
                Set-AzureRMContext -Subscription $sub.SubscriptionId -NAME $sub.Name -Force | Out-Null
                $subID = $sub.SubscriptionId
                #$azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
                #$subID = $azureContext.Subscription.Id
                Write-Host "Current subscription ID is: $subID"
            }
            elseif (($vmType -eq "AppServiceDB") -or ($vmType -eq "AppServiceFS")) {
                Write-Host "Logging into Azure Stack into the admin space, to create the backend resources"
                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                $azsLocation = (Get-AzureRmLocation).DisplayName
            }
                        
            Write-Host "Creating a dedicated Resource Group for all $vmType hosting assets"
            if (-not (Get-AzureRmResourceGroup -Name $rg -Location $azsLocation -ErrorAction SilentlyContinue)) {
                New-AzureRmResourceGroup -Name $rg -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
            }

            # Need to insert a while loop to try installation 3 times with try/catch
            $vmDeployAttempt = 1
            while (!(Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Succeeded" }) -and ($vmDeployAttempt -le 3)) {
                try {
                    Write-Host "This is deployment attempt $vmDeployAttempt for deploying the $vmType VM."
                    if ($vmType -eq "MySQL") {
                        Write-Host "Creating a dedicated $vmType database VM running on Ubuntu Server for database hosting"
                        if (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Succeeded" }) {
                            Write-Host "$vmType database VM has already been deployed - Deployment completed successfully"
                        }
                        elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Running" }) {
                            Write-Host "$vmType database VM is currently being deployed"
                            While (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Running" }) {
                                Write-Host "Checking $vmType database VM deployment in 20 seconds"
                                Start-Sleep -Seconds 20
                            }
                        }
                        elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Failed" }) {
                            Write-Host "Resource group currently in a failed state - cleaning up"
                            Get-AzureRmResource -ResourceGroupName "azurestack-dbhosting" | `
                                Where-Object { ($_.Name -like "mysql*") -and ($_.ResourceType -like "*VirtualMachines") } -ErrorAction SilentlyContinue | Remove-AzureRmResource -Force -Verbose
                            Get-AzureRmResource -ResourceGroupName "azurestack-dbhosting" | `
                                Where-Object { $_.Name -like "mysql*" } -ErrorAction SilentlyContinue | Remove-AzureRmResource -Force -Verbose
                            Remove-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName
                            Start-Sleep -Seconds 30
                            Write-Host "Starting deployment again..."
                            New-AzureRmResourceGroupDeployment -Name $deploymentName -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                                -vmName "mysqlhost" -adminUsername "mysqladmin" -adminPassword $secureVMpwd -mySQLPassword $secureVMpwd -allowRemoteConnections "Yes" `
                                -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "mysqlhost" `
                                -vmSize Standard_F1s -managedDiskAccountType "Premium_LRS" -mode Incremental -scriptBaseUrl $scriptBaseURI -Verbose -ErrorAction Stop
                        }
                        elseif (!(Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue)) {
                            Write-Host "No previous deployment found - starting deployment of $vmType database host"
                            New-AzureRmResourceGroupDeployment -Name $deploymentName -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                                -vmName "mysqlhost" -adminUsername "mysqladmin" -adminPassword $secureVMpwd -mySQLPassword $secureVMpwd -allowRemoteConnections "Yes" `
                                -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "mysqlhost" `
                                -vmSize Standard_F1s -managedDiskAccountType "Premium_LRS" -mode Incremental -scriptBaseUrl $scriptBaseURI -Verbose -ErrorAction Stop
                        }
                    }
                    elseif ($vmType -eq "SQLServer") {
                        Write-Host "Creating a dedicated $vmType database VM running on Ubuntu Server for database hosting"
                        if (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Succeeded" }) {
                            Write-Host "$vmType database VM has already been deployed - Deployment completed successfully"
                        }
                        elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Running" }) {
                            Write-Host "$vmType database VM is currently being deployed"
                            While (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Running" }) {
                                Write-Host "Checking $vmType database VM deployment in 20 seconds"
                                Start-Sleep -Seconds 20
                            }
                        }
                        elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Failed" }) {
                            Write-Host "Resource group currently in a failed state - cleaning up"
                            Get-AzureRmResource -ResourceGroupName "azurestack-dbhosting" | `
                                Where-Object { ($_.Name -like "sql*") -and ($_.ResourceType -like "*VirtualMachines") } -ErrorAction SilentlyContinue | Remove-AzureRmResource -Force -Verbose
                            Get-AzureRmResource -ResourceGroupName "azurestack-dbhosting" | `
                                Where-Object { $_.Name -like "sql*" } -ErrorAction SilentlyContinue | Remove-AzureRmResource -Force -Verbose
                            Remove-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName
                            Start-Sleep -Seconds 30
                            Write-Host "Starting deployment again..."
                            if ($skipMySQL -eq $true) {
                                #if MySQL RP was skipped, DB hosting resources should be created here
                                New-AzureRmResourceGroupDeployment -Name $deploymentName -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                                    -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $scriptBaseURI `
                                    -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "sqlhost" `
                                    -vmSize Standard_F1s -managedDiskAccountType "Premium_LRS" -mode Incremental -Verbose -ErrorAction Stop
                            }
                            else {
                                # Assume MySQL RP was deployed, and DB Hosting RG and networks were previously created
                                New-AzureRmResourceGroupDeployment -Name $deploymentName -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                                    -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $scriptBaseURI `
                                    -virtualNetworkNewOrExisting "existing" -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" `
                                    -publicIPAddressDomainNameLabel "sqlhost" -vmSize Standard_F1s -managedDiskAccountType "Premium_LRS" -mode Incremental -Verbose -ErrorAction Stop
                            }
                        }
                        elseif (!(Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue)) {
                            Write-Host "No previous deployment found - starting deployment of $vmType database host"
                            if ($skipMySQL -eq $true) {
                                #if MySQL RP was skipped, DB hosting resources should be created here
                                New-AzureRmResourceGroupDeployment -Name $deploymentName -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                                    -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $scriptBaseURI `
                                    -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "sqlhost" `
                                    -vmSize Standard_F1s -mode Incremental -Verbose -ErrorAction Stop
                            }
                            else {
                                # Assume MySQL RP was deployed, and DB Hosting RG and networks were previously created
                                New-AzureRmResourceGroupDeployment -Name $deploymentName -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                                    -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $scriptBaseURI `
                                    -virtualNetworkNewOrExisting "existing" -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" `
                                    -publicIPAddressDomainNameLabel "sqlhost" -vmSize Standard_F1s -managedDiskAccountType "Premium_LRS" -mode Incremental -Verbose -ErrorAction Stop
                            }
                        }
                    }
                    elseif ($vmType -eq "AppServiceFS") {
                        Write-Host "Creating a dedicated File Server on Windows Server 2016 for the App Service"
                        if (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Succeeded" }) {
                            Write-Host "File Server has already been deployed - Deployment completed successfully"
                        }
                        elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Running" }) {
                            Write-Host "File Server is currently being deployed"
                            While (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Running" }) {
                                Write-Host "Checking File Server deployment in 20 seconds"
                                Start-Sleep -Seconds 20
                            }
                        }
                        elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Failed" }) {
                            Write-Host "Resource group currently in a failed state - cleaning up"
                            Remove-AzureRmResourceGroup -Name $rg -Force
                            Start-Sleep -Seconds 30
                            Write-Host "Starting deployment again..."
                            Write-Host "Creating a dedicated Resource Group for all assets"
                            if (-not (Get-AzureRmResourceGroup -Name $rg -Location $azsLocation -ErrorAction SilentlyContinue)) {
                                New-AzureRmResourceGroup -Name $rg -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
                            }
                            New-AzureRmResourceGroupDeployment -Name $deploymentName -ResourceGroupName $rg -vmName "fileserver" -TemplateUri $mainTemplateURI `
                                -adminPassword $secureVMpwd -fileShareOwnerPassword $secureVMpwd -fileShareUserPassword $secureVMpwd `
                                -vmExtensionScriptLocation $scriptBaseURI -Mode Incremental -Verbose -ErrorAction Stop
                        }
                        elseif (!(Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue)) {
                            Write-Host "No previous deployment found - starting deployment of File Server"
                            Write-Host "Creating a dedicated Resource Group for all File Server assets"
                            if (-not (Get-AzureRmResourceGroup -Name $rg -Location $azsLocation -ErrorAction SilentlyContinue)) {
                                New-AzureRmResourceGroup -Name $rg -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
                            }
                            Write-Host "Starting deployment of the File Server for App Service"
                            New-AzureRmResourceGroupDeployment -Name $deploymentName -ResourceGroupName $rg -vmName "fileserver" -TemplateUri $mainTemplateURI `
                                -adminPassword $secureVMpwd -fileShareOwnerPassword $secureVMpwd -fileShareUserPassword $secureVMpwd `
                                -vmExtensionScriptLocation $scriptBaseURI -Mode Incremental -Verbose -ErrorAction Stop
                        }
                    }
                    elseif ($vmType -eq "AppServiceDB") {
                        Write-Host "Creating a dedicated database host for the App Service"
                        if (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Succeeded" }) {
                            Write-Host "App Service database host has already been deployed - Deployment completed successfully"
                        }
                        elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Running" }) {
                            Write-Host "App Service database host is currently being deployed"
                            While (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Running" }) {
                                Write-Host "Checking App Service database host deployment in 20 seconds"
                                Start-Sleep -Seconds 20
                            }
                        }
                        elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Failed" }) {
                            Write-Host "Resource group currently in a failed state - cleaning up"
                            Remove-AzureRmResourceGroup -Name $rg -Force
                            Start-Sleep -Seconds 30
                            Write-Host "Starting deployment again..."
                            Write-Host "Creating a dedicated Resource Group for all assets"
                            if (-not (Get-AzureRmResourceGroup -Name $rg -Location $azsLocation -ErrorAction SilentlyContinue)) {
                                New-AzureRmResourceGroup -Name $rg -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
                            }
                            New-AzureRmResourceGroupDeployment -Name $deploymentName -ResourceGroupName $rg -TemplateUri $mainTemplateURI -scriptBaseUrl $scriptBaseURI `
                                -vmName "sqlapp" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd `
                                -publicIPAddressDomainNameLabel "sqlapp" -publicIPAddressName "sqlapp_ip" -vmSize Standard_F1s `
                                -managedDiskAccountType "Premium_LRS" -mode Incremental -Verbose -ErrorAction Stop
                        }
                        elseif (!(Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue)) {
                            Write-Host "No previous deployment found - creating a dedicated database host for the App Service"
                            Write-Host "Creating a dedicated Resource Group for all assets"
                            if (-not (Get-AzureRmResourceGroup -Name $rg -Location $azsLocation -ErrorAction SilentlyContinue)) {
                                New-AzureRmResourceGroup -Name $rg -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
                            }
                            New-AzureRmResourceGroupDeployment -Name $deploymentName -ResourceGroupName $rg -TemplateUri $mainTemplateURI -scriptBaseUrl $scriptBaseURI `
                                -vmName "sqlapp" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd `
                                -publicIPAddressDomainNameLabel "sqlapp" -publicIPAddressName "sqlapp_ip" -vmSize Standard_F1s `
                                -managedDiskAccountType "Premium_LRS" -mode Incremental -Verbose -ErrorAction Stop
                        }
                        # Get the FQDN of the VM
                        Write-Host "Getting SQL Server FQDN for use with App Service"
                        $sqlAppServerFqdn = (Get-AzureRmPublicIpAddress -Name "sqlapp_ip" -ResourceGroupName $rg).DnsSettings.Fqdn
                        Write-Host "SQL Server located at: $sqlAppServerFqdn"
                                
                        # Invoke the SQL Server query to turn on contained database authentication
                        Write-Host "Configuring SQL Server for contained database authentication"
                        $sqlQuery = "sp_configure 'contained database authentication', 1;RECONFIGURE;"
                        Invoke-Sqlcmd -Query "$sqlQuery" -ServerInstance "$sqlAppServerFqdn" -Username sa -Password $VMpwd -Verbose -ErrorAction Stop
                    }
                }
                catch {
                    Write-Host "Deployment failed."
                    Write-Host "$_.Exception.Message"
                    $vmDeployAttempt++
                    Write-Host "Attempting deployment process again in 30 seconds"
                    Start-Sleep -Seconds 30
                }
            }

            if (!(Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name $deploymentName -ErrorAction SilentlyContinue | Where-Object { $_.ProvisioningState -eq "Succeeded" }) -and ($vmDeployAttempt -gt 3)) {
                throw "Deploying the $vmType VM failed after 3 attempts. Exiting process."
                Set-Location $ScriptLocation
                return
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