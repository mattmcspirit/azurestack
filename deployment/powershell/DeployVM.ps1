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
    [String] $skipAppService
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

if ($vmType -eq "MySQL") {
    $logFolder = "$($vmType)DBVM"
    $azpkg = "MySQL"
    $rg = "azurestack-dbhosting"
}
elseif ($vmType -eq "SQLServer") {
    $logFolder = "$($vmType)DBVM"
    $azpkg = "MSSQL"
    $rg = "azurestack-dbhosting"
}
elseif ($vmType -eq "AppServiceFS") {
    $logFolder = "AppServiceFileServer"
    $rg = "appservice-fileshare"
}
elseif ($vmType -eq "AppServiceDB") {
    $logFolder = "AppServiceSQLServer"
    $azpkg = "MSSQL"
    $rg = "appservice-sql"
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
            if ($vmType -ne "AppServiceFS") {
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
            }
            elseif ($vmType -eq "AppServiceFS") {
                $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                $serverFullJobCheck = [array]::IndexOf($progress.Stage, "ServerFullImage")
                while (($progress[$serverFullJobCheck].Status -ne "Complete")) {
                    Write-Verbose -Message "The ServerFullImage stage of the process has not yet completed. Checking again in 10 seconds"
                    Start-Sleep -Seconds 10
                    if ($progress[$serverFullJobCheck].Status -eq "Failed") {
                        throw "The ServerFullImage stage of the process has failed. This should fully complete before the File Server can be deployed. Check the ServerFullImage log, ensure that step is completed first, and rerun."
                    }
                    $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                    $serverFullJobCheck = [array]::IndexOf($progress.Stage, "ServerFullImage")
                }
            }
            # Need to ensure this stage doesn't start before the Ubuntu Server images have been put into the PIR
            if ($vmType -eq "MySQL") {
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
            elseif (($vmType -eq "SQLServer") -or ($vmType -eq "AppServiceDB")) {
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
            if ($vmType -eq "SQLServer") {
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
            if (-not (Get-AzureRmResourceGroup -Name $rg -Location $azsLocation -ErrorAction SilentlyContinue)) {
                New-AzureRmResourceGroup -Name $rg -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
            }

            # Dynamically retrieve the mainTemplate.json URI from the Azure Stack Gallery to determine deployment base URI
            if ($deploymentMode -eq "Online") {
                if ($vmType -eq "AppServiceFS") {
                    $mainTemplateURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/FileServer/azuredeploy.json"
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
                    -vmSize Standard_A3 -mode Incremental -scriptBaseUrl $scriptBaseURI -Verbose -ErrorAction Stop
            }
            elseif ($vmType -eq "SQLServer") {
                if ($skipMySQL -eq $true) {
                    Write-Verbose -Message "Creating a dedicated $vmType database VM running on Ubuntu Server 16.04 LTS for database hosting"
                    #if MySQL RP was skipped, DB hosting resources should be created here
                    New-AzureRmResourceGroupDeployment -Name "DeploySQLHost" -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                        -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $scriptBaseURI `
                        -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "sqlhost" `
                        -vmSize Standard_A3 -mode Incremental -Verbose -ErrorAction Stop
                }
                else {
                    Write-Verbose -Message "Creating a dedicated $vmType database VM running on Ubuntu Server 16.04 LTS for database hosting"
                    # Assume MySQL RP was deployed, and DB Hosting RG and networks were previously created
                    New-AzureRmResourceGroupDeployment -Name "DeploySQLHost" -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
                        -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -scriptBaseUrl $scriptBaseURI `
                        -virtualNetworkNewOrExisting "existing" -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" `
                        -publicIPAddressDomainNameLabel "sqlhost" -vmSize Standard_A3 -mode Incremental -Verbose -ErrorAction Stop
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
                New-AzureRmResourceGroupDeployment -Name "DeployAppServiceDB" -ResourceGroupName $rg -TemplateUri $mainTemplateURI -scriptBaseUrl $scriptBaseURI `
                    -vmName "sqlapp" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -storageAccountName "sqlappstor" `
                    -publicIPAddressDomainNameLabel "sqlapp" -publicIPAddressName "sqlapp_ip" -vmSize Standard_A3 -mode Incremental -Verbose -ErrorAction Stop
            
                # Get the FQDN of the VM
                $sqlAppServerFqdn = (Get-AzureRmPublicIpAddress -Name "sqlapp_ip" -ResourceGroupName $rg).DnsSettings.Fqdn
                        
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