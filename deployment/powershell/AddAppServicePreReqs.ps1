[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $azsPath,

    [parameter(Mandatory = $true)]
    [String]$downloadPath,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [Parameter(Mandatory = $true)]
    [String] $customDomainSuffix,

    [Parameter(Mandatory = $true)]
    [ValidateSet("AzureAd", "ADFS")]
    [String] $authenticationType,

    [Parameter(Mandatory = $false)]
    [String] $azureDirectoryTenantName,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [securestring] $secureVMpwd,

    [parameter(Mandatory = $true)]
    [String] $ERCSip,

    [Parameter(Mandatory = $true)]
    [String] $branch,

    [parameter(Mandatory = $true)]
    [pscredential] $azsCreds,

    [parameter(Mandatory = $true)]
    [pscredential] $pepAdminCreds,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

    [parameter(Mandatory = $false)]
    [String] $skipAppService,

    [Parameter(Mandatory = $true)]
    [String] $sqlServerInstance,

    [Parameter(Mandatory = $true)]
    [String] $databaseName,

    [Parameter(Mandatory = $true)]
    [String] $tableName,

    [parameter(Mandatory = $false)]
    [String] $certPath,

    [parameter(Mandatory = $true)]
    [securestring] $secureCertPwd,

    [parameter(Mandatory = $false)]
    [String] $multiNode,

    [Parameter(Mandatory = $true)]
    [ValidateSet("AzureChinaCloud", "AzureCloud", "AzureGermanCloud", "AzureUSGovernment")]
    [String] $azureEnvironment
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

$logFolder = "AddAppServicePreReqs"
$logName = $logFolder
$progressName = $logFolder

### SET LOG LOCATION ###
$logDate = Get-Date -Format FileDate
New-Item -ItemType Directory -Path "$ScriptLocation\Logs\$logDate\$logFolder" -Force | Out-Null
$logPath = "$ScriptLocation\Logs\$logDate\$logFolder"
$azCopyLogPath = "$logPath\AzCopy$logDate.log"
$journalPath = "$logPath\Journal"
New-Item -ItemType Directory -Path "$journalPath" -Force | Out-Null

# Add AzCopy to $env:Path
$testEnvPath = $Env:path
if (!($testEnvPath -contains "C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\")) {
    $Env:path = $env:path + ";C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\"
}

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
elseif (($skipAppService -eq $false) -and ($progressCheck -ne "Complete")) {
    # We first need to check if in a previous run, this section was skipped, but now, the user wants to add this, so we need to reset the progress.
    if ($progressCheck -eq "Skipped") {
        Write-Host "Operator previously skipped this step, but now wants to perform this step. Updating AzSPoC database to Incomplete."
        # Update the AzSPoC database back to incomplete
        StageReset -progressStage $progressStage
        $progressCheck = CheckProgress -progressStage $progressStage
    }
    if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
        try {
            if ($progressCheck -eq "Failed") {
                # Update the AzSPoC database back to incomplete status if previously failed
                Write-Host "Clearing previous Azure logins for this session"
                StageReset -progressStage $progressStage
                $progressCheck = CheckProgress -progressStage $progressStage
            }

            # Cleanup PS Context
            Write-Host "Clearing previous Azure logins for this session"
            Get-AzureRmContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force
            Disable-AzureRMContextAutosave -Scope CurrentUser

            # Need to ensure this stage doesn't start before the App Service components have been downloaded
            $appServiceDownloadJobCheck = CheckProgress -progressStage "DownloadAppService"
            while ($appServiceDownloadJobCheck -ne "Complete") {
                Write-Host "The DownloadAppService stage of the process has not yet completed. Checking again in 20 seconds"
                Start-Sleep -Seconds 20
                $appServiceDownloadJobCheck = CheckProgress -progressStage "DownloadAppService"
                if ($appServiceDownloadJobCheck -eq "Failed") {
                    throw "The DownloadAppService stage of the process has failed. This should fully complete before the App Service PreReqs can be started. Check the DownloadAppService log, ensure that step is completed first, and rerun."
                }
            }
            Write-Host "Logging into Azure Stack"
            $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            $ADauth = (Get-AzureRmEnvironment -Name "AzureStackAdmin").ActiveDirectoryAuthority.TrimEnd('/')

            <#Write-Host "Importing storage modules for Azure.Storage and AzureRM.Storage."
            Import-Module -Name Azure.Storage -RequiredVersion 4.5.0
            Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4
            #>

            #### Certificates ####
            Write-Host "Generating Certificates for App Service"
            $AppServicePath = "$azsPath\appservice"
            Set-Location "$AppServicePath"

            if ($multiNode -eq $false) {
                if (!$([System.IO.File]::Exists("$AppServicePath\CertsCreated.txt"))) {
                    Write-Host "Starting with the ASDK specific certs"
                    .\Create-AppServiceCerts.ps1 -PfxPassword $secureVMpwd -DomainName $customDomainSuffix
                    .\Get-AzureStackRootCert.ps1 -PrivilegedEndpoint $ERCSip -CloudAdminCredential $pepAdminCreds
                    New-Item -Path "$AppServicePath\CertsCreated.txt" -ItemType file -Force
                }
                else {
                    Write-Host "ASDK Certs have been previously successfully created"
                }
            }
            else {
                Write-Host "This is a multinode deployment, and therefore the required certificates should already be located at $certPath"
            }

            if (!$([System.IO.File]::Exists("$AppServicePath\RootCertGenerated.txt"))) {
                Write-Host "Gathering the root certificate from the Azure Stack system"
                .\Get-AzureStackRootCert.ps1 -PrivilegedEndpoint $ERCSip -CloudAdminCredential $pepAdminCreds
                if ($multiNode -eq $true) {
                    $multiNodeRootCert = Get-ChildItem -Path "$AppServicePath\*" -Recurse -Filter "*.cer" -ErrorAction Stop
                    if ($multiNodeRootCert) {
                        Write-Host "Found a certificate at $($multiNodeRootCert.FullName)"
                        Write-Host "Copying the located certificate to the originally supplied certificate path..."
                        Copy-Item -Path $multiNodeRootCert.FullName -Destination $certPath -Force -Confirm:$false -ErrorAction Stop
                        $multiNodeRootCert = Get-ChildItem -Path "$certPath\*" -Recurse -Filter "*.cer" -ErrorAction Stop
                        if ($multiNodeRootCert) {
                            Write-Host "Root cert now located at $($multiNodeRootCert.FullName)"
                        }
                        else {
                            throw "Error copying the generated root certificate to the target $certPath - please check permissions and logs for details"
                        }
                    }
                    else {
                        Write-Host "Could not locate any .cer files - it appears that the generation of the root certificate failed, so please check the logs then rerun the script." -ForegroundColor Red
                        Break
                    }
                }
                New-Item -Path "$AppServicePath\RootCertGenerated.txt" -ItemType file -Force
            }
            else {
                Write-Host "Root Cert has been previously successfully retrieved"
            }

            #### AD Service Principal ####
            if (!$([System.IO.File]::Exists("$downloadPath\ApplicationIDBackup.txt"))) {
                if (($authenticationType.ToString() -like "AzureAd") -and ($deploymentMode -ne "Offline")) {
                    # Logout to clean up
                    Write-Host "Clearing previous Azure logins for this session"
                    Get-AzureRmContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzureRmAccount | Out-Null
                    Clear-AzureRmContext -Scope CurrentUser -Force
                    Write-Host "Obtaining tenant ID"
                    $tenantId = (Invoke-RestMethod "$($ADauth)/$($azureDirectoryTenantName)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
                    Write-Host "Tenant ID is $tenantId"
                    Write-Host "Logging into Azure Cloud"
                    Add-AzureRmAccount -EnvironmentName $azureEnvironment -TenantId $tenantId -Credential $azsCreds -ErrorAction Stop
                    Set-Location "$AppServicePath" -Verbose
                    Write-Host "Generating the application ID for the App Service installation"
                    if ($multiNode -eq $false) {
                        $appID = . .\Create-AADIdentityApp.ps1 -DirectoryTenantName "$azureDirectoryTenantName" -AdminArmEndpoint "adminmanagement.$customDomainSuffix" -TenantArmEndpoint "management.$customDomainSuffix" `
                            -CertificateFilePath "$AppServicePath\sso.appservice.$customDomainSuffix.pfx" -CertificatePassword $secureVMpwd -AzureStackAdminCredential $azsCreds -Verbose
                    }
                    else {
                        $appID = . .\Create-AADIdentityApp.ps1 -DirectoryTenantName "$azureDirectoryTenantName" -AdminArmEndpoint "adminmanagement.$customDomainSuffix" -TenantArmEndpoint "management.$customDomainSuffix" `
                            -CertificateFilePath "$certPath\sso.appservice.$customDomainSuffix.pfx" -CertificatePassword $secureCertPwd -AzureStackAdminCredential $azsCreds -Verbose
                    }
                    $identityApplicationID = $applicationId
                    Write-Host "Application ID is $identityApplicationID"
                    Write-Host "You don't need to sign into the Azure Portal to grant permissions, Azure Stack POC Configurator will automate this for you. Please wait."
                    Write-Host "Waiting for 20 seconds to allow processes to finish."
                    Start-Sleep -Seconds 20
                    # Create Cleanup Doc - First Create File
                    Write-Host "Creating an AD Cleanup Script, if you wish to clean up the AAD Application when you redeploy the Azure Stack POC system."
                    $cleanUpAppServicePs1Path = "$downloadPath\AzSAppServiceCleanUp.ps1"
                    Write-Host "Cleanup script will be stored temporarily at $cleanUpAppServicePs1Path, but later moved to the 'Completed' folder"
                    Remove-Item -Path $cleanUpAppServicePs1Path -Confirm:$false -Force -ErrorAction SilentlyContinue -Verbose
                    New-Item "$cleanUpAppServicePs1Path" -ItemType file -Force -Verbose
                    Write-Host "Populating the Cleanup script with key information about this deployment."
                    # Populate key info
                    Write-Output "# This script should be used to remove an App Service resource from Azure AD, prior to redeploying your Azure Stack POC on this hardware." -Verbose -ErrorAction Stop | Out-File -FilePath "$cleanUpAppServicePs1Path" -Force -Verbose -Append
                    Write-Output "# Values are already populated based on the prior deployment.`n" -Verbose -ErrorAction Stop | Out-File -FilePath "$cleanUpAppServicePs1Path" -Force -Verbose -Append
                    Write-Output "# Populate key parameters" -Verbose -ErrorAction Stop | Out-File -FilePath "$cleanUpAppServicePs1Path" -Force -Verbose -Append
                    Write-Output "`$identityApplicationID = `"$identityApplicationID`"" -Verbose -ErrorAction Stop | Out-File -FilePath "$cleanUpAppServicePs1Path" -Force -Verbose -Append
                    # Populate AAD Information
                    Write-Output "`n# Populate AAD Information" -Verbose -ErrorAction Stop | Out-File -FilePath "$cleanUpAppServicePs1Path" -Force -Verbose -Append
                    $azureUsername = $($azsCreds).UserName
                    Write-Output "`$azureUsername = `"$azureUsername`"" -Verbose -ErrorAction Stop | Out-File -FilePath "$cleanUpAppServicePs1Path" -Force -Verbose -Append
                    Write-Output "`$azureTenantID = `"$tenantID`"" -Verbose -ErrorAction Stop | Out-File -FilePath "$cleanUpAppServicePs1Path" -Force -Verbose -Append
                    Write-Output "`$azureCreds = Get-Credential -UserName `"$azureUsername`" -Message `"Enter the AAD password you used when deploying this Azure Stack POC with the username: $azureUsername.`"" -Verbose -ErrorAction Stop | Out-File -FilePath "$cleanUpAppServicePs1Path" -Force -Verbose -Append
                    Write-Output "`$azureLogin = Add-AzureRmAccount -EnvironmentName `"AzureCloud`" -tenantId `"$tenantId`" -Credential `$azureCreds" -ErrorAction Stop | Out-File -FilePath "$cleanUpAppServicePs1Path" -Force -Verbose -Append
                    # Remove the App from Azure AD
                    Write-Output "`n# Remove the App from Azure AD" -Verbose -ErrorAction Stop | Out-File -FilePath "$cleanUpAppServicePs1Path" -Force -Verbose -Append
                    Write-Output "`$appToRemove = Get-AzureRmADApplication | Where-Object {`$_.ApplicationId -eq `"$identityApplicationID`"} -ErrorAction SilentlyContinue -Verbose" | Out-File -FilePath "$cleanUpAppServicePs1Path" -Force -Verbose -Append
                    Write-Output "Set-AzureRMADApplication -ObjectId `$appToRemove.ObjectId -AvailableToOtherTenants `$false -Verbose -ErrorAction Stop" | Out-File -FilePath "$cleanUpAppServicePs1Path" -Force -Verbose -Append
                    Write-Output "Remove-AzureRMADApplication -ObjectId `$appToRemove.ObjectId -ErrorAction Stop -Verbose -Force" | Out-File -FilePath "$cleanUpAppServicePs1Path" -Force -Verbose -Append
                    Write-Host "Saving the application ID to a backup file."
                    $appIdPath = "$downloadPath\ApplicationIDBackup.txt"
                    New-Item $appIdPath -ItemType file -Force
                    Write-Output $identityApplicationID > $appIdPath
                    Write-Host "Application ID backup file stored at $appIdPath"
                }
                elseif ($authenticationType.ToString() -like "ADFS") {
                    Write-Host "Logging into Azure Stack"
                    $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
                    Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
                    Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
                    $sub = Get-AzureRmSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
                    $azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
                    Set-Location "$AppServicePath" -Verbose
                    Write-Host "Generating the application ID for the App Service installation"
                    if ($multiNode -eq $false) {
                        $appID = .\Create-ADFSIdentityApp.ps1 -AdminArmEndpoint "adminmanagement.$customDomainSuffix" -PrivilegedEndpoint $ERCSip `
                            -CertificateFilePath "$AppServicePath\sso.appservice.$customDomainSuffix.pfx" -CertificatePassword $secureVMpwd -CloudAdminCredential $azsCreds -Verbose
                    }
                    else {
                        $appID = .\Create-ADFSIdentityApp.ps1 -AdminArmEndpoint "adminmanagement.$customDomainSuffix" -PrivilegedEndpoint $ERCSip `
                            -CertificateFilePath "$certPath\sso.appservice.$customDomainSuffix.pfx" -CertificatePassword $certPwd -CloudAdminCredential $azsCreds -Verbose
                    }
                    Write-Host "Saving the application ID to a backup file."
                    $appIdPath = "$downloadPath\ApplicationIDBackup.txt"
                    $identityApplicationID = $appID
                    New-Item $appIdPath -ItemType file -Force
                    Write-Output $identityApplicationID > $appIdPath
                    Write-Host "Application ID backup file stored at $appIdPath"
                }
                else {
                    Write-Host ("No valid application was created, please perform this step after the script has completed") -ErrorAction SilentlyContinue
                }       
            }
            else {
                Write-Host "Application Service Principal has already been previously successfully created"
                $identityApplicationID = Get-Content -Path "$downloadPath\ApplicationIDBackup.txt" -ErrorAction SilentlyContinue
                Write-Host "Application Service Principal ID is: $identityApplicationID"
            }

            #### Grant Azure AD App Permissions ####
            if (($authenticationType.ToString() -like "AzureAd") -and ($deploymentMode -ne "Offline")) {
                if (!$([System.IO.File]::Exists("$AppServicePath\AzureAdPermissions.txt"))) {
                    # Logout to clean up
                    Write-Host "Clearing previous Azure logins for this session"
                    Get-AzureRmContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzureRmAccount | Out-Null
                    Clear-AzureRmContext -Scope CurrentUser -Force
                    # Grant permissions to Azure AD Service Principal
                    try {
                        Write-Host "Attempting to grant permissions to the AAD application, for the App Service."
                        $tenantId = (Invoke-RestMethod "$($ADauth)/$($azureDirectoryTenantName)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
                        Write-Host "Tenant ID is $tenantId"
                        Write-Host "Logging into Azure Cloud"
                        Add-AzureRmAccount -EnvironmentName $azureEnvironment -TenantId $tenantId -Credential $azsCreds -ErrorAction Stop
                        Write-Host "Obtaining tokens"
                        $refreshToken = @([Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems() | Where-Object { $_.tenantId -eq $tenantId -and $_.ExpiresOn -gt (Get-Date) })[0].RefreshToken
                        $refreshtoken = $refreshtoken.Split("`n")[0]
                        Write-Host "Generating body and header information"
                        $body = "grant_type=refresh_token&refresh_token=$($refreshToken)&resource=74658136-14ec-4630-ad9b-26e160ff0fc6"
                        $apiToken = Invoke-RestMethod "https://login.windows.net/$tenantId/oauth2/token" -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded'
                        $header = @{
                            'Authorization'          = 'Bearer ' + $apiToken.access_token
                            'X-Requested-With'       = 'XMLHttpRequest'
                            'x-ms-client-request-id' = [guid]::NewGuid()
                            'x-ms-correlation-id'    = [guid]::NewGuid()
                        }
                        $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$identityApplicationID/Consent?onBehalfOfAll=true"
                        Write-Host "Granting permissions"
                        $grantPermission = Invoke-RestMethod –Uri $url –Headers $header –Method POST -ErrorAction Stop -Verbose
                        Write-Host "Creating text file to record confirmation of granting permissions successfully"
                        New-Item -Path "$AppServicePath\AzureAdPermissions.txt" -ItemType file -Force
                        Write-Output $grantPermission > "$AppServicePath\AzureAdPermissions.txt"
                    }
                    catch {
                        Write-Host "$_.Exception.Message"
                        Write-Host "There was an issue granting permissions to your Azure AD application with ID: $identityApplicationID "
                        Write-Host "Creating a document on the user's desktop with instructions on how to manually grant permissions to the Azure AD app"
                        $desktopPath = [Environment]::GetFolderPath("Desktop")
                        $manualAzureAdPermissions = "$desktopPath\PLEASE_READ_GrantAzureAdPermissions.txt"
                        New-Item $manualAzureAdPermissions -ItemType file -Force
                        Write-Output "Unfortunately, for Azure AD accounts that have no associated subscription, the Azure Ad Application cannot be automatically granted appropriate permissions for Azure Stack" >> $manualAzureAdPermissions
                        Write-Output "As a result, please manually activate using the steps below:" >> $manualAzureAdPermissions
                        Write-Output "To complete the App Service deployment, use this Application Id: $identityApplicationID" >> $manualAzureAdPermissions
                        Write-Output "Sign in to the Azure portal as your Azure Active Directory Service Admin ($azureAdUsername)" >> $manualAzureAdPermissions
                        Write-Output "Open the Azure AD resource provider." >> $manualAzureAdPermissions
                        Write-Output "Select App Registrations." >> $manualAzureAdPermissions
                        Write-Output "Search for Application Id ($identityApplicationID). An App Service application is listed." >> $manualAzureAdPermissions
                        Write-Output "Select Application in the list." >> $manualAzureAdPermissions
                        Write-Output "Select Settings." >> $manualAzureAdPermissions
                        Write-Output "Select Required Permissions > Grant Permissions > Yes." >> $manualAzureAdPermissions
                        Write-Output "Documented steps: https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-app-service-before-you-get-started#create-an-azure-active-directory-application" >> $manualAzureAdPermissions
                        New-Item -Path "$AppServicePath\AzureAdPermissions.txt" -ItemType file -Force
                    }
                }
                else {
                    Write-Host "Azure AD Permissions have been previously granted successfully"
                }
            }

            # Sideload the Custom Script Extension if the user is not registering
            # Check there's not a gallery item already uploaded to storage
            # Log back into Azure Stack
            # Firstly need to establish a check to see if the AddVmExtensions job is executing (to avoid conflict) and if it is, wait.  If it's not, start the sideload process.
            Write-Host "Checking on the AddVMExtensions step, to ensure CSE 1.9.x is present for App Service installation"
            $AddVmExtensionsJobCheck = CheckProgress -progressStage "AddVMExtensions"
            while ($AddVmExtensionsJobCheck -ne "Complete") {
                Write-Host "The AddVMExtensions stage of the process has not yet completed. Checking again in 20 seconds"
                Start-Sleep -Seconds 20
                $AddVmExtensionsJobCheck = CheckProgress -progressStage "AddVMExtensions"
                if ($AddVmExtensionsJobCheck -eq "Skipped") {
                    Write-Host "The AddVMExtensions stage of the process was skipped - the script will proceed to sideload a valid Custom Script Extension (1.9.x) into your Azure Stack environment to allow App Service deployment to continue."
                    BREAK
                }
                elseif ($AddVmExtensionsJobCheck -eq "Failed") {
                    Write-Host "The AddVMExtensions stage of the process failed - the script will proceed to sideload a valid Custom Script Extension (1.9.x) into your Azure Stack environment to allow App Service deployment to continue."
                    BREAK
                }
            }

            Write-Host "Logging into Azure Stack for further checks on the AddVMExtension stage"
            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
            $sub = Get-AzureRmSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
            $azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
            if ((Get-AzsVMExtension -Publisher Microsoft.Compute -Verbose:$false) | Where-Object { ($_.ExtensionType -eq "CustomScriptExtension") -and ($_.TypeHandlerVersion -ge "1.9") -and ($_.ProvisioningState -eq "Succeeded") }) {
                Write-Verbose -Message "You already have a valid Custom Script Extension (1.9.x) within your Azure Stack environment. App Service deployment can continue."
            }
            else {
                Write-Verbose -Message "You are missing a valid Custom Script Extension (1.9.x) within your Azure Stack environment. We will manually add one to your Azure Stack"
                $extensionPath = "$azsPath\appservice\extension"
                $extensionZipPath = "$azsPath\appservice\extension\CSE.zip"
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                if ($deploymentMode -eq "Online") {
                    if (-not [System.IO.File]::Exists("$azsPath\appservice\extension\CSE.zip")) {
                        Write-Host "This is an online deployment - downloading the Custom Script Extension from GitHub"
                        $extensionURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/appservice/extension/CSE.zip"
                        DownloadWithRetry -downloadURI $extensionURI -downloadLocation $extensionZipPath -retries 10
                    }
                    else {
                        Write-Host "Valid CSE.zip file found at $extensionZipPath. No need to download."
                    }
                }
                elseif ($deploymentMode -ne "Online") {
                    if (-not [System.IO.File]::Exists("$extensionZipPath")) {
                        throw "Missing CSE.zip file in extracted dependencies folder. Please ensure this exists at $extensionZipPath - Exiting process"
                    }
                    else {
                        Write-Host "Valid CSE.zip file found at $extensionZipPath. Continuing process."
                    }
                }
                Write-Host "Extracting CSE.zip file"
                Expand-Archive "$extensionZipPath" -DestinationPath "$extensionPath" -Force -Verbose
            
                # Create RG and Storage
                Write-Host "Creating resource group, storage account and container to hold side-loaded Custom Script Extension"
                $azsExtensionRGName = "azurestack-extension"
                $azsExtensionStorageAccountName = "azsextensionstor"
                $azsExtensionContainerName = "azsextensioncontainer"
                $azsLocation = (Get-AzureRmLocation).DisplayName
                Write-Host "Resource Group = $azsExtensionRGName, Storage Account = $azsExtensionStorageAccountName and Container = $azsExtensionContainerName"
                # Test/Create RG
                if (-not (Get-AzureRmResourceGroup -Name $azsExtensionRGName -Location $azsLocation -ErrorAction SilentlyContinue)) {
                    Write-Host "Creating the resource group: $azsExtensionRGName"
                    New-AzureRmResourceGroup -Name $azsExtensionRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop 
                }
                # Test/Create Storage
                $azsStorageAccount = Get-AzureRmStorageAccount -Name $azsExtensionStorageAccountName -ResourceGroupName $azsExtensionRGName -ErrorAction SilentlyContinue
                if (-not ($azsStorageAccount)) {
                    Write-Host "Creating the storage account: $azsExtensionStorageAccountName"
                    $azsStorageAccount = New-AzureRmStorageAccount -Name $azsExtensionStorageAccountName -Location $azsLocation -ResourceGroupName $azsExtensionRGName -Type Standard_LRS -ErrorAction Stop
                }
                Write-Host "Setting the storage context"
                Set-AzureRmCurrentStorageAccount -StorageAccountName $azsExtensionStorageAccountName -ResourceGroupName $azsExtensionRGName | Out-Null
                # Test/Create Container
                $azsContainer = Get-AzureStorageContainer -Name $azsExtensionContainerName -ErrorAction SilentlyContinue
                if (-not ($azsContainer)) { 
                    Write-Host "Creating the storage container: $azsExtensionContainerName"
                    $azsContainer = New-AzureStorageContainer -Name $azsExtensionContainerName -Permission Blob -Context $azsStorageAccount.Context -ErrorAction Stop 
                }
            
                # Upload files to Storage
                Write-Host "Uploading files to the newly created storage account"
                $extensionArray = @()
                $extensionArray.Clear()
                $extensionArray = Get-ChildItem -Path "$extensionPath" -Recurse -Include ("*.zip", "*.azpkg") -Exclude "CSE.zip" -ErrorAction Stop -Verbose
                foreach ($item in $extensionArray) {
                    $itemName = $item.Name
                    #$itemFullPath = $item.FullName
                    $itemDirectory = $item.DirectoryName
                    $uploadItemAttempt = 1
                    $sideloadCSEZipAttempt = 1
                    while (!$(Get-AzureStorageBlob -Container $azsExtensionContainerName -Blob $itemName -Context $azsStorageAccount.Context -ErrorAction SilentlyContinue) -and ($uploadItemAttempt -le 3)) {
                        try {
                            # Log back into Azure Stack to ensure login hasn't timed out
                            Write-Host "$itemName not found. Upload Attempt: $uploadItemAttempt"
                            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
                            $sub = Get-AzureRmSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
                            $azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
                            #Set-AzureStorageBlobContent -File "$itemFullPath" -Container $azsExtensionContainerName -Blob "$itemName" -Context $azsExtensionStorageAccount.Context -ErrorAction Stop -Verbose | Out-Null
                            ################## AzCopy Testing ##############################################
                            $containerDestination = '{0}{1}' -f $azsStorageAccount.PrimaryEndpoints.Blob, $azsExtensionContainerName
                            $azCopyPath = "C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\AzCopy.exe"
                            $storageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $azsExtensionRGName -Name $azsExtensionStorageAccountName).Value[0]
                            $azCopyCmd = [string]::Format("""{0}"" /source:""{1}"" /dest:""{2}"" /destkey:""{3}"" /Pattern:""{4}"" /Y /V:""{5}"" /Z:""{6}""", $azCopyPath, $itemDirectory, $containerDestination, $storageAccountKey, $itemName, $azCopyLogPath, $journalPath)
                            Write-Host "Executing the following command:`n'n$azCopyCmd"
                            $result = cmd /c $azCopyCmd
                            foreach ($s in $result) {
                                Write-Host $s 
                            }
                            if ($LASTEXITCODE -ne 0) {
                                Throw "Upload file failed: $itemName. Check logs at $azCopyLogPath";
                                break;
                            }
                            ################## AzCopy Testing ##############################################
                        }
                        catch {
                            Write-Host "Upload failed."
                            Write-Host "$_.Exception.Message"
                            $uploadItemAttempt++
                        }
                    }
                    if ($item.Extension -eq ".zip") {
                        while ($null -eq ((Get-AzsVMExtension -Publisher Microsoft.Compute -Verbose:$false) | Where-Object { ($_.ExtensionType -eq "CustomScriptExtension") -and ($_.TypeHandlerVersion -ge "1.9") -and ($_.ProvisioningState -eq "Succeeded") }) -and ($sideloadCSEZipAttempt -le 3)) {
                            try {
                                # Log back into Azure Stack to ensure login hasn't timed out
                                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
                                $sub = Get-AzureRmSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
                                $azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
                                Write-Host -Message "Adding Custom Script Extension (ZIP) to your environment. Attempt: $sideloadCSEZipAttempt"
                                $URI = '{0}{1}/{2}' -f $azsStorageAccount.PrimaryEndpoints.Blob, $azsExtensionContainerName, $itemName
                                $version = "1.9.3"
                                Add-AzsVMExtension -Publisher "Microsoft.Compute" -Type "CustomScriptExtension" -Version "$version" -ComputeRole "IaaS" -SourceBlob "$URI" -VmOsType "Windows" -ErrorAction Stop -Verbose -Force
                                Start-Sleep -Seconds 5
                            }
                            catch {
                                Write-Host -Message "Upload failed."
                                Write-Host -Message "$_.Exception.Message"
                                $sideloadCSEZipAttempt++
                            }
                        }
                    }
                }
            }
            # Update the AzSPoC database with successful completion
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
elseif ($skipAppService -and ($progressCheck -ne "Complete")) {
    Write-Host "Operator chose to skip App Service Deployment`r`n"
    # Update the AzSPoC database with skip status
    $progressStage = $progressName
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
$endTime = $(Get-Date).ToString("MMdd-HHmmss")
Write-Host "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue