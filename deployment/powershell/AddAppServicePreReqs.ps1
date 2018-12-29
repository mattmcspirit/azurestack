[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [parameter(Mandatory = $true)]
    [String]$downloadPath,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

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

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,

    [parameter(Mandatory = $true)]
    [pscredential] $cloudAdminCreds,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

    [parameter(Mandatory = $false)]
    [String] $skipAppService,

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

$logFolder = "AddAppServicePreReqs"
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

$progressStage = $progressName
$progressCheck = CheckProgress -progressStage $progressStage

if ($progressCheck -eq "Complete") {
    Write-Host "ASDK Configurator Stage: $progressStage previously completed successfully"
}
elseif (($skipAppService -eq $false) -and ($progressCheck -ne "Complete")) {
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

            # Cleanup PS Context
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
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
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            $ADauth = (Get-AzureRmEnvironment -Name "AzureStackAdmin").ActiveDirectoryAuthority.TrimEnd('/')

            Import-Module -Name Azure.Storage -RequiredVersion 4.5.0 -Verbose
            Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4 -Verbose

            #### Certificates ####
            Write-Host "Generating Certificates for App Service"
            $AppServicePath = "$ASDKpath\appservice"
            Set-Location "$AppServicePath"
            
            if (!$([System.IO.File]::Exists("$AppServicePath\CertsCreated.txt"))) {
                .\Create-AppServiceCerts.ps1 -PfxPassword $secureVMpwd -DomainName "local.azurestack.external"
                .\Get-AzureStackRootCert.ps1 -PrivilegedEndpoint $ERCSip -CloudAdminCredential $cloudAdminCreds
                New-Item -Path "$AppServicePath\CertsCreated.txt" -ItemType file -Force
            }
            else {
                Write-Host "Certs have been previously successfully created"
            }

            #### AD Service Principal ####
            if (!$([System.IO.File]::Exists("$downloadPath\ApplicationIDBackup.txt"))) {
                if (($authenticationType.ToString() -like "AzureAd") -and ($deploymentMode -ne "Offline")) {
                    # Logout to clean up
                    Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
                    Clear-AzureRmContext -Scope CurrentUser -Force
                    $tenantId = (Invoke-RestMethod "$($ADauth)/$($azureDirectoryTenantName)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
                    Add-AzureRmAccount -EnvironmentName "AzureCloud" -TenantId $tenantId -Credential $asdkCreds -ErrorAction Stop
                    Set-Location "$AppServicePath"
                    $appID = . .\Create-AADIdentityApp.ps1 -DirectoryTenantName "$azureDirectoryTenantName" -AdminArmEndpoint "adminmanagement.local.azurestack.external" -TenantArmEndpoint "management.local.azurestack.external" `
                        -CertificateFilePath "$AppServicePath\sso.appservice.local.azurestack.external.pfx" -CertificatePassword $secureVMpwd -AzureStackAdminCredential $asdkCreds
                    $appIdPath = "$downloadPath\ApplicationIDBackup.txt"
                    $identityApplicationID = $applicationId
                    New-Item $appIdPath -ItemType file -Force
                    Write-Output $identityApplicationID > $appIdPath
                    Write-Host "You don't need to sign into the Azure Portal to grant permissions, ASDK Configurator will automate this for you. Please wait."
                    Start-Sleep -Seconds 20
                }
                elseif ($authenticationType.ToString() -like "ADFS") {
                    $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
                    Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
                    Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    Set-Location "$AppServicePath"
                    $appID = .\Create-ADFSIdentityApp.ps1 -AdminArmEndpoint "adminmanagement.local.azurestack.external" -PrivilegedEndpoint $ERCSip `
                        -CertificateFilePath "$AppServicePath\sso.appservice.local.azurestack.external.pfx" -CertificatePassword $secureVMpwd -CloudAdminCredential $asdkCreds
                    $appIdPath = "$downloadPath\ApplicationIDBackup.txt"
                    $identityApplicationID = $appID
                    New-Item $appIdPath -ItemType file -Force
                    Write-Output $identityApplicationID > $appIdPath
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
                    Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
                    Clear-AzureRmContext -Scope CurrentUser -Force
                    # Grant permissions to Azure AD Service Principal
                    try {
                        $tenantId = (Invoke-RestMethod "$($ADauth)/$($azureDirectoryTenantName)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
                        Add-AzureRmAccount -EnvironmentName "AzureCloud" -TenantId $tenantId -Credential $asdkCreds -ErrorAction Stop
                        $refreshToken = @([Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems() | Where-Object {$_.tenantId -eq $tenantId -and $_.ExpiresOn -gt (Get-Date)})[0].RefreshToken
                        $refreshtoken = $refreshtoken.Split("`n")[0]
                        $body = "grant_type=refresh_token&refresh_token=$($refreshToken)&resource=74658136-14ec-4630-ad9b-26e160ff0fc6"
                        $apiToken = Invoke-RestMethod "https://login.windows.net/$tenantId/oauth2/token" -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded'
                        $header = @{
                            'Authorization'          = 'Bearer ' + $apiToken.access_token
                            'X-Requested-With'       = 'XMLHttpRequest'
                            'x-ms-client-request-id' = [guid]::NewGuid()
                            'x-ms-correlation-id'    = [guid]::NewGuid()
                        }
                        $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$identityApplicationID/Consent?onBehalfOfAll=true"
                        Invoke-RestMethod –Uri $url –Headers $header –Method POST -ErrorAction Stop
                        New-Item -Path "$AppServicePath\AzureAdPermissions.txt" -ItemType file -Force
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

            if ((Get-AzsVMExtension -Publisher Microsoft.Compute -Verbose:$false) | Where-Object {($_.ExtensionType -eq "CustomScriptExtension") -and ($_.TypeHandlerVersion -ge "1.9") -and ($_.ProvisioningState -eq "Succeeded")}) {
                Write-Verbose -Message "You already have a valid Custom Script Extension (1.9.x) within your Azure Stack environment. App Service deployment can continue."
            }
            else {
                Write-Verbose -Message "You are missing a valid Custom Script Extension (1.9.x) within your Azure Stack environment. We will manually add one to your Azure Stack"
                $extensionPath = "$ASDKpath\appservice\extension"
                $extensionZipPath = "$ASDKpath\appservice\extension\CSE.zip"
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                if ($deploymentMode -eq "Online") {
                    if (-not [System.IO.File]::Exists("$ASDKpath\appservice\extension\CSE.zip")) {
                        Write-Verbose "This is an online deployment - downloading the Custom Script Extension from GitHub"
                        $extensionURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/appservice/extension/CSE.zip"
                        DownloadWithRetry -downloadURI $extensionURI -downloadLocation $extensionZipPath -retries 10
                    }
                    else {
                        Write-Verbose "Valid CSE.zip file found at $extensionZipPath. No need to download."
                    }
                }
                elseif ($deploymentMode -ne "Online") {
                    if (-not [System.IO.File]::Exists("$extensionZipPath")) {
                        throw "Missing CSE.zip file in extracted dependencies folder. Please ensure this exists at $extensionZipPath - Exiting process"
                    }
                    else {
                        Write-Verbose "Valid CSE.zip file found at $extensionZipPath. Continuing process."
                    }
                }
                Write-Verbose "Extracting CSE.zip file"
                Expand-Archive "$extensionZipPath" -DestinationPath "$extensionPath" -Force
            
                # Create RG and Storage
                $asdkExtensionRGName = "azurestack-extension"
                $asdkExtensionStorageAccountName = "asdkextensionstor"
                $asdkExtensionContainerName = "asdkextensioncontainer"
                # Test/Create RG
                if (-not (Get-AzureRmResourceGroup -Name $asdkExtensionRGName -Location $azsLocation -ErrorAction SilentlyContinue)) { New-AzureRmResourceGroup -Name $asdkExtensionRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop }
                # Test/Create Storage
                $asdkStorageAccount = Get-AzureRmStorageAccount -Name $asdkExtensionStorageAccountName -ResourceGroupName $asdkExtensionRGName -ErrorAction SilentlyContinue
                if (-not ($asdkStorageAccount)) { $asdkStorageAccount = New-AzureRmStorageAccount -Name $asdkExtensionStorageAccountName -Location $azsLocation -ResourceGroupName $asdkExtensionRGName -Type Standard_LRS -ErrorAction Stop }
                Set-AzureRmCurrentStorageAccount -StorageAccountName $asdkExtensionStorageAccountName -ResourceGroupName $asdkExtensionRGName | Out-Null
                # Test/Create Container
                $asdkContainer = Get-AzureStorageContainer -Name $asdkExtensionContainerName -ErrorAction SilentlyContinue
                if (-not ($asdkContainer)) { $asdkContainer = New-AzureStorageContainer -Name $asdkExtensionContainerName -Permission Blob -Context $asdkStorageAccount.Context -ErrorAction Stop }
            
                # Upload files to Storage
                $extensionArray = @()
                $extensionArray.Clear()
                $extensionArray = Get-ChildItem -Path "$extensionPath" -Recurse -Include ("*.zip", "*.azpkg") -Exclude "CSE.zip" -ErrorAction Stop -Verbose
                foreach ($item in $extensionArray) {
                    $itemName = $item.Name
                    $itemFullPath = $item.FullName
                    $uploadItemAttempt = 1
                    $sideloadCSEZipAttempt = 1
                    $sideloadCSEAzpkgAttempt = 1
                    while (!$(Get-AzureStorageBlob -Container $asdkExtensionContainerName -Blob $itemName -Context $asdkExtensionStorageAccount.Context -ErrorAction SilentlyContinue) -and ($uploadItemAttempt -le 3)) {
                        try {
                            # Log back into Azure Stack to ensure login hasn't timed out
                            Write-Host "$itemName not found. Upload Attempt: $uploadItemAttempt"
                            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                            Set-AzureStorageBlobContent -File "$itemFullPath" -Container $asdkExtensionContainerName -Blob "$itemName" -Context $asdkExtensionStorageAccount.Context -ErrorAction Stop -Verbose | Out-Null
                        }
                        catch {
                            Write-Host "Upload failed."
                            Write-Host "$_.Exception.Message"
                            $uploadItemAttempt++
                        }
                    }
                    if ($item.Extension -eq ".zip") {
                        while ($null -eq ((Get-AzsVMExtension -Publisher Microsoft.Compute -Verbose:$false) | Where-Object {($_.ExtensionType -eq "CustomScriptExtension") -and ($_.TypeHandlerVersion -ge "1.9") -and ($_.ProvisioningState -eq "Succeeded")}) -and ($sideloadCSEZipAttempt -le 3)) {
                            try {
                                # Log back into Azure Stack to ensure login hasn't timed out
                                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                                Write-Verbose -Message "Adding Custom Script Extension (ZIP) to your environment. Attempt: $sideloadCSEZipAttempt"
                                $URI = '{0}{1}/{2}' -f $asdkStorageAccount.PrimaryEndpoints.Blob, $asdkExtensionContainerName, $itemName
                                $version = "1.9.1"
                                Add-AzsVMExtension -Publisher "Microsoft.Compute" -Type "CustomScriptExtension" -Version "$version" -ComputeRole "IaaS" -SourceBlob "$URI" -VmOsType "Windows" -ErrorAction Stop -Verbose -Force
                                Start-Sleep -Seconds 5
                            }
                            catch {
                                Write-Verbose -Message "Upload failed."
                                Write-Verbose -Message "$_.Exception.Message"
                                $sideloadCSEZipAttempt++
                            }
                        }
                    }
                    <#elseif ($item.Extension -eq ".azpkg") {
                        while ($null -eq (Get-AzsGalleryItem | Where-Object {($_.ItemName -like "*CustomScriptExtension*") -and ($_.Version -ge "2.0.50")}) -and ($sideloadCSEAzpkgAttempt -le 3)) {
                            try {
                                # Log back into Azure Stack to ensure login hasn't timed out
                                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                                Write-Verbose -Message "Adding Custom Script Extension (AZPKG) to your environment. Attempt: $sideloadCSEAzpkgAttempt"
                                $URI = '{0}{1}/{2}' -f $asdkStorageAccount.PrimaryEndpoints.Blob, $asdkExtensionContainerName, $itemName
                                Add-AzsGalleryItem -GalleryItemUri "URI" -ErrorAction Stop -Verbose -Force
                            }
                            catch {
                                Write-Verbose -Message "Upload failed."
                                Write-Verbose -Message "$_.Exception.Message"
                                $sideloadCSEAzpkgAttempt++
                            }
                        }
                    }#>
                }
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
elseif ($skipAppService -and ($progressCheck -ne "Complete")) {
    # Update the ConfigASDK database with skip status
    $progressStage = $progressName
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue