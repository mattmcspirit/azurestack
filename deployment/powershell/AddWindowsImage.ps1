[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ConfigASDKProgressLogPath,

    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $azsLocation,

    [Parameter(Mandatory = $false)]
    [String] $registerASDK,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [parameter(Mandatory = $true)]
    [String] $modulePath,

    [parameter(Mandatory = $false)]
    [String] $azureRegSubId,

    [parameter(Mandatory = $false)]
    [String] $azureRegTenantID,

    [parameter(Mandatory = $false)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [ValidateSet("ServerCore", "ServerFull")]
    [String] $windowsImage,

    [parameter(Mandatory = $false)]
    [pscredential] $azureRegCreds,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

### DOWNLOADER FUNCTION #####################################################################################################################################
#############################################################################################################################################################
function DownloadWithRetry([string] $downloadURI, [string] $downloadLocation, [int] $retries) {
    while ($true) {
        try {
            (New-Object System.Net.WebClient).DownloadFile($downloadURI, $downloadLocation)
            break
        }
        catch {
            $exceptionMessage = $_.Exception.Message
            Write-Verbose "Failed to download '$downloadURI': $exceptionMessage"
            if ($retries -gt 0) {
                $retries--
                Write-Verbose "Waiting 10 seconds before retrying. Retries left: $retries"
                Start-Sleep -Seconds 10
            }
            else {
                $exception = $_.Exception
                throw $exception
            }
        }
    }
}

### OFFLINE AZPKG FUNCTION ##################################################################################################################################
#############################################################################################################################################################
function Add-OfflineAZPKG {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string]$azpkgPackageName
    )
    begin {}
    process {
        #### Need to upload to blob storage first from extracted ZIP ####
        $azpkgFullPath = $null
        $azpkgFileName = $null
        $azpkgFullPath = Get-ChildItem -Path "$ASDKpath\packages" -Recurse -Include *$azpkgPackageName*.azpkg | ForEach-Object { $_.FullName }
        $azpkgFileName = Get-ChildItem -Path "$ASDKpath\packages" -Recurse -Include *$azpkgPackageName*.azpkg | ForEach-Object { $_.Name }
                                
        # Check there's not a gallery item already uploaded to storage
        if ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $azpkgFileName -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue)) {
            Write-Verbose "You already have an upload of $azpkgFileName within your Storage Account. No need to re-upload."
            Write-Verbose "Gallery path = $((Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $azpkgFileName -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue).ICloudBlob.StorageUri.PrimaryUri.AbsoluteUri)"
        }
        else {
            $uploadAzpkgAttempt = 1
            while (!$(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $azpkgFileName -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and ($uploadAzpkgAttempt -le 3)) {
                try {
                    # Log back into Azure Stack to ensure login hasn't timed out
                    Write-Verbose "No existing gallery item found. Upload Attempt: $uploadAzpkgAttempt"
                    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    Set-AzureStorageBlobContent -File "$azpkgFullPath" -Container $asdkImagesContainerName -Blob "$azpkgFileName" -Context $asdkStorageAccount.Context -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-Verbose "Upload failed."
                    Write-Verbose "$_.Exception.Message"
                    $uploadAzpkgAttempt++
                }
            }
        }
        $azpkgURI = '{0}{1}/{2}' -f $asdkStorageAccount.PrimaryEndpoints.Blob.AbsoluteUri, $asdkImagesContainerName, $azpkgFileName
        Write-Verbose "Uploading $azpkgFileName from $azpkgURI"
        return [string]$azpkgURI
    }
    end {}
}

### SET LOG LOCATION ###
$logDate = Get-Date -Format FileDate
New-Item -ItemType Directory -Path "$ScriptLocation\Logs\$logDate\WindowsImages" -Force | Out-Null
$logPath = "$ScriptLocation\Logs\$logDate\WindowsImages"

### START LOGGING ###
$runTime = $(Get-Date).ToString("MMdd-HHmmss")
$fullLogPath = "$logPath\$($windowsImage)$runTime.txt"
Start-Transcript -Path "$fullLogPath" -Append -IncludeInvocationHeader

$progress = Import-Csv -Path $ConfigASDKProgressLogPath
$RowIndex = [array]::IndexOf($progress.Stage, "$($windowsImage)Image")

if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Set path for Windows Updates
        $target = "$ASDKpath\images"
        Set-Location "$ASDKpath\images"
        # Log into Azure Stack to check for existing images and push new ones if required ###
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

        # Check which Windows Server image is being deployed
        if ($windowsImage -eq "ServerCore") {
            $sku = "2016-Datacenter-Server-Core"
            $edition = 'Windows Server 2016 SERVERDATACENTERCORE'
            $onlinePackage = "*Microsoft.WindowsServer2016DatacenterServerCore-ARM*"
            $offlinePackage = "Microsoft.WindowsServer2016DatacenterServerCore-ARM.1.0.0"
        }
        elseif ($windowsImage -eq "ServerFull") {
            $sku = "2016-Datacenter"
            $edition = 'Windows Server 2016 SERVERDATACENTER'
            $onlinePackage = "*Microsoft.WindowsServer2016Datacenter-ARM*"
            $offlinePackage = "Microsoft.WindowsServer2016Datacenter-ARM.1.0.0"
        }

        # Check if the image is missing
        Write-CustomVerbose -Message "Checking to see if a Windows Server 2016 image is present in your Azure Stack Platform Image Repository"
        Remove-Variable -Name existingPlatformImage -Force -ErrorAction SilentlyContinue

        $existingPlatformImage = Get-AzsPlatformImage -Location "$azsLocation" -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -Version "1.0.0" -ErrorAction SilentlyContinue
        if ($null -ne $existingPlatformImage -and $existingPlatformImage.ProvisioningState -eq 'Succeeded') {
            Write-CustomVerbose -Message "There appears to be at least 1 suitable Windows Server $sku image within your Platform Image Repository which we will use for the ASDK Configurator."
        }
        else {
            Write-CustomVerbose -Message "You're missing the Windows Server $sku image in your Platform Image Repository."
            Write-CustomVerbose -Message "Checking in Azure Stack storage account..."
            # Test/Create RG
            if (-not (Get-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -ErrorAction SilentlyContinue)) { New-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop }
            # Test/Create Storage
            $asdkStorageAccount = Get-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName -ErrorAction SilentlyContinue
            if (-not ($asdkStorageAccount)) { $asdkStorageAccount = New-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -Location $azsLocation -ResourceGroupName $asdkImagesRGName -Type Standard_LRS -ErrorAction Stop }
            Set-AzureRmCurrentStorageAccount -StorageAccountName $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName | Out-Null
            # Test/Create Container
            $asdkContainer = Get-AzureStorageContainer -Name $asdkImagesContainerName -ErrorAction SilentlyContinue
            if (-not ($asdkContainer)) { $asdkContainer = New-AzureStorageContainer -Name $asdkImagesContainerName -Permission Blob -Context $asdkStorageAccount.Context -ErrorAction Stop }
        }
        if ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob "$($windowsImage).vhd" -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue)) {
            Write-CustomVerbose -Message "You already have an upload of $($windowsImage).vhd within your Storage Account. No need to re-upload."
            Write-CustomVerbose -Message "Windows Server VHD path = $((Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $($windowsImage).vhd -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue).ICloudBlob.StorageUri.PrimaryUri.AbsoluteUri)"
        }
        else {
            Write-CustomVerbose -Message "There is no suitable $($windowsImage).vhd image within your Storage Account. We'll need to upload a new one."
            Write-CustomVerbose -Message "Checking for a local copy first..."
            # Check for local VHD first
            $windowsVHDpath = "$ASDKpath\images\$($windowsImage).vhd"
            $windowsVHDExists = [System.IO.File]::Exists($windowsVHDpath)
            # If there's no local VHD, create one.
            if ($windowsVHDExists -eq $false) {
                if ($deploymentMode -eq "Online") {
                    # Download Convert-WindowsImage.ps1
                    $convertWindowsURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/scripts/Convert-WindowsImage.ps1"
                    $convertWindowsDownloadLocation = "$ASDKpath\images\Convert-WindowsImage.ps1"
                    Write-CustomVerbose -Message "Downloading Convert-WindowsImage.ps1 to create the VHD from the ISO"
                    Write-CustomVerbose -Message "The download will be stored in $ASDKpath\images"
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    DownloadWithRetry -downloadURI "$convertWindowsURI" -downloadLocation "$convertWindowsDownloadLocation" -retries 10
                }
                .\Convert-WindowsImage.ps1 -SourcePath $ISOpath -SizeBytes 40GB -Edition "$edition" -VHDPath "$ASDKpath\images\$($windowsImage).vhd" `
                    -VHDFormat VHD -VHDType Fixed -VHDPartitionStyle MBR -Feature "NetFx3" -Package $target -Passthru -Verbose
            }
            # There now should be a VHD locally, either existing previously, or freshly created, so get the path and build the URI
            $windowsVHD = Get-ChildItem -Path "$ASDKpath\images" -Filter "*$($windowsImage).vhd"
            $windowsURI = '{0}{1}/{2}' -f $asdkStorageAccount.PrimaryEndpoints.Blob.AbsoluteUri, $asdkImagesContainerName, "$($windowsImage).vhd"
            # Now need to upload the local VHD to a storage account
            # Sometimes Add-AzureRmVHD has an error about "The pipeline was not run because a pipeline is already running. Pipelines cannot be run concurrently". Rerunning the upload typically helps.
            # Check that a) there's no VHD uploaded and b) the previous attempt(s) didn't complete successfully and c) you've attempted an upload no more than 3 times
            $uploadVhdAttempt = 1
            while (!$(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $($windowsImage).vhd -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$serverCoreUploadSuccess) -and ($uploadVhdAttempt -le 3)) {
                Try {
                    # Log back into Azure Stack to ensure login hasn't timed out
                    Write-CustomVerbose -Message "No existing image found. Upload Attempt: $uploadVhdAttempt"
                    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    Add-AzureRmVhd -Destination $windowsURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $windowsVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                    $serverCoreUploadSuccess = $true
                }
                catch {
                    Write-CustomVerbose -Message "Upload failed."
                    Write-CustomVerbose -Message "$_.Exception.Message"
                    $uploadVhdAttempt++
                    $serverCoreUploadSuccess = $false
                }
            }
            # Sometimes Add-AzureRmVHD has an error about "The pipeline was not run because a pipeline is already running. Pipelines cannot be run concurrently". Rerunning the upload typically helps.
            # Check that a) there's a VHD uploaded but b) the attempt didn't complete successfully (VHD in unreliable state) and c) you've attempted an upload no more than 3 times
            while ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $($windowsImage).vhd -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$serverCoreUploadSuccess) -and ($uploadVhdAttempt -le 3)) {
                Try {
                    # Log back into Azure Stack to ensure login hasn't timed out
                    Write-CustomVerbose -Message "There was a previously failed upload. Upload Attempt: $uploadVhdAttempt"
                    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    Add-AzureRmVhd -Destination $windowsURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $windowsVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                    $serverCoreUploadSuccess = $true
                }
                catch {
                    Write-CustomVerbose -Message "Upload failed."
                    Write-CustomVerbose -Message "$_.Exception.Message"
                    $uploadVhdAttempt++
                    $serverCoreUploadSuccess = $false
                }
            }
            # This is one final catch-all for the upload process
            # Check that a) there's no VHD uploaded and b) you've attempted an upload no more than 3 times
            while (!$(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $($windowsImage).vhd -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and ($uploadVhdAttempt -le 3)) {
                Try {
                    # Log back into Azure Stack to ensure login hasn't timed out
                    Write-CustomVerbose -Message "No existing image found. Upload Attempt: $uploadVhdAttempt"
                    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    Add-AzureRmVhd -Destination $windowsURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $windowsVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                    $serverCoreUploadSuccess = $true
                }
                catch {
                    Write-CustomVerbose -Message "Upload failed."
                    Write-CustomVerbose -Message "$_.Exception.Message"
                    $uploadVhdAttempt++
                    $serverCoreUploadSuccess = $false
                }
            }
            if ($uploadVhdAttempt -gt 3) {
                Write-CustomVerbose "Uploading VHD to Azure Stack storage failed after 3 upload attempts. Rerun the ConfigASDK.ps1 script to retry."
                $serverCoreUploadSuccess = $false
                throw "Uploading image failed"
                Set-Location $ScriptLocation
                return
            }
        }
        # Push the image into the PIR from the Storage Account
        Add-AzsPlatformImage -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "$sku" -Version "1.0.0" -OsType "Windows" -OsUri "$windowsURI" -Force -Confirm: $false -Verbose -ErrorAction Stop
            
        if ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "$sku" -Version "1.0.0" -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
            Write-CustomVerbose -Message ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" successfully uploaded.' -f "MicrosoftWindowsServer", "WindowsServer", "$sku", "1.0.0") -ErrorAction SilentlyContinue
            Write-CustomVerbose -Message "Cleaning up local hard drive space - deleting VHD file"
            Get-ChildItem -Path "$ASDKpath\images" -Filter *$($windowsImage).vhd | Remove-Item -Force
            Write-CustomVerbose -Message "Cleaning up VHD from storage account"
            Remove-AzureStorageBlob -Blob $($windowsImage).vhd -Container $asdkImagesContainerName -Context $asdkStorageAccount.Context -Force
        }
        elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "$sku" -Version "1.0.0" -ErrorAction SilentlyContinue).ProvisioningState -eq 'Failed') {
            throw "Adding VM image failed. Please check the logs and clean up the Azure Stack Platform Image Repository to remove the failed image, then retry."
        }
        elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "$sku" -Version "1.0.0" -ErrorAction SilentlyContinue).ProvisioningState -eq 'Canceled') {
            throw "Adding VM image was canceled. Confirm the image doesn't show in the Azure Stack Platform Image Repository and if it does, remove it, then retry."
        }

        if ($registerASDK -and ($deploymentMode -eq "Online")) {
            # Logout to clean up
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force

            ### Login to Azure to get all the details about the syndicated Ubuntu Server 16.04 marketplace offering ###
            Import-Module "$modulePath\Syndication\AzureStack.MarketplaceSyndication.psm1"
            Login-AzureRmAccount -EnvironmentName "AzureCloud" -SubscriptionId $azureRegSubId -TenantId $azureRegTenantID -Credential $azureRegCreds -ErrorAction Stop | Out-Null
            $azureEnvironment = Get-AzureRmEnvironment -Name AzureCloud
            Remove-Variable -Name Registration -Force -Confirm:$false -ErrorAction SilentlyContinue
            $Registration = ((Get-AzureRmResource | Where-Object { $_.ResourceType -eq "Microsoft.AzureStack/registrations"} | `
                        Where-Object { ($_.ResourceName -like "asdkreg*") -or ($_.ResourceName -like "AzureStack*")}) | Select-Object -First 1 -ErrorAction SilentlyContinue -Verbose).ResourceName
            if (!$Registration) {
                throw "No registration records found in your chosen Azure subscription. Please validate the success of your ASDK registration and ensure records have been created successfully."
                Set-Location $ScriptLocation
                return
            }
            # Retrieve the access token
            $token = $null
            $tokens = $null
            $tokens = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems()
            $token = $tokens | Where-Object Resource -EQ $azureEnvironment.ActiveDirectoryServiceEndpointResourceId | Where-Object TenantId -EQ $azureRegTenantID | Sort-Object ExpiresOn | Select-Object -Last 1 -ErrorAction Stop

            # Define variables and create an array to store all information
            $package = "$onlinePackage"
            $azpkg = $null
            $azpkg = @{
                id         = ""
                publisher  = ""
                sku        = ""
                offer      = ""
                azpkgPath  = ""
                name       = ""
                type       = ""
            }

            ### Get the package information ###
            $uri1 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($azureRegSubId.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products?api-version=2016-01-01"
            $Headers = @{ 'authorization' = "Bearer $($Token.AccessToken)"} 
            $product = (Invoke-RestMethod -Method GET -Uri $uri1 -Headers $Headers).value | Where-Object {$_.name -like "$package"} | Sort-Object -Property @{Expression = {$_.properties.offerVersion}; Ascending = $true} | Select-Object -Last 1 -ErrorAction Stop

            $azpkg.id = $product.name.Split('/')[-1]
            $azpkg.type = $product.properties.productKind
            $azpkg.publisher = $product.properties.publisherDisplayName
            $azpkg.sku = $product.properties.sku
            $azpkg.offer = $product.properties.offer

            # Get product info
            $uri2 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($azureRegSubId.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products/$($azpkg.id)?api-version=2016-01-01"
            $Headers = @{ 'authorization' = "Bearer $($Token.AccessToken)"} 
            $productDetails = Invoke-RestMethod -Method GET -Uri $uri2 -Headers $Headers
            $azpkg.name = $productDetails.properties.galleryItemIdentity

            # Get download location for Ubuntu Server 16.04 LTS AZPKG file
            $uri3 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($azureRegSubId.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products/$($azpkg.id)/listDetails?api-version=2016-01-01"
            $downloadDetails = Invoke-RestMethod -Method POST -Uri $uri3 -Headers $Headers
            $azpkg.azpkgPath = $downloadDetails.galleryPackageBlobSasUri

            # Display Legal Terms
            $legalTerms = $productDetails.properties.description
            $legalDisplay = $legalTerms -replace '<.*?>', ''
            Write-Host "$legalDisplay" -ForegroundColor Yellow
        }

        elseif ((!$registerASDK) -or ($registerASDK -and ($deploymentMode -ne "Online"))) {
            $azpkg = $null
            $azpkg = @{
                publisher  = "Canonical"
                sku        = "16.04-LTS"
                offer      = "UbuntuServer"
                vhdVersion = "1.0.0"
                osVersion  = "Linux"
                name       = "Canonical.UbuntuServer1604LTS-ARM.1.0.0"
            }
        }



        #####################################

        ### PACKAGES ###
        # Now check for and create (if required) AZPKG files for sideloading
        # If the user chose not to register the ASDK, but the deployment is "online", the step below will grab an azpkg file from Github
        if ($deploymentMode -eq "Online") {
            if ($registerASDK) {
                ### Login to Azure to get all the details about the syndicated Windows Server 2016 marketplace offering ###
                Import-Module "$modulePath\Syndication\AzureStack.MarketplaceSyndication.psm1"
                Login-AzureRmAccount -EnvironmentName "AzureCloud" -SubscriptionId $azureRegSubId -TenantId $azureRegTenantID -Credential $azureRegCreds -ErrorAction Stop | Out-Null
                $azureEnvironment = Get-AzureRmEnvironment -Name AzureCloud
                Remove-Variable -Name Registration -Force -Confirm:$false -ErrorAction SilentlyContinue
                $Registration = ((Get-AzureRmResource | Where-Object { $_.ResourceType -eq "Microsoft.AzureStack/registrations"} | `
                            Where-Object { ($_.ResourceName -like "asdkreg*") -or ($_.ResourceName -like "AzureStack*")}) | Select-Object -First 1 -ErrorAction SilentlyContinue -Verbose).ResourceName
                if (!$Registration) {
                    throw "No registration records found in your chosen Azure subscription. Please validate the success of your ASDK registration and ensure records have been created successfully."
                    Set-Location $ScriptLocation
                    return
                }
                # Retrieve the access token
                $token = $null
                $tokens = $null
                $tokens = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems()
                $token = $tokens | Where-Object Resource -EQ $azureEnvironment.ActiveDirectoryServiceEndpointResourceId | Where-Object TenantId -EQ $azureRegTenantID | Sort-Object ExpiresOn | Select-Object -Last 1 -ErrorAction Stop

                $package = $onlinePackage
                $azpkg = $null
                $azpkg = @{
                    id        = ""
                    publisher = ""
                    sku       = ""
                    offer     = ""
                    azpkgPath = ""
                    name      = ""
                    type      = ""
                }
                    # Get the package information
                    $uri1 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($azureRegSubId.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products?api-version=2016-01-01"
                    $Headers = @{ 'authorization' = "Bearer $($Token.AccessToken)"} 
                    $product = (Invoke-RestMethod -Method GET -Uri $uri1 -Headers $Headers).value | Where-Object {$_.name -like "$package"} | Sort-Object Name | Select-Object -Last 1

                        $azpkg.id = $product.name.Split('/')[-1]
                        $azpkg.type = $product.properties.productKind
                        $azpkg.publisher = $product.properties.publisherDisplayName
                        $azpkg.sku = $product.properties.sku
                        $azpkg.offer = $product.properties.offer

                        # Get product info
                        $uri2 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($azureRegSubId.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products/$($azpkg.id)?api-version=2016-01-01"
                        $Headers = @{ 'authorization' = "Bearer $($Token.AccessToken)"} 
                        $productDetails = Invoke-RestMethod -Method GET -Uri $uri2 -Headers $Headers
                        $azpkg.name = $productDetails.properties.galleryItemIdentity

                        # Get download location for AZPKG file
                        $uri3 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($azureRegSubId.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products/$($azpkg.id)/listDetails?api-version=2016-01-01"
                        $downloadDetails = Invoke-RestMethod -Method POST -Uri $uri3 -Headers $Headers
                        $azpkg.azpkgPath = $downloadDetails.galleryPackageBlobSasUri

                        # Display Legal Terms
                        $legalTerms = $productDetails.properties.description
                        $legalDisplay = $legalTerms -replace '<.*?>', ''
                        Write-Host "$legalDisplay" -ForegroundColor Yellow
                    }

                    elseif (!$registerASDK) {
                        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                        Write-CustomVerbose -Message "You chose not to register your Azure Stack to Azure. Checking for existing Windows Server gallery items"
                        $package = $null
                        $package = (Get-AzsGalleryItem | Where-Object {$_.name -like "$offlinePackage"} | Sort-Object CreatedTime -Descending | Select-Object -First 1)
                        # Check to see if the package exists already in the Gallery
                        if ($package) {
                            Write-CustomVerbose -Message "Found the following existing package in your gallery: $($package.Identity) - No need to upload a new one"
                        }

                    }

                ### With all the information stored in the arrays, log back into Azure Stack to check for existing gallery items and push new ones if required ###
                Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                foreach ($azpkg in $azpkgArray) {
                    Write-CustomVerbose -Message "Checking for the following packages: $($azpkg.name)"
                    if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$($azpkg.name)*"}) {
                        Write-CustomVerbose -Message "Found the following existing package in your Gallery: $($azpkg.name). No need to upload a new one"
                    }
                    else {
                        Write-CustomVerbose -Message "Didn't find this package: $($azpkg.name)"
                        Write-CustomVerbose -Message "Will need to side load it in to the gallery"
                        $Retries = 0
                        # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
                        while (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "$($azpkg.name)"}) -and ($Retries++ -lt 20)) {
                            try {
                                Write-CustomVerbose -Message "$($azpkg.name) doesn't exist in the gallery. Upload attempt #$Retries"
                                Write-CustomVerbose -Message "Uploading $($azpkg.name) from $($azpkg.azpkgPath)"
                                Add-AzsGalleryItem -GalleryItemUri $($azpkg.azpkgPath) -Force -Confirm:$false -ErrorAction SilentlyContinue
                            }
                            catch {
                                Write-CustomVerbose -Message "Upload wasn't successful. Waiting 5 seconds before retrying."
                                Write-CustomVerbose -Message "$_.Exception.Message"
                                Start-Sleep -Seconds 5
                            }
                        }
                        if (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "$($azpkg.name)"}) -and ($Retries++ -ge 20)) {
                            throw "Uploading gallery item failed after $Retries attempts. Exiting process."
                            Set-Location $ScriptLocation
                            return
                        }
                    }
                }
            }
            elseif (!$registerASDK) {
                Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                $packageArray = @()
                $packageArray.Clear()
                $packageArray = "Microsoft.WindowsServer2016Datacenter-ARM.1.0.0", "Microsoft.WindowsServer2016DatacenterServerCore-ARM.1.0.0"
                Write-CustomVerbose -Message "You chose not to register your Azure Stack to Azure. Checking for existing Windows Server gallery items"

                foreach ($package in $packageArray) {
                    $wsPackage = $null
                    $wsPackage = (Get-AzsGalleryItem | Where-Object {$_.name -like "$package"} | Sort-Object CreatedTime -Descending | Select-Object -First 1)
                    # Check to see if the package exists already in the Gallery
                    if ($wsPackage) {
                        Write-CustomVerbose -Message "Found the following existing package in your gallery: $($wsPackage.Identity) - No need to upload a new one"
                    }
                    else {
                        # If the package doesn't exist, sideload it directly from GitHub
                        $wsPackage = $package
                        Write-CustomVerbose -Message "Didn't find this package: $wsPackage"
                        Write-CustomVerbose -Message "Will need to sideload it in to the gallery"
                        $galleryItemUri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/WindowsServer/$wsPackage.azpkg"
                        $Retries = 0
                        # Sometimes the gallery item doesn't get added, so perform checks and attempt multiple times if necessary
                        While (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "$wsPackage"}) -and ($Retries++ -lt 20)) {
                            try {
                                Write-CustomVerbose -Message "$wsPackage doesn't exist in the gallery. Upload attempt #$Retries"
                                Write-CustomVerbose -Message "Uploading $wsPackage from $galleryItemUri"
                                Add-AzsGalleryItem -GalleryItemUri $galleryItemUri -Force -Confirm:$false -ErrorAction SilentlyContinue
                            }
                            catch {
                                Write-CustomVerbose -Message "Upload wasn't successful. Waiting 5 seconds before retrying."
                                Write-CustomVerbose -Message "$_.Exception.Message"
                                Start-Sleep -Seconds 5
                            }
                        }
                        if (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "$wsPackage"}) -and ($Retries++ -ge 20)) {
                            throw "Uploading gallery item failed after $Retries attempts. Exiting process."
                            Set-Location $ScriptLocation
                            return
                        }
                    }
                }
            }
            elseif (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline")) {
                Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                $packageArray = @()
                $packageArray.Clear()
                $packageArray = Get-ChildItem -Path "$ASDKpath\packages" -Recurse -Include "*WindowsServer*.azpkg" -ErrorAction Stop
                if (!$registerASDK) {
                    Write-CustomVerbose -Message "You chose not to register your Azure Stack to Azure. Checking for existing Windows Server gallery items"
                }
                # Check for existing gallery items
                foreach ($package in $packageArray) {
                    $wsPackage = $null
                    $wsPackage = (Get-AzsGalleryItem | Where-Object {$_.name -like "$($package.Basename)"} | Sort-Object CreatedTime -Descending | Select-Object -First 1)
                    if ($wsPackage) {
                        Write-CustomVerbose -Message "Found the following existing package in your gallery: $($wsPackage.Identity) - No need to upload a new one"
                    }
                    # If no gallery items found, sideload from the extracted zip file.
                    else {
                        $azpkgPackageName = $package.Basename
                        Write-CustomVerbose -Message "Didn't find this package: $azpkgPackageName"
                        Write-CustomVerbose -Message "Will need to sideload it in to the gallery"
                        $azpkgPackageURL = Add-OfflineAZPKG -azpkgPackageName $azpkgPackageName -Verbose
                        $Retries = 0
                        # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
                        while (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "*$azpkgPackageName*"}) -and ($Retries++ -lt 20)) {
                            try {
                                Write-CustomVerbose -Message "$azpkgPackageName doesn't exist in the gallery. Upload attempt #$Retries"
                                Write-CustomVerbose -Message "Uploading $azpkgPackageName from $azpkgPackageURL"
                                Add-AzsGalleryItem -GalleryItemUri $azpkgPackageURL -Force -Confirm:$false -ErrorAction SilentlyContinue
                            }
                            catch {
                                Write-CustomVerbose -Message "Upload wasn't successful. Waiting 5 seconds before retrying."
                                Write-CustomVerbose -Message "$_.Exception.Message"
                                Start-Sleep -Seconds 5
                            }
                        }
                        if (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "*$azpkgPackageName*"}) -and ($Retries++ -ge 20)) {
                            throw "Uploading gallery item failed after $Retries attempts. Exiting process."
                            Set-Location $ScriptLocation
                            return
                        }
                    }
                }
            }
        # Update the ConfigASDKProgressLog.csv file with successful completion
        Write-Verbose "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        throw "$_.Exception.Message"
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}
Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue