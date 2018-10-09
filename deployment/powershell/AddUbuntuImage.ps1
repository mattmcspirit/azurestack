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
New-Item -ItemType Directory -Path "$ScriptLocation\Logs\$logDate\Ubuntu" -Force | Out-Null
$logPath = "$ScriptLocation\Logs\$logDate\Ubuntu"

### START LOGGING ###
$runTime = $(Get-Date).ToString("MMdd-HHmmss")
$fullLogPath = "$logPath\Ubuntu$runTime.txt"
Start-Transcript -Path "$fullLogPath" -Append -IncludeInvocationHeader

$progress = Import-Csv -Path $ConfigASDKProgressLogPath
$RowIndex = [array]::IndexOf($progress.Stage, "UbuntuImage")

# Create RG & images folder
$asdkImagesRGName = "azurestack-images"
$asdkImagesStorageAccountName = "asdkimagesstor"
$asdkImagesContainerName = "asdkimagescontainer"

if (!$([System.IO.Directory]::Exists("$ASDKpath\images"))) {
    New-Item -Path "$ASDKpath\images" -ItemType Directory -Force | Out-Null
}

if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Log into Azure Stack to check for existing images and push new ones if required ###
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        # Test/Create RG
        if (-not (Get-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -ErrorAction SilentlyContinue)) {
            New-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
        }
        # Test/Create Storage
        $asdkStorageAccount = Get-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName -ErrorAction SilentlyContinue
        if (-not ($asdkStorageAccount)) {
            $asdkStorageAccount = New-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -Location $azsLocation -ResourceGroupName $asdkImagesRGName -Type Standard_LRS -ErrorAction Stop
        }
        Set-AzureRmCurrentStorageAccount -StorageAccountName $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName
        # Test/Create Container
        $asdkContainer = Get-AzureStorageContainer -Name $asdkImagesContainerName -ErrorAction SilentlyContinue
        if (-not ($asdkContainer)) {
            $asdkContainer = New-AzureStorageContainer -Name $asdkImagesContainerName -Permission Blob -Context $asdkStorageAccount.Context -ErrorAction Stop
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
            $package = "*Canonical.UbuntuServer1604LTS*"
            $azpkg = $null
            $azpkg = @{
                id         = ""
                publisher  = ""
                sku        = ""
                offer      = ""
                azpkgPath  = ""
                name       = ""
                type       = ""
                vhdPath    = ""
                vhdVersion = ""
                osVersion  = ""
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

            # Get download information for Ubuntu Server 16.04 LTS VHD file
            $azpkg.vhdPath = $downloadDetails.properties.osDiskImage.sourceBlobSasUri
            $azpkg.vhdVersion = $downloadDetails.properties.version
            $azpkg.osVersion = $downloadDetails.properties.osDiskImage.operatingSystem

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

        ### Log back into Azure Stack to check for existing images and push new ones if required ###
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

        Write-Verbose "Checking to see if an Ubuntu Server 16.04-LTS VM Image is present in your Azure Stack Platform Image Repository"
        if ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
            Write-Verbose "There appears to be at least 1 suitable Ubuntu Server 16.04-LTS VM image within your Platform Image Repository which we will use for the ASDK Configurator. Here are the details:"
            Write-Verbose ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}".' -f $azpkg.publisher, $azpkg.offer, $azpkg.sku, $azpkg.vhdVersion) -ErrorAction SilentlyContinue
        }

        else {
            Write-Verbose "No existing suitable Ubuntu Server 1604-LTS VM image exists." 
            Write-Verbose "The Ubuntu Server VM Image in the Azure Stack Platform Image Repository must have the following properties:"
            Write-Verbose "Publisher Name = $($azpkg.publisher)"
            Write-Verbose "Offer = $($azpkg.offer)"
            Write-Verbose "SKU = $($azpkg.sku)"
            Write-Verbose "Version = $($azpkg.vhdVersion)"
            Write-Verbose "Unfortunately, no image was found with these properties."
            Write-Verbose "Checking to see if the Ubuntu Server VHD already exists in ASDK Configurator folder"

            $validDownloadPathVHD = [System.IO.File]::Exists("$ASDKpath\images\$($azpkg.offer)$($azpkg.vhdVersion).vhd")
            $validDownloadPathZIP = [System.IO.File]::Exists("$ASDKpath\images\$($azpkg.offer)$($azpkg.vhdVersion).zip")

            if ($validDownloadPathVHD -eq $true) {
                Write-Verbose "Located Ubuntu Server VHD in this folder. No need to download again..."
                $UbuntuServerVHD = Get-ChildItem -Path "$ASDKpath\images\$($azpkg.offer)$($azpkg.vhdVersion).vhd"
                Write-Verbose "Ubuntu Server VHD located at $UbuntuServerVHD"
            }
            elseif ($validDownloadPathZIP -eq $true) {
                Write-Verbose "Cannot find a previously extracted Ubuntu Server VHD with name $($azpkg.offer)$($azpkg.vhdVersion).vhd"
                Write-Verbose "Checking to see if the Ubuntu Server ZIP already exists in ASDK Configurator folder"
                $UbuntuServerZIP = Get-ChildItem -Path "$ASDKpath\images\$($azpkg.offer)$($azpkg.vhdVersion).zip"
                Write-Verbose "Ubuntu Server ZIP located at $UbuntuServerZIP"
                Expand-Archive -Path $UbuntuServerZIP -DestinationPath "$ASDKpath\images" -Force -ErrorAction Stop
                $UbuntuServerVHD = Get-ChildItem -Path "$ASDKpath\images\" -Filter *.vhd | Rename-Item -NewName "$($azpkg.offer)$($azpkg.vhdVersion).vhd" -PassThru -Force -ErrorAction Stop
            }
            else {
                # No existing Ubuntu Server VHD or Zip exists that matches the name (i.e. that has previously been extracted and renamed) so a fresh one will be
                # downloaded, extracted and the variable $UbuntuServerVHD updated accordingly.
                Write-Verbose "Cannot find a previously extracted Ubuntu Server download or ZIP file"
                Write-Verbose "Begin download of correct Ubuntu Server ZIP and extraction of VHD into $ASDKpath"

                if ($registerASDK -and ($deploymentMode -eq "Online")) {
                    $ubuntuBuild = $azpkg.vhdVersion
                    $ubuntuBuild = $ubuntuBuild.Substring(0, $ubuntuBuild.Length - 1)
                    $ubuntuBuild = $ubuntuBuild.split('.')[2]
                    $ubuntuURI = "https://cloud-images.ubuntu.com/releases/16.04/release-$ubuntuBuild/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"

                }
                elseif (!$registerASDK -and ($deploymentMode -eq "Online")) {
                    $ubuntuURI = "https://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"
                }
                $ubuntuDownloadLocation = "$ASDKpath\images\$($azpkg.offer)$($azpkg.vhdVersion).zip"
                DownloadWithRetry -downloadURI "$ubuntuURI" -downloadLocation "$ubuntuDownloadLocation" -retries 10
       
                Expand-Archive -Path "$ASDKpath\images\$($azpkg.offer)$($azpkg.vhdVersion).zip" -DestinationPath "$ASDKpath\images\" -Force -ErrorAction Stop
                $UbuntuServerVHD = Get-ChildItem -Path "$ASDKpath\images\" -Filter *disk1.vhd | Rename-Item -NewName "$($azpkg.offer)$($azpkg.vhdVersion).vhd" -PassThru -Force -ErrorAction Stop
            }

            # Upload the image to the Azure Stack Platform Image Repository
            Write-Verbose "Extraction Complete. Beginning upload of VHD to Platform Image Repository"
            
            # Upload VHD to Storage Account
            $asdkStorageAccount.PrimaryEndpoints.Blob
            $ubuntuServerURI = '{0}{1}/{2}' -f $asdkStorageAccount.PrimaryEndpoints.Blob.AbsoluteUri, $asdkImagesContainerName, $UbuntuServerVHD.Name

            # Check there's not a VHD already uploaded to storage
            if ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $UbuntuServerVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and ($ubuntuUploadSuccess)) {
                Write-Verbose "You already have an upload of $($UbuntuServerVHD.Name) within your Storage Account. No need to re-upload."
                Write-Verbose "Core VHD path = $((Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $UbuntuServerVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue).ICloudBlob.StorageUri.PrimaryUri.AbsoluteUri)"
            }

            # Sometimes Add-AzureRmVHD has an error about "The pipeline was not run because a pipeline is already running. Pipelines cannot be run concurrently". Rerunning the upload typically helps.
            # Check that a) there's no VHD uploaded and b) the previous attempt(s) didn't complete successfully and c) you've attempted an upload no more than 3 times
            $uploadVhdAttempt = 1
            while (!$(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $UbuntuServerVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$ubuntuUploadSuccess) -and ($uploadVhdAttempt -le 3)) {
                Try {
                    # Log back into Azure Stack to ensure login hasn't timed out
                    Write-Verbose "No existing image found. Upload Attempt: $uploadVhdAttempt"
                    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    Add-AzureRmVhd -Destination $ubuntuServerURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $UbuntuServerVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                    $ubuntuUploadSuccess = $true
                }
                catch {
                    Write-Verbose "Upload failed."
                    Write-Verbose "$_.Exception.Message"
                    $uploadVhdAttempt++
                    $ubuntuUploadSuccess = $false
                }
            }

            # Sometimes Add-AzureRmVHD has an error about "The pipeline was not run because a pipeline is already running. Pipelines cannot be run concurrently". Rerunning the upload typically helps.
            # Check that a) there's a VHD uploaded but b) the attempt didn't complete successfully (VHD in unreliable state) and c) you've attempted an upload no more than 3 times

            while ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $UbuntuServerVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$ubuntuUploadSuccess) -and ($uploadVhdAttempt -le 3)) {
                Try {
                    # Log back into Azure Stack to ensure login hasn't timed out
                    Write-Verbose "There was a previously failed upload. Upload Attempt: $uploadVhdAttempt"
                    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    Add-AzureRmVhd -Destination $ubuntuServerURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $UbuntuServerVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                    $ubuntuUploadSuccess = $true
                }
                catch {
                    Write-Verbose "Upload failed."
                    Write-Verbose "$_.Exception.Message"
                    $uploadVhdAttempt++
                    $ubuntuUploadSuccess = $false
                }
            }

            # This is one final catch-all for the upload process
            # Check that a) there's no VHD uploaded and b) you've attempted an upload no more than 3 times
            while (!$(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $UbuntuServerVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and ($uploadVhdAttempt -le 3)) {
                Try {
                    # Log back into Azure Stack to ensure login hasn't timed out
                    Write-Verbose "No existing image found. Upload Attempt: $uploadVhdAttempt"
                    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    Add-AzureRmVhd -Destination $ubuntuServerURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $UbuntuServerVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                    $ubuntuUploadSuccess = $true
                }
                catch {
                    Write-Verbose "Upload failed."
                    Write-Verbose "$_.Exception.Message"
                    $uploadVhdAttempt++
                    $ubuntuUploadSuccess = $false
                }
            }

            if ($uploadVhdAttempt -gt 3) {
                Write-CustomVerbose "Uploading VHD to Azure Stack storage failed and 3 upload attempts. Rerun the ConfigASDK.ps1 script to retry."
                $ubuntuUploadSuccess = $false
                throw "Uploading image failed"
                Set-Location $ScriptLocation
                return
            }

            # Add the Platform Image
            Add-AzsPlatformImage -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -OsType $azpkg.osVersion -OsUri "$ubuntuServerURI" -Force -Confirm: $false -Verbose -ErrorAction Stop
            if ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
                Write-Verbose ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" successfully uploaded.' -f $azpkg.publisher, $azpkg.offer, $azpkg.sku, $azpkg.vhdVersion) -ErrorAction SilentlyContinue
                Write-Verbose "Cleaning up local hard drive space - deleting VHD file, but keeping ZIP"
                Get-ChildItem -Path "$ASDKpath\images" -Filter *.vhd | Remove-Item -Force
                Write-Verbose "Cleaning up VHD from storage account"
                Remove-AzureStorageBlob -Blob $UbuntuServerVHD.Name -Container $asdkImagesContainerName -Context $asdkStorageAccount.Context -Force
            }
            elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Failed') {
                throw "Adding VM image failed"
            }
            elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Canceled') {
                throw "Adding VM image was canceled"
            }
        }

        ### Add Packages ###
        ### If the user has chosen to register the ASDK as part of the process, the script will side load an AZPKG from the Azure Marketplace, otherwise ###
        ### it will add one from GitHub (assuming an online deployment choice) ###

        $azpkgPackageName = "$($azpkg.name)"
        Write-Verbose "Checking for the following package: $azpkgPackageName"
        if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$azpkgPackageName*"}) {
            Write-Verbose "Found the following existing package in your Gallery: $azpkgPackageName. No need to upload a new one"
        }
        else {
            Write-Verbose "Didn't find this package: $azpkgPackageName"
            Write-Verbose "Will need to side load it in to the gallery"

            if ($registerASDK -and ($deploymentMode -eq "Online")) {
                $azpkgPackageURL = $($azpkg.azpkgPath)
                Write-Verbose "Uploading $azpkgPackageName with the ID: $($azpkg.id) from $($azpkg.azpkgPath)"
            }
            elseif (!$registerASDK -and ($deploymentMode -eq "Online")) {     
                $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/Ubuntu/Canonical.UbuntuServer1604LTS-ARM.1.0.0.azpkg" 
            }
            # If this isn't an online deployment, use the extracted zip file, and upload to a storage account
            elseif (($registerASDK -or !$registerASDK) -and (($deploymentMode -eq "PartialOnline") -or ($deploymentMode -eq "Offline"))) {
                $azpkgPackageURL = Add-OfflineAZPKG -azpkgPackageName $azpkgPackageName -Verbose
            }
            $Retries = 0
            # Sometimes the gallery item doesn't get added successfully, so perform checks and attempt multiple uploads if necessary
            while (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "*$azpkgPackageName*"}) -and ($Retries++ -lt 20)) {
                try {
                    Write-Verbose "$azpkgPackageName doesn't exist in the gallery. Upload Attempt #$Retries"
                    Write-Verbose "Uploading $azpkgPackageName from $azpkgPackageURL"
                    Add-AzsGalleryItem -GalleryItemUri $azpkgPackageURL -Force -Confirm:$false -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Verbose "Upload wasn't successful. Waiting 5 seconds before retrying."
                    Write-Verbose "$_.Exception.Message"
                    Start-Sleep -Seconds 5
                }
            }
            if (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "*$azpkgPackageName*"}) -and ($Retries++ -ge 20)) {
                throw "Uploading gallery item failed after $Retries attempts. Exiting process."
                Set-Location $ScriptLocation
                return
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
        Write-Verbose "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue