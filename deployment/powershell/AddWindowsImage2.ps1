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

# Set Storage Variables
$asdkImagesRGName = "azurestack-images"
$asdkImagesStorageAccountName = "asdkimagesstor"
$asdkImagesContainerName = "asdkimagescontainer"

if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Set path for Windows Updates
        $target = "$ASDKpath\images"
        Set-Location "$ASDKpath\images"

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

        # Log into Azure Stack to check for existing images and push new ones if required ###
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        if ($registerASDK -and ($deploymentMode -eq "Online")) {
            # Logout to clean up
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force
            ### Login to Azure to get all the details about the syndicated Windows Server marketplace offering ###
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
                vhdVersion = "1.0.0"
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

            # Get download location for Windows Server AZPKG file
            $uri3 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($azureRegSubId.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products/$($azpkg.id)/listDetails?api-version=2016-01-01"
            $downloadDetails = Invoke-RestMethod -Method POST -Uri $uri3 -Headers $Headers
            $azpkg.azpkgPath = $downloadDetails.galleryPackageBlobSasUri
            $azpkg.osVersion = $downloadDetails.properties.osDiskImage.operatingSystem

            # Display Legal Terms
            $legalTerms = $productDetails.properties.description
            $legalDisplay = $legalTerms -replace '<.*?>', ''
            Write-Host "$legalDisplay" -ForegroundColor Yellow
        }
        elseif ((!$registerASDK) -or ($registerASDK -and ($deploymentMode -ne "Online"))) {
            $package = "$offlinePackage"
            $azpkg = $null
            $azpkg = @{
                publisher  = "Microsoft"
                sku        = "$sku"
                offer      = "WindowsServer"
                vhdVersion = "1.0.0"
                osVersion  = "Windows"
                name       = "$offlinePackage"
            }
        }

        ### Log back into Azure Stack to check for existing images and push new ones if required ###
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        Write-Verbose "Checking to see if the Windows Server Image is present in your Azure Stack Platform Image Repository"
        if ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
            Write-Verbose "There appears to be at least 1 suitable Windows Server $($azpkg.sku) VM image within your Platform Image Repository which we will use for the ASDK Configurator. Here are the details:"
            Write-Verbose ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}".' -f $azpkg.publisher, $azpkg.offer, $azpkg.sku, $azpkg.vhdVersion) -ErrorAction SilentlyContinue
        }
        else {
            Write-Verbose "No existing suitable Windows Server $($azpkg.sku) VM image exists." 
            Write-Verbose "The Windows Server VM Image in the Azure Stack Platform Image Repository must have the following properties:"
            Write-Verbose "Publisher Name = $($azpkg.publisher)"
            Write-Verbose "Offer = $($azpkg.offer)"
            Write-Verbose "SKU = $($azpkg.sku)"
            Write-Verbose "Version = $($azpkg.vhdVersion)"
            Write-Verbose "Unfortunately, no image was found with these properties."
            Write-Verbose "Checking to see if the Windows Server VHD already exists in an Azure Stack Storage Account"

            # Test/Create RG
            if (-not (Get-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -ErrorAction SilentlyContinue)) { New-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop }
            # Test/Create Storage
            $asdkStorageAccount = Get-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName -ErrorAction SilentlyContinue
            if (-not ($asdkStorageAccount)) { $asdkStorageAccount = New-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -Location $azsLocation -ResourceGroupName $asdkImagesRGName -Type Standard_LRS -ErrorAction Stop }
            Set-AzureRmCurrentStorageAccount -StorageAccountName $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName | Out-Null
            # Test/Create Container
            $asdkContainer = Get-AzureStorageContainer -Name $asdkImagesContainerName -ErrorAction SilentlyContinue
            if (-not ($asdkContainer)) { $asdkContainer = New-AzureStorageContainer -Name $asdkImagesContainerName -Permission Blob -Context $asdkStorageAccount.Context -ErrorAction Stop }
            if ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob "$($windowsImage).vhd" -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue)) {
                Write-CustomVerbose -Message "You already have an upload of $($windowsImage).vhd within your Storage Account. No need to re-upload."
                $windowsServerURI = "$((Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $($windowsImage).vhd -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue).ICloudBlob.StorageUri.PrimaryUri.AbsoluteUri)"
                Write-CustomVerbose -Message "Windows Server VHD path = $windowsServerURI"

            }
            else {
                Write-CustomVerbose -Message "There is no suitable $($windowsImage).vhd image within your Storage Account. We'll need to upload a new one."
                Write-CustomVerbose -Message "Checking for a local copy first..."
                # Check for local VHD first
                $validDownloadPathVHD = [System.IO.File]::Exists("$ASDKpath\images\$($windowsImage).vhd")
                # If there's no local VHD, create one.
                if ($validDownloadPathVHD -eq $true) {
                    Write-Verbose "Located suitable Windows Server VHD in this folder. No need to download again..."
                    $WindowsServerVHD = Get-ChildItem -Path "$ASDKpath\images\$($windowsImage).vhd"
                    Write-Verbose "Windows Server VHD located at $WindowsServerVHD"
                }
                else {
                    if ($deploymentMode -eq "Online") {
                        # Download Convert-WindowsImage.ps1
                        $convertWindowsURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/scripts/Convert-WindowsImage.ps1"
                        $convertWindowsDownloadLocation = "$ASDKpath\images\Convert-WindowsImage.ps1"
                        $convertWindowsImageExists = [System.IO.File]::Exists("$ASDKpath\images\Convert-WindowsImage.ps1")
                        if ($convertWindowsImageExists -eq $false) {
                            Write-CustomVerbose -Message "Downloading Convert-WindowsImage.ps1 to create the VHD from the ISO"
                            Write-CustomVerbose -Message "The download will be stored in $ASDKpath\images"
                            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                            DownloadWithRetry -downloadURI "$convertWindowsURI" -downloadLocation "$convertWindowsDownloadLocation" -retries 10
                        }
                    }
                    .\Convert-WindowsImage.ps1 -SourcePath $ISOpath -SizeBytes 40GB -Edition "$edition" -VHDPath "$ASDKpath\images\$($windowsImage).vhd" `
                        -VHDFormat VHD -VHDType Fixed -VHDPartitionStyle MBR -Feature "NetFx3" -Package $target -Passthru -Verbose
                    $WindowsServerVHD = Get-ChildItem -Path "$ASDKpath\images\$($windowsImage).vhd"
                }
                # At this point, there is a local image (either existing or new, that needs uploading, first to a Storage Account
                Write-Verbose "Beginning upload of VHD to Azure Stack Storage Account"
                # Upload VHD to Storage Account
                $windowsServerURI = "$((Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $($windowsImage).vhd -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue).ICloudBlob.StorageUri.PrimaryUri.AbsoluteUri)"

                # Sometimes Add-AzureRmVHD has an error about "The pipeline was not run because a pipeline is already running. Pipelines cannot be run concurrently". Rerunning the upload typically helps.
                # Check that a) there's no VHD uploaded and b) the previous attempt(s) didn't complete successfully and c) you've attempted an upload no more than 3 times
                $uploadVhdAttempt = 1
                while (!$(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $windowsServerVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$uploadSuccess) -and ($uploadVhdAttempt -le 3)) {
                    Try {
                        # Log back into Azure Stack to ensure login hasn't timed out
                        Write-Verbose "No existing image found. Upload Attempt: $uploadVhdAttempt"
                        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                        Add-AzureRmVhd -Destination $windowsServerURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $windowsServerVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                        $uploadSuccess = $true
                    }
                    catch {
                        Write-Verbose "Upload failed."
                        Write-Verbose "$_.Exception.Message"
                        $uploadVhdAttempt++
                        $uploadSuccess = $false
                    }
                }

                # Sometimes Add-AzureRmVHD has an error about "The pipeline was not run because a pipeline is already running. Pipelines cannot be run concurrently". Rerunning the upload typically helps.
                # Check that a) there's a VHD uploaded but b) the attempt didn't complete successfully (VHD in unreliable state) and c) you've attempted an upload no more than 3 times

                while ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $windowsServerVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$uploadSuccess) -and ($uploadVhdAttempt -le 3)) {
                    Try {
                        # Log back into Azure Stack to ensure login hasn't timed out
                        Write-Verbose "There was a previously failed upload. Upload Attempt: $uploadVhdAttempt"
                        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                        Add-AzureRmVhd -Destination $windowsServerURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $windowsServerVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                        $uploadSuccess = $true
                    }
                    catch {
                        Write-Verbose "Upload failed."
                        Write-Verbose "$_.Exception.Message"
                        $uploadVhdAttempt++
                        $uploadSuccess = $false
                    }
                }

                # This is one final catch-all for the upload process
                # Check that a) there's no VHD uploaded and b) you've attempted an upload no more than 3 times
                while (!$(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $windowsServerVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and ($uploadVhdAttempt -le 3)) {
                    Try {
                        # Log back into Azure Stack to ensure login hasn't timed out
                        Write-Verbose "No existing image found. Upload Attempt: $uploadVhdAttempt"
                        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                        Add-AzureRmVhd -Destination $windowsServerURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $windowsServerVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                        $uploadSuccess = $true
                    }
                    catch {
                        Write-Verbose "Upload failed."
                        Write-Verbose "$_.Exception.Message"
                        $uploadVhdAttempt++
                        $uploadSuccess = $false
                    }
                }

                if ($uploadVhdAttempt -gt 3) {
                    Write-CustomVerbose "Uploading VHD to Azure Stack storage failed and 3 upload attempts. Rerun the ConfigASDK.ps1 script to retry."
                    $uploadSuccess = $false
                    throw "Uploading image failed"
                    Set-Location $ScriptLocation
                    return
                }
            }

            # To reach this stage, there is now a valid image in the Storage Account, ready to be uploaded into the PIR
            # Add the Platform Image
            Add-AzsPlatformImage -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -OsType $azpkg.osVersion -OsUri "$windowsServerURI" -Force -Confirm: $false -Verbose -ErrorAction Stop
            if ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
                Write-Verbose ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" successfully uploaded.' -f $azpkg.publisher, $azpkg.offer, $azpkg.sku, $azpkg.vhdVersion) -ErrorAction SilentlyContinue
            }
            elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Failed') {
                throw "Adding VM image failed. Please check the logs and clean up the Azure Stack Platform Image Repository to remove the failed image, then retry."
            }
            elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Canceled') {
                throw "Adding VM image was canceled. Confirm the image doesn't show in the Azure Stack Platform Image Repository and if it does, remove it, then retry."
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
                $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/WindowsServer/$package.azpkg"
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
        Set-Location $ScriptLocation
        throw "$_.Exception.Message"
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue