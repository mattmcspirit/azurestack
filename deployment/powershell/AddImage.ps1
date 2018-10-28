[CmdletBinding()]
param (
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

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [ValidateSet("ServerCore", "ServerFull", "UbuntuServer")]
    [String] $image,

    [parameter(Mandatory = $false)]
    [pscredential] $azureRegCreds,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

    [parameter(Mandatory = $true)]
    [String] $ISOpath,

    [parameter(Mandatory = $true)]
    [ValidateSet("serial", "partialParallel", "parallel")]
    [String] $runMode,

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

if ($image -eq "UbuntuServer") {
    $logFolder = "UbuntuServer"
}
else {
    $logFolder = "WindowsImages"
}

### SET LOG LOCATION ###
$logDate = Get-Date -Format FileDate
New-Item -ItemType Directory -Path "$ScriptLocation\Logs\$logDate\$logFolder" -Force | Out-Null
$logPath = "$ScriptLocation\Logs\$logDate\$logFolder"

### START LOGGING ###
$runTime = $(Get-Date).ToString("MMdd-HHmmss")
$fullLogPath = "$logPath\$($image)$runTime.txt"
Start-Transcript -Path "$fullLogPath" -Append -IncludeInvocationHeader

$progressStage = "$($image)Image"
$progressCheck = CheckProgress -progressStage $progressStage

# Set Storage Variables
$asdkImagesRGName = "azurestack-images"
$asdkImagesStorageAccountName = "asdkimagesstor"
$asdkImagesContainerName = "asdkimagescontainer"
$csvImagePath = "C:\ClusterStorage\Volume1"

if (!$([System.IO.Directory]::Exists("$ASDKpath\images"))) {
    New-Item -Path "$ASDKpath\images" -ItemType Directory -Force | Out-Null   
}
if (!$([System.IO.Directory]::Exists("$ASDKpath\images\$image"))) {
    New-Item -Path "$ASDKpath\images\$image" -ItemType Directory -Force | Out-Null
}
if (!$([System.IO.Directory]::Exists("$csvImagePath\images"))) {
    New-Item -Path "$csvImagePath\images" -ItemType Directory -Force | Out-Null
}
if (!$([System.IO.Directory]::Exists("$csvImagePath\Images\$image"))) {
    New-Item -Path "$csvImagePath\Images\$image" -ItemType Directory -Force | Out-Null
}

if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
    try {
        if ($progressCheck -eq "Failed") {
            StageReset -progressStage $progressStage
        }
        # Need to confirm if Windows Update stage previously completed
        if ($image -ne "UbuntuServer") {
            $windowsUpdateCheck = CheckProgress -progressStage "WindowsUpdates"
            while ($windowsUpdateCheck -ne "Complete") {
                Write-Verbose -Message "The WindowsUpdates stage of the process has not yet completed. Checking again in 20 seconds"
                Start-Sleep -Seconds 20
                $windowsUpdateCheck = CheckProgress -progressStage "WindowsUpdates"     
                if ($windowsUpdateCheck -eq "Failed") {
                    throw "The WindowsUpdates stage of the process has failed. This is required before the Windows Server images can be created. Check the WindowsUpdates log, ensure that step is completed first, and rerun."
                }        
            }
        }
        # Need to confirm if the Ubuntu Server Image stage has completed (for partialParallel and serial deployments)
        if ($image -eq "ServerCore") {
            if (($runMode -eq "partialParallel") -or ($runMode -eq "serial")) {
                $ubuntuJobCheck = CheckProgress -progressStage "UbuntuServerImage"
                while ($ubuntuJobCheck -ne "Complete") {
                    Write-Verbose -Message "The UbuntuServerImage stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 20
                    $ubuntuJobCheck = CheckProgress -progressStage "UbuntuServerImage"
                    if ($ubuntuJobCheck -eq "Failed") {
                        throw "The UbuntuServerImage stage of the process has failed. This should fully complete before the Windows Server images are to be created. Check the UbuntuServerImage log, ensure that step is completed first, and rerun."
                    }
                }
            }
        }
        # Need to confirm if the Ubuntu Server Image stage has completed (for partialParallel and serial deployments)
        # and that the Server Core image stage has completed for serial deployments.
        if ($image -eq "ServerFull") {
            if ($runMode -eq "partialParallel") {
                $ubuntuJobCheck = CheckProgress -progressStage "UbuntuServerImage"
                while ($ubuntuJobCheck -ne "Complete") {
                    Write-Verbose -Message "The UbuntuServerImage stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 20
                    $ubuntuJobCheck = CheckProgress -progressStage "UbuntuServerImage"
                    if ($ubuntuJobCheck -eq "Failed") {
                        throw "The UbuntuServerImage stage of the process has failed. This should fully complete before the Windows Server images are to be created. Check the UbuntuServerImage log, ensure that step is completed first, and rerun."
                    }
                }
            }
            elseif ($runMode -eq "serial") {
                $serverCoreJobCheck = CheckProgress -progressStage "ServerCoreImage"
                while ($serverCoreJobCheck -ne "Complete") {
                    Write-Verbose -Message "The ServerCoreImage stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 20
                    $serverCoreJobCheck = CheckProgress -progressStage "ServerCoreImage"
                    if ($serverCoreJobCheck -eq "Failed") {
                        throw "The ServerCoreImage stage of the process has failed. This should fully complete before the Windows Server full image is created. Check the UbuntuServerImage log, ensure that step is completed first, and rerun."
                    }
                }
            }
        }
        Set-Location "$ASDKpath\images"
        # Check which image is being deployed
        if ($image -eq "ServerCore") {
            $sku = "2016-Datacenter-Server-Core"
            $edition = 'Windows Server 2016 SERVERDATACENTERCORE'
            $onlinePackage = "*Microsoft.WindowsServer2016DatacenterServerCore-ARM*"
            $offlinePackage = "Microsoft.WindowsServer2016DatacenterServerCore-ARM.1.0.0"
            $vhdVersion = "1.0.0"
            $publisher = "MicrosoftWindowsServer"
            $offer = "WindowsServer"
            $osVersion = "Windows"
        }
        elseif ($image -eq "ServerFull") {
            $sku = "2016-Datacenter"
            $edition = 'Windows Server 2016 SERVERDATACENTER'
            $onlinePackage = "*Microsoft.WindowsServer2016Datacenter-ARM*"
            $offlinePackage = "Microsoft.WindowsServer2016Datacenter-ARM.1.0.0"
            $vhdVersion = "1.0.0"
            $publisher = "MicrosoftWindowsServer"
            $offer = "WindowsServer"
            $osVersion = "Windows"
        }
        elseif ($image -eq "UbuntuServer") {
            $sku = "16.04-LTS"
            $onlinePackage = "*Canonical.UbuntuServer1604LTS*"
            $offlinePackage = "Canonical.UbuntuServer1604LTS-ARM.1.0.0"
            $publisher = "Canonical"
            $offer = "UbuntuServer"
            if ((!$registerASDK) -or ($registerASDK -and ($deploymentMode -ne "Online"))) {
                $vhdVersion = "1.0.0"
            }
            else {
                $vhdVersion = ""
            }
            $osVersion = "Linux"
        }

        # Log into Azure Stack to check for existing images and push new ones if required ###
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        if ($registerASDK -and ($deploymentMode -eq "Online")) {
            # Logout to clean up
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force
            ### Login to Azure to get all the details about the syndicated marketplace offering ###
            Import-Module "$modulePath\Syndication\AzureStack.MarketplaceSyndication.psm1"
            Add-AzureRmAccount -EnvironmentName "AzureCloud" -SubscriptionId $azureRegSubId -TenantId $azureRegTenantID -Credential $azureRegCreds -ErrorAction Stop | Out-Null
            $azureEnvironment = Get-AzureRmEnvironment -Name AzureCloud
            Remove-Variable -Name Registration -Force -Confirm:$false -ErrorAction SilentlyContinue
            $asdkHostName = ($env:computername).ToLower()
            $Registration = (Get-AzureRmResource | Where-Object { ($_.ResourceType -eq "Microsoft.AzureStack/registrations") `
                        -and (($_.Name -like "asdkreg-$asdkHostName*") -or ($_.Name -like "AzureStack*"))} | Select-Object -First 1 -ErrorAction SilentlyContinue -Verbose).Name
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
                vhdVersion = "$vhdVersion"
                osVersion  = ""
            }

            ### Get the package information ###
            $uri1 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($azureRegSubId.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products?api-version=2016-01-01"
            $Headers = @{ 'authorization' = "Bearer $($Token.AccessToken)"} 
            $product = (Invoke-RestMethod -Method GET -Uri $uri1 -Headers $Headers).value | Where-Object {$_.name -like "$package"} | Sort-Object -Property @{Expression = {$_.properties.offerVersion}; Ascending = $true} | Select-Object -Last 1 -ErrorAction Stop

            $azpkg.id = $product.name.Split('/')[-1]
            $azpkg.type = $product.properties.productKind
            $azpkg.publisher = $product.properties.publisherIdentifier
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
            $azpkg.osVersion = $downloadDetails.properties.osDiskImage.operatingSystem

            # Display Legal Terms
            $legalTerms = $productDetails.properties.description
            $legalDisplay = $legalTerms -replace '<.*?>', ''
            Write-Host "$legalDisplay" -ForegroundColor Yellow

            if ($image -eq "UbuntuServer") {
                # Get download information for Ubuntu Server 16.04 LTS VHD file
                $azpkg.vhdPath = $downloadDetails.properties.osDiskImage.sourceBlobSasUri
                $azpkg.vhdVersion = $downloadDetails.properties.version
            }
        }
        elseif ((!$registerASDK) -or ($registerASDK -and ($deploymentMode -ne "Online"))) {
            $package = "$offlinePackage"
            $azpkg = $null
            $azpkg = @{
                publisher  = "$publisher"
                sku        = "$sku"
                offer      = "$offer"
                vhdVersion = "$vhdVersion"
                osVersion  = "$osVersion"
                name       = "$offlinePackage"
            }
        }

        ### Log back into Azure Stack to check for existing images and push new ones if required ###
        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        Write-Verbose "Checking to see if the image is present in your Azure Stack Platform Image Repository"
        if ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
            Write-Verbose "There appears to be at least 1 suitable $($azpkg.sku) VM image within your Platform Image Repository which we will use for the ASDK Configurator. Here are the details:"
            Write-Verbose ('VM Image with publisher " {0}", offer " {1}", sku " {2}", version " {3}".' -f $azpkg.publisher, $azpkg.offer, $azpkg.sku, $azpkg.vhdVersion) -ErrorAction SilentlyContinue
        }
        else {
            Write-Verbose "No existing suitable $($azpkg.sku) VM image exists." 
            Write-Verbose "The image in the Azure Stack Platform Image Repository must have the following properties:"
            Write-Verbose "Publisher Name = $($azpkg.publisher)"
            Write-Verbose "Offer = $($azpkg.offer)"
            Write-Verbose "SKU = $($azpkg.sku)"
            Write-Verbose "Version = $($azpkg.vhdVersion)"
            Write-Verbose "Unfortunately, no image was found with these properties."
            Write-Verbose "Checking to see if the VHD already exists in an Azure Stack Storage Account"

            # Test/Create RG
            if (-not (Get-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -ErrorAction SilentlyContinue)) { New-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop }
            # Test/Create Storage
            $asdkStorageAccount = Get-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName -ErrorAction SilentlyContinue
            if (-not ($asdkStorageAccount)) { $asdkStorageAccount = New-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -Location $azsLocation -ResourceGroupName $asdkImagesRGName -Type Standard_LRS -ErrorAction Stop }
            Set-AzureRmCurrentStorageAccount -StorageAccountName $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName | Out-Null
            # Test/Create Container
            $asdkContainer = Get-AzureStorageContainer -Name $asdkImagesContainerName -ErrorAction SilentlyContinue
            if (-not ($asdkContainer)) { $asdkContainer = New-AzureStorageContainer -Name $asdkImagesContainerName -Permission Blob -Context $asdkStorageAccount.Context -ErrorAction Stop }

            if ($image -eq "UbuntuServer") { $blobName = "$($azpkg.offer)$($azpkg.vhdVersion).vhd" }
            else { $blobName = "$($image).vhd" }

            if ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob "$blobName" -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue)) {
                Write-Verbose "You already have an upload of $blobName within your Storage Account. No need to re-upload."
                $imageURI = $((Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob "$blobName" -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue).ICloudBlob.StorageUri.PrimaryUri.AbsoluteUri)
                Write-Verbose "VHD path = $imageURI"
            }
            else {
                Write-Verbose "There is no suitable $blobName image within your Storage Account. We'll need to upload a new one."
                $validDownloadPathVHD = [System.IO.File]::Exists("$csvImagePath\Images\$image\$blobName")
                Write-Verbose "Checking for a local copy first..."
                # If there's no local VHD, create one.
                if ($validDownloadPathVHD -eq $true) {
                    Write-Verbose "Located suitable VHD in this folder. No need to download again..."
                    $serverVHD = Get-ChildItem -Path "$csvImagePath\Images\$image\$blobName"
                    Write-Verbose "VHD located at $serverVHD"
                }
                else {
                    if ($image -eq "UbuntuServer") {
                        # Split for Ubuntu Image
                        $validDownloadPathZIP = [System.IO.File]::Exists("$ASDKpath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip")
                        if ($validDownloadPathZIP -eq $true) {
                            Write-Verbose "Cannot find a previously extracted Ubuntu Server VHD with name $blobName"
                            Write-Verbose "Checking to see if the Ubuntu Server ZIP already exists in ASDK Configurator folder"
                            $UbuntuServerZIP = Get-ChildItem -Path "$ASDKpath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip"
                            Write-Verbose "Ubuntu Server ZIP located at $UbuntuServerZIP"
                            if (!([System.IO.File]::Exists("$csvImagePath\Images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip"))) {
                                Copy-Item -Path "$ASDKpath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip" -Destination "$csvImagePath\Images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip" -Force -Verbose -ErrorAction Stop
                                $UbuntuServerZIP = Get-ChildItem -Path "$csvImagePath\Images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip"
                            }
                            else {
                                $UbuntuServerZIP = Get-ChildItem -Path "$csvImagePath\Images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip"
                            }
                            Expand-Archive -Path $UbuntuServerZIP -DestinationPath "$csvImagePath\Images\$image\" -Force -ErrorAction Stop
                            $serverVHD = Get-ChildItem -Path "$csvImagePath\Images\$image\" -Filter *disk1.vhd | Rename-Item -NewName "$blobName" -PassThru -Force -ErrorAction Stop
                        }
                        else {
                            # No existing Ubuntu Server VHD or Zip exists that matches the name (i.e. that has previously been extracted and renamed) so a fresh one will be
                            # downloaded, extracted and the variable $UbuntuServerVHD updated accordingly.
                            Write-Verbose "Cannot find a previously extracted Ubuntu Server download or ZIP file"
                            Write-Verbose "Begin download of correct Ubuntu Server ZIP to $ASDKpath"

                            if ($registerASDK -and ($deploymentMode -eq "Online")) {
                                $ubuntuBuild = $azpkg.vhdVersion
                                $ubuntuBuild = $ubuntuBuild.Substring(0, $ubuntuBuild.Length - 1)
                                $ubuntuBuild = $ubuntuBuild.split('.')[2]
                                $ubuntuURI = "https://cloud-images.ubuntu.com/releases/16.04/release-$ubuntuBuild/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"

                            }
                            elseif (!$registerASDK -and ($deploymentMode -eq "Online")) {
                                $ubuntuURI = "https://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"
                            }
                            $ubuntuDownloadLocation = "$ASDKpath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip"
                            DownloadWithRetry -downloadURI "$ubuntuURI" -downloadLocation "$ubuntuDownloadLocation" -retries 10
                            if (!([System.IO.File]::Exists("$csvImagePath\Images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip"))) {
                                Copy-Item -Path "$ASDKpath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip" -Destination "$csvImagePath\Images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip" -Force -Verbose -ErrorAction Stop
                                $UbuntuServerZIP = Get-ChildItem -Path "$csvImagePath\Images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip"
                            }
                            else {
                                $UbuntuServerZIP = Get-ChildItem -Path "$csvImagePath\Images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip"
                            }
                            Expand-Archive -Path $UbuntuServerZIP -DestinationPath "$csvImagePath\Images\$image\" -Force -ErrorAction Stop
                            $serverVHD = Get-ChildItem -Path "$csvImagePath\Images\$image\" -Filter *disk1.vhd | Rename-Item -NewName "$blobName" -PassThru -Force -ErrorAction Stop
                        }
                    }
                    elseif ($image -ne "UbuntuServer") {
                        # Split for Windows Server Images
                        if ($deploymentMode -eq "Online") {
                            # Download Convert-WindowsImage.ps1
                            $convertWindowsURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/scripts/Convert-WindowsImage.ps1"
                            $convertWindowsDownloadLocation = "$ASDKpath\images\$image\Convert-Windows$($image)Image.ps1"
                            $convertWindowsImageExists = [System.IO.File]::Exists("$ASDKpath\images\$image\Convert-Windows$($image)Image.ps1")
                            if ($convertWindowsImageExists -eq $false) {
                                Write-Verbose "Downloading Convert-Windows$($image)Image.ps1 to create the VHD from the ISO"
                                Write-Verbose "The download will be stored in $ASDKpath\images"
                                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                                DownloadWithRetry -downloadURI "$convertWindowsURI" -downloadLocation "$convertWindowsDownloadLocation" -retries 10
                            }
                        }
                        elseif ($deploymentMode -ne "Online") {
                            $convertWindowsImageExists = [System.IO.File]::Exists("$ASDKpath\images\Convert-WindowsImage.ps1")
                            if ($convertWindowsImageExists -eq $true) {
                                Copy-Item -Path "$ASDKpath\images\Convert-WindowsImage.ps1" -Destination "$ASDKpath\images\$image\Convert-Windows$($image)Image.ps1" -Force -Verbose -ErrorAction Stop
                            }
                            else {
                                throw "Convert-WindowsImage.ps1 is missing from your download folder. This is required for the image creation and should be located here: $ASDKpath\images"
                            }
                        }
                        Set-Location "$ASDKpath\images\$image"
                        # Set path for Windows Updates (for Windows images). Copy to CSV first
                        Copy-Item -Path "$ASDKpath\images\*" -Include "*.msu" -Destination "$csvImagePath\Images\$image\" -Force -Verbose -ErrorAction Stop
                        $target = "$csvImagePath\Images\$image\"
                        if ($image -eq "ServerCore") {
                            .\Convert-WindowsServerCoreImage.ps1 -SourcePath $ISOpath -SizeBytes 40GB -Edition "$edition" -VHDPath "$csvImagePath\Images\$image\$($image).vhd" `
                                -VHDFormat VHD -VHDType Fixed -VHDPartitionStyle MBR -Feature "NetFx3" -Package $target -Passthru -Verbose
                        }
                        elseif ($image -eq "ServerFull") {
                            .\Convert-WindowsServerFullImage.ps1 -SourcePath $ISOpath -SizeBytes 40GB -Edition "$edition" -VHDPath "$csvImagePath\Images\$image\$($image).vhd" `
                                -VHDFormat VHD -VHDType Fixed -VHDPartitionStyle MBR -Feature "NetFx3" -Package $target -Passthru -Verbose
                        }
                        $serverVHD = Get-ChildItem -Path "$csvImagePath\Images\$image\$blobName"
                    }
                }
                # At this point, there is a local image (either existing or new, that needs uploading, first to a Storage Account
                Write-Verbose "Beginning upload of VHD to Azure Stack Storage Account"
                $imageURI = '{0}{1}/{2}' -f $asdkStorageAccount.PrimaryEndpoints.Blob, $asdkImagesContainerName, $serverVHD.Name
                # Upload VHD to Storage Account
                # Sometimes Add-AzureRmVHD has an error about "The pipeline was not run because a pipeline is already running. Pipelines cannot be run concurrently". Rerunning the upload typically helps.
                # Check that a) there's no VHD uploaded and b) the previous attempt(s) didn't complete successfully and c) you've attempted an upload no more than 3 times
                $uploadVhdAttempt = 1
                while (!$(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $serverVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$uploadSuccess) -and ($uploadVhdAttempt -le 3)) {
                    Try {
                        # Log back into Azure Stack to ensure login hasn't timed out
                        Write-Verbose "Upload Attempt: $uploadVhdAttempt"
                        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                        Add-AzureRmVhd -Destination $imageURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $serverVHD.FullName -OverWrite -Verbose -ErrorAction Stop
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
                while ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $serverVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$uploadSuccess) -and ($uploadVhdAttempt -le 3)) {
                    Try {
                        # Log back into Azure Stack to ensure login hasn't timed out
                        Write-Verbose "There was a previously failed upload. Upload Attempt: $uploadVhdAttempt"
                        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                        Add-AzureRmVhd -Destination $imageURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $serverVHD.FullName -OverWrite -Verbose -ErrorAction Stop
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
                while (!$(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $serverVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and ($uploadVhdAttempt -le 3)) {
                    Try {
                        # Log back into Azure Stack to ensure login hasn't timed out
                        Write-Verbose "No existing image found. Upload Attempt: $uploadVhdAttempt"
                        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                        Add-AzureRmVhd -Destination $imageURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $serverVHD.FullName -OverWrite -Verbose -ErrorAction Stop
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
                    $uploadSuccess = $false
                    throw "Uploading VHD to Azure Stack storage failed after 3 upload attempts. Review the logs, then rerun the ConfigASDK.ps1 script to retry."
                    Set-Location $ScriptLocation
                    return
                }
            }
            # To reach this stage, there is now a valid image in the Storage Account, ready to be uploaded into the PIR
            # Add the Platform Image
            Add-AzsPlatformImage -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -OsType $azpkg.osVersion -OsUri "$imageURI" -Force -Confirm: $false -Verbose -ErrorAction Stop
            if ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
                Write-Verbose ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" successfully uploaded.' -f $azpkg.publisher, $azpkg.offer, $azpkg.sku, $azpkg.vhdVersion) -ErrorAction SilentlyContinue
                if ($image -eq "UbuntuServer") {
                    Write-Verbose "Cleaning up local hard drive space - deleting VHD file and ZIP from Cluster Shared Volume"
                    Get-ChildItem -Path "$csvImagePath\Images\$image\" -Filter "$($azpkg.offer)$($azpkg.vhdVersion).vhd" | Remove-Item -Force
                    Get-ChildItem -Path "$csvImagePath\Images\$image\" -Filter "$($azpkg.offer)$($azpkg.vhdVersion).ZIP" | Remove-Item -Force
                    Get-ChildItem -Path "$csvImagePath\Images\$image\*" -Include "*.msu" | Remove-Item -Force
                    Write-Verbose "Cleaning up VHD from storage account"
                    Remove-AzureStorageBlob -Blob $serverVHD.Name -Container $asdkImagesContainerName -Context $asdkStorageAccount.Context -Force
                }
                else {
                    Write-Verbose "Cleaning up local hard drive space - deleting VHD file"
                    Get-ChildItem -Path "$csvImagePath\Images\$image\" -Filter "$($image).vhd" | Remove-Item -Force
                    Write-Verbose "Cleaning up VHD from storage account"
                    Remove-AzureStorageBlob -Blob $serverVHD.Name -Container $asdkImagesContainerName -Context $asdkStorageAccount.Context -Force
                }
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
                if ($image -eq "UbuntuServer") {
                    $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/Ubuntu/Canonical.UbuntuServer1604LTS-ARM.1.0.0.azpkg"
                }
                else {
                    $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/WindowsServer/$package.azpkg"
                }
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
        $progressStage = "$($image)Image"
        StageComplete -progressStage $progressStage
    }
    catch {
        StageFailed -progressStage $progressStage
        Set-Location $ScriptLocation
        throw $_.Exception.Message
        return
    }
}
elseif ($progressCheck -eq "Complete") {
    Write-Verbose "ASDK Configurator Stage: $progressStage previously completed successfully"
}
Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue