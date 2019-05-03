[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ImagePath,

    [parameter(Mandatory = $true)]
    [ValidateSet("ServerCore", "ServerFull")]
    [String] $image,

    [parameter(Mandatory = $true)]
    [String] $ISOpath,

    [parameter(Mandatory = $true)]
    [String] $ArmEndpoint,

    [parameter(Mandatory = $false)]
    [String] $azureDirectoryTenantName,

    [Parameter(Mandatory = $true)]
    [ValidateSet("AzureAd", "ADFS")]
    [String] $authenticationType,

    [parameter(Mandatory = $true)]
    [String] $vhdSizeInGB
)

### DOWNLOADER FUNCTION #####################################################################################################################################
#############################################################################################################################################################
function DownloadWithRetry([string] $downloadURI, [string] $downloadLocation, [int] $retries) {
    while ($true) {
        try {
            Write-Host "Downloading: $downloadURI"
            (New-Object System.Net.WebClient).DownloadFile($downloadURI, $downloadLocation)
            break
        }
        catch {
            $exceptionMessage = $_.Exception.Message
            Write-Host "Failed to download '$downloadURI': $exceptionMessage"
            if ($retries -gt 0) {
                $retries--
                Write-Host "Waiting 10 seconds before retrying. Retries left: $retries"
                Start-Sleep -Seconds 10
            }
            else {
                $exception = $_.Exception
                throw $exception
            }
        }
    }
}

#############################################################################################################################################################
#############################################################################################################################################################

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

#$modulePath = "C:\AzureStack-Tools-master"
Import-Module -Name Azure.Storage -RequiredVersion 4.5.0
Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4

### SET IMAGE PROPERTIES ####################################################################################################################################
#############################################################################################################################################################

Set-Location "$ImagePath"
$date = Get-Date -Format FileDate
$blobName = "$($image)$date.vhd"

# Check which image is being deployed
if ($image -eq "ServerCore") {
    $sku = "2019-Datacenter-Server-Core"
    $edition = 'Windows Server 2019 SERVERDATACENTERCORE'
    $azpkgPackage = "Microsoft.WindowsServer2019DatacenterServerCore-ARM"
    $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/WindowsServer/Microsoft.WindowsServer2019DatacenterServerCore-ARM.1.0.0.azpkg"
    $vhdVersion = "2019.$vhdSizeInGB.$date"
    $publisher = "MicrosoftWindowsServer"
    $offer = "WindowsServer"
    $osVersion = "Windows"
}
elseif ($image -eq "ServerFull") {
    $sku = "2019-Datacenter"
    $edition = 'Windows Server 2019 SERVERDATACENTER'
    $azpkgPackage = "Microsoft.WindowsServer2019Datacenter-ARM"
    $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/WindowsServer/Microsoft.WindowsServer2019Datacenter-ARM.1.0.0.azpkg"
    $vhdVersion = "2019.$vhdSizeInGB.$date"
    $publisher = "MicrosoftWindowsServer"
    $offer = "WindowsServer"
    $osVersion = "Windows"
}

# Log into Azure Stack
Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
if ($authenticationType.ToString() -like "AzureAd") {
    $ADauth = (Get-AzureRmEnvironment -Name "AzureStackAdmin").ActiveDirectoryAuthority.TrimEnd('/')
    $tenantId = (Invoke-RestMethod "$($ADauth)/$($azureDirectoryTenantName)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
    $uploadCreds = Get-Credential -Message "Enter your Azure Stack credentials"
    Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantId -Credential $uploadCreds -ErrorAction Stop
}
elseif ($authenticationType.ToString() -like "ADFS") {
    $uploadCreds = Get-Credential -Message "Enter your Azure Stack credentials. For an ASDK with ADFS authentication, this will be cloudadmin@azurestack.local, but for an Integrated System, check with your Service Administrator."
    Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -Credential $uploadCreds -ErrorAction Stop
}

# Get current Azure Stack location
$azsLocation = (Get-AzsLocation).Name

### TEST/CREATE RG & STORAGE ACCOUNTS #######################################################################################################################
#############################################################################################################################################################

$asdkImagesRGName = "azurestack-images"
$asdkImagesStorageAccountName = "asdkimagesstor"
$asdkImagesContainerName = "asdkimagescontainer"

# Test/Create RG
if (-not (Get-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -ErrorAction SilentlyContinue)) { New-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop }

# Test/Create Storage
$asdkStorageAccount = Get-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName -ErrorAction SilentlyContinue
if (-not ($asdkStorageAccount)) { $asdkStorageAccount = New-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -Location $azsLocation -ResourceGroupName $asdkImagesRGName -Type Standard_LRS -ErrorAction Stop }
Set-AzureRmCurrentStorageAccount -StorageAccountName $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName | Out-Null

# Test/Create Container
$asdkContainer = Get-AzureStorageContainer -Name $asdkImagesContainerName -ErrorAction SilentlyContinue
if (-not ($asdkContainer)) { $asdkContainer = New-AzureStorageContainer -Name $asdkImagesContainerName -Permission Blob -Context $asdkStorageAccount.Context -ErrorAction Stop }

### ADD IMAGE TO STORAGE ACCOUNT ############################################################################################################################
#############################################################################################################################################################

if ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob "$blobName" -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue)) {
    Write-Host "You already have an upload of $blobName within your Storage Account. No need to re-upload."
    $imageURI = $((Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob "$blobName" -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue).ICloudBlob.StorageUri.PrimaryUri.AbsoluteUri)
    Write-Host "VHD path = $imageURI"
}
else {
    Write-Host "There is no suitable $blobName image within your Storage Account. We'll need to upload a new one."
    $validDownloadPathVHD = [System.IO.File]::Exists("$ImagePath\$blobName")
    Write-Host "Checking for a local copy first..."
    # If there's no local VHD, create one.
    if ($validDownloadPathVHD -eq $true) {
        Write-Host "Located suitable VHD in this folder. No need to download again..."
        $serverVHD = Get-ChildItem -Path "$ImagePath\$blobName"
        Write-Host "VHD located at $serverVHD"
    }
    else {
        # Split for Windows Server Images
        # Download Convert-WindowsImage.ps1
        $convertWindowsURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/scripts/Convert-WindowsImage.ps1"
        $convertWindowsDownloadLocation = "$ImagePath\Convert-Windows$($image)Image.ps1"
        $convertWindowsImageExists = [System.IO.File]::Exists("$ImagePath\Convert-Windows$($image)Image.ps1")
        if ($convertWindowsImageExists -eq $false) {
            Write-Host "Downloading Convert-Windows$($image)Image.ps1 to create the VHD from the ISO"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            DownloadWithRetry -downloadURI "$convertWindowsURI" -downloadLocation "$convertWindowsDownloadLocation" -retries 10
        }
        Set-Location "$ImagePath"
        $vhdSize = ("$($vhdSizeInGB)GB" / 1GB) * 1GB
        # Set path for Windows Updates (for Windows images).
        if ($image -eq "ServerCore") {
            .\Convert-WindowsServerCoreImage.ps1 -SourcePath $ISOpath -SizeBytes $vhdSize -Edition "$edition" -VHDPath "$ImagePath\$blobname" `
                -VHDFormat VHD -VHDType Fixed -VHDPartitionStyle MBR -Feature "NetFx3" -Package $ImagePath -Passthru -Verbose
        }
        elseif ($image -eq "ServerFull") {
            .\Convert-WindowsServerFullImage.ps1 -SourcePath $ISOpath -SizeBytes $vhdSize -Edition "$edition" -VHDPath "$ImagePath\$blobname" `
                -VHDFormat VHD -VHDType Fixed -VHDPartitionStyle MBR -Feature "NetFx3" -Package $ImagePath -Passthru -Verbose
        }
        $serverVHD = Get-ChildItem -Path "$ImagePath\$blobName"
    }

    # At this point, there is a local image (either existing or new, that needs uploading, first to a Storage Account
    Write-Host "Beginning upload of VHD to Azure Stack Storage Account"
    $imageURI = '{0}{1}/{2}' -f $asdkStorageAccount.PrimaryEndpoints.Blob, $asdkImagesContainerName, $serverVHD.Name
    # Upload VHD to Storage Account
    # Sometimes Add-AzureRmVHD has an error about "The pipeline was not run because a pipeline is already running. Pipelines cannot be run concurrently". Rerunning the upload typically helps.
    # Check that a) there's no VHD uploaded and b) the previous attempt(s) didn't complete successfully and c) you've attempted an upload no more than 3 times
    $uploadVhdAttempt = 1
    while (!$(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $serverVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$uploadSuccess) -and ($uploadVhdAttempt -le 3)) {
        Try {
            # Log back into Azure Stack to ensure login hasn't timed out
            Write-Host "Upload Attempt: $uploadVhdAttempt"
            if ($authenticationType.ToString() -like "AzureAd") {
                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $uploadCreds -ErrorAction Stop | Out-Null
            }
            elseif ($authenticationType.ToString() -like "ADFS") {
                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -Credential $uploadCreds -ErrorAction Stop
            }
            Add-AzureRmVhd -Destination $imageURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $serverVHD.FullName -OverWrite -Verbose -ErrorAction Stop
            $uploadSuccess = $true
        }
        catch {
            Write-Host "Upload failed."
            Write-Host "$_.Exception.Message"
            $uploadVhdAttempt++
            $uploadSuccess = $false
        }
    }
    # Sometimes Add-AzureRmVHD has an error about "The pipeline was not run because a pipeline is already running. Pipelines cannot be run concurrently". Rerunning the upload typically helps.
    # Check that a) there's a VHD uploaded but b) the attempt didn't complete successfully (VHD in unreliable state) and c) you've attempted an upload no more than 3 times
    while ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $serverVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$uploadSuccess) -and ($uploadVhdAttempt -le 3)) {
        Try {
            # Log back into Azure Stack to ensure login hasn't timed out
            Write-Host "There was a previously failed upload. Upload Attempt: $uploadVhdAttempt"
            if ($authenticationType.ToString() -like "AzureAd") {
                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $uploadCreds -ErrorAction Stop | Out-Null
            }
            elseif ($authenticationType.ToString() -like "ADFS") {
                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -Credential $uploadCreds -ErrorAction Stop
            }
            Add-AzureRmVhd -Destination $imageURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $serverVHD.FullName -OverWrite -Verbose -ErrorAction Stop
            $uploadSuccess = $true
        }
        catch {
            Write-Host "Upload failed."
            Write-Host "$_.Exception.Message"
            $uploadVhdAttempt++
            $uploadSuccess = $false
        }
    }
    # This is one final catch-all for the upload process
    # Check that a) there's no VHD uploaded and b) you've attempted an upload no more than 3 times
    while (!$(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $serverVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and ($uploadVhdAttempt -le 3)) {
        Try {
            # Log back into Azure Stack to ensure login hasn't timed out
            Write-Host "No existing image found. Upload Attempt: $uploadVhdAttempt"
            if ($authenticationType.ToString() -like "AzureAd") {
                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $uploadCreds -ErrorAction Stop | Out-Null
            }
            elseif ($authenticationType.ToString() -like "ADFS") {
                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -Credential $uploadCreds -ErrorAction Stop
            }
            Add-AzureRmVhd -Destination $imageURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $serverVHD.FullName -OverWrite -Verbose -ErrorAction Stop
            $uploadSuccess = $true
        }
        catch {
            Write-Host "Upload failed."
            Write-Host "$_.Exception.Message"
            $uploadVhdAttempt++
            $uploadSuccess = $false
        }
    }
    if ($uploadVhdAttempt -gt 3) {
        $uploadSuccess = $false
        throw "Uploading VHD to Azure Stack storage failed after 3 upload attempts. Review the logs, then rerun the ConfigASDK.ps1 script to retry."
        return
    }
}

### ADD IMAGE TO FROM STORAGE ACCOUNT TO PIR ################################################################################################################
#############################################################################################################################################################

Add-AzsPlatformImage -Publisher $publisher -Offer $offer -Sku $sku -Version $vhdVersion -OsType $osVersion -OsUri "$imageURI" -Force -Confirm: $false -Verbose -ErrorAction Stop
if ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $publisher -Offer $offer -Sku $sku -Version $vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
    Write-Host ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" successfully uploaded.' -f $publisher, $offer, $sku, $vhdVersion) -ErrorAction SilentlyContinue
    Write-Host "Cleaning up local hard drive space - deleting VHD file"
    Get-ChildItem -Path "$ImagePath" -Filter "$blobname" | Remove-Item -Force
    Write-Host "Cleaning up VHD from storage account"
    Remove-AzureStorageBlob -Blob $serverVHD.Name -Container $asdkImagesContainerName -Context $asdkStorageAccount.Context -Force
}
elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $publisher -Offer $offer -Sku $sku -Version $vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Failed') {
    throw "Adding VM image failed. Please check the logs and clean up the Azure Stack Platform Image Repository to remove the failed image, then retry."
}
elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $publisher -Offer $offer -Sku $sku -Version $vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Canceled') {
    throw "Adding VM image was canceled. Confirm the image doesn't show in the Azure Stack Platform Image Repository and if it does, remove it, then retry."
}

### ADD GALLERY ITEM PACKAGE DIRECT FROM GITHUB #############################################################################################################
#############################################################################################################################################################

Write-Host "Checking for the following package: $azpkgPackage"
if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$azpkgPackage*"}) {
    Write-Host "Found the following existing package in your Gallery: $azpkgPackage. No need to upload a new one"
}
else {
    Write-Host "Didn't find this package: $azpkgPackage"
    Write-Host "Will need to side load it in to the gallery"
    Write-Host "Uploading $azpkgPackage from $azpkgPackageURL"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Retries = 0
    # Sometimes the gallery item doesn't get added successfully, so perform checks and attempt multiple uploads if necessary
    while (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "*$azpkgPackage*"}) -and ($Retries++ -lt 20)) {
        try {
            Write-Host "$azpkgPackage doesn't exist in the gallery. Upload Attempt #$Retries"
            Write-Host "Uploading $azpkgPackage from $azpkgPackageURL"
            Add-AzsGalleryItem -GalleryItemUri $azpkgPackageURL -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "Upload wasn't successful. Waiting 5 seconds before retrying."
            Write-Host "$_.Exception.Message"
            Start-Sleep -Seconds 5
        }
    }
    if (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "*$azpkgPackage*"}) -and ($Retries++ -ge 20)) {
        throw "Uploading gallery item failed after $Retries attempts. Exiting process."
        return
    }
}