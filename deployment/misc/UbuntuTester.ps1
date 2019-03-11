[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $imagePath,

    [Parameter(Mandatory = $True, HelpMessage = 'Specify the path of the CSV file')]
    [Alias('CSVFile')]
    [string]$FilePath
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
####################################

$Global:VerbosePreference = "SilentlyContinue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

Try {
    $CSVData = @(Import-CSV -Path $FilePath -ErrorAction Stop)
    Write-Host "Successfully imported entries from $FilePath" -ForegroundColor Green
    Write-Host "Total no. of entries in CSV are : $($CSVData.count)"
} 
Catch {
    Write-Host "Failed to read from the CSV file $FilePath - Exiting!" -ForegroundColor Red
    Break
}

$asdkCreds = Get-Credential -Message "Please enter your Azure Stack Service Admin credentials"

Foreach ($Entry in $CSVData) {

    ### SET LOG LOCATION ###
    $logFolder = "$($Entry.UbuntuRelease)"
    $logDate = Get-Date -Format FileDate
    New-Item -ItemType Directory -Path "$imagePath\Logs\$logDate\$logFolder" -Force | Out-Null
    $logPath = "$imagePath\Logs\$logDate\$logFolder"
    $azCopyLogPath = "$logPath\AzCopy-$($Entry.UbuntuRelease)-$logDate.log"
    $journalPath = "$logPath\$($($Entry.UbuntuRelease))Journal"
    New-Item -ItemType Directory -Path "$journalPath" -Force | Out-Null

    $sku = "$($Entry.UbuntuSku)-LTS"
    $publisher = "Canonical"
    $offer = "UbuntuServer"
    $vhdVersion = "$($Entry.UbuntuSku).$($Entry.UbuntuRelease)"
    $shortVhdVersion = $vhdVersion.substring(0, 14)
    $ubuntuBuild = $vhdVersion.split(".", 3)[2]
    $osVersion = "Linux"
    if ($($Entry.UbuntuSku) -eq "14.04") {
        $filter = "*trusty*.vhd"
    }
    elseif ($($Entry.UbuntuSku) -eq "16.04") {
        $filter = "*xenial*.vhd"
    }
    elseif ($($Entry.UbuntuSku) -eq "18.04") {
        $filter = "*bionic*.vhd"
    }

    # Set Storage Variables
    $asdkImagesRGName = "azurestack-images"
    $asdkImagesStorageAccountName = "asdkimagesstor"
    $asdkImagesContainerName = "asdkimagescontainer"

    Write-Host "`nImporting storage modules"
    Import-Module -Name Azure.Storage -RequiredVersion 4.5.0
    Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4

    Write-Host "Clearing previous Azure/Azure Stack logins"
    Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
    Clear-AzureRmContext -Scope CurrentUser -Force | Out-Null
    Disable-AzureRMContextAutosave -Scope CurrentUser

    Write-Host "Logging into Azure Stack"
    $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
    Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
    Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -Credential $asdkCreds -ErrorAction Stop | Out-Null
    $azsLocation = (Get-AzsLocation).Name

    ### Log back into Azure Stack to check for existing images and push new ones if required ###
    Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -Credential $asdkCreds -ErrorAction Stop | Out-Null
    Write-Host "Checking to see if the image is present in your Azure Stack Platform Image Repository"
    Write-Host "We first want to check if there is a failed or canceled upload from a previous attempt"
    if ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($sku)/*") -and $_.ProvisioningState -eq "Failed"}) {
        Write-Host "There appears to be at least 1 suitable $($sku) VM image within your Platform Image Repository which we will use for the ASDK Configurator, however, it's in a failed state"
        Write-Host "Cleaning up the image from the PIR"
        (Get-AzsPlatformImage -Location $azsLocation -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($sku)/*") -and $_.ProvisioningState -eq "Failed"} | Remove-AzsPlatformImage -Force -Verbose -ErrorAction Stop
    }
    elseif ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($sku)/*") -and $_.ProvisioningState -eq "Canceled"}) {
        Write-Host "There appears to be at least 1 suitable $($sku) VM image within your Platform Image Repository which we will use for the ASDK Configurator, however, it's in a canceled state"
        Write-Host "Cleaning up the image from the PIR"
        (Get-AzsPlatformImage -Location $azsLocation -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($sku)/*") -and $_.ProvisioningState -eq "Canceled"} | Remove-AzsPlatformImage -Force -Verbose -ErrorAction Stop
    }
    Write-Host "There are no failed or canceled images in the PIR, so moving on to checking for a valid, successful image"
    if ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($sku)/*") -and $_.ProvisioningState -eq "Succeeded"}) {
        Write-Host "There appears to be at least 1 suitable $($sku) VM image within your Platform Image Repository which we will use for the ASDK Configurator. Here are the details:"
        Write-Host ('VM Image with publisher " {0}", offer " {1}", sku " {2}", version " {3}".' -f $publisher, $offer, $sku, $vhdVersion) -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "No existing suitable $($sku) VM image exists." 
        Write-Host "The image in the Azure Stack Platform Image Repository should have the following properties:"
        Write-Host "Publisher Name = $($publisher)"
        Write-Host "Offer = $($offer)"
        Write-Host "SKU = $($sku)"
        Write-Host "Version = $($vhdVersion)"
        Write-Host "Unfortunately, no image was found with these properties."
        Write-Host "Checking to see if the VHD already exists in an Azure Stack Storage Account"

        # Test/Create RG
        if (-not (Get-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -ErrorAction SilentlyContinue)) { New-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop }
        # Test/Create Storage
        $asdkStorageAccount = Get-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName -ErrorAction SilentlyContinue
        if (-not ($asdkStorageAccount)) { $asdkStorageAccount = New-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -Location $azsLocation -ResourceGroupName $asdkImagesRGName -Type Standard_LRS -ErrorAction Stop }
        Set-AzureRmCurrentStorageAccount -StorageAccountName $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName | Out-Null
        # Test/Create Container
        $asdkContainer = Get-AzureStorageContainer -Name $asdkImagesContainerName -ErrorAction SilentlyContinue
        if (-not ($asdkContainer)) { $asdkContainer = New-AzureStorageContainer -Name $asdkImagesContainerName -Permission Blob -Context $asdkStorageAccount.Context -ErrorAction Stop }

        $blobName = "$($offer)$($vhdVersion).vhd"

        if ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob "$blobName" -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue)) {
            Write-Host "You already have an upload of $blobName within your Storage Account. No need to re-upload."
            $imageURI = $((Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob "$blobName" -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue).ICloudBlob.StorageUri.PrimaryUri.AbsoluteUri)
            Write-Host "VHD path = $imageURI"
        }
        else {
            Write-Host "There is no suitable $blobName image within your Storage Account. We'll need to upload a new one."
            $validDownloadPathVHD = [System.IO.File]::Exists("$imagePath\$blobName")
            Write-Host "Checking for a local copy first..."
            # If there's no local VHD, create one.
            if ($validDownloadPathVHD -eq $true) {
                Write-Host "Located suitable VHD in this folder. No need to download again..."
                $serverVHD = Get-ChildItem -Path "$imagePath\$blobName"
                Write-Host "VHD located at $serverVHD"
            }
            else {
                # Split for Ubuntu Image
                $validDownloadPathZIP = $(Get-ChildItem -Path "$imagePath\$($offer)$($vhdVersion).zip" -ErrorAction SilentlyContinue)
                if ($validDownloadPathZIP) {
                    Write-Host "Cannot find a previously extracted Ubuntu Server VHD with name $blobName"
                    Write-Host "Checking to see if the Ubuntu Server ZIP already exists in $imagePath folder"
                    $UbuntuServerZIP = Get-ChildItem -Path "$imagePath\$($offer)$($vhdVersion).zip"
                    Write-Host "Ubuntu Server ZIP located at $UbuntuServerZIP"
                    Write-Host "Expanding ZIP found at $UbuntuServerZIP"
                    Expand-Archive -Path $UbuntuServerZIP -DestinationPath "$imagePath\" -Force -ErrorAction Stop
                    $serverVHD = Get-ChildItem -Path "$imagePath\" -Filter "$filter" | Rename-Item -NewName "$blobName" -PassThru -Force -ErrorAction Stop
                }
                else {
                    # No existing Ubuntu Server VHD or Zip exists that matches the name (i.e. that has previously been extracted and renamed) so a fresh one will be
                    # downloaded, extracted and the variable $UbuntuServerVHD updated accordingly.
                    Write-Host "Cannot find a previously extracted Ubuntu Server download or ZIP file"
                    Write-Host "Begin download of correct Ubuntu Server ZIP to $imagePath"
                    if ($($Entry.UbuntuSku) -eq "18.04") {
                        $ubuntuURI = "https://cloud-images.ubuntu.com/releases/$($Entry.UbuntuSku)/release-$ubuntuBuild/ubuntu-$($Entry.UbuntuSku)-server-cloudimg-amd64.vhd.zip"
                    }
                    else {
                        $ubuntuURI = "https://cloud-images.ubuntu.com/releases/$($Entry.UbuntuSku)/release-$ubuntuBuild/ubuntu-$($Entry.UbuntuSku)-server-cloudimg-amd64-disk1.vhd.zip"
                    }
                    $ubuntuDownloadLocation = "$imagePath\$($offer)$($vhdVersion).zip"
                    DownloadWithRetry -downloadURI "$ubuntuURI" -downloadLocation "$ubuntuDownloadLocation" -retries 10
                    $UbuntuServerZIP = Get-ChildItem -Path "$imagePath\$($offer)$($vhdVersion).zip"
                    Write-Host "Expanding ZIP found at $UbuntuServerZIP"
                    Expand-Archive -Path $UbuntuServerZIP -DestinationPath "$imagePath\" -Force -ErrorAction Stop
                    Write-Host "Renaming VHD to $blobname"
                    $serverVHD = Get-ChildItem -Path "$imagePath\" -Filter "$filter" | Rename-Item -NewName "$blobName" -PassThru -Force -ErrorAction Stop
                }
            }
            # At this point, there is a local image (either existing or new, that needs uploading, first to a Storage Account
            Write-Host "Beginning upload of VHD to Azure Stack Storage Account using AzCopy"
            $imageURI = '{0}{1}/{2}' -f $asdkStorageAccount.PrimaryEndpoints.Blob, $asdkImagesContainerName, $serverVHD.Name
            # Upload VHD to Storage Account
            # Check that a) there's no VHD uploaded and b) the previous attempt(s) didn't complete successfully and c) you've attempted an upload no more than 3 times
            $uploadVhdAttempt = 1
            $uploadSuccess = $false
            while (!$(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $serverVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$uploadSuccess) -and ($uploadVhdAttempt -le 3)) {
                Try {
                    # Log back into Azure Stack to ensure login hasn't timed out
                    Write-Host "Clearing previous Azure/Azure Stack logins"
                    Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
                    Clear-AzureRmContext -Scope CurrentUser -Force | Out-Null
                    Write-Host "Upload Attempt: $uploadVhdAttempt"
                    Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    $serverVHDDirectory = ($serverVHD).DirectoryName
                    $containerDestination = '{0}{1}' -f $asdkStorageAccount.PrimaryEndpoints.Blob, $asdkImagesContainerName
                    $azCopyPath = "C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\AzCopy.exe"
                    $storageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $asdkImagesRGName -Name $asdkImagesStorageAccountName).Value[0]
                    $azCopyCmd = [string]::Format("""{0}"" /source:""{1}"" /dest:""{2}"" /destkey:""{3}"" /BlobType:""page"" /Pattern:""{4}"" /Y /V:""{5}"" /Z:""{6}""", $azCopyPath, $serverVHDDirectory, $containerDestination, $storageAccountKey, $blobName, $azCopyLogPath, $journalPath)
                    Write-Host "Executing the following command:`n$azCopyCmd`n"
                    $result = cmd /c $azCopyCmd
                    foreach ($s in $result) {
                        Write-Host $s
                    }
                    if ($LASTEXITCODE -ne 0) {
                        Throw "Upload file failed: $itemName. Check logs at $azCopyLogPath";
                        break;
                    }
                    $uploadSuccess = $true
                }
                catch {
                    Write-Host "Upload failed."
                    Write-Host "$_.Exception.Message"
                    $uploadVhdAttempt++
                    $uploadSuccess = $false
                }
            }
        }

        # To reach this stage, there is now a valid image in the Storage Account, ready to be uploaded into the PIR
        # Add the Platform Image
        $uploadToPIRAttempt = 1
        $uploadPIRSuccess = $false
        while ((!$(Get-AzsPlatformImage -Location $azsLocation -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') -and (!$uploadPIRSuccess) -and ($uploadToPIRAttempt -le 3) ) {
            Try {
                # Log back into Azure Stack to ensure login hasn't timed out
                Write-Host "Clearing previous Azure/Azure Stack logins"
                Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
                Clear-AzureRmContext -Scope CurrentUser -Force | Out-Null
                Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -Credential $asdkCreds -ErrorAction Stop | Out-Null
                $startTime = Get-Date -Format g
                $sw = [Diagnostics.Stopwatch]::StartNew()
                Write-Host "`nAdding $blobName to the Platform Image Repository. Attempt $uploadToPIRAttempt started at $startTime"
                Add-AzsPlatformImage -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -OsType $osVersion -OsUri "$imageURI" -Force -Confirm: $false -ErrorAction Stop
                $endTime = Get-Date -Format g
                $sw.Stop()
                $Hrs = $sw.Elapsed.Hours
                $Mins = $sw.Elapsed.Minutes
                $Secs = $sw.Elapsed.Seconds
                $difference = '{0:00}h:{1:00}m:{2:00}s' -f $Hrs, $Mins, $Secs
                Write-Host "`nAdding $blobName to the Platform Image Repository completed successfully. Upload completed at $endTime and took $difference"
                $uploadPIRSuccess = $true
            }
            catch {
                Write-Host "Upload to the PIR failed."
                Write-Host "$_.Exception.Message"
                $uploadToPIRAttempt++
                $uploadPIRSuccess = $false
                if ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($sku)/*") -and $_.ProvisioningState -eq "Failed"}) {
                    Write-Host "There appears to be at least 1 suitable $($sku) VM image within your Platform Image Repository which we will use for the ASDK Configurator, however, it's in a failed state"
                    Write-Host "Cleaning up the image from the PIR"
                    (Get-AzsPlatformImage -Location $azsLocation -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($sku)/*") -and $_.ProvisioningState -eq "Failed"} | Remove-AzsPlatformImage -Force -Verbose -ErrorAction Stop
                }
                elseif ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($sku)/*") -and $_.ProvisioningState -eq "Canceled"}) {
                    Write-Host "There appears to be at least 1 suitable $($sku) VM image within your Platform Image Repository which we will use for the ASDK Configurator, however, it's in a canceled state"
                    Write-Host "Cleaning up the image from the PIR"
                    (Get-AzsPlatformImage -Location $azsLocation -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($sku)/*") -and $_.ProvisioningState -eq "Canceled"} | Remove-AzsPlatformImage -Force -Verbose -ErrorAction Stop
                }
            }
        }
        
        if ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
            Write-Host ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" successfully uploaded.' -f $publisher, $offer, $sku, $vhdVersion) -ErrorAction SilentlyContinue
            Write-Host "Cleaning up local hard drive space within $imagePath"
            Get-ChildItem -Path "$imagePath\" -Filter "$($offer)$($vhdVersion).vhd" | Remove-Item -Force
            #Get-ChildItem -Path "$imagePath\" -Filter "$($offer)$($vhdVersion).zip" | Remove-Item -Force
            Write-Host "Cleaning up VHD from storage account"
            Remove-AzureStorageBlob -Blob $blobName -Container $asdkImagesContainerName -Context $asdkStorageAccount.Context -Force
        }
        elseif ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Failed') {
            throw "Adding VM image failed. Please check the logs and rerun to clean up the Azure Stack Platform Image Repository to remove the failed image, then retry."
        }
        elseif ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $publisher -Offer $offer -Sku $sku -Version $shortVhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Canceled') {
            throw "Adding VM image was canceled. Please check the logs and rerun."
        }
    }

    # Deploy a VM to test image
    Write-Host "Starting deployment of Ubuntu Server $vhdVersion"
    $mainTemplateURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/misc/UbuntuReleaseTest.json"
    $guid = ((New-Guid).ToString()).Substring(0, 6)
    $deploymentName = "DeployUbuntuTest$($vhdVersion)_$guid"
    $rg = "UbuntuServer$($ubuntuBuild)_$guid"
    $vmPwd = "Passw0rd123!"
    $secureVMpwd = ConvertTo-SecureString -AsPlainText $VMpwd -Force
    if (-not (Get-AzureRmResourceGroup -Name $rg -Location $azsLocation -ErrorAction SilentlyContinue)) {
        New-AzureRmResourceGroup -Name $rg -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
    }

    New-AzureRmResourceGroupDeployment -Name "$deploymentName" -ResourceGroupName $rg -TemplateUri $mainTemplateURI `
        -vmName "UbuntuBuild$ubuntuBuild" -adminUsername "localadmin" -adminPassword $secureVMpwd -imageSku $sku -imageVersion $shortVhdVersion -Verbose -ErrorAction Continue

    ### SET LOCATION ###
    $ScriptLocation = Get-Location
    $txtPath = "$scriptLocation\UbuntuImageTesting.txt"
    if (!$([System.IO.File]::Exists("$txtPath"))) {
        New-Item "$txtPath" -ItemType file -Force
    }

    if (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "$deploymentName" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Succeeded"}) {
        Write-Host "The Ubuntu Server $vhdVersion image is valid for use on Azure Stack - Deployment completed successfully" -ForegroundColor Green
        Write-Output "The Ubuntu Server $vhdVersion image is valid for use on Azure Stack - Deployment completed successfully" >> $txtPath

    }
    elseif (Get-AzureRmResourceGroupDeployment -ResourceGroupName $rg -Name "$deploymentName" -ErrorAction SilentlyContinue | Where-Object {$_.ProvisioningState -eq "Failed"}) {
        Write-Host "The Ubuntu Server $vhdVersion image is NOT valid for use on Azure Stack - Deployment failed" -ForegroundColor Red
        Write-Output "The Ubuntu Server $vhdVersion image is NOT valid for use on Azure Stack - Deployment failed" >> $txtPath
    }

    $output = Get-Content -Path $txtPath
    Write-Host "`nSo far, you've tested the following images:"
    foreach ($o in $output) {
        Write-Host "$o"
    }
}