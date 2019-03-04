[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $customDomainSuffix,

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
    [ValidateSet("ServerCore2016", "ServerFull2016", "ServerCore2019", "ServerFull2019", "UbuntuServer")]
    [String] $image,

    [parameter(Mandatory = $false)]
    [pscredential] $azureRegCreds,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

    [parameter(Mandatory = $true)]
    [String] $ISOpath,

    [Parameter(Mandatory = $false)]
    [String] $ISOPath2019,

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
$azCopyLogPath = "$logPath\AzCopy-$image-$logDate.log"
$journalPath = "$logPath\$($image)Journal"
New-Item -ItemType Directory -Path "$journalPath" -Force | Out-Null

### START LOGGING ###
$runTime = $(Get-Date).ToString("MMdd-HHmmss")
$fullLogPath = "$logPath\$($image)-$runTime.txt"
Start-Transcript -Path "$fullLogPath" -Append
Write-Host "Creating log folder"
Write-Host "Log folder has been created at $logPath"
Write-Host "Log file stored at $fullLogPath"
Write-Host "Starting logging"
Write-Host "Log started at $runTime"

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
if (!$([System.IO.Directory]::Exists("$ASDKpath\images\2016"))) {
    New-Item -Path "$ASDKpath\images\2016" -ItemType Directory -Force | Out-Null   
}
if ($ISOPath2019) {
    if (!$([System.IO.Directory]::Exists("$ASDKpath\images\2019"))) {
        New-Item -Path "$ASDKpath\images\2019" -ItemType Directory -Force | Out-Null   
    }
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

# Check if 2019 images are going to be created by confirming ISO path is present
if (($progressStage -eq "ServerCore2019Image") -or ($progressStage -eq "ServerFull2019Image")) {
    Write-Host "Checking if valid ISO file has been provided for Windows Server 2019"
    if (!$ISOPath2019) {
        Write-Host "No ISO file has been provided for Windows Server 2019 - skipping creating 2019 Images"
        $skip2019Images = $true
    }
}

Write-Host "Checking on current status for this stage: $progressStage"
if ($progressCheck -eq "Complete") {
    Write-Host "ASDK Configurator Stage: $progressStage previously completed successfully"
}
elseif ((!$skip2019Images) -and ($progressCheck -ne "Complete")) {
    Write-Host "skip2019Images doesn't exist, and status isn't complete"
    if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
        try {
            if ($progressCheck -eq "Failed") {
                StageReset -progressStage $progressStage
            }

            Write-Host "Cleaning up old stale logins for this session"
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force
            Disable-AzureRMContextAutosave -Scope CurrentUser

            Write-Host "Importing storage modules"
            Import-Module -Name Azure.Storage -RequiredVersion 4.5.0
            Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4

            # Need to confirm if Windows Update stage previously completed
            if ($image -ne "UbuntuServer") {
                Write-Host "Checking the Windows Update stage progress"
                $windowsUpdateCheck = CheckProgress -progressStage "WindowsUpdates"
                while ($windowsUpdateCheck -ne "Complete") {
                    Write-Host "The WindowsUpdates stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 20
                    $windowsUpdateCheck = CheckProgress -progressStage "WindowsUpdates"     
                    if ($windowsUpdateCheck -eq "Failed") {
                        throw "The WindowsUpdates stage of the process has failed. This is required before the Windows Server images can be created. Check the WindowsUpdates log, ensure that step is completed first, and rerun."
                    }        
                }
            }
            # Need to confirm if the Ubuntu Server Image stage has completed (for partialParallel and serial deployments)
            if ($image -eq "ServerCore2016") {
                if (($runMode -eq "partialParallel") -or ($runMode -eq "serial")) {
                    $ubuntuJobCheck = CheckProgress -progressStage "UbuntuServerImage"
                    while ($ubuntuJobCheck -ne "Complete") {
                        Write-Host "The UbuntuServerImage stage of the process has not yet completed. Checking again in 20 seconds"
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
            if ($image -eq "ServerFull2016") {
                if ($runMode -eq "partialParallel") {
                    $ubuntuJobCheck = CheckProgress -progressStage "UbuntuServerImage"
                    while ($ubuntuJobCheck -ne "Complete") {
                        Write-Host "The UbuntuServerImage stage of the process has not yet completed. Checking again in 20 seconds"
                        Start-Sleep -Seconds 20
                        $ubuntuJobCheck = CheckProgress -progressStage "UbuntuServerImage"
                        if ($ubuntuJobCheck -eq "Failed") {
                            throw "The UbuntuServerImage stage of the process has failed. This should fully complete before the Windows Server images are to be created. Check the UbuntuServerImage log, ensure that step is completed first, and rerun."
                        }
                    }
                }
                elseif ($runMode -eq "serial") {
                    $serverCore2016JobCheck = CheckProgress -progressStage "ServerCore2016Image"
                    while ($serverCore2016JobCheck -ne "Complete") {
                        Write-Host "The ServerCore2016Image stage of the process has not yet completed. Checking again in 20 seconds"
                        Start-Sleep -Seconds 20
                        $serverCore2016JobCheck = CheckProgress -progressStage "ServerCore2016Image"
                        if ($serverCore2016JobCheck -eq "Failed") {
                            throw "The ServerCore2016Image stage of the process has failed. This should fully complete before the Windows Server full image is created. Check the Windows Server logs, ensure that step is completed first, and rerun."
                        }
                    }
                }
            }
            if ($image -eq "ServerCore2019") {
                Write-Host "Image is $image - checking run mode and progress"
                <# Need to ensure this stage doesn't start before the Windows Server images have been put into the PIR
                $serverCore2016JobCheck = CheckProgress -progressStage "ServerCore2016Image"
                while ($serverCore2016JobCheck -ne "Complete") {
                    Write-Host "The ServerCore2016Image stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 30
                    $serverCore2016JobCheck = CheckProgress -progressStage "ServerCore2016Image"
                    if ($serverCore2016JobCheck -eq "Failed") {
                        Write-Host "The ServerCore2016Image stage of the process has failed. This should ideally complete before the Windows Server 2019 Core image is created, but we can continue the process to create the 2019 image anyway."
                        BREAK
                    }
                }#>
                if ($runMode -eq "partialParallel") {
                    $serverCore2016JobCheck = CheckProgress -progressStage "ServerCore2016Image"
                    while ($serverCore2016JobCheck -ne "Complete") {
                        Write-Host "The ServerCore2016Image stage of the process has not yet completed. Checking again in 20 seconds"
                        Start-Sleep -Seconds 20
                        $serverCore2016JobCheck = CheckProgress -progressStage "ServerCore2016Image"
                        if ($serverCore2016JobCheck -eq "Failed") {
                            throw "The ServerCore2016Image stage of the process has failed. This should fully complete before the Windows Server 2019 full image is created. Check the Windows Server logs, ensure that step is completed first, and rerun."
                        }
                    }
                }
                elseif ($runMode -eq "serial") {
                    Write-Host "Image is $image - checking run mode and progress"
                    $serverFull2016JobCheck = CheckProgress -progressStage "ServerFull2016Image"
                    while ($serverFull2016JobCheck -ne "Complete") {
                        Write-Host "The ServerFull2016Image stage of the process has not yet completed. Checking again in 20 seconds"
                        Start-Sleep -Seconds 20
                        $serverFull2016JobCheck = CheckProgress -progressStage "ServerFull2016Image"
                        if ($serverFull2016JobCheck -eq "Failed") {
                            throw "The ServerFull2016Image stage of the process has failed. This should fully complete before the Windows Server full image is created. Check the Windows Server logs, ensure that step is completed first, and rerun."
                        }
                    }
                }
            }
            if ($image -eq "ServerFull2019") {
                Write-Host "Image is $image - checking run mode and progress"
                <#$serverFull2016JobCheck = CheckProgress -progressStage "ServerFull2016Image"
                while ($serverFull2016JobCheck -ne "Complete") {
                    Write-Host "The ServerFull2016Image stage of the process has not yet completed. Checking again in 20 seconds"
                    Start-Sleep -Seconds 30
                    $serverFull2016JobCheck = CheckProgress -progressStage "ServerFull2016Image"
                    if ($serverFull2016JobCheck -eq "Failed") {
                        Write-Host "The ServerFull2016Image stage of the process has failed. This should ideally complete before the Windows Server 2019 Full image is created, but we can continue the process to create the 2019 image anyway."
                        BREAK
                    }
                }#>
                if ($runMode -eq "partialParallel") {
                    $serverFull2016JobCheck = CheckProgress -progressStage "ServerFull2016Image"
                    while ($serverFull2016JobCheck -ne "Complete") {
                        Write-Host "The ServerFull2016Image stage of the process has not yet completed. Checking again in 20 seconds"
                        Start-Sleep -Seconds 20
                        $serverFull2016JobCheck = CheckProgress -progressStage "ServerFull2016Image"
                        if ($serverFull2016JobCheck -eq "Failed") {
                            throw "The ServerFull2016Image stage of the process has failed. This should fully complete before the Windows Server full image is created. Check the Windows Server logs, ensure that step is completed first, and rerun."
                        }
                    }
                }
                elseif ($runMode -eq "serial") {
                    $serverCore2019JobCheck = CheckProgress -progressStage "ServerCore2019Image"
                    while ($serverCore2019JobCheck -ne "Complete") {
                        Write-Host "The ServerCore2019Image stage of the process has not yet completed. Checking again in 20 seconds"
                        Start-Sleep -Seconds 20
                        $serverCore2019JobCheck = CheckProgress -progressStage "ServerCore2019Image"
                        if ($serverCore2019JobCheck -eq "Failed") {
                            throw "The ServerCore2019Image stage of the process has failed. This should fully complete before the Windows Server Core image is created. Check the Windows Server logs, ensure that step is completed first, and rerun."
                        }
                    }
                }
            }
            Set-Location "$ASDKpath\images"
            # Check which image is being deployed
            if ($image -eq "ServerCore2016") {
                $sku = "2016-Datacenter-Server-Core"
                $edition = 'Windows Server 2016 SERVERDATACENTERCORE'
                $onlinePackage = "*Microsoft.WindowsServer2016DatacenterServerCore-ARM*"
                $offlinePackage = "Microsoft.WindowsServer2016DatacenterServerCore-ARM.1.0.0"
                $date = Get-Date -Format FileDate
                $vhdVersion = "2016.40.$date"
                $publisher = "MicrosoftWindowsServer"
                $offer = "WindowsServer"
                $osVersion = "Windows"
                $imageType = "ServerCore"
                $delay = 60
            }
            elseif ($image -eq "ServerFull2016") {
                $sku = "2016-Datacenter"
                $edition = 'Windows Server 2016 SERVERDATACENTER'
                $onlinePackage = "*Microsoft.WindowsServer2016Datacenter-ARM*"
                $offlinePackage = "Microsoft.WindowsServer2016Datacenter-ARM.1.0.0"
                $date = Get-Date -Format FileDate
                $vhdVersion = "2016.40.$date"
                $publisher = "MicrosoftWindowsServer"
                $offer = "WindowsServer"
                $osVersion = "Windows"
                $imageType = "ServerFull"
                $delay = 45
            }
            if ($image -eq "ServerCore2019") {
                $sku = "2019-Datacenter-Server-Core"
                $edition = 'Windows Server 2019 SERVERDATACENTERCORE'
                $onlinePackage = "*Microsoft.WindowsServer2019DatacenterServerCore-ARM*"
                $offlinePackage = "Microsoft.WindowsServer2019DatacenterServerCore-ARM.1.0.0"
                $date = Get-Date -Format FileDate
                $vhdVersion = "2019.40.$date"
                $publisher = "MicrosoftWindowsServer"
                $offer = "WindowsServer"
                $osVersion = "Windows"
                $imageType = "ServerCore"
                $delay = 90
            }
            elseif ($image -eq "ServerFull2019") {
                $sku = "2019-Datacenter"
                $edition = 'Windows Server 2019 SERVERDATACENTER'
                $onlinePackage = "*Microsoft.WindowsServer2019Datacenter-ARM*"
                $offlinePackage = "Microsoft.WindowsServer2019Datacenter-ARM.1.0.0"
                $date = Get-Date -Format FileDate
                $vhdVersion = "2019.40.$date"
                $publisher = "MicrosoftWindowsServer"
                $offer = "WindowsServer"
                $osVersion = "Windows"
                $imageType = "ServerFull"
                $delay = 75
            }
            elseif ($image -eq "UbuntuServer") {
                $sku = "16.04-LTS"
                $onlinePackage = "*Canonical.UbuntuServer1604LTS*"
                $offlinePackage = "Canonical.UbuntuServer1604LTS-ARM.1.0.0"
                $publisher = "Canonical"
                $offer = "UbuntuServer"
                if (($registerASDK -eq $false) -or (($registerASDK -eq $true) -and ($deploymentMode -ne "Online"))) {
                    $date = Get-Date -Format FileDate
                    $vhdVersion = "16.04.$date"
                }
                else {
                    $vhdVersion = ""
                }
                $osVersion = "Linux"
                $delay = 30
            }

            # Log into Azure Stack to check for existing images and push new ones if required ###
            Write-Host "Logging into Azure Stack"
            $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            $azsLocation = (Get-AzsLocation).Name
            if (($registerASDK -eq $true) -and ($deploymentMode -eq "Online")) {
                if ($image -notlike "*2019") {
                    # Logout to clean up
                    Write-Host "Logging out to clear up stale logins"
                    Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
                    Clear-AzureRmContext -Scope CurrentUser -Force
                    ### Login to Azure to get all the details about the syndicated marketplace offering ###
                    Import-Module "$modulePath\Syndication\AzureStack.MarketplaceSyndication.psm1"
                    Add-AzureRmAccount -EnvironmentName "AzureCloud" -SubscriptionId $azureRegSubId -TenantId $azureRegTenantID -Credential $azureRegCreds -ErrorAction Stop | Out-Null
                    $azureEnvironment = Get-AzureRmEnvironment -Name AzureCloud
                    Remove-Variable -Name Registration -Force -Confirm:$false -ErrorAction SilentlyContinue
                    $asdkHostName = ($env:computername).ToLower()
                    $Registration = (Get-AzureRmResource | Where-Object { ($_.ResourceType -eq "Microsoft.AzureStack/registrations") `
                                -and (($_.Name -like "asdkreg-$asdkHostName*") -or ($_.Name -like "AzureStack*"))} | Select-Object -First 1 -ErrorAction SilentlyContinue).Name
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
                    $productList = (Invoke-RestMethod -Method GET -Uri $uri1 -Headers $Headers).value | Where-Object {$_.name -like "$package"} | Sort-Object -Property @{Expression = {$_.properties.offerVersion}; Ascending = $false} -ErrorAction Stop
                    foreach ($product in $productList) {
                        if (($product.properties.productProperties.version).Length -gt 14) {
                            $product.properties.productProperties.version = ($product.properties.productProperties.version) -replace ".$"
                        }
                    }
                    $product = $productList | Sort-Object -Property @{Expression = {$_.properties.productProperties.version}; Ascending = $true} | Select-Object -Last 1 -ErrorAction Stop
                    #$product = (Invoke-RestMethod -Method GET -Uri $uri1 -Headers $Headers).value | Where-Object {$_.name -like "$package"} | Sort-Object -Property @{Expression = {$_.properties.offerVersion}; Ascending = $true} | Select-Object -Last 1 -ErrorAction Stop

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
                    Write-Host "Legal display for AZPKG file: $legalDisplay"

                    if ($image -eq "UbuntuServer") {
                        # Get download information for Ubuntu Server 16.04 LTS VHD file
                        $azpkg.vhdPath = $downloadDetails.properties.osDiskImage.sourceBlobSasUri
                        $azpkg.vhdVersion = $downloadDetails.properties.version
                    }
                }
                elseif ($image -like "*2019") {
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
            }
            elseif (($registerASDK -eq $false) -or (($registerASDK -eq $true) -and ($deploymentMode -ne "Online"))) {
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
            Write-Host "Checking to see if the image is present in your Azure Stack Platform Image Repository"
            Write-Host "We first want to check if there is a failed or canceled upload from a previous attempt"
            if ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($azpkg.sku)/*") -and $_.ProvisioningState -eq "Failed"}) {
                Write-Host "There appears to be at least 1 suitable $($azpkg.sku) VM image within your Platform Image Repository which we will use for the ASDK Configurator, however, it's in a failed state"
                Write-Host "Cleaning up the image from the PIR"
                (Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($azpkg.sku)/*") -and $_.ProvisioningState -eq "Failed"} | Remove-AzsPlatformImage -Force -Verbose -ErrorAction Stop
            }
            elseif ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($azpkg.sku)/*") -and $_.ProvisioningState -eq "Canceled"}) {
                Write-Host "There appears to be at least 1 suitable $($azpkg.sku) VM image within your Platform Image Repository which we will use for the ASDK Configurator, however, it's in a canceled state"
                Write-Host "Cleaning up the image from the PIR"
                (Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($azpkg.sku)/*") -and $_.ProvisioningState -eq "Canceled"} | Remove-AzsPlatformImage -Force -Verbose -ErrorAction Stop
            }
            Write-Host "There are no failed or canceled images in the PIR, so moving on to checking for a valid, successful image"
            if ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -ErrorAction SilentlyContinue) | Where-Object {($_.Id -like "*$($azpkg.sku)/*") -and $_.ProvisioningState -eq "Succeeded"}) {
                Write-Host "There appears to be at least 1 suitable $($azpkg.sku) VM image within your Platform Image Repository which we will use for the ASDK Configurator. Here are the details:"
                Write-Host ('VM Image with publisher " {0}", offer " {1}", sku " {2}".' -f $azpkg.publisher, $azpkg.offer, $azpkg.sku) -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "No existing suitable $($azpkg.sku) VM image exists." 
                Write-Host "The image in the Azure Stack Platform Image Repository should have the following properties:"
                Write-Host "Publisher Name = $($azpkg.publisher)"
                Write-Host "Offer = $($azpkg.offer)"
                Write-Host "SKU = $($azpkg.sku)"
                Write-Host "Version = $($azpkg.vhdVersion)"
                Write-Host "Unfortunately, no image was found with these properties."
                Write-Host "Checking to see if the VHD already exists in an Azure Stack Storage Account"

                #Triggering a delay to stagger the creation of an RG/StorageAccount/Container etc
                Start-Sleep -Seconds $delay

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
                else { $blobName = "$($imageType).$($vhdVersion).vhd" }

                if ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob "$blobName" -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue)) {
                    Write-Host "You already have an upload of $blobName within your Storage Account. No need to re-upload."
                    $imageURI = $((Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob "$blobName" -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue).ICloudBlob.StorageUri.PrimaryUri.AbsoluteUri)
                    Write-Host "VHD path = $imageURI"
                }
                else {
                    Write-Host "There is no suitable $blobName image within your Storage Account. We'll need to upload a new one."
                    $validDownloadPathVHD = [System.IO.File]::Exists("$csvImagePath\Images\$image\$blobName")
                    Write-Host "Checking for a local copy first..."
                    # If there's no local VHD, create one.
                    if ($validDownloadPathVHD -eq $true) {
                        Write-Host "Located suitable VHD in this folder. No need to download again..."
                        $serverVHD = Get-ChildItem -Path "$csvImagePath\Images\$image\$blobName"
                        Write-Host "VHD located at $serverVHD"
                    }
                    else {
                        if ($image -eq "UbuntuServer") {
                            # Split for Ubuntu Image
                            $validDownloadPathZIP = $(Get-ChildItem -Path "$ASDKpath\images\$image\$($azpkg.offer)*.zip" -ErrorAction SilentlyContinue)
                            if ($validDownloadPathZIP) {
                                Write-Host "Cannot find a previously extracted Ubuntu Server VHD with name $blobName"
                                Write-Host "Checking to see if the Ubuntu Server ZIP already exists in ASDK Configurator folder"
                                $UbuntuServerZIP = Get-ChildItem -Path "$ASDKpath\images\$image\$($azpkg.offer)*.zip"
                                Write-Host "Ubuntu Server ZIP located at $UbuntuServerZIP"
                                if (!$(Get-ChildItem -Path "$csvImagePath\Images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip" -ErrorAction SilentlyContinue)) {
                                    Copy-Item -Path "$ASDKpath\images\$image\$($azpkg.offer)*.zip" -Destination "$csvImagePath\Images\$image\$($azpkg.offer)$($azpkg.vhdVersion).zip" -Force -Verbose -ErrorAction Stop
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
                                Write-Host "Cannot find a previously extracted Ubuntu Server download or ZIP file"
                                Write-Host "Begin download of correct Ubuntu Server ZIP to $ASDKpath"

                                if (($registerASDK -eq $true) -and ($deploymentMode -eq "Online")) {
                                    $ubuntuBuild = $azpkg.vhdVersion
                                    if (($ubuntuBuild).Length -gt 14) {
                                        $ubuntuBuild = $ubuntuBuild.Substring(0, $ubuntuBuild.Length - 1)
                                    }
                                    $ubuntuBuild = $ubuntuBuild.split('.')[2]
                                    $ubuntuURI = "https://cloud-images.ubuntu.com/releases/16.04/release-$ubuntuBuild/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"
                                }
                                elseif (($registerASDK -eq $false) -and ($deploymentMode -eq "Online")) {
                                    #$ubuntuURI = "https://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"
                                    #Hard coding to a known working Azure Stack image.
                                    $ubuntuURI = "https://cloud-images.ubuntu.com/releases/16.04/release-20180831/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"
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
                                $convertWindowsDownloadLocation = "$ASDKpath\images\$image\Convert-Windows$($imageType)Image.ps1"
                                $convertWindowsImageExists = [System.IO.File]::Exists("$ASDKpath\images\$image\Convert-Windows$($imageType)Image.ps1")
                                if ($convertWindowsImageExists -eq $false) {
                                    Write-Host "Downloading Convert-Windows$($imageType)Image.ps1 to create the VHD from the ISO"
                                    Write-Host "The download will be stored in $ASDKpath\images"
                                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                                    DownloadWithRetry -downloadURI "$convertWindowsURI" -downloadLocation "$convertWindowsDownloadLocation" -retries 10
                                }
                            }
                            elseif ($deploymentMode -ne "Online") {
                                $convertWindowsImageExists = [System.IO.File]::Exists("$ASDKpath\images\Convert-WindowsImage.ps1")
                                if ($convertWindowsImageExists -eq $true) {
                                    Copy-Item -Path "$ASDKpath\images\Convert-WindowsImage.ps1" -Destination "$ASDKpath\images\$image\Convert-Windows$($imageType)Image.ps1" -Force -Verbose -ErrorAction Stop
                                }
                                else {
                                    throw "Convert-WindowsImage.ps1 is missing from your download folder. This is required for the image creation and should be located here: $ASDKpath\images"
                                }
                            }
                            Set-Location "$ASDKpath\images\$image"
                            # Set path for Windows Updates (for Windows images). Copy to CSV first

                            if ($image -like "*2019") {
                                $v = "2019"
                                $ISOpath = $ISOPath2019
                            }
                            else {
                                $v = "2016"
                            }
                            Copy-Item -Path "$ASDKpath\images\$v\*" -Destination "$csvImagePath\Images\$image\" -Recurse -Force -Verbose -ErrorAction Stop
                            $target = "$csvImagePath\Images\$image\SSU"

                            $imageCreationSuccess = $false
                            $imageRetries = 0
                            # Sometimes the gallery item doesn't get added successfully, so perform checks and attempt multiple uploads if necessary
                            while (($imageCreationSuccess -eq $false) -and ($imageRetries++ -lt 3)) {
                                try {
                                    Write-Host "Starting image creation process. Creation attempt: $imageRetries"
                                    if ($image -eq "ServerCore$($v)") {
                                        .\Convert-WindowsServerCoreImage.ps1 -SourcePath $ISOpath -SizeBytes 40GB -Edition "$edition" -VHDPath "$csvImagePath\Images\$image\$($blobname)" `
                                            -VHDFormat VHD -VHDType Fixed -VHDPartitionStyle MBR -Feature "NetFx3" -Package $target -Passthru -Verbose
                                    }
                                    elseif ($image -eq "ServerFull$($v)") {
                                        .\Convert-WindowsServerFullImage.ps1 -SourcePath $ISOpath -SizeBytes 40GB -Edition "$edition" -VHDPath "$csvImagePath\Images\$image\$($blobname)" `
                                            -VHDFormat VHD -VHDType Fixed -VHDPartitionStyle MBR -Feature "NetFx3" -Package $target -Passthru -Verbose
                                    }
                                    if (!$(Get-ChildItem -Path "$csvImagePath\Images\$image\$blobName" -ErrorAction SilentlyContinue)) {
                                        Write-Host "Something went wrong during image creation but the error cannot be caught here."
                                        Write-Host "Cleaning up"
                                        $imageCreationSuccess = $false
                                        throw "Image creation failed. Check the logs but we'll retry a few times."
                                    }
                                    else {
                                        Write-Host "$blobname has been successfully created with Servicing Stack Updates."
                                        Write-Host "Mounting $blobname to inject cumulative updates"
                                        Write-Host "Creating a mount directory"
                                        $mountPath = "$ASDKpath\images\$image\Mount"
                                        New-Item -ItemType Directory -Path "$mountPath" -Force | Out-Null
                                        Write-Host "Mounting the VHD"
                                        Mount-WindowsImage -ImagePath "$csvImagePath\Images\$image\$blobName" -Index 1 `
                                        -Path "$mountPath" -Verbose -LogPath "$csvImagePath\Images\$image\$($image)Dism.log"
                                        Write-Host "Adding the Update packages"
                                        Add-WindowsPackage -Path "$mountPath" -PackagePath "$csvImagePath\Images\$image\CU" `
                                        -Verbose -LogPath "$csvImagePath\Images\$image\$($image)Dism.log"
                                        Write-Host "Saving the image"
                                        Dismount-WindowsImage -Path "$mountPath" -Save `
                                        -Verbose -LogPath "$csvImagePath\Images\$image\$($image)Dism.log"
                                        $imageCreationSuccess = $true
                                    }
                                }
                                catch {
                                    Write-Host "Image creation wasn't successful. Cleaning up, then waiting 10 seconds before retrying."
                                    Write-Host "$_.Exception.Message"
                                    Dismount-DiskImage -ImagePath $ISOPath -ErrorAction SilentlyContinue
                                    Get-ChildItem -Path "$csvImagePath\Images\$image\*" -Include "*.vhd" | Remove-Item -Force -ErrorAction SilentlyContinue
                                    Start-Sleep -Seconds 10
                                }
                            }
                            if (($imageCreationSuccess -eq $false) -and ($imageRetries -ge 3)) {
                                Dismount-DiskImage -ImagePath $ISOPath -ErrorAction SilentlyContinue
                                Get-ChildItem -Path "$csvImagePath\Images\$image\*" -Include "*.vhd" | Remove-Item -Force -ErrorAction SilentlyContinue
                                $imageRetries = --$imageRetries;
                                throw "Creating a Windows Server ($blobname) image failed after $imageRetries attempts. Check the logs then retry. Exiting process."
                                Set-Location $ScriptLocation
                                return
                            }
                            $serverVHD = Get-ChildItem -Path "$csvImagePath\Images\$image\$blobName"
                        }
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
                            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                            #Add-AzureRmVhd -Destination $imageURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $serverVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                            ################## AzCopy Testing ##############################################
                            $serverVHDDirectory = ($serverVHD).DirectoryName
                            $containerDestination = '{0}{1}' -f $asdkStorageAccount.PrimaryEndpoints.Blob, $asdkImagesContainerName
                            $azCopyPath = "C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\AzCopy.exe"
                            $storageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $asdkImagesRGName -Name $asdkImagesStorageAccountName).Value[0]
                            $azCopyCmd = [string]::Format("""{0}"" /source:""{1}"" /dest:""{2}"" /destkey:""{3}"" /BlobType:""page"" /Pattern:""{4}"" /Y /V:""{5}"" /Z:""{6}""", $azCopyPath, $serverVHDDirectory, $containerDestination, $storageAccountKey, $blobName, $azCopyLogPath, $journalPath)
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
                            $uploadSuccess = $true
                        }
                        catch {
                            Write-Host "Upload failed."
                            Write-Host "$_.Exception.Message"
                            $uploadVhdAttempt++
                            $uploadSuccess = $false
                        }
                    }
                    <#Commenting out for AzCopy Testing
                    # Sometimes Add-AzureRmVHD has an error about "The pipeline was not run because a pipeline is already running. Pipelines cannot be run concurrently". Rerunning the upload typically helps.
                    # Check that a) there's a VHD uploaded but b) the attempt didn't complete successfully (VHD in unreliable state) and c) you've attempted an upload no more than 3 times
                    while ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $serverVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$uploadSuccess) -and ($uploadVhdAttempt -le 3)) {
                        Try {
                            # Log back into Azure Stack to ensure login hasn't timed out
                            Write-Host "There was a previously failed upload. Upload Attempt: $uploadVhdAttempt"
                            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                            #Add-AzureRmVhd -Destination $imageURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $serverVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                            $azCopyUpload = AzCopy /Source:"$($serverVHD.FullName)" /Dest:$asdkImagesContainerName /Pattern:"$($serverVHD.Name)" /Y /V:$azCopyLogPath
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
                            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                            #Add-AzureRmVhd -Destination $imageURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $serverVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                            $azCopyUpload = AzCopy /Source:"$($serverVHD.FullName)" /Dest:$asdkImagesContainerName /Pattern:"$($serverVHD.Name)" /Y /V:$azCopyLogPath
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
                        Set-Location $ScriptLocation
                        return
                    }
                    End of AzCopy Testing #>
                }
                # To reach this stage, there is now a valid image in the Storage Account, ready to be uploaded into the PIR
                # Add the Platform Image
                Add-AzsPlatformImage -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -OsType $azpkg.osVersion -OsUri "$imageURI" -Force -Confirm: $false -Verbose -ErrorAction Stop
                #Add-AzsPlatformImage -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -OsType $azpkg.osVersion -OsUri "$($serverVHD.FullName)" -Force -Confirm: $false -Verbose -ErrorAction Stop
                if ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
                    Write-Host ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" successfully uploaded.' -f $azpkg.publisher, $azpkg.offer, $azpkg.sku, $azpkg.vhdVersion) -ErrorAction SilentlyContinue
                    if ($image -eq "UbuntuServer") {
                        Write-Host "Cleaning up local hard drive space - deleting VHD file and ZIP from Cluster Shared Volume"
                        Get-ChildItem -Path "$csvImagePath\Images\$image\" -Filter "$($azpkg.offer)$($azpkg.vhdVersion).vhd" | Remove-Item -Force
                        Get-ChildItem -Path "$csvImagePath\Images\$image\" -Filter "$($azpkg.offer)$($azpkg.vhdVersion).ZIP" | Remove-Item -Force
                        Get-ChildItem -Path "$csvImagePath\Images\$image\*" -Include "*.msu" | Remove-Item -Force
                        Write-Host "Cleaning up VHD from storage account"
                        Remove-AzureStorageBlob -Blob $blobName -Container $asdkImagesContainerName -Context $asdkStorageAccount.Context -Force
                    }
                    else {
                        Write-Host "Cleaning up local hard drive space - deleting VHD file"
                        Get-ChildItem -Path "$csvImagePath\Images\$image\" -Filter "$($blobname)" | Remove-Item -Force
                        Write-Host "Cleaning up VHD from storage account"
                        Remove-AzureStorageBlob -Blob $blobName -Container $asdkImagesContainerName -Context $asdkStorageAccount.Context -Force
                    }
                }
                elseif ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Failed') {
                    throw "Adding VM image failed. Please check the logs and clean up the Azure Stack Platform Image Repository to remove the failed image, then retry."
                }
                elseif ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Canceled') {
                    throw "Adding VM image was canceled. Confirm the image doesn't show in the Azure Stack Platform Image Repository and if it does, remove it, then retry."
                }
            }

            ### Add Packages ###
            ### If the user has chosen to register the ASDK as part of the process, the script will side load an AZPKG from the Azure Marketplace, otherwise ###
            ### it will add one from GitHub (assuming an online deployment choice) ###

            $azpkgPackageName = "$($azpkg.name)"
            Write-Host "Checking for the following package: $azpkgPackageName"
            if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$azpkgPackageName*"}) {
                Write-Host "Found the following existing package in your Gallery: $azpkgPackageName. No need to upload a new one"
            }
            else {
                Write-Host "Didn't find this package: $azpkgPackageName"
                Write-Host "Will need to side load it in to the gallery"

                if (($registerASDK -eq $true) -and ($deploymentMode -eq "Online")) {
                    if ($image -like "*2019") {
                        $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/WindowsServer/$package.azpkg"
                    }
                    else {
                        $azpkgPackageURL = $($azpkg.azpkgPath)
                    }
                    Write-Host "Uploading $azpkgPackageName with the ID: $($azpkg.id) from $($azpkg.azpkgPath)"
                }
                elseif (($registerASDK -eq $false) -and ($deploymentMode -eq "Online")) {
                    if ($image -eq "UbuntuServer") {
                        $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/Ubuntu/Canonical.UbuntuServer1604LTS-ARM.1.0.0.azpkg"
                    }
                    else {
                        $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/WindowsServer/$package.azpkg"
                    }
                }
                # If this isn't an online deployment, use the extracted zip file, and upload to a storage account
                elseif ((($registerASDK -eq $true) -or ($registerASDK -eq $false)) -and (($deploymentMode -ne "Online"))) {
                    $asdkStorageAccount = Get-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName -ErrorAction SilentlyContinue
                    Set-AzureRmCurrentStorageAccount -StorageAccountName $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName | Out-Null
                    $asdkContainer = Get-AzureStorageContainer -Name $asdkImagesContainerName -ErrorAction SilentlyContinue
                    $azpkgPackageURL = AddOfflineAZPKG -azpkgPackageName $azpkgPackageName -azCopyLogPath $azCopyLogPath -Verbose
                }
                $Retries = 0
                # Sometimes the gallery item doesn't get added successfully, so perform checks and attempt multiple uploads if necessary
                while (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "*$azpkgPackageName*"}) -and ($Retries++ -lt 20)) {
                    try {
                        Write-Host "$azpkgPackageName doesn't exist in the gallery. Upload Attempt #$Retries"
                        Write-Host "Uploading $azpkgPackageName from $azpkgPackageURL"
                        Add-AzsGalleryItem -GalleryItemUri $azpkgPackageURL -Force -Confirm:$false -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Host "Upload wasn't successful. Waiting 5 seconds before retrying."
                        Write-Host "$_.Exception.Message"
                        Start-Sleep -Seconds 5
                    }
                }
                if (!$(Get-AzsGalleryItem | Where-Object {$_.name -like "*$azpkgPackageName*"}) -and ($Retries -ge 20)) {
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
}
elseif (($skip2019Images) -and ($progressCheck -ne "Complete")) {
    # Update the ConfigASDK database with skip status
    $progressStage = "$($image)Image"
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
$endTime = $(Get-Date).ToString("MMdd-HHmmss")
Write-Host "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue