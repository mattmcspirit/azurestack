[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $azsPath,

    [Parameter(Mandatory = $true)]
    [String] $customDomainSuffix,

    [Parameter(Mandatory = $false)]
    [String] $registerAzS,

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
    [pscredential] $azsCreds,
    
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
    [String] $tableName,

    [parameter(Mandatory = $false)]
    [String] $multiNode,

    [parameter(Mandatory = $false)]
    [String] $azsRegName,

    [Parameter(Mandatory = $true)]
    [ValidateSet("AzureChinaCloud", "AzureCloud", "AzureGermanCloud", "AzureUSGovernment")]
    [String] $azureEnvironment
)

######################
Function ExtractGZ {
    Param(
        $infile,
        $outfile = ($infile -replace '\.gz$', '')
    )

    $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
    $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
    $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)

    $buffer = New-Object byte[](1024)
    while ($true) {
        $read = $gzipstream.Read($buffer, 0, 1024)
        if ($read -le 0) { break }
        $output.Write($buffer, 0, $read)
    }

    $gzipStream.Close()
    $output.Close()
    $input.Close()
}

#####################

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
$azsImagesRGName = "azurestack-adminimages"
$azsImagesStorageAccountName = "azsimagesstor"
$azsImagesContainerName = "azsimagescontainer"

if (!$([System.IO.Directory]::Exists("$azsPath\images"))) {
    New-Item -Path "$azsPath\images" -ItemType Directory -Force | Out-Null   
}
if (!$([System.IO.Directory]::Exists("$azsPath\images\2016"))) {
    New-Item -Path "$azsPath\images\2016" -ItemType Directory -Force | Out-Null   
}
if ($ISOPath2019) {
    if (!$([System.IO.Directory]::Exists("$azsPath\images\2019"))) {
        New-Item -Path "$azsPath\images\2019" -ItemType Directory -Force | Out-Null   
    }
}
if (!$([System.IO.Directory]::Exists("$azsPath\images\$image"))) {
    New-Item -Path "$azsPath\images\$image" -ItemType Directory -Force | Out-Null
}

if ($multiNode -eq $false) {
    if ($([System.IO.Directory]::Exists("C:\ClusterStorage\SU1_Volume"))) {
        Write-Host "This is a Windows Server 2019 ASDK host - setting imageRootPath to C:\ClusterStorage\SU1_Volume"
        $imageRootPath = "C:\ClusterStorage\SU1_Volume"
    }
    elseif ($([System.IO.Directory]::Exists("C:\ClusterStorage\Volume1"))) {
        Write-Host "This is a Windows Server 2016 ASDK host - setting imageRootPath to C:\ClusterStorage\Volume1"
        $imageRootPath = "C:\ClusterStorage\Volume1"
    }
}
else {
    $imageRootPath = $azsPath
}

if ($multiNode -eq $false) {
    if (!$([System.IO.Directory]::Exists("$imageRootPath\images"))) {
        New-Item -Path "$imageRootPath\images" -ItemType Directory -Force | Out-Null
    }
    if (!$([System.IO.Directory]::Exists("$imageRootPath\images\$image"))) {
        New-Item -Path "$imageRootPath\images\$image" -ItemType Directory -Force | Out-Null
    }
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
    Write-Host "Azure Stack POC Configurator Stage: $progressStage previously completed successfully"
}
elseif ((!$skip2019Images) -and ($progressCheck -ne "Complete")) {
    Write-Host "skip2019Images doesn't exist, and status isn't complete"
    if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
        try {
            if ($progressCheck -eq "Failed") {
                StageReset -progressStage $progressStage
            }

            Write-Host "Cleaning up old stale logins for this session"
            Get-AzureRmContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force
            Disable-AzureRMContextAutosave -Scope CurrentUser

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
            if ($multinode -eq $true) {
                $windowsVhd = 60
                $windowsVhdSize = [bigint]60GB
            }
            else {
                $windowsVhd = 40
                $windowsVhdSize = [bigint]40GB
            }
            
            Set-Location "$azsPath\images"
            # Check which image is being deployed
            if ($image -eq "ServerCore2016") {
                $sku = "2016-Datacenter-Server-Core"
                $edition = 'Windows Server 2016 SERVERDATACENTERCORE'
                $onlinePackage = "*Microsoft.WindowsServer2016DatacenterServerCore-ARM-payg*"
                $offlinePackage = "Microsoft.WindowsServer2016DatacenterServerCore-ARM.1.0.0"
                $date = Get-Date -Format FileDate
                $vhdVersion = "2016.$windowsVhd.$date"
                $publisher = "MicrosoftWindowsServer"
                $offer = "WindowsServer"
                $osVersion = "Windows"
                $imageType = "ServerCore"
                $delay = 60
            }
            elseif ($image -eq "ServerFull2016") {
                $sku = "2016-Datacenter"
                $edition = 'Windows Server 2016 SERVERDATACENTER'
                $onlinePackage = "*Microsoft.WindowsServer2016Datacenter-ARM-payg*"
                $offlinePackage = "Microsoft.WindowsServer2016Datacenter-ARM.1.0.0"
                $date = Get-Date -Format FileDate
                $vhdVersion = "2016.$windowsVhd.$date"
                $publisher = "MicrosoftWindowsServer"
                $offer = "WindowsServer"
                $osVersion = "Windows"
                $imageType = "ServerFull"
                $delay = 45
            }
            if ($image -eq "ServerCore2019") {
                $sku = "2019-Datacenter-Core"
                $edition = 'Windows Server 2019 SERVERDATACENTERCORE'
                $onlinePackage = "*Microsoft.WindowsServer2019DatacenterServerCore-ARM-payg*"
                $offlinePackage = "Microsoft.WindowsServer2019DatacenterServerCore-ARM.1.0.0"
                $date = Get-Date -Format FileDate
                $vhdVersion = "2019.$windowsVhd.$date"
                $publisher = "MicrosoftWindowsServer"
                $offer = "WindowsServer"
                $osVersion = "Windows"
                $imageType = "ServerCore"
                $delay = 90
            }
            elseif ($image -eq "ServerFull2019") {
                $sku = "2019-Datacenter"
                $edition = 'Windows Server 2019 SERVERDATACENTER'
                $onlinePackage = "*Microsoft.WindowsServer2019Datacenter-ARM-payg*"
                $offlinePackage = "Microsoft.WindowsServer2019Datacenter-ARM.1.0.0"
                $date = Get-Date -Format FileDate
                $vhdVersion = "2019.$windowsVhd.$date"
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
                if (($registerAzS -eq $false) -or (($registerAzS -eq $true) -and ($deploymentMode -ne "Online"))) {
                    $date = Get-Date -Format FileDate
                    # Temporarily hard coding to newest known working version
                    #$vhdVersion = "16.04.$date"
                    $vhdVersion = "16.04.20200318"
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
            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
            $sub = Get-AzureRmSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
            $azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
            $azsLocation = (Get-AzureRmLocation).DisplayName
            if (($registerAzS -eq $true) -and ($deploymentMode -eq "Online")) {
                #if ($image -notlike "*2019") {
                if ($image) {
                    # Logout to clean up
                    Write-Host "Logging out to clear up stale logins"
                    Get-AzureRmContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzureRmAccount | Out-Null
                    Clear-AzureRmContext -Scope CurrentUser -Force
                    ### Login to Azure to get all the details about the syndicated marketplace offering ###
                    Import-Module "$modulePath\Syndication\AzureStack.MarketplaceSyndication.psm1"
                    Add-AzureRmAccount -EnvironmentName $azureEnvironment -SubscriptionId $azureRegSubId -TenantId $azureRegTenantID -Credential $azureRegCreds -ErrorAction Stop | Out-Null
                    $azureEnv = Get-AzureRmEnvironment -Name $azureEnvironment
                    Remove-Variable -Name Registration -Force -Confirm:$false -ErrorAction SilentlyContinue
                    $Registration = (Get-AzureRmResource | Where-Object { ($_.ResourceType -eq "Microsoft.AzureStack/registrations") `
                                -and (($_.Name -like "*$azsRegName*") -or ($_.Name -like "AzureStack*")) } | Select-Object -First 1 -ErrorAction SilentlyContinue).Name
                    if (!$Registration) {
                        throw "No registration records found in your chosen Azure subscription. Please validate the success of your Azure Stack POC registration and ensure records have been created successfully."
                        Set-Location $ScriptLocation
                        return
                    }
                    # Retrieve the access token
                    $token = $null
                    $tokens = $null
                    $tokens = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems()
                    $token = $tokens | Where-Object Resource -EQ $azureEnv.ActiveDirectoryServiceEndpointResourceId | Where-Object TenantId -EQ $azureRegTenantID | Sort-Object ExpiresOn | Select-Object -Last 1 -ErrorAction Stop

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
                    $uri1 = "$($azureEnv.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($azureRegSubId.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products?api-version=2016-01-01"
                    $Headers = @{ 'authorization' = "Bearer $($Token.AccessToken)" } 
                    $productList = (Invoke-RestMethod -Method GET -Uri $uri1 -Headers $Headers).value | Where-Object { $_.name -like "$package" } | Sort-Object -Property @{Expression = { $_.properties.offerVersion }; Ascending = $false } -ErrorAction Stop
                    foreach ($product in $productList) {
                        if (($product.properties.productProperties.version).Length -gt 14) {
                            $product.properties.productProperties.version = ($product.properties.productProperties.version) -replace ".$"
                        }
                    }
                    $product = $productList | Sort-Object -Property @{Expression = { $_.properties.productProperties.version }; Ascending = $true } | Select-Object -Last 1 -ErrorAction Stop
                    #$product = (Invoke-RestMethod -Method GET -Uri $uri1 -Headers $Headers).value | Where-Object {$_.name -like "$package"} | Sort-Object -Property @{Expression = {$_.properties.offerVersion}; Ascending = $true} | Select-Object -Last 1 -ErrorAction Stop

                    $azpkg.id = $product.name.Split('/')[-1]
                    $azpkg.type = $product.properties.productKind
                    $azpkg.publisher = $product.properties.publisherIdentifier
                    $azpkg.sku = $product.properties.sku
                    $azpkg.offer = $product.properties.offer

                    # Get product info
                    $uri2 = "$($azureEnv.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($azureRegSubId.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products/$($azpkg.id)?api-version=2016-01-01"
                    $Headers = @{ 'authorization' = "Bearer $($Token.AccessToken)" } 
                    $productDetails = Invoke-RestMethod -Method GET -Uri $uri2 -Headers $Headers
                    $azpkg.name = $productDetails.properties.galleryItemIdentity

                    # Get download location for AZPKG file
                    $uri3 = "$($azureEnv.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($azureRegSubId.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products/$($azpkg.id)/listDetails?api-version=2016-01-01"
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
                        # Temporarily hard coding to newest known working Ubuntu image
                        #$azpkg.vhdVersion = $downloadDetails.properties.version
                        $azpkg.vhdVersion = "16.04.20200318"
                    }
                }
                <#
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
                } #>
            }
            elseif (($registerAzS -eq $false) -or (($registerAzS -eq $true) -and ($deploymentMode -ne "Online"))) {
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
            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
            $sub = Get-AzureRmSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
            $azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
            Write-Host "Checking to see if the image is present in your Azure Stack Platform Image Repository"
            Write-Host "We first want to check if there is a failed or canceled upload from a previous attempt"
            if ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -ErrorAction SilentlyContinue) | Where-Object { ($_.Id -like "*$($azpkg.sku)/*") -and $_.ProvisioningState -eq "Failed" }) {
                Write-Host "There appears to be at least 1 suitable $($azpkg.sku) VM image within your Platform Image Repository which we will use for the Azure Stack POC Configurator, however, it's in a failed state"
                Write-Host "Cleaning up the image from the PIR"
                (Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -ErrorAction SilentlyContinue) | Where-Object { ($_.Id -like "*$($azpkg.sku)/*") -and $_.ProvisioningState -eq "Failed" } | Remove-AzsPlatformImage -Force -Verbose -ErrorAction Stop
            }
            elseif ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -ErrorAction SilentlyContinue) | Where-Object { ($_.Id -like "*$($azpkg.sku)/*") -and $_.ProvisioningState -eq "Canceled" }) {
                Write-Host "There appears to be at least 1 suitable $($azpkg.sku) VM image within your Platform Image Repository which we will use for the Azure Stack POC Configurator, however, it's in a canceled state"
                Write-Host "Cleaning up the image from the PIR"
                (Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -ErrorAction SilentlyContinue) | Where-Object { ($_.Id -like "*$($azpkg.sku)/*") -and $_.ProvisioningState -eq "Canceled" } | Remove-AzsPlatformImage -Force -Verbose -ErrorAction Stop
            }
            Write-Host "There are no failed or canceled images in the PIR, so moving on to checking for a valid, successful image"
            if ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -ErrorAction SilentlyContinue) | Where-Object { ($_.Id -like "*$($azpkg.sku)/*") -and $_.ProvisioningState -eq "Succeeded" }) {
                Write-Host "There appears to be at least 1 suitable $($azpkg.sku) VM image within your Platform Image Repository which we will use for the Azure Stack POC Configurator. Here are the details:"
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
                if (-not (Get-AzureRmResourceGroup -Name $azsImagesRGName -Location $azsLocation -ErrorAction SilentlyContinue)) { New-AzureRmResourceGroup -Name $azsImagesRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop }
                # Test/Create Storage
                $azsStorageAccount = Get-AzureRmStorageAccount -Name $azsImagesStorageAccountName -ResourceGroupName $azsImagesRGName -ErrorAction SilentlyContinue
                if (-not ($azsStorageAccount)) { $azsStorageAccount = New-AzureRmStorageAccount -Name $azsImagesStorageAccountName -Location $azsLocation -ResourceGroupName $azsImagesRGName -Type Standard_LRS -ErrorAction Stop }
                Set-AzureRmCurrentStorageAccount -StorageAccountName $azsImagesStorageAccountName -ResourceGroupName $azsImagesRGName | Out-Null
                # Test/Create Container
                $azsContainer = Get-AzureStorageContainer -Name $azsImagesContainerName -ErrorAction SilentlyContinue
                if (-not ($azsContainer)) { $azsContainer = New-AzureStorageContainer -Name $azsImagesContainerName -Permission Blob -Context $azsStorageAccount.Context -ErrorAction Stop }

                if ($image -eq "UbuntuServer") { $blobName = "$($azpkg.offer)$($azpkg.vhdVersion).vhd" }
                else { $blobName = "$($imageType).$($vhdVersion).vhd" }

                if ($(Get-AzureStorageBlob -Container $azsImagesContainerName -Blob "$blobName" -Context $azsStorageAccount.Context -ErrorAction SilentlyContinue)) {
                    Write-Host "You already have an upload of $blobName within your Storage Account. No need to re-upload."
                    $imageURI = $((Get-AzureStorageBlob -Container $azsImagesContainerName -Blob "$blobName" -Context $azsStorageAccount.Context -ErrorAction SilentlyContinue).ICloudBlob.StorageUri.PrimaryUri.AbsoluteUri)
                    Write-Host "VHD path = $imageURI"
                }
                else {
                    Write-Host "There is no suitable $blobName image within your Storage Account. We'll need to upload a new one."
                    $validDownloadPathVHD = [System.IO.File]::Exists("$imageRootPath\images\$image\$blobName")
                    Write-Host "Checking for a local copy first..."
                    # If there's no local VHD, create one.
                    if ($validDownloadPathVHD -eq $true) {
                        Write-Host "Located suitable VHD in this folder. No need to download again..."
                        $serverVHD = Get-ChildItem -Path "$imageRootPath\images\$image\$blobName"  
                        Write-Host "VHD located at $serverVHD"
                    }
                    else {
                        if ($image -eq "UbuntuServer") {
                            # At this stage there is no VHD
                            # Firstly check if the Tar has been created on the CSV
                            $validDownloadPathTar = $(Get-ChildItem -Path "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar" -ErrorAction SilentlyContinue)
                            if ($validDownloadPathTar) {
                                # Now have a Tar file ready for extraction to a VHD
                                Write-Host "Tar located at $validDownloadPathTar"
                            }
                            else {
                                # Check the $imageRootPath for the GZ file
                                $validDownloadPathGZ = $(Get-ChildItem -Path "$azsPath\images\$image\$($azpkg.offer)*.tar.gz" -ErrorAction SilentlyContinue)
                                if ($validDownloadPathGZ) {
                                    # If there is a GZ file, we need to extract it to get a Tar file
                                    $UbuntuServerGZ = Get-ChildItem -Path "$azsPath\images\$image\$($azpkg.offer)*.tar.gz"
                                    Write-Host "Ubuntu Server GZ located at $UbuntuServerGZ"
                                    if (!$(Get-ChildItem -Path "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion)*.tar.gz" -ErrorAction SilentlyContinue)) {
                                        Copy-Item -Path "$azsPath\images\$image\$($azpkg.offer)*.tar.gz" -Destination "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar.gz" -Force -Verbose -ErrorAction Stop
                                        $UbuntuServerGZ = Get-ChildItem -Path "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion)*.tar.gz"
                                    }
                                    else {
                                        $UbuntuServerGZ = Get-ChildItem -Path "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion)*.tar.gz"
                                    }
                                    Write-Host "Ubuntu Server GZ now located at $UbuntuServerGZ"
                                    Write-Host "Extracting GZ file to retrieve Tar file"
                                    try {
                                        ExtractGZ $($UbuntuServerGZ.FullName) "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar"
                                    }
                                    catch {
                                        Write-Host "$_.Exception.Message" -ErrorAction Stop
                                        Set-Location $ScriptLocation
                                        return
                                    }
                                    $UbuntuServerTar = (Get-ChildItem -Path "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar").FullName
                                    # Should now have a Tar which is ready to be extracted to a VHD
                                    Write-Host "Ubuntu Server Tar now located at $UbuntuServerTar"
                                }
                                else {
                                    # If there is no GZ file, we'll have to download one
                                    # Need to bring download logic into this section
                                    Write-Host "There is no Ubuntu Server GZ file, so one will have to be downloaded."
                                    Write-Host "Cannot find a previously extracted Ubuntu Server VHD, Tar or GZ file"
                                    Write-Host "Begin download of correct Ubuntu Server GZ to $azsPath"
    
                                    $ubuntuBuild = $azpkg.vhdVersion
                                    if (($ubuntuBuild).Length -gt 14) {
                                        $ubuntuBuild = $ubuntuBuild.substring(0, 14)
                                    }
                                    $ubuntuBuild = $ubuntuBuild.split('.')[2]
                                    $ubuntuURI = "https://cloud-images.ubuntu.com/releases/xenial/release-$ubuntuBuild/ubuntu-16.04-server-cloudimg-amd64-azure.vhd.tar.gz"
                                    $ubuntuDownloadLocation = "$azsPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar.gz"
                                    DownloadWithRetry -downloadURI "$ubuntuURI" -downloadLocation "$ubuntuDownloadLocation" -retries 10
                                    if (!([System.IO.File]::Exists("$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar.gz"))) {
                                        Copy-Item -Path "$azsPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar.gz" -Destination "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar.gz" -Force -Verbose -ErrorAction Stop
                                        $UbuntuServerGZ = Get-ChildItem -Path "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar.gz"
                                    }
                                    else {
                                        $UbuntuServerGZ = Get-ChildItem -Path "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar.gz"
                                    }
                                    Write-Host "Ubuntu Server GZ now located at $UbuntuServerGZ"
                                    # Now extract the GZ file to get the Tar
                                    try {
                                        $session = New-PSSession -Name ExtractTar -ComputerName $env:COMPUTERNAME -EnableNetworkAccess
                                        Write-Host "Expanding GZ found at $UbuntuServerGZ"
                                        ExtractGZ $($UbuntuServerGZ.FullName) "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar"
                                    }
                                    catch {
                                        Write-Host "$_.Exception.Message" -ErrorAction Stop
                                        Set-Location $ScriptLocation
                                        return
                                    }
                                }
                            }
                            # Need Tar extract logic here
                            $UbuntuServerTar = (Get-ChildItem -Path "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar").FullName
                            Write-Host "Ubuntu Server Tar now located at $UbuntuServerTar"
                            try {
                                $UbuntuServerTar = (Get-ChildItem -Path "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar").FullName
                                $UbuntuServerTarDirectory = (Get-ChildItem -Path "$imageRootPath\images\$image\$($azpkg.offer)$($azpkg.vhdVersion).tar").DirectoryName
                                $session = New-PSSession -Name ExtractTar -ComputerName $env:COMPUTERNAME -EnableNetworkAccess
                                Invoke-Command -Session $session -ArgumentList $deploymentMode, $azsPath, $UbuntuServerTar, $UbuntuServerTarDirectory, $imageRootPath, $blobName -ScriptBlock {
                                    if ($Using:deploymentMode -eq "Online") {
                                        Install-Module -Name 7Zip4PowerShell -Verbose -Force
                                    }
                                    elseif ($Using:deploymentMode -ne "Online") {
                                        $SourceLocation = "$Using:azsPath\PowerShell"
                                        $RepoName = "AzSPoCRepo"
                                        if (!(Get-PSRepository -Name $RepoName -ErrorAction SilentlyContinue)) {
                                            Register-PSRepository -Name $RepoName -SourceLocation $SourceLocation -InstallationPolicy Trusted
                                        }
                                        Install-Module 7Zip4PowerShell -Repository $RepoName -Force -ErrorAction Stop -Verbose
                                    }
                                    Write-Host "Expanding Tar found at $Using:UbuntuServerTar"
                                    Expand-7Zip -ArchiveFileName "$Using:UbuntuServerTar" -TargetPath "$Using:UbuntuServerTarDirectory"
                                    Get-ChildItem -Path "$Using:UbuntuServerTarDirectory" -Filter "*.vhd" | Rename-Item -NewName "$Using:blobName" -PassThru -Force -ErrorAction Stop
                                    Remove-Module -Name 7Zip4PowerShell -Verbose -Force
                                }
                                Remove-PSSession -Name ExtractTar -Confirm:$false -ErrorAction SilentlyContinue -Verbose
                                Remove-Variable -Name session -Force -ErrorAction SilentlyContinue -Verbose
                                Uninstall-Module -Name 7Zip4PowerShell -Force -Confirm:$false -Verbose
                            }
                            catch {
                                Write-Host "$_.Exception.Message" -ErrorAction Stop
                                Set-Location $ScriptLocation
                                return
                            }
                            # Now get VHD path
                            $serverVHD = Get-ChildItem -Path "$imageRootPath\images\$image\" -Filter *.vhd | Rename-Item -NewName "$blobName" -PassThru -Force -ErrorAction Stop
                        }
                        elseif ($image -ne "UbuntuServer") {
                            # Split for Windows Server Images
                            if ($deploymentMode -eq "Online") {
                                # Download Convert-WindowsImage.ps1
                                $convertWindowsURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/$branch/deployment/scripts/Convert-WindowsImage.ps1"
                                $convertWindowsDownloadLocation = "$azsPath\images\$image\Convert-Windows$($imageType)Image.ps1"
                                $convertWindowsImageExists = [System.IO.File]::Exists("$azsPath\images\$image\Convert-Windows$($imageType)Image.ps1")
                                if ($convertWindowsImageExists -eq $false) {
                                    Write-Host "Downloading Convert-Windows$($imageType)Image.ps1 to create the VHD from the ISO"
                                    Write-Host "The download will be stored in $azsPath\images"
                                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                                    DownloadWithRetry -downloadURI "$convertWindowsURI" -downloadLocation "$convertWindowsDownloadLocation" -retries 10
                                }
                            }
                            elseif ($deploymentMode -ne "Online") {
                                $convertWindowsImageExists = [System.IO.File]::Exists("$azsPath\images\Convert-WindowsImage.ps1")
                                if ($convertWindowsImageExists -eq $true) {
                                    Copy-Item -Path "$azsPath\images\Convert-WindowsImage.ps1" -Destination "$azsPath\images\$image\Convert-Windows$($imageType)Image.ps1" -Force -Verbose -ErrorAction Stop
                                }
                                else {
                                    throw "Convert-WindowsImage.ps1 is missing from your download folder. This is required for the image creation and should be located here: $azsPath\images"
                                }
                            }
                            Set-Location "$azsPath\images\$image"
                            # Set path for Windows Updates (for Windows images). Copy to CSV first

                            if ($image -like "*2019") {
                                $v = "2019"
                                $ISOpath = $ISOPath2019
                            }
                            else {
                                $v = "2016"
                            }
                            Copy-Item -Path "$azsPath\images\$v\*" -Destination "$imageRootPath\images\$image\" -Recurse -Force -Verbose -ErrorAction Stop
                            $target = "$imageRootPath\images\$image\SSU"

                            $imageCreationSuccess = $false
                            $imageRetries = 0
                            # Sometimes the gallery item doesn't get added successfully, so perform checks and attempt multiple uploads if necessary
                            while (($imageCreationSuccess -eq $false) -and ($imageRetries++ -lt 3)) {
                                try {
                                    Write-Host "Starting image creation process. Creation attempt: $imageRetries"
                                    if ($image -eq "ServerCore$($v)") {
                                        .\Convert-WindowsServerCoreImage.ps1 -SourcePath $ISOpath -SizeBytes $windowsVhdSize -Edition "$edition" -VHDPath "$imageRootPath\images\$image\$($blobname)" `
                                            -VHDFormat VHD -VHDType Fixed -VHDPartitionStyle MBR -Feature "NetFx3" -Package $target -Passthru -Verbose
                                    }
                                    elseif ($image -eq "ServerFull$($v)") {
                                        .\Convert-WindowsServerFullImage.ps1 -SourcePath $ISOpath -SizeBytes $windowsVhdSize -Edition "$edition" -VHDPath "$imageRootPath\images\$image\$($blobname)" `
                                            -VHDFormat VHD -VHDType Fixed -VHDPartitionStyle MBR -Feature "NetFx3" -Package $target -Passthru -Verbose
                                    }
                                    if (!$(Get-ChildItem -Path "$imageRootPath\images\$image\$blobName" -ErrorAction SilentlyContinue)) {
                                        Write-Host "Something went wrong during image creation but the error cannot be caught here."
                                        Write-Host "Cleaning up"
                                        $imageCreationSuccess = $false
                                        throw "Image creation failed. Check the logs but we'll retry a few times."
                                    }
                                    else {
                                        Write-Host "$blobname has been successfully created with Servicing Stack Updates."
                                        Write-Host "Mounting $blobname to inject cumulative updates"
                                        Write-Host "Creating a mount directory"
                                        $mountPath = "$azsPath\images\$image\Mount"
                                        New-Item -ItemType Directory -Path "$mountPath" -Force | Out-Null
                                        Write-Host "Mounting the VHD"
                                        Mount-WindowsImage -ImagePath "$imageRootPath\images\$image\$blobName" -Index 1 `
                                            -Path "$mountPath" -Verbose -LogPath "$imageRootPath\images\$image\$($image)Dism.log"
                                        Write-Host "Adding the Update packages"
                                        try {
                                            Add-WindowsPackage -Path "$mountPath" -PackagePath "$imageRootPath\images\$image\CU" `
                                                -Verbose -LogPath "$imageRootPath\images\$image\$($image)Dism.log" -ErrorAction SilentlyContinue
                                        }
                                        catch {
                                            Write-Host "One of the packages didn't install correctly, but process can continue."
                                        }

                                        if ($multinode -eq $true) {
                                            # Product Key changes / Edition Updates
                                            Write-Host "Getting current Windows Server edition from the image ahead of potential AVMA configuration"
                                            $edition = (Get-WindowsEdition -Path $mountPath).Edition
                                            # If the user has supplied eval media, this should run
                                            if ($edition -eq "ServerDatacenterEval") {
                                                Write-Host "Your image currently has the $edition Edition. We need to first update this to ServerDatacenter"
                                                if ($image -like "*2016") {
                                                    Write-Host "This image will also be updated with the Automatic VM Activation Key"
                                                    Write-Host "Updating the Windows Server Edition and AVMA product key. This may take a while."
                                                    Write-Host "This is a $edition image, and will now be updated to the correct edition and key. Please be patient."
                                                    dism /image:$mountPath /set-edition:ServerDatacenter /ProductKey:TMJ3Y-NTRTM-FJYXT-T22BY-CWG3J /AcceptEula /LogPath:"$imageRootPath\images\$image\$($image)Dism.log"
                                                }
                                                elseif ($image -like "*2019") {
                                                    #Write-Host "This is a $edition image, and will now be updated to the correct edition and key. Please be patient."
                                                    #dism /image:$mountPath /set-edition:ServerDatacenter /ProductKey:H3RNG-8C32Q-Q8FRX-6TDXV-WMBMW /AcceptEula /LogPath:"$azsPath\images\$image\$($image)Dism.log"
                                                    Write-Host "Your image currently has the $edition Edition. This cannot be updated to use the Automatic VM Activation service"
                                                    Write-Host "Any VM deployed from this image will not be activated by Azure Stack, and will stop working after 180 days."
                                                }
                                            }
                                            elseif ($edition -eq "ServerDatacenterEvalCor") {
                                                Write-Host "Your image currently has the $edition Edition. This cannot be updated to a different edition"
                                                Write-Host "Any VM deployed from this image will not be activated by Azure Stack, and will stop working after 180 days."
                                            }
                                            # If the user has supplied MSDN/VL media - this should run but as of 9/17, doesn't seem to be working
                                            elseif (($edition -eq "ServerDatacenter") -or ($edition -eq "ServerDatacenterCor")) {
                                                Write-Host "Your image currently has the $edition Edition. This is the correct edition for automatic activation, however we will now update the product key for AVMA"
                                                if ($image -like "*2016") {
                                                    Write-Host "This is a $edition image, and will now be updated to the correct AVMA key. Please be patient."
                                                    dism /image:$mountPath /Set-ProductKey:TMJ3Y-NTRTM-FJYXT-T22BY-CWG3J /LogPath:"$imageRootPath\images\$image\$($image)Dism.log"
                                                }
                                                elseif ($image -like "*2019") {
                                                    try {
                                                        Write-Host "This is a $edition image, and will now be updated to the correct AVMA key. Please be patient."
                                                        dism /image:$mountPath /Set-ProductKey:H3RNG-8C32Q-Q8FRX-6TDXV-WMBMW /LogPath:"$imageRootPath\images\$image\$($image)Dism.log"
                                                        #Set-WindowsProductKey -Path $mountPath -ProductKey 'H3RNG-8C32Q-Q8FRX-6TDXV-WMBMW' -LogPath "$imageRootPath\images\$image\$($image)Dism.log" -Verbose -ErrorAction SilentlyContinue
                                                    }
                                                    catch {
                                                        Write-Host "With current Windows Server 2019 builds, it appears that the key cannot be updated."
                                                        Write-Host "$_.Exception.Message"
                                                        Write-Host "Using MSDN/VL media doesn't seem to work any longer. You 2019 images will have a 180 day expiration, which should be fine for POC purposes."
                                                    }
                                                }
                                            }
                                        }

                                        Write-Host "Saving the image"
                                        Dismount-WindowsImage -Path "$mountPath" -Save `
                                            -Verbose -LogPath "$imageRootPath\images\$image\$($image)Dism.log"
                                        $imageCreationSuccess = $true
                                    }
                                }
                                catch {
                                    Write-Host "Image creation wasn't successful. Cleaning up, then waiting 10 seconds before retrying."
                                    Write-Host "$_.Exception.Message"
                                    Dismount-DiskImage -ImagePath $ISOPath -ErrorAction SilentlyContinue
                                    Get-ChildItem -Path "$imageRootPath\images\$image\*" -Include "*.vhd" | Remove-Item -Force -ErrorAction SilentlyContinue
                                    Start-Sleep -Seconds 10
                                }
                            }
                            if (($imageCreationSuccess -eq $false) -and ($imageRetries -ge 3)) {
                                Dismount-DiskImage -ImagePath $ISOPath -ErrorAction SilentlyContinue
                                Get-ChildItem -Path "$imageRootPath\images\$image\*" -Include "*.vhd" | Remove-Item -Force -ErrorAction SilentlyContinue
                                $imageRetries = --$imageRetries;
                                throw "Creating a Windows Server ($blobname) image failed after $imageRetries attempts. Check the logs then retry. Exiting process."
                                Set-Location $ScriptLocation
                                return
                            }
                            $serverVHD = Get-ChildItem -Path "$imageRootPath\images\$image\$blobName"
                        }
                    }
                    # At this point, there is a local image (either existing or new, that needs uploading, first to a Storage Account
                    Write-Host "Beginning upload of VHD to Azure Stack Storage Account"
                    $imageURI = '{0}{1}/{2}' -f $azsStorageAccount.PrimaryEndpoints.Blob, $azsImagesContainerName, $serverVHD.Name
                    # Upload VHD to Storage Account
                    # Sometimes Add-AzureRmVHD has an error about "The pipeline was not run because a pipeline is already running. Pipelines cannot be run concurrently". Rerunning the upload typically helps.
                    # Check that a) there's no VHD uploaded and b) the previous attempt(s) didn't complete successfully and c) you've attempted an upload no more than 3 times
                    $uploadVhdAttempt = 1
                    while (!$(Get-AzureStorageBlob -Container $azsImagesContainerName -Blob $serverVHD.Name -Context $azsStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$uploadSuccess) -and ($uploadVhdAttempt -le 3)) {
                        Try {
                            # Log back into Azure Stack to ensure login hasn't timed out
                            Write-Host "Upload Attempt: $uploadVhdAttempt"
                            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
                            $sub = Get-AzureRmSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
                            $azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
                            #Add-AzureRmVhd -Destination $imageURI -ResourceGroupName $azsImagesRGName -LocalFilePath $serverVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                            ################## AzCopy Testing ##############################################
                            $serverVHDDirectory = ($serverVHD).DirectoryName
                            $containerDestination = '{0}{1}' -f $azsStorageAccount.PrimaryEndpoints.Blob, $azsImagesContainerName
                            $azCopyPath = "C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\AzCopy.exe"
                            $storageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $azsImagesRGName -Name $azsImagesStorageAccountName).Value[0]
                            $azCopyCmd = [string]::Format("""{0}"" /source:""{1}"" /dest:""{2}"" /destkey:""{3}"" /BlobType:""page"" /Pattern:""{4}"" /Y /V:""{5}"" /Z:""{6}""", $azCopyPath, $serverVHDDirectory, $containerDestination, $storageAccountKey, $blobName, $azCopyLogPath, $journalPath)
                            Write-Host "Executing the following command:`n$azCopyCmd"
                            $result = cmd /c $azCopyCmd
                            foreach ($s in $result) {
                                Write-Host $s
                            }
                            if ($LASTEXITCODE -ne 0) {
                                Throw "Upload file failed: $blobName. Check logs at $azCopyLogPath";
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
                }
                # To reach this stage, there is now a valid image in the Storage Account, ready to be uploaded into the PIR
                # Add the Platform Image

                # ************ Need to add some retry control here *************

                Add-AzsPlatformImage -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -OsType $azpkg.osVersion -OsUri "$imageURI" -Force -Confirm: $false -Verbose -ErrorAction Stop
                if ($(Get-AzsPlatformImage -Location $azsLocation -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
                    Write-Host ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" successfully uploaded.' -f $azpkg.publisher, $azpkg.offer, $azpkg.sku, $azpkg.vhdVersion) -ErrorAction SilentlyContinue
                    if ($image -eq "UbuntuServer") {
                        Write-Host "Cleaning up local hard drive space - deleting VHD file, along with tar and GZ file from Cluster Shared Volume"
                        Get-ChildItem -Path "$imageRootPath\images\$image\" -Filter "$($azpkg.offer)$($azpkg.vhdVersion).vhd" | Remove-Item -Force
                        Get-ChildItem -Path "$imageRootPath\images\$image\" -Filter "$($azpkg.offer)$($azpkg.vhdVersion).tar" | Remove-Item -Force
                        Get-ChildItem -Path "$imageRootPath\images\$image\" -Filter "$($azpkg.offer)$($azpkg.vhdVersion).tar.gz" | Remove-Item -Force
                        Write-Host "Cleaning up VHD from storage account"
                        Remove-AzureStorageBlob -Blob $blobName -Container $azsImagesContainerName -Context $azsStorageAccount.Context -Force
                    }
                    else {
                        Write-Host "Cleaning up local hard drive space - deleting VHD file"
                        Get-ChildItem -Path "$imageRootPath\images\$image\" -Filter "$($blobname)" | Remove-Item -Force
                        Write-Host "Cleaning up VHD from storage account"
                        Remove-AzureStorageBlob -Blob $blobName -Container $azsImagesContainerName -Context $azsStorageAccount.Context -Force
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
            ### If the user has chosen to register the Azure Stack POC system as part of the process, the script will side load an AZPKG from the Azure Marketplace, otherwise ###
            ### it will add one from GitHub (assuming an online deployment choice) ###

            $azpkgPackageName = "$($azpkg.name)"
            Write-Host "Checking for the following package: $azpkgPackageName"
            if (Get-AzsGalleryItem | Where-Object { $_.Name -like "*$azpkgPackageName*" }) {
                Write-Host "Found the following existing package in your Gallery: $azpkgPackageName. No need to upload a new one"
            }
            else {
                Write-Host "Didn't find this package: $azpkgPackageName"
                Write-Host "Will need to side load it in to the gallery"

                if (($registerAzS -eq $true) -and ($deploymentMode -eq "Online")) {
                    <#
                    if ($image -like "*2019") {
                        $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/WindowsServer/$package.azpkg"
                    }
                    else {
                        $azpkgPackageURL = $($azpkg.azpkgPath)
                    }
                    #>
                    $azpkgPackageURL = $($azpkg.azpkgPath)
                    Write-Host "Uploading $azpkgPackageName with the ID: $($azpkg.id) from $($azpkg.azpkgPath)"
                }

                elseif (($registerAzS -eq $false) -and ($deploymentMode -eq "Online")) {
                    if ($image -eq "UbuntuServer") {
                        $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/Ubuntu/Canonical.UbuntuServer1604LTS-ARM.1.0.0.azpkg"
                    }
                    else {
                        $azpkgPackageURL = "https://github.com/mattmcspirit/azurestack/raw/$branch/deployment/packages/WindowsServer/$package.azpkg"
                    }
                }
                # If this isn't an online deployment, use the extracted zip file, and upload to a storage account
                elseif ((($registerAzS -eq $true) -or ($registerAzS -eq $false)) -and (($deploymentMode -ne "Online"))) {
                    $azsStorageAccount = Get-AzureRmStorageAccount -Name $azsImagesStorageAccountName -ResourceGroupName $azsImagesRGName -ErrorAction SilentlyContinue
                    Set-AzureRmCurrentStorageAccount -StorageAccountName $azsImagesStorageAccountName -ResourceGroupName $azsImagesRGName | Out-Null
                    $azsContainer = Get-AzureStorageContainer -Name $azsImagesContainerName -ErrorAction SilentlyContinue
                    $azpkgPackageURL = AddOfflineAZPKG -azpkgPackageName $azpkgPackageName -azCopyLogPath $azCopyLogPath -Verbose
                }
                $Retries = 0
                # Sometimes the gallery item doesn't get added successfully, so perform checks and attempt multiple uploads if necessary
                while (!$(Get-AzsGalleryItem | Where-Object { $_.name -like "*$azpkgPackageName*" }) -and ($Retries++ -lt 20)) {
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
                if (!$(Get-AzsGalleryItem | Where-Object { $_.name -like "*$azpkgPackageName*" }) -and ($Retries -ge 20)) {
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
    # Update the AzSPoC database with skip status
    $progressStage = "$($image)Image"
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
$endTime = $(Get-Date).ToString("MMdd-HHmmss")
Write-Host "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue