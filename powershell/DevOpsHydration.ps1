<#

.SYNOPSIS

This script can be used to hydrate a number of key open source DevOps tools into an Azure Stack environment, to enable you to deploy, test and learn about key DevOps tools,
and offer them to your tenants for their own consumption.

.DESCRIPTION

DevOpsHydration runs locally on the Azure Stack host, to download and hydrate key assets into your Azure Stack environment. It can be modfied as necessary to meet your specific goals.

The script will follow four steps:
- Login to Azure Stack with your provided credentials.
- Check your existing Platform Image Repository for an Ubuntu Server image, which matches the required attributes, and if needed, download a new Ubuntu Server image and upload into Azure Stack
- Download the pre-packaged open source DevOps tools, in the format .azpkg
- Check for the existence of the packages already within your Azure Stack, and update/replace/upload as appropriate.

.PARAMETER azureDirectoryTenantName

Name of your AAD Tenant which your Azure subscription is a part of. This parameter is mandatory.

.PARAMETER authenticationType

Either AzureAd or ADFS - which one that is entered will determine which ARM endpoints are used


.EXAMPLE

This script must be run from the Host machine of the POC.
.\DevOpsHydration.ps1 -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType "AzureAd"

#>

##############################################################################################################################################################

[CmdletBinding()]
param(

    [Parameter(Mandatory = $true)]
    [String] $azureDirectoryTenantName,

    [Parameter(Mandatory = $true)]
    [ValidateSet("AzureAd","ADFS")]
    [String] $authenticationType
)

function Select-Folder {
    [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $browse = New-Object System.Windows.Forms.FolderBrowserDialog
    $browse.SelectedPath = "C:\"
    $browse.ShowNewFolderButton = $True
    $browse.Description = "Select a directory to store your downloads - You must have administrative permission to store files in this location"

    $loop = $true
    while($loop) {
        if ($browse.ShowDialog() -eq "OK") {
            $loop = $false
        }
        else {
            $res = [System.Windows.Forms.MessageBox]::Show("You clicked Cancel. Would you like to try again or exit?", "Select a location", [System.Windows.Forms.MessageBoxButtons]::RetryCancel)
            if($res -eq "Cancel") {
                return
            }
        }
    }
    $browse.SelectedPath
    $browse.Dispose()
}

$VerbosePreference = "SilentlyContinue"
$ErrorActionPreference = 'Stop'

##############################################################################################################################################################
##############################################################################################################################################################

### CLEAR SCREEN ###
Clear-Host

### DISPLAY INTRO TEXT AND DELAY ###

Write-Host "`n`nWELCOME TO THE DEVOPS HYDRATION TOOLKIT`nVersion: 1.0.0" -ForegroundColor Green
Write-Host "`nThis toolkit can be used to quickly setup a Proof of Concept (POC) environment containing an
Ubuntu Server 16.04-LTS VM image, along with a selection of Open Source DevOps tools, including Chef, Puppet, Jenkins, Ansible and more.
This DevOps Hydration Toolkit will perform the following tasks:`n"
Write-Host "1) Download the appropriate Azure Stack Tools and PowerShell Modules for Administration
2) Securely login to your Azure Stack environment, through either ADFS or Azure AD credentials
3) Check your existing Azure Stack Platform Image Repository for a suitable Ubuntu Server 16.04-LTS VM Image and upload one if required
4) Download the latest Open Source DevOps Azure Stack Marketplace Packages from Github and upload into your Azure Stack Marketplace
`n" -ForegroundColor White
Write-Host "The DevOps Hydration Toolkit will start shortly...`n" -ForegroundColor Yellow
Start-Sleep -Seconds 35
Write-Host "Starting in 5...."
Start-Sleep -Seconds 1
Write-Host "Starting in 4...."
Start-Sleep -Seconds 1
Write-Host "Starting in 3...."
Start-Sleep -Seconds 1
Write-Host "Starting in 2...."
Start-Sleep -Seconds 1
Write-Host "Starting in 1...."
Start-Sleep -Seconds 1
Write-Host "LET'S GO!"
Start-Sleep -Seconds 3

### CLEAR SCREEN ###
Clear-Host

### SET LOCATION ###
$ScriptLocation = Get-Location

### DOWNLOAD & EXTRACT TOOLS ###
# Change directory to the root directory 
Set-Location C:\

# Download the tools archive
Write-Host "Downloading Azure Stack Tools to ensure you have the latest versions. This may take a few minutes, depending on your connection speed."
Start-Sleep -Seconds 5
invoke-webrequest https://github.com/Azure/AzureStack-Tools/archive/master.zip -OutFile master.zip -ErrorAction Stop

# Expand the downloaded files
Write-Host "Expanding Archive"
Start-Sleep -Seconds 3
expand-archive master.zip -DestinationPath . -Force
Write-Host "Archive expanded. Cleaning up."
Remove-Item master.zip -ErrorAction Stop
Start-Sleep -Seconds 3

# Change to the tools directory
Write-Host "Changing Directory"
Set-Location C:\AzureStack-Tools-master

# Set the execution policy and import the Azure Stack Connect Module
Write-Host "Setting the execution policy and importing the Azure Stack Connect Module"
Set-ExecutionPolicy RemoteSigned -Confirm:$false -Force -WarningAction SilentlyContinue
Write-Host "Execution Policy Set to RemoteSigned"
Import-Module .\Connect\AzureStack.Connect.psm1
Disable-AzureRmDataCollection -WarningAction SilentlyContinue
Write-Host "Azure Stack Connect module imported successfully"

### CONNECT TO AZURE STACK ###
# Register an AzureRM environment that targets your administrative Azure Stack instance
Write-Host "You will now be prompted to log in to your Azure Stack environment"
Start-Sleep -Seconds 3
Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "https://adminmanagement.local.azurestack.external" -ErrorAction Stop

# Add GraphEndpointResourceId value for Azure AD or ADFS and obtain Tenant ID, then login to Azure Stack
if ($authenticationType.ToString() -like "AzureAd")
    {
        Write-Host ("Azure Active Directory selected by Administrator")
        Set-AzureRmEnvironment -Name "AzureStackAdmin" -GraphAudience "https://graph.windows.net/" -ErrorAction Stop
        Write-Host ("Setting GraphEndpointResourceId value for Azure AD")
        Write-Host ("Getting Tenant ID for Login to Azure Stack")
        $TenantID = Get-AzsDirectoryTenantId -AADTenantName $azureDirectoryTenantName -EnvironmentName "AzureStackAdmin"
        Write-Host "Login with your Azure Stack Administrator Account used with Azure Active Directory"
        Start-Sleep -Seconds 3
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -ErrorAction Stop
    }
elseif ($authenticationType.ToString() -like "ADFS")
    {
        Write-Host ("Active Directory Federation Services selected by Administrator")
        Set-AzureRmEnvironment -Name "AzureStackAdmin" -GraphAudience "https://graph.local.azurestack.external/" -EnableAdfsAuthentication:$true
        Write-Host ("Setting GraphEndpointResourceId value for ADFS")
        Write-Host ("Getting Tenant ID for Login to Azure Stack")
        $TenantID = Get-AzsDirectoryTenantId -ADFS -EnvironmentName "AzureStackAdmin"
        Write-Host "Login with your Azure Stack Administrator Account used with ADFS"
        Start-Sleep -Seconds 3
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -ErrorAction Stop
    }
else
    {
        Write-Host ("No valid authentication types specified - please use AzureAd or ADFS") -ForegroundColor Red -ErrorAction Stop
    }

###  PIR IMAGE VERIFCATION & UPLOAD ###
# Import the Azure Stack Compute Modules
Write-Host "Importing Azure Stack Compute Module"
Start-Sleep -Seconds 5
Set-Location C:\AzureStack-Tools-master
Import-Module .\ComputeAdmin\AzureStack.ComputeAdmin.psm1
Write-Host "Azure Stack Compute module imported successfully"
Start-Sleep -Seconds 3

# Query existing Platform Image Repository for Compatible Ubuntu Server Image
# If existing image is in place, use the existing image, otherwise, download from Ubuntu and upload into the Platform Image Repository

Write-Host "Checking to see if an Ubuntu Server 16.04-LTS VM Image is present in your Azure Stack Platform Image Repository"
Start-Sleep -Seconds 5

$platformImage = Get-AzureRmVMImage -Location "local" -PublisherName Canonical -Offer UbuntuServer -Skus "16.04-LTS" -ErrorAction SilentlyContinue
$platformImageTable = $platformImage | Sort-Object Version
$platformImageTableTop1 = $platformImageTable | Select-Object -Last 1

if ($platformImage -ne $null -and $platformImage.StatusCode -eq "OK")
    {
        Write-Host "There appears to be at least 1 suitable Ubuntu Server 16.04-LTS VM image within your Platform Image Repository `nwhich we will use for the DevOps Hydration Toolkit. Here are the details:" -ForegroundColor Green
        Start-Sleep -Seconds 1
        Write-Output $platformImageTable | Format-Table location, Offer, PublisherName, Skus, Version
        Start-Sleep -Seconds 1
        Write-Host "The DevOps Hydration Toolkit will automatically use the latest Ubuntu Server 16.04-LTS version from this list, which will be:"
        Write-Output $platformImageTableTop1 | Format-Table location, Offer, PublisherName, Skus, Version
        Start-Sleep -Seconds 1
        Write-Host "The DevOps Hydration Toolkit is now ready to begin uploading packages for DevOps tools to the Azure Stack Marketplace"
        Start-Sleep -Seconds 5
        Write-Host "Select a folder to store your Azure Stack Marketplace packages"
        Start-Sleep -Seconds 5
    }
else
    {
        Write-Host "No existing suitable Ubuntu Server 1604-LTS VM image exists." -ForegroundColor Red
        Start-Sleep -Seconds 2
        Write-Host "The Ubuntu Server VM Image in the Azure Stack Platform Image Repository must have the following properties:"
        Write-Host "Publisher Name = Canonical"
        Write-Host "Offer = UbuntuServer"
        Write-Host "SKU = 16.04-LTS"
        Start-Sleep -Seconds 2
        Write-Host "Unfortunately, no image was found with these properties. You therefore have 3 options to add an image to your Platform Image Repository`n"
        Start-Sleep -Seconds 3

        [int]$downloadChoice = 0
        while ( $downloadChoice -lt 1 -or $downloadChoice -gt 3 ){
        Write-Host "1. Download manually from Canonical and upload into Azure Stack using the Azure Stack documentation" -ForegroundColor Yellow
        Write-Host "2. Allow the DevOps Hydration Toolkit to automatically download a suitable image from Canonical and upload into your Azure Stack" -ForegroundColor Yellow
        Write-Host "3. Enable Azure Marketplace Syndication and download through the Syndication service`n" -ForegroundColor Yellow
        [Int]$downloadChoice = Read-Host "Please select an option: 1, 2 or 3"
        }
        if ($downloadChoice -eq 1) {
            Write-Host "You have chosen to download manually from Canonical and upload manually into Azure Stack"
            Start-Sleep -Seconds 1
            Write-Host "Please refer to the Azure Stack documentation on how to proceed, then rerun this script."
            Start-Sleep -Seconds 2
            Write-Host "Opening documentation page..."
            Start-Sleep -Seconds 2
            Start-Process 'https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-linux'
            Set-Location $ScriptLocation
            Write-Host "Exiting Script..."
            Start-Sleep -Seconds 2
            return
        }
        elseif ($downloadChoice -eq 2) {
            Write-Host "You have chosen to allow the DevOps Hydration Toolkit to download an Ubuntu Server image for you"
            Write-Host "Downloading Ubuntu Server 16.04-LTS - Select a Download Folder"
            Start-Sleep -Seconds 3
        
            # Execute the Find-Folders function to obtain a desired storage location from the user
            $SetFilePath = Select-Folder
            if (!$SetFilePath) {
                    Write-Host "No valid folder path was selected. Please select a valid folder to store the VHD"
                    $SetFilePath = Select-Folder
                    if (!$SetFilePath)
                        {
                            Write-Host "No valid folder path was selected again. Exiting process..." -ErrorAction Stop
                            Set-Location $ScriptLocation
                            return
                        }
            }
            else
                {
                    # Check if DevOps Hydration folder needs creating or not
                    Write-Host "Checking to see if the DevOps Hydration folder exists"
                    Start-Sleep -Seconds 5
                    if (-not (test-path "$SetFilePath\DevOpsHydration"))
                    {
                        # Create the DevOps Hydration folder.
                        Write-Host "DevOps Hydration folder doesn't exist, creating it"
                        mkdir "$SetFilePath\DevOpsHydration" -Force 
                        $UpdatedFilePath = "$SetFilePath\DevOpsHydration"
                    }
                    elseif (test-path "$SetFilePath\DevOpsHydration")
                    {
                        # No need to create the DevOps Hydration folder as it already exists. Set $UpdatedFilePath to the new location.
                        Write-Host "DevOps Hydration folder exists, no need to create it"
                        Start-Sleep -Seconds 1
                        Write-Host "DevOps Hydration folder is within $SetFilePath"
                        Start-Sleep -Seconds 1
                        $UpdatedFilePath = Set-Location -Path "$SetFilePath\DevOpsHydration" -PassThru
                        Write-Host "DevOps Hydration folder full path is $UpdatedFilePath"
                    }
                    # Check if VHD exists that matches previously extracted VHD in the DevOps Hydration folder.
                    Write-Host "Checking to see if the Ubuntu Server VHD already exists in DevOps Hydration folder"
                    Start-Sleep -Seconds 5
                    if (Test-Path "$UpdatedFilePath\UbuntuServer.vhd")
                    {
                        # If VHD exists, update the $UbuntuServerVHD variable with the correct name and path.
                        Write-Host "Located Ubuntu Server VHD in this folder. No need to download again..."
                        Start-Sleep -Seconds 3
                        $UbuntuServerVHD = Get-ChildItem -Path "$UpdatedFilePath\UbuntuServer.vhd"
                        Start-Sleep -Seconds 3
                        Write-Host "Ubuntu Server VHD located at $UbuntuServerVHD"
                    }
                    elseif (Test-Path "$UpdatedFilePath\UbuntuServer.zip")
                    {
                        # If VHD exists, update the $UbuntuServerVHD variable with the correct name and path.
                        Write-Host "Cannot find a previously extracted Ubuntu Server VHD with name UbuntuServer.vhd"
                        Write-Host "Checking to see if the Ubuntu Server ZIP already exists in DevOps Hydration folder"
                        Start-Sleep -Seconds 3
                        $UbuntuServerZIP = Get-ChildItem -Path "$UpdatedFilePath\UbuntuServer.zip"
                        Start-Sleep -Seconds 3
                        Write-Host "Ubuntu Server ZIP located at $UbuntuServerZIP"
                        Expand-Archive -Path "$UpdatedFilePath\UbuntuServer.zip" -DestinationPath $UpdatedFilePath -Force -ErrorAction Stop
                        $UbuntuServerVHD = Get-ChildItem -Path "$UpdatedFilePath" -Filter *.vhd | Rename-Item -NewName UbuntuServer.vhd -PassThru -Force -ErrorAction Stop
                    }
                    else
                    {
                        # No existing Ubuntu Server VHD or Zip exists that matches the name (i.e. that has previously been extracted and renamed) so a fresh one will be
                        # downloaded, extracted and the variable $UbuntuServerVHD updated accordingly.
                        Write-Host "Cannot find a previously extracted Ubuntu Server download"
                        Write-Host "Begin download of correct Ubuntu Server ZIP and extraction of VHD"
                        Start-Sleep -Seconds 5
                        Invoke-Webrequest http://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip -OutFile "$UpdatedFilePath\UbuntuServer.zip" -ErrorAction Stop
                        Expand-Archive -Path "$UpdatedFilePath\UbuntuServer.zip" -DestinationPath $UpdatedFilePath -Force -ErrorAction Stop
                        $UbuntuServerVHD = Get-ChildItem -Path "$UpdatedFilePath" -Filter *.vhd | Rename-Item -NewName UbuntuServer.vhd -PassThru -Force -ErrorAction Stop
                    }
                # Upload the image to the Azure Stack Platform Image Repository

                Write-Host "Extraction Complete. Beginning upload of VHD to Platform Image Repository"
                Start-Sleep -Seconds 5
                Add-AzsVMImage -publisher Canonical -offer UbuntuServer -sku 16.04-LTS -version 1.0.0 -osType Linux -osDiskLocalPath "$UbuntuServerVHD" -ErrorAction Stop
                Write-Host "Ubuntu Server image successfully uploaded to the Platform Image Repository."
                Write-Host "Now ready to begin uploading packages to the Azure Stack Marketplace"
                Start-Sleep -Seconds 5
            }
        }
        elseif ($downloadChoice -eq 3) {
            Write-Host "You have chosen to download a syndicated VM image from the Azure Marketplace, into Azure Stack"
            Start-Sleep -Seconds 1
            Write-Host "Syndication PowerShell modules are currently not publicly available"
            Start-Sleep -Seconds 1
            Write-Host "You will need to manually register your Azure Stack, then download the Ubuntu Server 16.04-LTS VM image"
            Start-Sleep -Seconds 1
            Write-Host "Once completed, you can rerun this script and it will detect your Ubuntu Server 16.04-LTS VM image. Opening documentation page..."
            Start-Sleep -Seconds 10
            Start-Process 'https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-register'
            Set-Location $ScriptLocation
            Write-Host "Exiting Script..."
            Start-Sleep -Seconds 2
            # Import the Syndication Modules when available
            # Check if Syndication is enabled and if not, enable it
            # Trigger the download of the UbuntuServer image
            # Wait for completion 
            return
        }
        else {
            Set-Location $ScriptLocation
            return 
        }
    }

### DOWNLOAD THE PACKAGES FROM GITHUB ###
# If the variable $UpdatedFilePath hasn't been defined (which it won't unless the DevOps Hydration Toolkit was used to download the image from Canonical)
# then we will ask for the folder here, and use it for storing the packages going forward.
if (!$UpdatedFilePath) {
    $SetFilePath = Select-Folder
            if (!$SetFilePath) {
                    Write-Host "No valid folder path was selected. Please select a valid folder to store the Azure Stack marketplace packages"
                    $SetFilePath = Select-Folder
                    if (!$SetFilePath) {
                            Write-Host "No valid folder path was selected again. Exiting process..." -ErrorAction Stop
                            Set-Location $ScriptLocation
                            return
                        }
            }
            else {
                    # Check if DevOps Hydration folder needs creating or not
                    Write-Host "Checking to see if the DevOps Hydration folder exists"
                    Start-Sleep -Seconds 5
                    if (-not (test-path "$SetFilePath\DevOpsHydration"))
                    {
                        # Create the DevOps Hydration folder.
                        Write-Host "DevOps Hydration folder doesn't exist, creating it"
                        New-Item -ItemType Directory "$SetFilePath\DevOpsHydration" -Force 
                        $UpdatedFilePath = "$SetFilePath\DevOpsHydration"
                    }
                    elseif (test-path "$SetFilePath\DevOpsHydration")
                    {
                        # No need to create the DevOps Hydration folder as it already exists. Set $UpdatedFilePath to the new location.
                        Write-Host "DevOps Hydration folder exists, no need to create it"
                        Start-Sleep -Seconds 1
                        Write-Host "DevOps Hydration folder is within $SetFilePath"
                        Start-Sleep -Seconds 1
                        $UpdatedFilePath = Set-Location -Path "$SetFilePath\DevOpsHydration" -PassThru
                        Write-Host "DevOps Hydration folder full path is $UpdatedFilePath"
                    }
            }
}

Write-Host "Checking DevOps Hydration folder for existing DevOpsTools.zip file from previous download"
Start-Sleep -Seconds 5
if (Test-Path "$UpdatedFilePath\DevOpsTools.zip")
    {
        # If zip exists, remove it, and re-download to ensure you have the latest version.
        Write-Host "Located DevOpsTools.zip - removing and re-downloading to ensure you have the newest version"
        Remove-Item -Path "$UpdatedFilePath\DevOpsTools.zip" -Force
        Remove-Item -Path "$UpdatedFilePath\azurestack-master" -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "$UpdatedFilePath\DevOpsTools" -Recurse -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Invoke-Webrequest https://github.com/mattmcspirit/azurestack/archive/master.zip -OutFile "$UpdatedFilePath\DevOpsTools.zip" -ErrorAction Stop
    }
else
    {
        Write-Host "No DevOpsTools.zip file exists in the DevOps Hydration - downloading now..."
        Remove-Item -Path "$UpdatedFilePath\azurestack-master" -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "$UpdatedFilePath\DevOpsTools" -Recurse -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Invoke-Webrequest https://github.com/mattmcspirit/azurestack/archive/master.zip -OutFile "$UpdatedFilePath\DevOpsTools.zip" -ErrorAction Stop
    }
Write-Host "Extracting DevOpsTools.zip"
Expand-Archive -Path "$UpdatedFilePath\DevOpsTools.zip" -DestinationPath $UpdatedFilePath -Force -ErrorAction Stop
Rename-Item -Path "$UpdatedFilePath\azurestack-master" -NewName DevOpsTools -Force
Write-Host "DevOps Tools are now extracted.  Cleaning up the zip file..."
Remove-Item -Path "$UpdatedFilePath\DevOpsTools.zip" -Force
Start-Sleep -Seconds 3
Write-Host "Cleaned up.  Searching for Packages..."
Start-Sleep -Seconds 3
Write-Host "Returning user to original folder that the script was executed from"
Start-Sleep -Seconds 3
Set-Location $ScriptLocation
