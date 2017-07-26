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
function Find-Folders {
    [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $browse = New-Object System.Windows.Forms.FolderBrowserDialog
    $browse.SelectedPath = "C:\"
    $browse.ShowNewFolderButton = $True
    $browse.Description = "Select a directory to store your downloads - you need at least 32GB of available space to store the downladed Ubuntu Server zip, and the extracted VHD. You must also have administrative permission to store files in this location"

    $loop = $true
    while($loop)
    {
        if ($browse.ShowDialog() -eq "OK")
        {
        $loop = $false
		
		#Insert your script here
		
        } else
        {
            $res = [System.Windows.Forms.MessageBox]::Show("You clicked Cancel. Would you like to try again or exit?", "Select a location", [System.Windows.Forms.MessageBoxButtons]::RetryCancel)
            if($res -eq "Cancel")
            {
                #Ends script
                return
            }
        }
    }
    $browse.SelectedPath
    $browse.Dispose()
}

$VerbosePreference = "Continue"
$ErrorActionPreference = 'Stop'

##############################################################################################################################################################
##############################################################################################################################################################

### DOWNLOAD & EXTRACT TOOLS ###
# Change directory to the root directory 
Set-Location C:\

# Download the tools archive
Write-Verbose -Message "Downloading Azure Stack Tools"
invoke-webrequest https://github.com/Azure/AzureStack-Tools/archive/master.zip -OutFile master.zip -ErrorAction Stop -Verbose

# Expand the downloaded files
Write-Verbose -Message "Expanding Archive"
expand-archive master.zip -DestinationPath . -Force
Remove-Item master.zip -Verbose -ErrorAction Stop

# Change to the tools directory
Write-Verbose -Message "Changing Directory"
Set-Location C:\AzureStack-Tools-master

# Set the execution policy and import the Azure Stack Connect Module
Write-Verbose -Message "Setting the execution policy and importing the Azure Stack Connect Module"
Set-ExecutionPolicy RemoteSigned -Confirm:$false -Force
Import-Module .\Connect\AzureStack.Connect.psm1
Disable-AzureRmDataCollection

### CONNECT TO AZURE STACK ###
# Register an AzureRM environment that targets your administrative Azure Stack instance
Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "https://adminmanagement.local.azurestack.external" -ErrorAction Stop -Verbose

# Add GraphEndpointResourceId value for Azure AD or ADFS and obtain Tenant ID, then login to Azure Stack
if ($authenticationType.ToString() -like "AzureAd")
    {
        Write-Verbose -Message ("Azure Active Directory selected by Administrator")
        Set-AzureRmEnvironment -Name "AzureStackAdmin" -GraphAudience "https://graph.windows.net/" -ErrorAction Stop
        Write-Verbose -Message ("Setting GraphEndpointResourceId value for Azure AD")
        Write-Verbose -Message ("Getting Tenant ID for Login to Azure Stack")
        $TenantID = Get-AzsDirectoryTenantId -AADTenantName $azureDirectoryTenantName -EnvironmentName "AzureStackAdmin" -Verbose
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -ErrorAction Stop -Verbose
    }
Elseif ($authenticationType.ToString() -like "ADFS")
    {
        Write-Verbose -Message ("Active Directory Federation Services selected by Administrator")
        Set-AzureRmEnvironment -Name "AzureStackAdmin" -GraphAudience "https://graph.local.azurestack.external/" -EnableAdfsAuthentication:$true
        Write-Verbose -Message ("Setting GraphEndpointResourceId value for ADFS")
        Write-Verbose -Message ("Getting Tenant ID for Login to Azure Stack")
        $TenantID = Get-AzsDirectoryTenantId -ADFS -EnvironmentName "AzureStackAdmin" -Verbose
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -ErrorAction Stop -Verbose
    }
Else
    {
        Write-Verbose -Message ("No valid authentication types specified - please use AzureAd or ADFS") -ErrorAction Stop
    }

### UPLOAD AN IMAGE TO THE PIR ###
# Import the Azure Stack Compute Module
Write-Verbose -Message "Importing Azure Stack Compute Module"
Start-Sleep -Seconds 5
Set-Location C:\AzureStack-Tools-master
Import-Module .\ComputeAdmin\AzureStack.ComputeAdmin.psm1

# Query existing Platform Image Repository for Compatible Ubuntu Server Image
# If existing image is in place, use the existing image, otherwise, download from Ubuntu and upload into the Platform Image Repository

$publisher = "Canonical"
$offer = "UbuntuServer"
$sku = "16.04-LTS"
$version = "1.0.0"
$location = "local"
$platformImage = Get-AzsVMImage -publisher $publisher -offer $offer -sku $sku -version $version -location $location

Write-Verbose -Message "Checking to see if an Ubuntu Server VM Image is present in your Azure Stack Platform Image Repository"
Start-Sleep -Seconds 5

if ($platformImage.Properties.ProvisioningState -eq 'Succeeded')
    {
        Write-Verbose -Message ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" already present in your Azure Stack.' -f $publisher, $offer, $sku, $version)
    }
elseif ($platformImage.Properties.ProvisioningState -eq 'Failed')
    {
        # If a previous attempt has been made to upload this image to the PIR, but was unsuccessful, this will clean up the image from the PIR.
        Write-Verbose -Message ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" seems to be present in your Azure Stack, but the upload was unsuccessful. Cleaning up...' -f $publisher, $offer, $sku, $version)
        Start-Sleep -Seconds 5
        Remove-AzsVMImage -publisher $publisher -offer $offer -sku $sku -version $version -Force
    }
elseif ($platformImage.Properties.ProvisioningState -eq 'Canceled')
    {
        # If a previous attempt has been made to upload this image to the PIR, but was unsuccessful, this will clean up the image from the PIR.
        Write-Verbose -Message ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" seems to be present in your Azure Stack, but the upload was canceled. Cleaning up...' -f $publisher, $offer, $sku, $version)
        Start-Sleep -Seconds 5
        Remove-AzsVMImage -publisher $publisher -offer $offer -sku $sku -version $version -Force
    }
else
    {
        Write-Verbose -Message ("No existing Ubuntu Server VM image exists. Downloading Ubuntu Server 16.04-LTS with Azure Agent 2.2.9 - Select a Download Folder")
        # Execute the Find-Folders function to obtain a desired storage location from the user
        $SetFilePath = Find-Folders
        if (!$SetFilePath)
            {
                Write-Verbose -Message "No valid folder path was selected. Please select a valid folder to store the VHD"
                $SetFilePath = Find-Folders
                if (!$SetFilePath)
                    {
                        Write-Verbose -Message "No valid folder path was selected again. Exiting process" -ErrorAction Stop
                    }
            }
        else
            {
                # Check if DevOps Hydration folder needs creating or not
                Write-Verbose -Message "Checking to see if the DevOps Hydration folder exists"
                Start-Sleep -Seconds 5
                if (-not (test-path "$SetFilePath\DevOpsHydration"))
                {
                    # Create the DevOps Hydration folder.
                    Write-Verbose -Message "DevOps Hydration folder doesn't exist, creating it"
                    mkdir "$SetFilePath\DevOpsHydration" -Force -Verbose
                    $UpdatedFilePath = "$SetFilePath\DevOpsHydration"
                }
                elseif (test-path "$SetFilePath\DevOpsHydration")
                {
                    # No need to create the DevOps Hydration folder as it already exists. Set $UpdatedFilePath to the new location.
                    Write-Verbose -Message "DevOps Hydration folder exists, no need to create it"
                    Write-Verbose -Message "DevOps Hydration folder is within $SetFilePath"
                    $UpdatedFilePath = Set-Location -Path "$SetFilePath\DevOpsHydration" -PassThru
                    Write-Verbose -Message "DevOps Hydration folder full path is $UpdatedFilePath"
                }
                # Check if VHD exists that matches previously extracted VHD in the DevOps Hydration folder.
                Write-Verbose -Message "Checking to see if the Ubuntu Server VHD already exists in DevOps Hydration folder"
                Start-Sleep -Seconds 5
                if (Test-Path "$UpdatedFilePath\UbuntuServer20170516.vhd")
                {
                    # If VHD exists, update the $UbuntuServerVHD variable with the correct name and path.
                    Write-Verbose -Message "Located Ubuntu Server VHD in this folder. No need to download again..."
                    Start-Sleep -Seconds 3
                    $UbuntuServerVHD = Get-ChildItem -Path "$UpdatedFilePath\UbuntuServer20170516.vhd"
                    Start-Sleep -Seconds 3
                    Write-Verbose -Message "Ubuntu Server VHD located at $UbuntuServerVHD"
                }
                else
                {
                    # No existing Ubuntu Server VHD exists that matches the name (i.e. that has previously been extracted and renamed) so a fresh one will be
                    # downloaded, extracted and the variable $UbuntuServerVHD updated accordingly.
                    Write-Verbose -Message "Cannot find a previously extracted Ubuntu Server VHD with name UbuntuServer20170516.vhd"
                    Write-Verbose -Message "Begin download of correct Ubuntu Server VHD"
                    Start-Sleep -Seconds 5
                    Invoke-Webrequest https://partner-images.canonical.com/azure/releases/xenial/azure-20170516-vhd.zip -OutFile "$UpdatedFilePath\UbuntuServer.zip" -ErrorAction Stop
                    Expand-Archive -Path "$UpdatedFilePath\UbuntuServer.zip" -DestinationPath $UpdatedFilePath -Force -ErrorAction Stop
                    $UbuntuServerVHD = Get-ChildItem -Path "$UpdatedFilePath" -Filter *.vhd -Verbose | Rename-Item -NewName UbuntuServer20170516.vhd -PassThru -Force -ErrorAction Stop
                }
            # Upload the image to the Azure Stack Platform Image Repository
            Add-AzsVMImage -publisher $publisher -offer $offer -sku $sku -version $version -osType Linux -osDiskLocalPath "$UbuntuServerVHD" -createGalleryItem:$false -ErrorAction Stop -Verbose
            Write-Verbose -Message "Ubuntu Server image successfully uploaded to the Platform Image Repository."
            Write-Verbose -Message "Now ready to begin uploading packages to the Azure Stack Marketplace"
            Start-Sleep -Seconds 5
        }
    }

### DOWNLOAD THE PACKAGES FROM GITHUB ###
# Download the tools archive
Write-Verbose -Message "Checking DevOps Hydration folder for existing DevOpsTools.zip file from previous download"
Start-Sleep -Seconds 5
if (Test-Path "$UpdatedFilePath\DevOpsTools.zip")
    {
        # If zip exists, remove it, and re-download to ensure you have the latest version.
        Write-Verbose -Message "Located DevOpsTools.zip - removing and re-downloading to ensure you have the newest version"
        Remove-Item -Path "$UpdatedFilePath\DevOpsTools.zip" -Force
        Start-Sleep -Seconds 3
        Invoke-Webrequest https://github.com/mattmcspirit/azurestack/archive/master.zip -OutFile "$UpdatedFilePath\DevOpsTools.zip" -ErrorAction Stop -Verbose
    }
else
    {
        Write-Verbose -Message "No DevOpsTools.zip file exists in the DevOps Hydration - downloading now..."
        Start-Sleep -Seconds 3
        Invoke-Webrequest https://github.com/mattmcspirit/azurestack/archive/master.zip -OutFile "$UpdatedFilePath\DevOpsTools.zip" -ErrorAction Stop -Verbose
    }
Write-Verbose -Message "Extracting DevOpsTools.zip"
Expand-Archive -Path "$UpdatedFilePath\DevOpsTools.zip" -DestinationPath $UpdatedFilePath -Force -ErrorAction Stop -Verbose
RenameItem -Path "$UpdatedFilePath\azurestack-master" -NewName DevOpsTools
Write-Verbose -Message "DevOps Tools are now extracted.  Searching for packages..."
Start-Sleep -Seconds 3