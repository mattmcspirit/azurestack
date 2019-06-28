<#

.SYNOPSIS
Allows an automated updating of existing Azure Stack Marketplace Items.

.DESCRIPTION
The script will automate the testing of Ubuntu Server images by iterating through the images listed in the CSV file. The CSV should be
populated with a SKU: 14.04, 16.04 or 18.04 and a corresponding build, for example 20190308
(from here: https://cloud-images.ubuntu.com/releases/)

See the current example CSV file here: https://github.com/mattmcspirit/azurestack/blob/master/deployment/misc/UbuntuTests.csv 

.NOTES
File Name : UbuntuTester.ps1
Author    : Matt McSpirit
Version   : 1.0
Date      : 03-March-2019
Update    : 03-March-2019
Requires  : PowerShell Version 5.0 or above
Module    : Tested with AzureRM 2.4.0 and Azure Stack 1.7.0 already installed
Product   : Requires AzCopy for Azure Stack installed (https://docs.microsoft.com/en-us/azure/azure-stack/user/azure-stack-storage-transfer#azcopy)

.EXAMPLE
.\UbuntuTester.ps1 -FilePath "C:\users\AzureStackAdmin\Desktop\UbuntuTests.csv" -imagePath "C:\ClusterStorage\Volume1\Images\UbuntuServer"

Ensure that the -imagePath exists before running the deployment.

This example will import all listed server images from a CSV File, download the images from Ubuntu's Cloud Images repo, unzip, push into
the PIR, and then attempt to deploy a VM from that image. Should it succeed, the image will be recommened for use. Should it fail, it will
not be recommended. A txt document will list the images that have been tested.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $armEndpoint,

    [Parameter(Mandatory = $true)]
    [String] $tenant,

    [switch] $deleteOldVersions
)

$Global:VerbosePreference = "SilentlyContinue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

# Register an Azure Resource Manager environment that targets your Azure Stack instance. Get your Azure Resource Manager endpoint value from your service provider.
Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$armEndpoint"
# Set your tenant name
$AuthEndpoint = (Get-AzureRmEnvironment -Name "AzureStackAdmin").ActiveDirectoryAuthority.TrimEnd('/')
$TenantId = (Invoke-Restmethod "$($AuthEndpoint)/$($tenant)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]

# After signing in to your environment, Azure Stack cmdlets
# can be easily targeted at your Azure Stack instance.
Write-Host "Logging into Azure Stack"
Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantId

$activationName = "default"
$activationRG = "azurestack-activation"
$currentDownloads = Get-AzsAzureBridgeDownloadedProduct -ActivationName $activationName -ResourceGroupName $activationRG -ErrorAction SilentlyContinue | Where-Object { $_.ProductKind -eq "virtualMachineExtension" }

foreach ($download in $currentDownloads) {
    Write-Host "Current version of $($download.DisplayName) is $($download.ProductProperties.Version)"
    Write-Host "Checking for a newer version in the Azure Stack Marketplace..."
    $newerVersion = Get-AzsAzureBridgeProduct -ActivationName $activationName -ResourceGroupName $activationRG -ErrorAction SilentlyContinue | `
        Where-Object { ($_.ProductKind -eq "virtualMachineExtension") -and ($_.DisplayName -like "$($download.DisplayName)") -and ($_.ProductProperties.Version -gt "$($download.ProductProperties.Version)" ) }
    if ($newerVersion) {
        Write-Host "Newer version of $($newerVersion.DisplayName) has been located. New version is $($newerVersion.ProductProperties.Version)"
        Write-Host "Starting download of the newer version of $($newerVersion.DisplayName) from the Azure Stack Marketplace" -ForegroundColor Green
        $newerVersionName = (($newerVersion).Name) -replace "default/", ""
        Invoke-AzsAzureBridgeProductDownload -ActivationName $activationName -Name $newerVersionName -ResourceGroupName $activationRG -Force -Confirm:$false -ErrorAction Stop
        if ($deleteOldVersions) {
            Write-Host "Removing old version from the Azure Stack Marketplace`n" -ForegroundColor Green
            $oldVersionName = (($download).Name) -replace "default/", ""
            Remove-AzsAzureBridgeDownloadedProduct -ActivationName $activationName -Name $oldVersionName -ResourceGroupName $activationRG -Force -Confirm:$false -ErrorAction Stop
        }
    }
    else {
        Write-Host "No new version of $($download.DisplayName) found.`n" -ForegroundColor Yellow
    }
}

$getDownloads = (Get-AzsAzureBridgeDownloadedProduct -ActivationName $activationName -ResourceGroupName $activationRG -ErrorAction SilentlyContinue | Where-Object { ($_.ProductKind -eq "virtualMachineExtension") })
Write-Host "Your Azure Stack gallery now has the following VM Extensions for enhancing your deployments:`r`n"
foreach ($download in $getDownloads) {
    Write-Host "$($download.DisplayName) | Version: $($download.ProductProperties.Version)"
}