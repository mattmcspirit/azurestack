<#

.SYNOPSIS
Allows an automated updating of existing Azure Stack Marketplace Items.

.DESCRIPTION
The script will automate the updating of Marketplace items that currently exist within your Azure Stack environment.
It will scan your current downloads and if it locates a newer version (based on the display name), it will download the newer version
and optionally, delete the old version(s)

.NOTES
File Name : MarketplaceUpdater.ps1
Author    : Matt McSpirit
Version   : 1.0
Date      : 06-June-2019
Update    : 06-June-2019
Requires  : PowerShell Version 5.0 or above
Module    : Tested with AzureRM 2.5.0 and Azure Stack 1.7.2 already installed

.EXAMPLE
.\MarketplaceUpdater.ps1 -armEndpoint "https://adminmanagement.local.azurestack.external" -tenant "contoso.onmicrosoft.com" `
-authType "AzureAd" -activationRG "azurestack-activation" -deleteOldVersions

This example will attempt to connect to the endpoint https://adminmanagement.local.azurestack.external,
authenticate you (prompts for login credentials) via your chosen auth method (AzureAd or ADFS) and if successful, will begin the
update process. In this example, the script will also clean up old versions of extensions. You can locate the activation
resource group in the administration portal within your registered Azure Stack system. The -deleteOldVersions switch is optional. 
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("AzureAd", "ADFS")]
    [String] $authType,

    [Parameter(Mandatory = $true)]
    [String] $tenant,

    [Parameter(Mandatory = $true)]
    [String] $armEndpoint,

    [Parameter(Mandatory = $true)]
    [String] $activationRG = "azurestack-activation",

    [switch] $deleteOldVersions
)

$Global:VerbosePreference = "SilentlyContinue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

Write-Host "Beginning login process into your Azure Stack system"
Write-Host "Selected Active Directory authentication type is $authType"
Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$armEndpoint"
Write-Host "Using the following Azure Stack ARM Endpoint: $armEndpoint"
Write-Host "Obtaining tenant name"
$AuthEndpoint = (Get-AzureRmEnvironment -Name "AzureStackAdmin").ActiveDirectoryAuthority.TrimEnd('/')

if ($authType.ToString() -like "AzureAd") {
    $tenantId = (Invoke-Restmethod "$($AuthEndpoint)/$($tenant)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
}
elseif ($authType.ToString() -like "ADFS") {
    $tenantId = (invoke-restmethod -Verbose:$false "$($AuthEndpoint)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
}

# After signing in to your environment, Azure Stack cmdlets
# can be easily targeted at your Azure Stack instance.
Write-Host "Logging into Azure Stack. Triggering credential pop-up."
Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantId

Write-Host "Getting the current Azure Stack activation info"
$activationName = (Get-AzsAzureBridgeActivation -ResourceGroupName $activationRG).Name
Write-Host "Getting current Azure Stack Marketplace downloads"
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