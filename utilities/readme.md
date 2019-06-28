# Azure Stack - Utilities
In these subfolders, you'll find a number of useful PowerShell-based utilities that can streamline certain tasks on Azure Stack systems.

## Marketplace Updater
**Main Use:** Allows an automated updating of existing Azure Stack Marketplace Items.

The script will automate the updating of Marketplace items (today, extensions only) that currently exist within your Azure Stack environment.
It will scan your current downloads and if it locates a newer version (based on the display name), it will download the newer version
and optionally, delete the old version(s).

```powershell
.\MarketplaceUpdater.ps1 -armEndpoint "https://adminmanagement.local.azurestack.external" `
-tenant "contoso.onmicrosoft.com" -authType "AzureAd" `
-activationRG "azurestack-activation" -deleteOldVersions
```

This example will attempt to connect to the endpoint https://adminmanagement.local.azurestack.external,
authenticate you (prompts for login credentials) via your chosen auth method (AzureAd or ADFS) and if successful, will begin the
update process. In this example, the script will also clean up old versions of extensions. You can locate the activation
resource group in the administration portal within your registered Azure Stack system. The -deleteOldVersions switch is optional.

## Ubuntu Tester
**Main Use:** Test a variety of Ubuntu Server 14.04/16.04/18.04 images for use on Azure Stack.

The script will automate the testing of Ubuntu Server images by iterating through the images listed in a CSV file. The CSV should be
populated with a SKU: 14.04, 16.04 or 18.04 and a corresponding build, for example 20190308
(from here: https://cloud-images.ubuntu.com/releases/)

See the current example CSV file here: https://github.com/mattmcspirit/azurestack/blob/master/deployment/misc/UbuntuTests.csv 

```powershell
.\UbuntuTester.ps1 -FilePath "C:\users\AzureStackAdmin\Desktop\UbuntuTests.csv" `
-imagePath "C:\ClusterStorage\Volume1\Images\UbuntuServer"
```

Ensure that the -imagePath exists before running the deployment.

This example will import all listed server images from a CSV File, download the images from Ubuntu's Cloud Images repo, unzip, push into
the PIR, and then attempt to deploy a VM from that image. Should it succeed, the image will be recommended for use. Should it fail, it will
not be recommended. A txt document will list the images that have been tested.

## Memory Usage
**Main Use:** For a particular user, gather total memory usage associated with deployed VMs.

If you'd like to understand the total VM memory consumption associated with your user account, you can use this script to query
your Azure Stack system. It can only be used to target the Administration OR tenant space, and not both simultaneously. It will query and return
the total memory consumed across both native virtual machines, and virtual machines deployed as part of a VM Scale Set (VMSS)

.NOTES
File Name : MemoryUsage.ps1
Author    : Matt McSpirit
Version   : 1.0
Date      : 28-June-2019
Update    : 28-June-2019
Requires  : PowerShell Version 5.0 or above
Module    : Tested with AzureRM 2.5.0 and Azure Stack 1.7.2 already installed

```powershell
.\MemoryUsage.ps1 -authType AzureAd -tenant "contoso.onmicrosoft.com" `
-armEndpoint "https://adminmanagement.local.azurestack.external"

.\MemoryUsage.ps1 -authType AzureAd -tenant "contoso.onmicrosoft.com" `
-armEndpoint "https://management.local.azurestack.external"
```

These examples will use Azure AD as the authentication model, and the same tenant. The difference here is, that the first example is
targeting the administration space, and the second is targeting the tenant space.
