# Azure Stack - Utilities
In these subfolders, you'll find a number of useful PowerShell-based utilities that can streamline certain tasks on Azure Stack systems.

## Marketplace Updater
Main Use: Allows an automated updating of existing Azure Stack Marketplace Items.

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
Main Use: Test a variety of Ubuntu Server 14.04/16.04/18.04 images for use on Azure Stack.

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
the PIR, and then attempt to deploy a VM from that image. Should it succeed, the image will be recommened for use. Should it fail, it will
not be recommended. A txt document will list the images that have been tested.
