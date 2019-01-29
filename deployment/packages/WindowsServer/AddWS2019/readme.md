Adding Windows Server 2019 Eval Images to Azure Stack
==============
There is not currently a Windows Server 2019 image available for deployment within an Azure Stack environment. For those of you who wish to add a Windows Server 2019 Evaluation image, for either Server Core, Server with Desktop Experience, or both, the following guide will help you do add the images and corresponding gallery items to your Azure Stack system.

Requirements
-----------
Before you run the scripts, you will need the following:

* A **Windows Server 2019 Evaluation ISO** - this can be downloaded from https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019.
* A machine with access to your Azure Stack environment. If this is an ASDK, you can run these scripts on the ASDK host. If this is an integrated system, you will want to use a machine that can access the integrated system over a fast network, as the upload process from your machine to the integrated system involves a **large transfer of data**.
* The machine you use for running the scripts, and uploading the images, needs to have **the latest Azure Stack PowerShell modules** installed. If you configured your ASDK with my ASDK Configurator, you will already have the appropriate PowerShell modules installed. If you did not use my ASDK Configurator, follow guidance here: https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-powershell-install.
* The machine you use for running the script **must have enough storage space**, locally, to create a VHD from the ISO. This means, if you choose to create a 50GB Windows Server 2019 VHD, you will need around ~55-60GB (which includes the space for the ISO file, and any overhead).

Step by Step guidance
-----------
Open a PowerShell ISE window (as administrator) and run the following commands:

```powershell
# Create directory on a chosen drive.
New-Item -ItemType Directory -Force -Path "D:\WS2019IMAGES"
Set-Location "D:\WS2019IMAGES"

# Download the scripts.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-Webrequest https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/packages/WindowsServer/AddWS2019/WS2019Images.ps1 `
-UseBasicParsing -OutFile WS2019Images.ps1
Invoke-Webrequest https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/packages/WindowsServer/AddWS2019/WS2019Updates.ps1 `
-UseBasicParsing -OutFile WS2019Updates.ps1
```

With the 2 script files downloaded, you **first run the WS2019Updates** script, which will mount your ISO file, check the build, then go to the internet and download a select set of updates including Servicing Stack updates, Cumulative Updates and .NET updates.

To run the script, simply provide the folder you would like to download the updates into, and the path to your newly downloaded Windows Server 2019 ISO file.

```powershell
.\WS2019Updates.ps1 -UpdatePath "D:\WS2019IMAGES" -ISOPath "D:\WS2019IMAGES\WS2019EVAL.iso"
```

This will take a few minutes to run, depending on your connection speed.  Once complete, you should have a number of updates downloaded, including one with "SSU" in the file name.

With the updates downloaded, you can now run the 2nd script. For this script, simply run the following:

### For an Azure Stack system deployed with Azure AD authentication ###

* Choose your authentication type: Azure AD
* Choose ServerFull or ServerCore
* Path to temporarily store the VHD while it is being created
* Path to WS2019EVAL iso file
* ArmEndpoint - for the ASDK, you can use the example below, but for your integrated system, yours will differ. It may be something like https://adminmanagement.westus.contoso.com - check with your administrator.
* VHD size - you only need to specify the number, not "GB"
* Provide your **directory tenant name**. If this is an Azure AD deployment, use your appropriate Azure AD tenant.

```powershell
.\WS2019Images.ps1 -authenticationType AzureAD -azureDirectoryTenantName "contoso.onmicrosoft.com" -ImagePath "D:\ImageUpdates" `
-image ServerFull -ISOPath "D:\WS2019EVALISO.iso" -ArmEndpoint "https://adminmanagement.local.azurestack.external" -vhdSize "30"
```

### For an Azure Stack system deployed with ADFS authentication ###

For an ADFS-deployed Azure Stack, everything is the same as above **apart from**:

* Provide your **directory tenant name**. If this is an Azure AD deployment, use your appropriate Azure AD tenant.

```powershell
.\WS2019Images.ps1 -authenticationType ADFS -ImagePath "D:\ImageUpdates" -image ServerFull -ISOPath "D:\WS2019EVALISO.iso" `
-ArmEndpoint "https://adminmanagement.local.azurestack.external" -vhdSize "30"
```

Post-Script
-----------
Once the script has completed running successfully, you should be able to easily validate the new Windows Server 2019 images and gallery items in the Admin Portal. Log into the portal, and navigate to **Region Management**, then **Compute**, then **VM Images**, and you should see your Windows Server 2019 images shown:

![WS2019Image](</deployment/offline/media/WS2019Image.png>)

In addition, you should also see a Windows Server 2019 Datacenter gallery item, for you and your users to deploy using the Azure Stack portal.

![WS2019gallery](</deployment/offline/media/WS2019gallery.png>)

### Cleanup
Should you want to remove the images and gallery items, run the following:

```powershell
Get-AzsGalleryItem | Where-Object {$_.Name -like "*WindowsServer2019Datacenter-ARM*"} | Remove-AzsGalleryItem -Confirm:$true
Get-AzsGalleryItem | Where-Object {$_.Name -like "*WindowsServer2019DatacenterServerCore-ARM*"} | Remove-AzsGalleryItem -Confirm:$true
Get-AzsPlatformImage | Where-Object {$_.Sku -like "2019-Datacenter"} | Remove-AzsPlatformImage -Confirm:$true
Get-AzsPlatformImage | Where-Object {$_.Sku -like "2019-Datacenter-Server-Core"} | Remove-AzsPlatformImage -Confirm:$true
```

### Known Issues
* These scripts have been developed with simplicity in mind, and don't have the same level of error validation as the main ASDK Configurator scripts, so you may experience the occasional random error.
* Windows Server 2019 or any of the Windows Server Semi-Annual Channel releases (1709, 1803, 1809) are not validated for support with the database and App Service resource providers on an Azure Stack system, so don't use those builds at this time for those purposes. Use the Windows Server 2016 evaluation release.

### Troubleshooting & Improvements
This scripts, and the packages have been developed, and tested, to the best of my ability.  I'm not a PowerShell guru, thus, if you do encounter issues, [let me know through GitHub](<../../issues>) and I'll do my best to resolve them.

Likewise, if you are awesome at PowerShell and would like to improve the solution, let me know, and we can collaborate to improve the overall project!
