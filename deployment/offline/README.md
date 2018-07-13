ASDK Offline Dependencies Downloader 1805.3
==============

Version Compatibility
-----------
The current version of the ConfigASDKdependencies.ps1 script has been **tested with the following versions**:
* ASDK Configurator (ConfigASDK.ps1) **1805.3**

Description
-----------
The ASDK Configurator script automates the installation of a variety of post-deployment tools, images, resource providers and more. However, the script relies on your ASDK host having an internet connection to download the necessary files. By using the Azure Stack Development Kit Offline Dependencies Downloader, you can automate the download of all of the necessary components required by the ASDK Configurator, and zips them up into a convenient single package, ready to be imported, extracted and used by the ASDK Configurator script.

Important Considerations
------------
The ASDK Offline Dependencies Downloader **requires at least PowerShell 5.0**. This is built into Windows 10, and Windows Server 2016 and is available for other platforms here: <https://go.microsoft.com/fwlink/?linkid=830436>.  The only other requirement for the machine where you will download the dependency files, is that it **requires an internet connection**, which, goes without saying, really.

Instructions
------------
To download the ASDK Offline Dependencies Downloader, **open an administrative PowerShell console**, and run the following:

```powershell
# Create directory on the root drive.
New-Item -ItemType Directory -Force -Path "C:\ConfigASDKfiles"
Set-Location "C:\ConfigASDKfiles"

# Download the ConfigASDK Script.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-Webrequest http://bit.ly/asdkoffline -UseBasicParsing -OutFile ConfigASDKdependencies.ps1
```

Once you've downloaded the script, you can run it using the following guidance. The length of time the script takes to execute will depend on your internet connection speed, and the speed of you local storage.

Usage Example:
-------------

```powershell
# Initiate the downloader.
.\ConfigASDKdependencies.ps1 -downloadPath "C:\ASDKdependencies" -ISOPath "C:\WS2016EVAL.iso"
```

**General Guidance**
* For the **-downloadPath**, ensure the folder exists, and you have enough space to hold up to 10GB of files
* **-ISOPath** should point to the Windows Server 2016 Evaluation media that you downloaded with your ASDK files

The script will create a folder structure within your chosen **downloadPath**, and will create a copy of your ISO file, and include this within the download path also. By the end of the process, your download path will contain items (and subdirectories etc.):
* ConfigASDKfiles (Directory)
* ConfigASDKfiles.zip (Zip file with all key files)
* ConfigASDK.ps1 (Script)
* ConfigASDKDependencyLogDateTime.txt (Log file)

Of these 4 files, you should copy **ConfigASDKfiles.zip** and **ConfigASDK.ps1** to the target ASDK host.

Next Step - Using the ASDK Configurator in Offline mode
-------------

TBC

#### Offline Example ####

As this is an offline deployment, **ADFS is required** for authentication. In addition, as the ASDK is offline, and disconnected from the internet, the script will be configured **not to register the ASDK to Azure** as part of the automated process. Finally, the additional **Host Customizations**, such as installation of useful apps via Chocolatey, such as Putty, Visual Studio Code, Google Chrome and more, will **not** be performed in this release.  You can optionally skip other parts of the installation, as described below.

```powershell
.\ConfigASDK.ps1 -authenticationType ADFS -downloadPath "D:\ASDKfiles" -azureStackAdminPwd "Passw0rd123!" `
-VMpwd "Passw0rd123!" -offline -configAsdkOfflinePath "D:\ConfigASDKfiles.zip"
```

**General Guidance**
* For the **-downloadPath**, ensure the folder exists, and you have enough space to hold up to 10GB of files
* **-ISOPath** should point to the Windows Server 2016 Evaluation media that you downloaded with your ASDK files

#### Optional Actions - New in ASDK Configurator 1805 ####

Use the following switches to skip deployment of additional Resource Providers, or host customization. Note, if you don't specify these switches, the Resource Provider installation/customization will be performed as part of the deployment.

* Use **-skipMySQL** to **not** install the MySQL Resource Provider, Hosting Server and SKU/Quotas.
* Use **-skipMSSQL** to **not** install the Microsoft SQL Server Resource Provider, Hosting Server and SKU/Quotas.
* Use **-skipAppService** to **not** install the App Service pre-requisites and App Service Resource Provider.
* Use **-skipCustomizeHost** to **not** customize your ASDK host with useful apps such as Putty, Visual Studio Code, Google Chrome and more.

In addition, you can choose to skip a particular resource provider deployment, such as -skipMySQL, but later, re-run the Configurator (using the same launch command) and **not** specify the -skipMySQL switch, and the Configurator will add that particular functionality.

Post-Script Actions
-------------------
The ConfigASDK.ps1 script can take over 6 hours to finish, depending on your hardware. An offline deployment will generally be quicker than a connected one, as you have already downloaded the relevant files in advance.  There are no other specific post-script actions to perform after an offline ADFS deployment.

#### Troubleshooting & Improvements ####
This script, and the packages have been developed, and tested, to the best of my ability.  I'm not a PowerShell guru, nor a specialist in Linux scripting, thus, if you do encounter issues, [let me know through GitHub](<../../issues>) and I'll do my best to resolve them.

Likewise, if you are awesome at PowerShell, or Linux scripting, or would like to improve the solution, let me know, and we can collaborate to improve the overall project!