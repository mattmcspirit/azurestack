ASDK Offline Dependencies Downloader 1807
==============

Who is this for?
-----------
* Have you deployed your ASDK in an environment that doesn't have internet connectivity?
* Do you want to download the 5GB+ of required dependencies (Ubuntu image, Database resource providers, App Service binaries, JSON files etc) in advance of running the script?

If you answered **Yes** to either of those questions, read on....

Version Compatibility
-----------
The current version of the ConfigASDKdependencies.ps1 script has been **tested with the following versions**:
* ASDK Configurator (ConfigASDK.ps1) **1807 and 1805.3**

Description
-----------
The ASDK Configurator script automates the installation of a variety of post-deployment tools, images, resource providers and more. However, the script relies on your ASDK host having an internet connection to download the necessary files. By using the ASDK Offline Dependencies Downloader, you can automate the download of all of the necessary components required by the ASDK Configurator, and zips them up into a convenient single package, ready to be imported, extracted and used by the main ASDK Configurator script.

Important Considerations
------------
The ASDK Offline Dependencies Downloader **requires at least PowerShell 5.0**. This is built into Windows 10, and Windows Server 2016 and is available for other platforms here: <https://go.microsoft.com/fwlink/?linkid=830436>.  The only other requirement for the machine where you will download the dependency files, is that it **requires an internet connection**, which, goes without saying, really.

Step by Step Guidance - Download Dependencies
------------

### Step 1 - Download the ConfigASDKdependencies.ps1 script ###
**On an internet-connected machine**, to download the ASDK Offline Dependencies Downloader, **open an administrative PowerShell console**, and run the following commands.  You can change the -Path to a different file path on your machine if you prefer.

```powershell
# Create directory on the root drive.
New-Item -ItemType Directory -Force -Path "C:\ConfigASDKfiles"
Set-Location "C:\ConfigASDKfiles"

# Download the ConfigASDK Script.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-Webrequest http://bit.ly/asdkoffline -UseBasicParsing -OutFile ConfigASDKdependencies.ps1
```

Once you've downloaded the script, you can run it using the following guidance. The length of time the script takes to execute will depend on your internet connection speed, and the speed of you local storage.  The script will download the required dependencies, such as an Ubuntu image, Database resource providers, App Service binaries and more. It will also grab your Windows Server 2016 ISO file, and zip them all up into a convenient zip file.

### Step 2 - Run the ConfigASDKdependencies.ps1 script ###

```powershell
# Initiate the downloader.
.\ConfigASDKdependencies.ps1 -downloadPath "C:\ASDKdependencies" -ISOPath "C:\WS2016EVAL.iso"
```

**General Guidance**
* For the **-downloadPath**, ensure the folder exists, and you have enough space to hold up to 15GB of files
* **-ISOPath** should point to the Windows Server 2016 Evaluation media that you downloaded with your ASDK files

The script will create a folder structure within your chosen **downloadPath**, and will create a copy of your ISO file, and include this within the download path also. By the end of the process, your download path will contain items (and subdirectories etc.):
* ConfigASDKfiles (Directory)
* ConfigASDKfiles.zip (Zip file with all key files)
* ConfigASDK.ps1 (Script)
* ConfigASDKDependencyLogDateTime.txt (Log file)

### Step 3 - Copy files to target ASDK host ###
Of the files produced in the previous step, you should copy the **ConfigASDKfiles.zip** file and the **ConfigASDK.ps1** script to your target ASDK host. For my examples, I've copied my ConfigASDK.ps1 and ConfigASDKfiles.zip to my D:\, as shown below:

### Step 4 - Run the ConfigASDK.ps1 script ###
With your ConfigASDKfiles.zip and ConfigASDK.ps1 files copied to your ASDK host, you can now run the main ConfigASDK.ps1 script to customize your ASDK host.  When the ConfigASDK.ps1 script runs, it will now make 2 important checks.

1. Can this ASDK host reach the internet? - the script will run some basic internet connectivity tests
2. Has the user specified a -configAsdkOfflineZipPath and a valid zip file?

If the ASDK host can reach the internet, **and** the -configAsdkOfflineZipPath has been provided, the ASDK Configurator will operate in a **PartialOnline** mode, where it will use the zip file for most dependencies, but will grab a few pieces of extra information (some azpkg files, some scripts) from the internet when required.

If your ASDK host cannot reach the internet, **and** the -configAsdkOfflineZipPath has been provided, the ASDK Configurator will operate in an **Offline** mode, and will use the zip file for all dependencies and can operate completely disconnected from the internet.

There are certain combinations that cannot work, for instance, choosing Azure AD as your authentication mode, or choosing to register your ASDK to Azure but failing the internet connection tests. The ASDK Configurator will test for these scenarios and error gracefully if it encounters them.

**NOTE** - when providing the zip file path, you **do not** have to provide the Windows Server 2016 ISO path. The script assumes the ISO file is contained within your zip file and will be located automatically.

Usage Examples:
-------------
**General Guidance**
* For the **-downloadPath**, ensure the folder exists, and you have enough space to hold up to 40GB of files.

### PartialOnline Scenarios

**Scenario 1** - Using Azure AD for authentication. You wish to register the ASDK to Azure as part of the automated process. For registration, you wish to use the same Azure AD credentials as you used when you deployed your ASDK. You have provided a valid -configAsdkOfflineZipPath:

```powershell
.\ConfigASDK.ps1 -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType AzureAD `
-downloadPath "D:\ASDKfiles" -configAsdkOfflineZipPath "D:\ConfigASDKfiles.zip" -azureStackAdminPwd "Passw0rd123!" `
-VMpwd "Passw0rd123!" -azureAdUsername "admin@contoso.onmicrosoft.com" -azureAdPwd "Passw0rd123!" `
-registerASDK -useAzureCredsForRegistration -azureRegSubId "01234567-abcd-8901-234a-bcde5678fghi"
```

**Scenario 2** - Using Azure AD for authentication. You wish to register the ASDK to Azure as part of the automated process. For registration, you wish to use a different set of Azure AD credentials from the set you used when you deployed your ASDK. You have provided a valid -configAsdkOfflineZipPath:

```powershell
.\ConfigASDK.ps1 -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType AzureAD `
-downloadPath "D:\ASDKfiles" -configAsdkOfflineZipPath "D:\ConfigASDKfiles.zip" -azureStackAdminPwd "Passw0rd123!" `
-VMpwd "Passw0rd123!" -azureAdUsername "admin@contoso.onmicrosoft.com" -azureAdPwd "Passw0rd123!" `
-registerASDK -azureRegUsername "admin@fabrikam.onmicrosoft.com" -azureRegPwd "Passw0rd123!" `
-azureRegSubId "01234567-abcd-8901-234a-bcde5678fghi"
```

**Scenario 3** - Using Azure AD for authentication. You choose **not** to register the ASDK to Azure as part of the automated process. You have provided a valid -configAsdkOfflineZipPath:

```powershell
.\ConfigASDK.ps1 -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType AzureAD `
-downloadPath "D:\ASDKfiles" -configAsdkOfflineZipPath "D:\ConfigASDKfiles.zip" -azureStackAdminPwd "Passw0rd123!" `
-VMpwd "Passw0rd123!" -azureAdUsername "admin@contoso.onmicrosoft.com" -azureAdPwd "Passw0rd123!"
```

**Scenario 4** - Using ADFS for authentication. You wish to register the ASDK to Azure as part of the automated process. For registration, you will have to use a different set of Azure AD credentials as your ASDK was deployed with ADFS. You have provided a valid -configAsdkOfflineZipPath:

```powershell
.\ConfigASDK.ps1 -authenticationType ADFS -downloadPath "D:\ASDKfiles" -configAsdkOfflineZipPath "D:\ConfigASDKfiles.zip" `
-azureStackAdminPwd "Passw0rd123!" -VMpwd "Passw0rd123!" -registerASDK `
-azureRegUsername "admin@fabrikam.onmicrosoft.com" -azureRegPwd "Passw0rd123!" `
-azureRegSubId "01234567-abcd-8901-234a-bcde5678fghi"
```

**Scenario 5** - Using ADFS for authentication. You choose **not** to register the ASDK to Azure as part of the automated process. You have provided a valid -configAsdkOfflineZipPath:

```powershell
.\ConfigASDK.ps1 -authenticationType ADFS -downloadPath "D:\ASDKfiles" -configAsdkOfflineZipPath "D:\ConfigASDKfiles.zip" `
-azureStackAdminPwd "Passw0rd123!" -VMpwd "Passw0rd123!"
```

### Offline Scenarios

**Scenario 6** - This is a **disconnected scenario**. You cannot use Azure AD, so you are using ADFS for authentication. You **cannot** register the ASDK to Azure as part of the automated process as you have no internet connection. You have provided a valid -configAsdkOfflineZipPath:. Also, the ASDK host will not be customized, as this requires Chocolatey binaries which are pulled from the internet. This may be addressed in a future update to the ASDK Configurator.

```powershell
.\ConfigASDK.ps1 -authenticationType ADFS -downloadPath "D:\ASDKfiles" -configAsdkOfflineZipPath "D:\ConfigASDKfiles.zip" `
-azureStackAdminPwd "Passw0rd123!" -VMpwd "Passw0rd123!"
```

### Optional Actions

Use the following switches to skip deployment of additional Resource Providers, or host customization. Note, if you don't specify these switches, the Resource Provider installation/customization will be performed as part of the deployment.

* Use **-skipMySQL** to **not** install the MySQL Resource Provider, Hosting Server and SKU/Quotas.
* Use **-skipMSSQL** to **not** install the Microsoft SQL Server Resource Provider, Hosting Server and SKU/Quotas.
* Use **-skipAppService** to **not** install the App Service pre-requisites and App Service Resource Provider.
* Use **-skipCustomizeHost** to **not** customize your ASDK host with useful apps such as Putty, Visual Studio Code, Google Chrome and more.

In addition, you can choose to skip a particular resource provider deployment, such as -skipMySQL, but later, re-run the Configurator (using the same launch command) and **not** specify the -skipMySQL switch, and the Configurator will add that particular functionality.

Post-Script Actions
-------------------
The ConfigASDK.ps1 script can take over 6 hours to finish, depending on your hardware. An offline deployment will generally be quicker than a connected one, as you have already downloaded the relevant files in advance.

Assuming the script has completed successfully, after **deployments that use Azure AD**, you **must** activate both the Azure Stack administrator and tenant portals. This activation consents to giving the Azure Stack portal and Azure Resource Manager the correct permissions (listed on the consent page) for all users of the directory.

* For the administrator portal, navigate to <https://adminportal.local.azurestack.external/guest/signup>, read the information, and then click Accept. After accepting, you can add service administrators who are not also directory tenant administrators.

* For the tenant portal, navigate to <https://portal.local.azurestack.external/guest/signup>, read the information, and then click Accept. After accepting, users in the directory can sign in to the tenant portal.

The script does open the browser to prompt you to perform these tasks, but for more information, go here: <https://docs.microsoft.com/en-us/azure/azure-stack/asdk/asdk-post-deploy#activate-the-administrator-and-tenant-portals>

#### Troubleshooting & Improvements ####
This script, and the packages have been developed, and tested, to the best of my ability.  I'm not a PowerShell guru, nor a specialist in Linux scripting, thus, if you do encounter issues, [let me know through GitHub](<../../issues>) and I'll do my best to resolve them.

Likewise, if you are awesome at PowerShell, or Linux scripting, or would like to improve the solution, let me know, and we can collaborate to improve the overall project!