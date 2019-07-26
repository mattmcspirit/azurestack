Azure Stack POC Configurator 1907 - Multi-Node Guidance
==============

If you are using an ASDK and not a multinode deployment, **STOP** and **[go back to the main readme.](</deployment/README.md>)**

Version Compatibility
-----------
The current version of the AzSPoC.ps1 script has been **tested with the following versions**:
* Azure Stack build **1.1907.0.20 (1907)**
* Azure Stack PowerShell Module **1.7.2**

**IMPORTANT** - this version of the AzSPoC.ps1 script has been tested with Azure Stack build 1907, Azure Stack PowerShell 1.7.2. and the new AzureRM PowerShell 2.5.0.

Description
-----------
Once you have **completed the deployment of your Azure Stack system**, you need to populate it with content, in order to have a more complete experience for a POC. This content may include virtual machine images, extensions, database hosts, app services and more. All of that takes time to install and configure.
The purpose of this AzSPoC.ps1 script is to automate as much as possible, the post-deployment tasks for an Azure Stack POC.

This includes (**for a multinode POC**):
* Validates all input parameters
* Installs Azure Stack PowerShell and AzureRM modules on your machine used to run the script
* Ensures password for VMs meets complexity required for App Service installation
* Tools installation (Azure Stack Tools)
* Registration of the Azure Stack system to Azure (Optional - enables Marketplace Syndication)
* Windows Server 2016 Datacenter (Full + Core) images added to the Platform Image Repository
* Windows Server 2019 Datacenter (Full + Core) images added to the Platform Image Repository (Optional)
* All Windows Server images are patched with latest SSU and CUs automatically
* Ubuntu Server 16.04-LTS image added to the Platform Image Repository
* Corresponding gallery items created in the Marketplace for the Windows Server and Ubuntu Server images
* Gallery item created for MySQL 5.7, 8.0 and SQL Server 2017 (all on Ubuntu Server 16.04 LTS)
* Automates adding of Microsoft VM Extensions to Gallery from Marketplace (for registered ASDKs)
* MySQL Resource Provider installation
* SQL Server Resource Provider installation
* Deployment of a MySQL 8.0 hosting server on Ubuntu Server 16.04 LTS
* Deployment of a SQL Server 2017 hosting server on Ubuntu Server 16.04 LTS
* Adding SQL Server & MySQL hosting servers to Resource Providers including SKU/Quotas
* App Service prerequisites installation (SQL Server PowerShell, SQL Server DB VM and Standalone File Server)
* App Service Resource Provider sources download and certificates generation
* App Service Service Principal Created (for Azure AD and ADFS)
* Grants App Service Service Principal Admin Consent (for Azure AD)
* Automates deployment of the latest App Service release using dynamically constructed JSON
* Set new default Quotas for MySQL, SQL Server, Compute, Network, Storage and Key Vault
* Creates a Base Plan and Offer containing all deployed services
* Creates a user subscription for the logged in tenant, and activates all resource providers
* MySQL, SQL, and App Service can be optionally skipped
* Cleans up download folder to ensure clean future runs
* Transcript Log for errors and troubleshooting
* Progress Tracking and rerun reliability with AzSPoC database hosted on SqlLocalDB (2017)
* Stores script output in a AzSPoCOutput.txt, for future reference
* Supports usage in offline/disconnected environments

Additionally, if you encounter an issue, try re-running the script with the same command you used to run it previously. The script is written in such a way that it shouldn't try to rerun previously completed steps.

Important Considerations
------------
Firstly, **you must have already deployed the Azure Stack system**. Secondly, for an **Azure AD deployment of the Azure Stack** (or if you want use AzSPoC.ps1 with an ADFS deployment of Azure Stack, but **register** it to Azure), to run the AzSPoC.ps1 script, you need to be using a true **organizational account**, such as admin@contoso.onmicrosoft.com or admin@contoso.com, and this account should have global admin credentials for the specified Azure AD directory. Even if you have a non-organizational account, such as an outlook.com account, that has the right level of privilege in Azure AD, the AzSPoC.ps1 script **uses a -Credential switch for non-interactive login, which doesn’t work with non-organizational accounts**. You will receive an error.

**You do not need to install Azure/AzureStack PowerShell before running the script. The Azure Stack POC Configurator will install and configure Azure/AzureStack PowerShell for you. If you have already installed the Azure/AzureStack PowerShell modules, the script will first clean your PowerShell configuration to ensure optimal operation.**

Offline/Disconnected Support
------------
* Do you want to configure your Azure Stack multinode system in an environment that **doesn't have internet connectivity**?
* Do you want to download the 5GB+ of required dependencies (Ubuntu image, Database resource providers, App Service binaries, JSON files etc) in advance of running the script?

If you answered **yes** to any of those, you can deploy the AzSPoC in an offline/disconnected mode. To do so, you should **[read the offline/disconnected documentation.](</deployment/multinode/offline/README.md>)**

IMPORTANT - Step by Step Guidance (for internet-connected Azure Stack systems)
------------

### Step 1 - Download the AzSPoC.ps1 script ###
The first step in the process is to create a local folder on your workstation, and then download the AzSPoC.ps1.

* Deploy your Azure Stack system
* Once complete, login to your workstation.  **NOTE - this workstation needs to remain connected to the Azure Stack system for the duration of the script execution.**
* Open an elevated PowerShell window and run the following script to download the AzSPoC.ps1 file:

```powershell
# Create directory on the root drive.
New-Item -ItemType Directory -Force -Path "C:\AzSPoC"
Set-Location "C:\AzSPoC"

# Download the AzSPoC Script.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-Webrequest http://bit.ly/AzSPoC -UseBasicParsing -OutFile AzSPoC.ps1
```

### Step 2 - Previous Run Cleanup ###
If you have run the Azure Stack POC Configurator successfully on this physical host before, you may have artifacts left over in your -downloadPath (assuming you use the same path each time) that can affect the next deployment, so please remove any existing files and folders from within your -downloadPath before running the AzSPoC.ps1 script. If you only have a "Completed" folder, this does not need to be deleted.

![Existing files](deployment/offline/media/AsdkFolderCleanup.png)

### Step 3 - Run the AzSPoC.ps1 script ###
With the script downloaded successfully, you can move on to running the script. Below, you will find a number of examples to help you run the script, depending on your scenario. Before you use the examples, please read the general guidance below:

**General Guidance**

Parameter | Explanation
------------ | -------------
**-azureDirectoryTenantName** | You can use your "domain.onmicrosoft.com" tenant name, or if you are using a custom domain name in Azure AD, such as contoso.com, you can also use that.
**-downloadPath** | Ensure the folder exists, and you have enough space to hold up to 40GB of files. **This should be a path that is local to your ASDK host, NOT a mapped drive - known issues exist with mapped drives at this time**

* **-azureDirectoryTenantName** - You can use your "domain.onmicrosoft.com" tenant name, or if you are using a custom domain name in Azure AD, such as contoso.com, you can also use that.
* **-downloadPath** - ensure the folder exists, and you have enough space to hold up to 40GB of files. **This should be a path that is local to your ASDK host, NOT a mapped drive - known issues exist with mapped drives at this time**
* **-ISOPath** should point to the Windows Server 2016 **MSDN/Visual Studio/VL** media. **Do NOT use Windows Server 2019 or any of the semi-annual releases as these are not supported by the database and App Service resource providers at this time. Evaluation media will not be supported with multinode systems**
* **-ISOPath2019** is optional, and should point to the Windows Server 2019 **MSDN/Visual Studio/VL** media. **Note - this will not be used for deployment of any Resource Providers such as the Database RPs, or the App Service - these will still use the 2016 images. Also, evaluation media will not be supported with multinode systems**
* **-VMpwd** is the password assigned to all VMs created by the script. **Important** - App Service installation requires a strong password, at least 12 characters long, with at least 3 of the following options: 1 upper case, lower case, 1 number, 1 special character.
* **-azureAdUsername** and **-azureAdPwd** are the *Service Administrator* credentials you used when you deployed your ASDK host (in Azure AD connected mode)
* Use the **-registerAzS** flag to instruct the script to register your ASDK to Azure.
* Use the **-useAzureCredsForRegistration** flag if you want to use the same *Service Administrator* Azure AD credentials to register the ASDK, as you did when deploying the ASDK.
* If you specify -registerAzS but forget to use -useAzureCredsForRegistration, you will be prompted for alternative credentials.
* If you are using older hardware, or lower performance hardware with no SSD storage, and are experiencing VM deployment errors, use **-serialMode** to set the script to deploy VMs one at a time, rather than in parallel. This can help with reliability on older, lower performance hardware.
* If you chose to customize the initial deployment of your ASDK by changing the region (default = "local") or the domain suffix (default = "azurestack.external"), you can use the flag **-customDomainSuffix** along with a correctly formed region and domain suffix, such as "west.contoso.com"


Usage Examples:
-------------

**Scenario 1** - Using Azure AD for authentication. You wish to register the Azure Stack system to Azure as part of the automated process. For registration, you wish to use the same Azure AD credentials as you used when you deployed your Azure Stack system:

```powershell
.\AzSPoC.ps1 -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType AzureAD `
-downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" -azureStackAdminPwd 'Passw0rd123!' `
-VMpwd 'Passw0rd123!' -azureAdUsername "admin@contoso.onmicrosoft.com" -azureAdPwd 'Passw0rd123!' `
-registerAzS -useAzureCredsForRegistration -azureRegSubId "01234567-abcd-8901-234a-bcde5678fghi"
```

**Please Note**
* If you also want the script to create and upload Windows Server 2019 images, simply include **-ISOPath2019 "D:\WS2019EVALISO.iso"** and the script will take care of the rest.

**Scenario 2** - Using Azure AD for authentication. You wish to register the ASDK to Azure as part of the automated process. For registration, you wish to use a **different** set of Azure AD credentials from the set you used when you deployed your ASDK:

```powershell
.\AzSPoC.ps1 -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType AzureAD `
-downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" -azureStackAdminPwd 'Passw0rd123!' `
-VMpwd 'Passw0rd123!' -azureAdUsername "admin@contoso.onmicrosoft.com" -azureAdPwd 'Passw0rd123!' `
-registerAzS -azureRegUsername "admin@fabrikam.onmicrosoft.com" -azureRegPwd 'Passw0rd123!' `
-azureRegSubId "01234567-abcd-8901-234a-bcde5678fghi"
```

**Please Note**
* The key difference this time, is that the **-azureRegUsername** and **-azureRegPwd** flags are used, to capture the different set of Azure AD credentials (and therefore, different subscription) for registering the ASDK to Azure.

**Scenario 3** - Using Azure AD for authentication. You choose **not** to register the ASDK to Azure as part of the automated process:

```powershell
.\AzSPoC.ps1 -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType AzureAD `
-downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" -azureStackAdminPwd 'Passw0rd123!' `
-VMpwd 'Passw0rd123!' -azureAdUsername "admin@contoso.onmicrosoft.com" -azureAdPwd 'Passw0rd123!'
```

**Scenario 4** - Using ADFS for authentication. You wish to register the ASDK to Azure as part of the automated process. For registration, you will have to use a different set of Azure AD credentials as your ASDK was deployed with ADFS:

```powershell
.\AzSPoC.ps1 -authenticationType ADFS -downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" `
-azureStackAdminPwd 'Passw0rd123!' -VMpwd 'Passw0rd123!' -registerAzS `
-azureRegUsername "admin@fabrikam.onmicrosoft.com" -azureRegPwd 'Passw0rd123!' `
-azureRegSubId "01234567-abcd-8901-234a-bcde5678fghi"
```

**Scenario 5** - Using ADFS for authentication. You choose **not** to register the ASDK to Azure as part of the automated process:

```powershell
.\AzSPoC.ps1 -authenticationType ADFS -downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" `
-azureStackAdminPwd 'Passw0rd123!' -VMpwd 'Passw0rd123!'
```

Optional Actions
----------------

Use the following switches to skip deployment of additional Resource Providers, or host customization. Note, if you don't specify these switches, the Resource Provider installation/customization will be performed as part of the deployment.

* Use **-skipMySQL** to **not** install the MySQL Resource Provider, Hosting Server and SKU/Quotas.
* Use **-skipMSSQL** to **not** install the Microsoft SQL Server Resource Provider, Hosting Server and SKU/Quotas.
* Use **-skipAppService** to **not** install the App Service pre-requisites and App Service Resource Provider.
* Use **-skipCustomizeHost** to **not** customize your ASDK host with useful apps such as Putty, Visual Studio Code, Google Chrome and more.

In addition, you can choose to skip a particular resource provider deployment, such as -skipMySQL, but later, re-run the Configurator (using the same launch command) and **not** specify the -skipMySQL switch, and the Configurator will add that particular functionality.

Post-Script Actions
-------------------
This script can take many hours to finish, depending on your hardware and download speeds. There are no specific post-script actions to perform after the script has finished.

### Known Issues
* A Windows Server 2016 ISO is required.  This should be build 1607 (The RTM release) and not any of the Windows Server Semi-Annual Channel releases (1709, 1803, 1809). These have not been validated for support with the database and App Service resource providers, so don't use those builds at this time. The script will block their usage.
* If you wish to upload Windows Server 2019 images for testing, please use the 17763 build, which is the Windows Server 2019 RTM and can be downloaded from here: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019
* Do not use a mapped drive for your -downloadPath on your ASDK host. There are known issues which are yet to be resolved. Please use a local drive.

### Troubleshooting & Improvements
This script, and the packages have been developed, and tested, to the best of my ability.  I'm not a PowerShell guru, nor a specialist in Linux scripting, thus, if you do encounter issues, [let me know through GitHub](<../../issues>) and I'll do my best to resolve them.

Likewise, if you are awesome at PowerShell, or Linux scripting, or would like to improve the solution, let me know, and we can collaborate to improve the overall project!