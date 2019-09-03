Azure Stack POC Configurator 1908
==============

Version Compatibility
-----------
The current version of the AzSPoC.ps1 script has been **tested with the following versions**:
* ASDK build **1.1908.0.20 (1908)**
* Azure Stack PowerShell Module **1.7.2**

**IMPORTANT** - this version of the AzSPoC.ps1 script has been tested with ASDK build 1908, Azure Stack PowerShell 1.7.2. and the new AzureRM PowerShell 2.5.0.  A version that supports the older ASDK builds (1811 etc) can be found in the archive folder, however this will not be maintained. You should upgrade to a later ASDK.

Description
-----------
Once you have **completed the installation of your ASDK**, you need to populate it with content, in order to have a more complete experience. This content may include virtual machine images, extensions, database hosts, app services and more. All of that takes time to install and configure.
The purpose of this AzSPoC.ps1 script is to automate as much as possible, the post-deployment tasks for the Azure Stack Development Kit

This includes:
* Validates all input parameters
* Checks ASDK host memory for enough resources
* Installs Azure Stack PowerShell and AzureRM modules
* Ensures password for VMs meets complexity required for App Service installation
* Updated password expiration (180 days)
* Disable Windows Update on all infrastructures VMs and ASDK host (To avoid the temptation to apply the patches...)
* Tools installation (Azure Stack Tools)
* Registration of the ASDK to Azure (Optional - enables Marketplace Syndication)
* Windows Server 2016 Datacenter Evaluation (Full + Core) images added to the Platform Image Repository
* Windows Server 2019 Datacenter Evaluation (Full + Core) images added to the Platform Image Repository (Optional)
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
* Installs a selection of useful apps via Chocolatey (Putty, Chrome, VS Code, WinDirStat, WinSCP, Python3)
* Configures Python & Azure CLI for usage with ASDK
* MySQL, SQL, App Service and Host Customization can be optionally skipped
* Cleans up download folder to ensure clean future runs
* Transcript Log for errors and troubleshooting
* Progress Tracking and rerun reliability with AzSPoC database hosted on SqlLocalDB (2017)
* Stores script output in a AzSPoCOutput.txt, for future reference
* Supports usage in offline/disconnected environments
* New -serialMode which excecutes VM deployments in serial, rather than parallel - better for older hardware
* Now supports ASDKs that have been depoyed with a custom domain suffix, e.g. https://portal.west.contoso.lab

Additionally, if you encounter an issue, try re-running the script with the same command you used to run it previously. The script is written in such a way that it shouldn't try to rerun previously completed steps.

New in 1907 onwards - Multi-Node Support
-----------
If you are regularly performing **POCs** on Azure Stack Multi-Node systems (aka Integrated System, or "multinode"), the Azure Stack POC Configurator now provides **experimental** support for configuring a multinode system.  There is **specific** guidance on how to use the script with a multinode deployment. Again, **THIS IS FOR POC USE ONLY** and for this release, should be considered **EXPERIMENTAL** although I do want to ensure it works as well as the current version for ASDKs.

If you're interested, you should **[read more about the multinode deployment option here.](</deployment/multinode/README.md>)** 

Important Considerations
------------
Firstly, **you must have already deployed the ASDK**. Secondly, for an **Azure AD deployment of the ASDK** (or if you want use AzSPoC.ps1 with an ADFS deployment of the ASDK, but **register** it to Azure), to run the AzSPoC.ps1 script, you need to be using a true **organizational account**, such as admin@contoso.onmicrosoft.com or admin@contoso.com, and this account should have global admin credentials for the specified Azure AD directory. Even if you have a non-organizational account, such as an outlook.com account, that has the right level of privilege in Azure AD, the AzSPoC.ps1 script **uses a -Credential switch for non-interactive login, which doesn’t work with non-organizational accounts**. You will receive an error.

**You do not need to install Azure/AzureStack PowerShell before running the script. The Azure Stack POC Configurator will install and configure Azure/AzureStack PowerShell for you. If you have already installed the Azure/AzureStack PowerShell modules, the script will first clean your PowerShell configuration to ensure optimal operation.**

ASDK Host Sizing
------------
The Azure Stack POC Configurator will deploy a total of 12 additional virtual machines to support the MySQL, SQL Server, and App Service Resource Providers, should you choose to deploy all the RPs.  You will therefore need an ASDK host machine that has at least 29.5GB free memory to support these additional virtual machines:

* **MySQL RP** - 2 VMs (RP VM, DB Host VM) = **5.5GB**
* **SQL Server RP** - 2 VMs (RP VM, DB Host VM) = **5.5GB**
* **App Service** - 7 VMs (File Server, SQL Host, Front End Scale Set, Shared Worker Tier, Publisher Scale Set, CN0-VM, Management Servers Scale Set) = **23GB**

**Total with all RPs deployed = 34GB in addition to the core running Azure Stack ASDK VMs**

Before you run the Azure Stack POC Configurator, ensure that you have enough memory available on your ASDK host system. On a typical ASDK system, the core Azure Stack VMs will already consume between 50-60GB of host memory, so please ensure you have enough remaining to deploy the additional resource providers. As per the updated specs here: https://docs.microsoft.com/en-us/azure/azure-stack/asdk/asdk-deploy-considerations, a system with at least 192GB memory is recommended to evaluate all features.

Running on older/low performance hardware
------------
If your ASDK system doesn't have SSDs, or is an older system, the Azure Stack POC Configurator may experience issues during parallel deployment of virtual machines. This may also be true in environments where you have virtualized the ASDK, and are running it nested on an alternative virtualization/cloud platform, such as ESXi, or in an Azure VM. If that's the case, it's recommended to run the AzSPoC.ps1 script with the **-serialMode flag**, and this will instruct the script to deploy any VMs, one at a time. This takes a little longer, but offers increased reliability on systems with lower levels of performance.

Offline/Disconnected Support
------------
* Do you want to deploy your ASDK in an environment that **doesn't have internet connectivity**?
* Do you want to download the 5GB+ of required dependencies (Ubuntu image, Database resource providers, App Service binaries, JSON files etc) in advance of running the script?

If you answered **yes** to any of those, you can deploy the AzSPoC in an offline/disconnected mode. To do so, you should **[read the offline/disconnected documentation.](</deployment/offline/README.md>)**

Step by Step Guidance (for internet-connected ASDK)
------------

### Step 1 - Download the AzSPoC.ps1 script ###
The first step in the process is to create a local folder on the ASDK host, and then download the AzSPoC.ps1.

* Deploy your ASDK
* Once complete, login as azurestack\azurestackadmin on your ASDK host.
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
* For the **-azureDirectoryTenantName**, You can use your "domain.onmicrosoft.com" tenant name, or if you are using a custom domain name in Azure AD, such as contoso.com, you can also use that.
* For the **-downloadPath**, ensure the folder exists, and you have enough space to hold up to 40GB of files. **This should be a path that is local to your ASDK host, NOT a mapped drive - known issues exist with mapped drives at this time**
* **-ISOPath** should point to the Windows Server 2016 Evaluation media that you downloaded with your ASDK files. **Do NOT use Windows Server 2019 or any of the semi-annual releases as these are not supported by the database and App Service resource providers at this time**
* **-ISOPath2019** is optional, and should point to the Windows Server 2019 Evaluation media that you can download from here: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019. **Note - this will not be used for deployment of any Resource Providers such as the Database RPs, or the App Service - these will still use the 2016 images**
* **-asdkHostPwd** is the password you used when deploying your ASDK (for ASDK deployments only)
* **-VMpwd** is the password assigned to all VMs created by the script. **Important** - App Service installation requires a strong password, at least 12 characters long, with at least 3 of the following options: 1 upper case, lower case, 1 number, 1 special character.
* **-azureAdUsername** and **-azureAdPwd** are the *Service Administrator* credentials you used when you deployed your Azure Stack system (in Azure AD connected mode)
* Use the **-registerAzS** flag to instruct the script to register your Azure Stack system to Azure.
* Use the **-useAzureCredsForRegistration** flag if you want to use the same *Service Administrator* Azure AD credentials to register the ASDK, as you did when deploying the ASDK.
* If you specify -registerAzS but forget to use -useAzureCredsForRegistration, you will be prompted for alternative credentials.
* If you are using older hardware, or lower performance hardware with no SSD storage, and are experiencing VM deployment errors, use **-serialMode** to set the script to deploy VMs one at a time, rather than in parallel. This can help with reliability on older, lower performance hardware.
* If you chose to customize the initial deployment of your ASDK by changing the region (default = "local") or the domain suffix (default = "azurestack.external"), you can use the flag **-customDomainSuffix** along with a correctly formed region and domain suffix, such as "west.contoso.com"

Usage Examples:
-------------

**Scenario 1** - Using Azure AD for authentication. You wish to register the ASDK to Azure as part of the automated process. For registration, you wish to use the same Azure AD credentials as you used when you deployed your ASDK:

```powershell
.\AzSPoC.ps1 -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType AzureAD `
-downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" -asdkHostPwd 'Passw0rd123!' `
-VMpwd 'Passw0rd123!' -azureAdUsername "admin@contoso.onmicrosoft.com" -azureAdPwd 'Passw0rd123!' `
-registerAzS -useAzureCredsForRegistration -azureRegSubId "01234567-abcd-8901-234a-bcde5678fghi"
```

**Please Note**
* If you also want the script to create and upload Windows Server 2019 images, simply include **-ISOPath2019 "D:\WS2019EVALISO.iso"** and the script will take care of the rest.

**Scenario 2** - Using Azure AD for authentication. You wish to register the ASDK to Azure as part of the automated process. For registration, you wish to use a **different** set of Azure AD credentials from the set you used when you deployed your ASDK:

```powershell
.\AzSPoC.ps1 -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType AzureAD `
-downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" -asdkHostPwd 'Passw0rd123!' `
-VMpwd 'Passw0rd123!' -azureAdUsername "admin@contoso.onmicrosoft.com" -azureAdPwd 'Passw0rd123!' `
-registerAzS -azureRegUsername "admin@fabrikam.onmicrosoft.com" -azureRegPwd 'Passw0rd123!' `
-azureRegSubId "01234567-abcd-8901-234a-bcde5678fghi"
```

**Please Note**
* The key difference this time, is that the **-azureRegUsername** and **-azureRegPwd** flags are used, to capture the different set of Azure AD credentials (and therefore, different subscription) for registering the ASDK to Azure.

**Scenario 3** - Using Azure AD for authentication. You choose **not** to register the ASDK to Azure as part of the automated process:

```powershell
.\AzSPoC.ps1 -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType AzureAD `
-downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" -asdkHostPwd 'Passw0rd123!' `
-VMpwd 'Passw0rd123!' -azureAdUsername "admin@contoso.onmicrosoft.com" -azureAdPwd 'Passw0rd123!'
```

**Scenario 4** - Using ADFS for authentication. You wish to register the ASDK to Azure as part of the automated process. For registration, you will have to use a different set of Azure AD credentials as your ASDK was deployed with ADFS:

```powershell
.\AzSPoC.ps1 -authenticationType ADFS -downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" `
-asdkHostPwd 'Passw0rd123!' -VMpwd 'Passw0rd123!' -registerAzS `
-azureRegUsername "admin@fabrikam.onmicrosoft.com" -azureRegPwd 'Passw0rd123!' `
-azureRegSubId "01234567-abcd-8901-234a-bcde5678fghi"
```

**Scenario 5** - Using ADFS for authentication. You choose **not** to register the ASDK to Azure as part of the automated process:

```powershell
.\AzSPoC.ps1 -authenticationType ADFS -downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" `
-asdkHostPwd 'Passw0rd123!' -VMpwd 'Passw0rd123!'
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