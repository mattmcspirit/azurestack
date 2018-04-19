Azure Stack Development Kit | Configurator Tool
==============

ASDK Version
-----------
The current version of the ConfigASDK.ps1 Script has been tested with ASDK build **20180329.1**

Description
-----------
Once you have completed the installation of your ASDK, you need to populate it with content, in order to have a more complete experience. This content may include
virtual machine images, extensions, database hosts, app services and more. All of that takes time to install and configure.
The purpose of this ConfigASDK.ps1 script is to automate as much as possible, the post-deployment tasks for the Azure Stack Development Kit

This includes:
* Updated password expiration (180 days)
* Disable Windows Update on all infrastructures VMs and ASDK host (To avoid the tempation to apply the patches...)
* Tools installation (Azure Stack Tools)
* Registration of the ASDK to Azure (Optional - enables Marketplace Syndication)
* Windows Server 2016 Datacenter Evaluation (Full + Core) images added to the Platform Image Repository
* Ubuntu Server 16.04-LTS image added to the Platform Image Repository
* Corresponding gallery items created in the Marketplace for the Windows Server and Ubuntu Server images.
* Gallery item created for MySQL 5.7 and SQL Server 2017 (both on Ubuntu Server 16.04 LTS)
* Creates VM Scale Set gallery item
* MySQL Resource Provider installation
* SQL Server Resource Provider installation
* Deployment of a MySQL 5.7 hosting server on Ubuntu Server 16.04 LTS
* Deployment of a SQL Server 2017 hosting server on Ubuntu Server 16.04 LTS
* Adding SQL Server & MySQL hosting servers to Resource Providers including SKU/Quotas
* App Service prerequisites installation (SQL Server and Standalone File Server)
* App Service Resource Provider sources download and certificates generation
* Set new default Quotas for MySQL, SQL Server, Compute, Network, Storage and Key Vault
* Generate output text file for use in the next steps of configuration.

It's important to note, that the ConfigASDK.ps1 script cannot automate everything today. The App Service installation, for instance, cannot be automated today
however, the script completes with an output text file, that can be used to populate the App Service installer, to streamline deployment of the App Service.

Important Considerations
------------
The current version of the ConfigASDK.ps1 script relies on your ASDK having an internet connection. During the execution, the script will download a number of
files from the internet, including the Azure Stack Tools, Ubuntu Server 16.04 VHD, Windows Updates for the Windows Server image creation process, and more. Future versions
of the ConfigASDK.ps1 script may include more offline support.

Instructions
------------
#### Install PowerShell for Azure Stack ####

* Login as azurestack\azurestackadmin on your ASDK host.
* Open an elevated PowerShell window and run the following script to install PowerShell for Azure Stack:

```PowerShell
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
Get-Module -ListAvailable | where-Object {$_.Name -like “Azure*”} | Uninstall-Module

# Install the AzureRM.Bootstrapper module. Select Yes when prompted to install NuGet.
Install-Module -Name AzureRm.BootStrapper

# Install and import the API Version Profile required by Azure Stack into the current PowerShell session.
Use-AzureRmProfile -Profile 2017-03-09-profile -Force
Install-Module -Name AzureStack -RequiredVersion 1.2.11
```

* Detailed instructions for installing the PowerShell for Azure Stack can be found here: https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-powershell-install
* Once completed successfully, close your PowerShell console window.

#### Download the ConfigASDK.ps1 script ####

* Open an elevated PowerShell window and run the following script to download the ConfigASDK.ps1 file:

```PowerShell
# Create directory on the root drive.
New-Item -ItemType Directory -Force -Path "C:\ConfigASDK"
Set-Location "C:\ConfigASDK"

# Download the ConfigASDK Script.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-Webrequest https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/ConfigASDK.ps1 `
-OutFile ConfigASDK.ps1
```

Usage Examples:
-------------

**Scenario 1** - Using Azure AD for authentication. You wish to register the ASDK to Azure as part of the automated process. For registration, you wish to use the same Azure AD credentials
as you used when you deployed your ASDK:

```PowerShell
.\ConfigASDK.ps1 -ASDK -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType AzureAD `
-downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" -azureStackAdminPwd P@ssw0rd! `
-VMpwd P@ssw0rd! -azureAdUsername "admin@contoso.onmicrosoft.com" -azureAdPwd P@ssw0rd! `
-registerASDK -useAzureCredsForRegistration -azureRegSubId "01234567-abcd-8901-234a-bcde5678fghi"
```

**Please Note**
* For the -azureDirectoryTenantName, You can use your "domain.onmicrosoft.com" tenant name, or if you are using a custom domain name in Azure AD, such as contoso.com, you can also use that
* For the -downloadPath, ensure the folder exists, and you have enough space to hold up to 40GB of files
* -ISOPath should point to the Windows Server 2016 Evaluation media that you downloaded with your ASDK files
* -azureStackAdminPwd is the password you used when deploying your ASDK
* Use the -registerASDK flag to instruct the script to register your ASDK to Azure
* Use the -useAzureCredsForRegistration flag if you want to use the same Azure AD credentials to register the ASDK, as you did when deploying the ASDK
* If you specify -registerASDK but forget to use -useAzureCredsForRegistration, you will be prompted for alternative credentials

**Scenario 2** - Using Azure AD for authentication. You wish to register the ASDK to Azure as part of the automated process. For registration, you wish to use a different set of Azure AD credentials from the set you used when you deployed your ASDK:

```PowerShell
.\ConfigASDK.ps1 -ASDK -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType AzureAD `
-downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" -azureStackAdminPwd P@ssw0rd! `
-VMpwd P@ssw0rd! -azureAdUsername "admin@contoso.onmicrosoft.com" -azureAdPwd P@ssw0rd! `
-registerASDK -azureRegUsername "admin@fabrikam.onmicrosoft.com" -azureRegPwd P@ssw0rd! `
-azureRegSubId "01234567-abcd-8901-234a-bcde5678fghi"
```

**Please Note**
* The key difference this time, is that the -azureRegUsername and -azureRegPwd flags are used, to capture the different set of credentials for registering the ASDK to Azure.

**Scenario 3** - Using Azure AD for authentication. You choose **not** to register the ASDK to Azure as part of the automated process:

```PowerShell
.\ConfigASDK.ps1 -ASDK -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType AzureAD `
-downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" -azureStackAdminPwd P@ssw0rd! `
-VMpwd P@ssw0rd! -azureAdUsername "admin@contoso.onmicrosoft.com" -azureAdPwd P@ssw0rd!
```


**Scenario 4** - Using ADFS for authentication. You wish to register the ASDK to Azure as part of the automated process. For registration, you will have to use a different set of Azure AD credentials as your ASDK was deployed with ADFS:

```PowerShell
.\ConfigASDK.ps1 -ASDK -authenticationType ADFS -downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" `
-azureStackAdminPwd P@ssw0rd! -VMpwd P@ssw0rd! -registerASDK `
-azureRegUsername "admin@fabrikam.onmicrosoft.com" -azureRegPwd P@ssw0rd! `
-azureRegSubId "01234567-abcd-8901-234a-bcde5678fghi"
```

**Please Note**
* This scenario requires testing.

**Scenario 5** - Using ADFS for authentication. You choose **not** to register the ASDK to Azure as part of the automated process:

```PowerShell
.\ConfigASDK.ps1 -ASDK -authenticationType ADFS -downloadPath "D:\ASDKfiles" -ISOPath "D:\WS2016EVALISO.iso" `
-azureStackAdminPwd P@ssw0rd! -VMpwd P@ssw0rd!
```

**Please Note**
* This scenario requires testing.

Post-Script Actions
-------------------
This script can take up to 6 hours to finish.
Once the script has completed, be sure to look in your downloadPath folder, as it will contain a ConfigASDKOutput.txt file, with useful information for the next steps for deploying the App Service.
Please refer to your .txt file for specific guidance and links.

#### Troubleshooting & Improvements
This script, and the packages have been developed, and tested, to the best of my ability.  I'm not a PowerShell guru, nor a specialist in Linux scripting, thus, if you do encounter issues, [let me know through GitHub](<../../issues>) and I'll do my best to resolve them.

Likewise, if you are awesome at PowerShell, or Linux scripting, or would like to improve the solution, let me know, and we can collaborate to improve the overall project!