ConfigASDK.ps1 (updated for asdk build 20170928.3)
==============
Description
-----------

The purpose of this script is to automate as much as possible post deployment tasks in Azure Stack Development Kit
This include :
* Set password expiration
* Disable windows update on all infrastructures VMs and ASDK host
* Tools installation (git, azstools, Azure Stack PS module)
* Windows Server 2016 and Ubuntu 16.04-LTS images installation
* Creates VM scale set gallery item
* MySQL Resource Provider Installation
* SQL Resource Provider Installation
* Deployment of a MySQL 5.7 hosting Server on Windows Server 2016 Core
* Deployment of a SQL 2014 hosting server on Windows 2016
* AppService prerequisites deployments (fileserver and sqlserver vms)
* AppService Resource Provider sources download to c:\Temp\appservice and certificate generations
* Set new default Quotas for Compute, Network, Storage and keyvault
* Create a simple offer and plan to provide IaaS capabilities to tenants

Instructions
------------

* Login as azurestack\azurestackadmin on your ASDK host.
* Open an elevated powershell window and run the script with the following parameters:

		-AAD switch if you are using Azure AD otherwise the script will assume this is an ADFS deployment. 
		-rppassword "YourPassword"; this will be the administrator password set for each vm deployed for PaaS services
		-ISOPath "c:\xxx\xx.iso" ; specify the path to your Windows Server 2016 Datacenter evaluation iso file
		
* You will be prompted for credentials twice. (for azurestackadmin account and for your service admin account if AAD)
* mysqlrp and sqlrp administrator account will be "cloudadmin". These logins are also applicable for hosting servers.
* fileserver vm for appservice will use fileshareowner as administrator account


Post script actions
-------------------	
This script can take up to 6 hours to finish.
Once the script is finished you have to complete the following:

* For AppService installation you need to continue from the Create AAD application step from here : https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-app-service-before-you-get-started
* You need to attach your capacity hosts (sql and mysql) to their resource providers adapters from the admin portal.
* You have to register your system if you want to enable marketplace syndication. follow these steps https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-register
* Create your plans to offer services to tenants
* Enjoy !

Usage Example:
-------------

 .\ConfigASDK.ps1 -AAD -rppassword "mypassword" -ISOPath "c:\flat\14393.0.161119-1705.RS1_REFRESH_SERVER_EVAL_X64FRE_EN-US.ISO"
