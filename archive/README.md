# Table of Contents
- [What is Azure Stack?](#what-is-azure-stack)
- [Deliver Azure services to your datacenter](#deliver-azure-services-to-your-datacenter)
- [What is the DevOps Toolkit?](#what-is-the-devops-toolkit)
- [DevOps Toolkit Process](#devops-toolkit-process)
- [DevOps Toolkit Prerequisites](#devops-toolkit-prerequisites)
- [Running the DevOps Toolkit Script](#running-the-devops-toolkit-script)
- [Post-Deployment Walkthough](#post-deployment-walkthough---example-jenkins)
- [Troubleshooting & Improvements](#troubleshooting--improvements)
- [Changelog](#changelog)

## What is Azure Stack?

Microsoft Azure Stack is a new hybrid cloud platform product that enables you to deliver Azure services from your own datacenter.

Azure Stack gives you the power of cloud services, yet enables IT to maintain control of your datacenter for true hybrid cloud agility. You decide where to keep your data and applications—in your own datacenter or with a hosting service provider. Easily access public cloud resources to scale at busy times, for dev-test, or whenever you need them.

### Deliver Azure services to your datacenter

Azure Stack enables you to transform on-premises datacenter resources into cloud services for maximum agility. Run Azure IaaS services—including Virtual Machines, Blob/Table storage, and Docker-integrated Linux containers—for applications like SQL Server or SharePoint. Empower developers to write cloud-first applications using on-premises deployments of Azure PaaS services such as App Service. Make your application counterparts productive by enabling the same self-service experience as Azure.

You can learn more about Azure Stack on the dedicated [Azure Stack website](https://azure.microsoft.com/en-us/overview/azure-stack/) and see some cool videos on the [Azure Stack Channel on Channel 9](https://channel9.msdn.com/Blogs/azurestack)

It's also a great platform to learn about DevOps, and what better way to learn about DevOps, than through utilizing the DevOps Toolkit.

## What is the DevOps Toolkit?
The DevOps Toolkit is a PowerShell script that automates the deployment of a number of pre-packaged, open-source DevOps tools, including Ansible, Chef, Jenkins, Puppet, Salt and Terraform, into your Azure Stack environment, specifically into the Azure Stack marketplace, to enable consumption by your tenants. These open-source offerings consist of an .azpkg file, which contains an ARM template for deployment, and a variety of other files, along with links to additional deployment scripts [hosted on GitHub](/scripts).

Once you've successfully run the DevOpsToolkit.ps1 script, you'll be presented with a dedicated section of the navigation for the DevOps Toolkit, and inside, you'll find a selection of open-source DevOps tools, ready for deployment.

![DevOps Toolkit Deployed](</../media/DevOpsToolkitPortal.PNG>)

### DevOps Toolkit Process

Upon deployment, the PowerShell script will walk through a series of steps to automate the deployment of key dependencies, and the marketplace packages themselves.  Below is a graphic that represents the process.

![DevOps Toolkit Process Flow](</media/DevOpsToolkitFlow.png>)

At a high level, when you kick off the process, the DevOpsToolkit.ps1 script will first download the required tools to interact correctly with Azure Stack.  Once downloaded, and extracted, you'll be prompted to log in to either Azure AD, or ADFS, to connect with your Azure Stack.  You'll use which one you selected at Azure Stack deployment time.  Once logged in successfully, the script will check for the existence of an Ubuntu Server 16.04 LTS image.  If it finds one with the correct characteristics, it will use that, however if it doesn't find one, the script will prompt you to download an image, and add it to your Azure Stack Platform Image Repository (PIR), using one of three methods:

- **Manual Download** - the script will open a webpage with the instructions on where to download an Ubuntu Server 16.04 LTS image, and how to manually add it to Azure Stack.  Once you've done this, you'll rerun the script from the beginning.
- **Syndicated Download** - Syndication is a feature that has to be enabled for your Azure Stack, and once enabled, you'll be able to 'Add from Azure', specific images, to your Azure Stack.  If you select this option, the script will open a webpage with instructions on how to perform the necessary tasks. You'll then rerun the script from the beginning.
- **Automated Download** - the script will automatically download a suitable Ubuntu Server 16.04 LTS image from Ubuntu's repository, and upload it into your Azure Stack.  This will take around 20 minutes, depending on your hardware.

Once completed, you'll have an image within your PIR, and the script can continue.

The script will then pull down the necessary packages from GitHub, and begin the upload into your Azure Stack marketplace.  This will first involve cleaning up any remnant packages that may already be present, and then, creating a temporary resource group and storage account to hold the necessary files, before uploading them into the Azure Stack Marketplace.  Once completed, the script will clean up this temporary resource group, and storage account, and the process will be complete.

### DevOps Toolkit Prerequisites

Before you begin, you **must** have the following:

- Access to your Azure Stack host, in order to execute the DevOpsToolkit.ps1 script
- Installed Azure Stack compatible Azure PowerShell modules [as per these instructions](https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-powershell-install)
- Run PowerShell as administrator.
- It is highly recommended to use the regular PowerShell console, and not the PowerShell ISE

### Running the DevOps Toolkit Script

In order to download the script, you'll want to run the following from your administrative PowerShell console:

```powershell
    # Variables
    $Uri = 'https://raw.githubusercontent.com/mattmcspirit/azurestack/master/powershell/DevOpsToolkit.ps1'
    $LocalPath = 'c:\DevOpsToolkit'

    # Create folder
    New-Item $LocalPath -Type directory

    # Download file
    Invoke-WebRequest $uri -OutFile ($LocalPath + '\' + 'DevOpsToolkit.ps1')
    Set-Location $LocalPath
```

Once downloaded, in order to execute the script, you will simply run the following, substituting your values where appropriate:

```powershell
    .\DevOpsToolkit.ps1 -azureDirectoryTenantName <yourdirectoryname> -authenticationType <yourauthenticationtype>
```

- For -azureDirectoryTenantName, you would use either **yourDirectoryTenantName.onmicrosoft.com**, or, if you're using a custom domain name, you'd use that, such as **contoso.com**. You **don't** need to specify a user@domain at this time.
- For -authenticationType, specify **either AzureAD or ADFS**

So, for instance, a completed example may look like:

```powershell
    .\DevOpsToolkit.ps1 -azureDirectoryTenantName contosoazurestack.com -authenticationType AzureAD
```

## Post-Deployment Walkthough - Example: Jenkins
When the deployment has completed, you should see a new category within your **New** menu, entitled **DevOps Tooling**, and within this folder, you'll find the respective marketplace offerings you can deploy.

If we use **Jenkins** as an example, by clicking on Jenkins, you'll be asked to enter a number of **parameters**, including an administrator username, password, a name of the VM (which will also form the public DNS name of the Jenkins VM) and finally, you can select a size for the VM.  **Standard A3** is the default, and will deploy a VM with 7GB RAM, and 4 cores.  Click **OK** to confirm your parameters.

If you wish, you can edit the template and make modifications, however for most POC environments, the current configuration should be adequate.

With the parameters entered, give the **resource group** a name and you're ready to click **Create**

![Jenkins Deployment](</media/DevOpsJenkins.PNG>)

Your deployment will begin, and depending on your hardware, will take a few minutes.

Once completed, you should receive a notification, and in the **Deployment blade**, you should see information about the success (or failure!) of the deployment, including the FQDN to access the Jenkins virtual machine.

![Jenkins Deployment Completed](</media/DevOpsJenkinsFinished.PNG>)

With that completed, in the case of Jenkins, you can go to the Jenkins Master FQDN, which in my case, is http://jenkins1.local.cloudapp.azurestack.external:8080, and I'll need to access this from within my Azure Stack environment.

![Jenkins Deployment Completed](</media/UnlockJenkins.PNG>)

Now in the case of Jenkins, you'll also need to SSH into the VM itself, using a tool such as Putty, in order to retrieve the initial admin password, and once done, paste into the browser, and you're pretty much there to a Jenkins deployment, perfect for kicking the tires, testing, learning and more.

If you want to automate the deployment, instead of deploying through the portal, I've provided PowerShell scripts within each of the individual package folders, which can be found within the main [Packages folder](packages)

## Troubleshooting & Improvements
This script, and the packages have been developed, and tested, to the best of my ability.  I'm not a PowerShell guru, nor a specialist in Linux scripting, thus, if you do encounter issues, [let me know through GitHub](<../../issues>) and I'll do my best to resolve them.

Likewise, if you are awesome at PowerShell, or Linux scripting, or would like to have additional tools included within the packages, let me know, and we can collaborate to improve the overall project!

## Changelog
To view version history, and see changes made for new versions, check out the [changelog](changelog.md)
