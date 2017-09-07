# Table of Contents
- [What is Azure Stack?](#what-is-azure-stack)
- [Deliver Azure services to your datacenter](deliver-azure-services-to-your-datacenter)
- [What is the DevOps Toolkit?](what-is-the-devops-toolkit)

## What is Azure Stack?

Microsoft Azure Stack is a new hybrid cloud platform product that enables you to deliver Azure services from your own datacenter.

Azure Stack gives you the power of cloud services, yet enables IT to maintain control of your datacenter for true hybrid cloud agility. You decide where to keep your data and applications—in your own datacenter or with a hosting service provider. Easily access public cloud resources to scale at busy times, for dev-test, or whenever you need them.

### Deliver Azure services to your datacenter

Azure Stack enabled you to transform on-premises datacenter resources into cloud services for maximum agility. Run Azure IaaS services—including Virtual Machines, Blob/Table storage, and Docker-integrated Linux containers—for applications like SQL Server or SharePoint. Empower developers to write cloud-first applications using on-premises deployments of Azure PaaS services such as App Service. Make your application counterparts productive by enabling the same self-service experience as Azure.

You can learn more about Azure Stack on the dedicated [Azure Stack website](https://azure.microsoft.com/en-us/overview/azure-stack/) and see some cool videos on the [Azure Stack Channel on Channel 9](https://channel9.msdn.com/Blogs/azurestack)

It's also a great platform to learn about DevOps, and what better way to learn about DevOps, than through utilizing the DevOps Toolkit.

## What is the DevOps Toolkit?
The DevOps Toolkit is a PowerShell script that automates the deployment of a number of pre-packaged, open-source DevOps tools, including Ansible, Chef, Jenkins, Puppet, Salt and Terraform, into your Azure Stack environment, specifically into the Azure Stack marketplace, to enable consumption by your tenants. These open-source offerings consist of a .azpkg file, which contains an ARM template for deployment, and a variety of other files, along with links to additional deployment scripts [hosted on GitHub](/scripts).

Once you've successfully run the DevOpsToolkit.ps1 script, you'll be presented with a dedicated section of the navigation for the DevOps Toolkit, and inside, you'll find a selection of open-source DevOps tools, ready for deployment.

![DevOps Toolkit Deployed](</media/DevOpsToolkitPortal.PNG>)

### DevOps Toolkit Process

Upon deployment, the PowerShell script will walk through a series of steps to automate the deployment of key dependencies, and the marketplace packages themselves.  Below is a graphic that represents the process.

![DevOps Toolkit Process Flow](</media/DevOpsToolkitFlow.png>)

