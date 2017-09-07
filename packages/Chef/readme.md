# Deploy Chef into Azure Stack with PowerShell

Instead of using the Azure Stack Portal, you can use PowerShell to deploy the DevOps tools through Azure Resource Manager templates, to the Azure Stack Development Kit. Azure Resource Manager templates deploy and provision all resources for your application in a single, coordinated operation.

## Run AzureRM PowerShell cmdlets
In this example, you run a script to deploy a virtual machine to Azure Stack Development Kit using a Resource Manager template.  Before proceeding, ensure you have [configured PowerShell](https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-powershell-configure-admin)  

1. Go to the [Chef template folder](<DevOpsToolkit.ChefServer/DeploymentTemplates>) and grab the mainTemplate.json, saving it to the following location: c:\\templates\\chefTemplate.json.
2. In PowerShell, run the following deployment script. Replace *username* and *password* with your username and password. On subsequent uses, increment the value for the *$myNum* parameter to prevent overwriting your deployment.
   
   ```PowerShell
       # Set Deployment Variables
       $myNum = "001" #Modify this per deployment
       $RGName = "chefRG$myNum"
       $myLocation = "local"
   
       # Create Resource Group for Template Deployment
       New-AzureRmResourceGroup -Name $RGName -Location $myLocation
   
       # Deploy Chef Template
       New-AzureRmResourceGroupDeployment `
           -Name chefDeployment$myNum `
           -ResourceGroupName $RGName `
           -TemplateFile c:\templates\chefTemplate.json `
           -vmName chefVM$myNum `
           -vmSize "Standard_A3" `
           -adminUsername <username> `
           -adminPassword ("<password>" | ConvertTo-SecureString -AsPlainText -Force) `
           -chefAdminUsername <username> `
           -chefAdminPassword ("<password>" | ConvertTo-SecureString -AsPlainText -Force) `
           -adminFirstName <first name> `
           -adminLastName <first name> `
           -adminEmailAddress <email address> `
           -organizationName <organization name> `
   ```
3. Open the Azure Stack portal, click **Browse**, click **Virtual machines**, and look for your new virtual machine (*myDeployment001*).

Feel free to modify the above information to suit your needs!
