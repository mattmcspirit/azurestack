# Deploy SQL Server 2017 on Ubuntu Server 16.04 LTS into Azure Stack with PowerShell

Instead of using the Azure Stack Portal, you can use PowerShell to deploy SQL Server 2017 on Ubuntu Server 16.04 LTS, using Azure Resource Manager templates, to the Azure Stack Development Kit. Azure Resource Manager templates deploy and provision all resources for your application in a single, coordinated operation.

## Run AzureRM PowerShell cmdlets
In this example, you run a script to deploy a virtual machine to Azure Stack Development Kit using a Resource Manager template.  Before proceeding, ensure you have [configured PowerShell](https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-powershell-configure-admin)  

1. Go to the [MSSQL template folder](<ASDKConfigurator.MSSQL/DeploymentTemplates>) and grab the mainTemplate.json, saving it to the following location: c:\\templates\\SQLTemplate.json.
2. In PowerShell, run the following deployment script. Replace *username*, *password* and *msSQlPassword* with your username and password. On subsequent uses, increment the value for the *$myNum* parameter to prevent overwriting your deployment.
   
   ```PowerShell
       # Set Deployment Variables
       $myNum = "001" #Modify this per deployment
       $RGName = "SQLRG$myNum"
       $myLocation = "local"
   
       # Create Resource Group for Template Deployment
       New-AzureRmResourceGroup -Name $RGName -Location $myLocation
   
       # Deploy SQL Server 2017 on Ubuntu Server 16.04 LTS Template
       New-AzureRmResourceGroupDeployment `
           -Name SQLDeployment$myNum `
           -ResourceGroupName $RGName `
           -TemplateFile c:\templates\SQLTemplate.json `
           -vmName SQLVM$myNum `
           -vmSize "Standard_A3" `
           -storageAccountNewOrExisting new `
           -storageAccountName sqlstor$myNum `
           -storageAccountType standard_lrs `
           -adminUsername <username> `
           -adminPassword ("<password>" | ConvertTo-SecureString -AsPlainText -Force) `
           -msSQLPassword ("<password>" | ConvertTo-SecureString -AsPlainText -Force) `
           -authenticationType password `
           -virtualNetworkName sql_vnet$myNum `
           -virtualNetworkAddressPrefix 10.0.0.0/16 `
           -virtualNetworkNewOrExisting new `
           -virtualNetworkSubnetName sql_subnet$myNum `
           -virtualNetworkSubnetAddressPrefix 10.0.0.0/24 `
           -publicIPAddressName sql_ip$myNum `
           -publicIPAddressDomainNameLabel sql$myNum `
           -publicIPAddressNewOrExisting new `
           -scriptBaseUrl "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/scripts/" `
           -templateBaseUrl "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/packages/MSSQL/ASDKConfigurator.MSSQL/DeploymentTemplates/"
   ```
3. Open the Azure Stack portal, click **Browse**, click **Virtual machines**, and look for your new virtual machine (*SQLDeployment001*).

Feel free to modify the above information to suit your needs!