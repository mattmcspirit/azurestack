## MySql Server on Windows for AzureStack ##

<b>DESCRIPTION</b>

This template deploys Windows Server, install given MySql server and configures it.


<b>DEPLOY</b>

Login to AzureStack portal
Click 'New' -> 'Custom' -> 'Template Deployment'
Copy content in azuredeploy.json, click 'Edit Template', paste all the content and click 'Save'
Fill in the parameters
Click 'Create New' to create a new 'Resource Group'
Click 'Create'
Wait for results to appear in 'Storage Account' of a given 'Resource Group' parameter name resource



<b>PARAMETERS</b>
```Poweshell
VM Name: <Name of the VM to deploy MySQL Server>
VM Time Zone: <Timezone for Windows VM>
VM Size: <Size of the VM>
Windows OS Version: <Version of Windows Server>
Admin Username: <Username for Windows VM>
Admin Password: <Password for Windows VM>
MySql Service Port: <Port number for MySql Server>
MySql Version: <Select from given supported MySql version>
