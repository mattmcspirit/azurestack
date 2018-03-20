
<#

.SYNOPSYS

    The purpose of this script is to automate as much as possible post deployment tasks in Azure Stack Development Kit
    This include :
        - Set password expiration
        - Disable windows update on all infrastructures VMs and ASDK host
        - Tools installation (git, azstools, Azure Stack PS module)
        - Windows Server 2016 and Ubuntu 16.04-LTS images installation
        - Creates VM scale set gallery item
        - MySQL Resource Provider Installation
        - SQL Resource Provider Installation
        - Deployment of a MySQL 5.7 hosting Server on Windows Server 2016 Core
        - Deployment of a SQL 2014 hosting server on Windows 2016
        - AppService prerequisites installation (sql server and file server)
        - AppService Resource Provider sources download and certificates generation
        - Set new default Quotas for Compute, Network, Storage and keyvault

.VERSION

    2.0  update for release 1.0.280917.3 
    1.0: small bug fixes and adding quotas/plan/offer creation
    0.5: add SQL 2014 VM deployment
    0.4: add Windows update disable
    0.3: Bug fix (SQL Provider prompting for tenantdirectoryID)
    0.2: Bug Fix (AZStools download)

.AUTHOR

    Alain VETIER 
    Blog: http://aka.ms/alainv 
    Email: alainv@microsoft.com 

.PARAMETERS

	-AAD (if you use AAD deployment)
	-rppassword "yourpassword" this will be the administrator password for every vm deployed
	-ISOPath "c:\xxxx\xxx.iso" specify the path to your Windows Server 2016 Datacenter evaluation iso 

.EXAMPLE

	ConfigASDK.ps1 -AAD -rppassword "yourpassword" -ISOPath "c:\mywin2016eval.iso" -verbose

#>

#####################################################################################################
# This sample script is not supported under any Microsoft standard support program or service.      #
# The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims     #
# all implied warranties including, without limitation, any implied warranties of merchantability   #
# or of fitness for a particular purpose. The entire risk arising out of the use or performance of  #
# the sample scripts and documentation remains with you. In no event shall Microsoft, its authors,  #
# or anyone else involved in the creation, production, or delivery of the scripts be liable for any #
# damages whatsoever (including, without limitation, damages for loss of business profits, business #
# interruption, loss of business information, or other pecuniary loss) arising out of the use of or #
# inability to use the sample scripts or documentation, even if Microsoft has been advised of the   #
# possibility of such damages                                                                       #
#####################################################################################################


[CmdletBinding()]

Param (

# if AAD deployment
[switch]$AAD,

# local administrator password for appservice, mysql and sql vms
[parameter(Mandatory=$true)]
[string]$rppassword,

# Path to Windows Server 2016 Datacenter evaluation iso
[parameter(Mandatory=$true)]
[string]$ISOPath

)

# more variables but they should not be changed
$ERCSip = "192.168.200.225"
$vmLocalAdminPass = ConvertTo-SecureString "$rppassword" -AsPlainText -Force
$AZDCredential = Get-Credential -Credential Azurestack\AzurestackAdmin
if ($AAD) {
$Azscredential = Get-Credential -Message "Enter your Azure Stack Service Administrator credentials xx@xx.onmicrosoft.com"
$azureDirectoryTenantName = Read-Host -Prompt "Specify your Azure AD Tenant Directory Name for Azure Stack"
}
else {
$Azscredential = $AZDCredential
}

# set password expiration to 180 days
Write-host "Configuring password expiration policy"
Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 180.00:00:00 -Identity azurestack.local
Get-ADDefaultDomainPasswordPolicy

# Disable Server Manager at Logon
Write-Host "Disabling Server Manager at logon..."
Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask -Verbose

# Disable IE ESC
Write-Host "Disabling IE Enhanced Security Configuration (ESC)."
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
Stop-Process -Name explorer -Force
Write-Host "IE Enhanced Security Configuration (ESC) has been disabled."

# Set Power Policy
Write-Host "Optimizing power policy for high performance"
POWERCFG.EXE /S SCHEME_MIN

# Disable Windows update on infrastructure VMs and host
Write-Host "Disabling Windows Update on Infrastructure VMs and ASDK Host"
$AZSvms = get-vm -Name AZS*
$scriptblock = {
sc.exe config wuauserv start=disabled
Get-Service -Name wuauserv | fl StartType,Status
}
foreach ($vm in $AZSvms) {
Invoke-Command -VMName $vm.name -ScriptBlock $scriptblock -Credential $AZDCredential
}
sc.exe config wuauserv start=disabled

# Disable DNS Server on host
Write-Host "Disabling DNS Server on ASDK Host"
Stop-Service -Name DNS -Force -Confirm:$false
Set-Service -Name DNS -startuptype disabled -Confirm:$false

# Install Azure Stack PS module
Write-host "Installing Azure Stack PowerShell module"
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
Install-Module -Name AzureRm.BootStrapper
Use-AzureRmProfile -Profile 2017-03-09-profile -Force
Install-Module -Name AzureStack -RequiredVersion 1.2.11

# Download git
Write-host "installing Git"
install-script install-gitscm -Force
install-gitscm.ps1

#Download AZSTools from my fork for Windows Datacenter Core sku fix
Write-host "Downloading AzureStack-Tools"
cd \
git clone https://github.com/alainv-msft/AzureStack-Tools.git

# login to AzureStackAdmin environment
Set-ExecutionPolicy RemoteSigned
ipmo C:\AzureStack-Tools\Connect\AzureStack.Connect.psm1
ipmo C:\AzureStack-Tools\ComputeAdmin\AzureStack.ComputeAdmin.psm1
Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "https://adminmanagement.local.azurestack.external" 
if ($AAD) {
$TenantID = Get-AzsDirectoryTenantId -AADTenantName  $azureDirectoryTenantName -EnvironmentName AzureStackAdmin 
set-AzureRmEnvironment -Name AzureStackAdmin -GraphAudience https://graph.windows.net/
}
else {
$TenantID = Get-AzsDirectoryTenantId -ADFS -EnvironmentName AzureStackAdmin
Set-AzureRmEnvironment AzureStackAdmin -GraphAudience https://graph.local.azurestack.external -EnableAdfsAuthentication:$true
}
Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $Azscredential

# Create Windows Server 2016 Images
Write-host "installing Windows Server 2016 Datacenter full and Core images"
New-AzsServer2016VMImage -ISOPath $ISOPath -Version Both -IncludeLatestCU -Net35 $true -CreateGalleryItem $true
del *.vhd -Force
del *.msu -Force
del *.cab -Force

# Create Ubuntu 16.04-LTS image
Write-host "downloading Ubuntu 16.04-LTS Image"
invoke-webrequest https://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip -OutFile "C:\Temp\ubuntu.zip"
cd C:\Temp
expand-archive ubuntu.zip -DestinationPath . -Force
Write-host "Adding Ubuntu image to Azure Stack"
Add-AzsVMimage -publisher "Canonical" -offer "UbuntuServer" -sku "16.04-LTS" -version "1.0.0" -osType Linux -osDiskLocal 'C:\Temp\xenial-server-cloudimg-amd64-disk1.vhd'
del ubuntu.zip -Force
del xenial-server-cloudimg-amd64-disk1.vhd -Force

# Create VM Scale Set marketplatce item
Add-AzsVMSSGalleryItem -Location local

# Install MySQL Resource Provider
Write-host "downloading and installing MySQL resource provider"
Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $Azscredential
Invoke-WebRequest https://aka.ms/azurestackmysqlrp -OutFile "c:\temp\MySql.zip"
cd C:\Temp
expand-archive c:\temp\MySql.zip -DestinationPath .\MySQL -Force
cd C:\Temp\MySQL
$vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("cloudadmin", $vmLocalAdminPass)
$PfxPass = ConvertTo-SecureString "$rppassword" -AsPlainText -Force
.\DeployMySQLProvider.ps1 -AzCredential $Azscredential -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $AZDCredential -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $PfxPass -AcceptLicense

# Install SQL Resource Provider
Write-host "downloading and installing SQL resource provider"
Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $Azscredential
cd C:\Temp
Invoke-WebRequest https://aka.ms/azurestacksqlrp -OutFile "c:\Temp\sql.zip"
expand-archive c:\temp\Sql.zip -DestinationPath .\SQL -Force
cd C:\Temp\SQL
$vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("cloudadmin", $vmLocalAdminPass)
$PfxPass = ConvertTo-SecureString "$rppassword" -AsPlainText -Force
.\DeploySQLProvider.ps1 -AzCredential $Azscredential -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $AZDCredential -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $PfxPass

# Register resources providers
foreach($s in (Get-AzureRmSubscription)) {
Select-AzureRmSubscription -SubscriptionId $s.SubscriptionId | Out-Null
Write-Progress $($s.SubscriptionId + " : " + $s.SubscriptionName)
Get-AzureRmResourceProvider -ListAvailable | Register-AzureRmResourceProvider
} 

# Deploy a mysql VM for hosting tenant db
Write-host "Creating a dedicated MySQL host VM for database hosting"
New-AzureRmResourceGroup -Name MySQL-Host -Location local
New-AzureRmResourceGroupDeployment -Name MySQLHost -ResourceGroupName MySQL-Host -TemplateUri https://raw.githubusercontent.com/alainv-msft/Azure-Stack/master/Templates/MySQL/azuredeploy.json -vmName "mysqlhost1" -adminUsername "cloudadmin" -adminPassword $vmlocaladminpass -vmSize Standard_A2 -windowsOSVersion '2016-Datacenter' -mode Incremental -Verbose

# Create SKU and add host server to mysql RP - requires fix
#Write-Host "Attaching MySQL hosting server to MySQL resource provider"
#New-AzureRmResourceGroupDeployment -ResourceGroupName mysql-host -TemplateUri https://raw.githubusercontent.com/alainv-msft/Azure-Stack/master/Templates/mysqladapter-add-hosting-server/azuredeploy.json -username "mysqlrpadmin" -password $vmLocalAdminPass -totalSpaceMB 10240 -skuName MySQL57 -Mode Incremental -Verbose

# Deploy a SQL 2014 VM for hosting tenant db
Write-Host "Creating a dedicated SQL 2014 host for database hosting"
New-AzureRmResourceGroup -Name SQL-Host -Location local
New-AzureRmResourceGroupDeployment -Name sqlhost1 -ResourceGroupName SQL-Host -TemplateUri https://raw.githubusercontent.com/alainv-msft/Azure-Stack/master/Templates/SQL2014/azuredeploy.json -adminPassword $vmlocaladminpass -adminUsername "cloudadmin" -windowsOSVersion "2016-Datacenter" -Mode Incremental -Verbose

# Create SKU and add host server to sql RP - requires fix
#Write-Host "Attaching SQL hosting server to SQL resource provider"
#New-AzureRmResourceGroupDeployment -ResourceGroupName sql-host -TemplateUri https://raw.githubusercontent.com/alainv-msft/Azure-Stack/master/Templates/sqladapter-add-hosting-server/azuredeploy.json -hostingServerSQLLoginName "sa" -hostingServerSQLLoginPassword $vmLocalAdminPass -totalSpaceMB 10240 -skuName SQL2014 -Mode Incremental -Verbose

# deploy prerequisites for app service
Write-Host "deploying file server"
New-AzureRmResourceGroup -Name appservice-fileshare -Location local
New-AzureRmResourceGroupDeployment -Name fileshareserver -ResourceGroupName appservice-fileshare -TemplateUri https://raw.githubusercontent.com/alainv-msft/Azure-Stack/master/Templates/appservice-fileserver-standalone/azuredeploy.json -adminPassword $vmLocalAdminPass -fileShareOwnerPassword $vmLocalAdminPass -fileShareUserPassword $vmLocalAdminPass -Mode Incremental -Verbose 
Write-Host "deploying sql server for appservice"
New-AzureRmResourceGroup -Name appservice-sql -Location local
New-AzureRmResourceGroupDeployment -Name sqlapp -ResourceGroupName appservice-sql -TemplateUri https://raw.githubusercontent.com/alainv-msft/Azure-Stack/master/Templates/SQL2014/azuredeploy.json -adminPassword $vmlocaladminpass -adminUsername "cloudadmin" -windowsOSVersion "2016-Datacenter" -vmName "sqlapp" -dnsNameForPublicIP "sqlapp" -Mode Incremental -Verbose

# install App Service To be added
Write-host "downloading appservice installer"
cd C:\Temp
Invoke-WebRequest https://aka.ms/appsvconmashelpers -OutFile "c:\temp\appservicehelper.zip"
Expand-Archive C:\Temp\appservicehelper.zip -DestinationPath .\AppService\ -Force
Invoke-WebRequest http://aka.ms/appsvconmasrc1installer -OutFile "c:\temp\AppService\appservice.exe"
Write-Host "generating certificates"
cd C:\Temp\AppService
.\Create-AppServiceCerts.ps1 -PfxPassword $vmLocalAdminPass -DomainName "local.azurestack.external"
.\Get-AzureStackRootCert.ps1 -PrivilegedEndpoint $ERCSip -CloudAdminCredential $AZDCredential

# Configure a simple base plan and offer for IaaS
Import-Module C:\AzureStack-Tools\Connect\AzureStack.Connect.psm1
Import-Module C:\AzureStack-Tools\ServiceAdmin\AzureStack.ServiceAdmin.psm1
Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $Azscredential

# Default quotas, plan, and offer
$PlanName = "SimplePlan"
$OfferName = "SimpleOffer"
$RGName = "PlansandoffersRG"
$Location = (Get-AzsLocation).Name

$computeParams = @{
Name = "computedefault"
CoresLimit = 200
AvailabilitySetCount = 20
VirtualMachineCount = 100
VmScaleSetCount = 20
Location = $Location
}

$netParams = @{
Name = "netdefault"
PublicIpsPerSubscription = 500
VNetsPerSubscription = 500
GatewaysPerSubscription = 10
ConnectionsPerSubscription = 20
LoadBalancersPerSubscription = 500
NicsPerSubscription = 1000
SecurityGroupsPerSubscription = 500
Location = $Location
}

$storageParams = @{
Name = "storagedefault"
NumberOfStorageAccounts = 200
CapacityInGB = 2048
Location = $Location
}

$kvParams = @{
Location = $Location
}

$quotaIDs = @()
$quotaIDs += (New-AzsNetworkQuota @netParams).ID
$quotaIDs += (New-AzsComputeQuota @computeParams).ID
$quotaIDs += (New-AzsStorageQuota @storageParams).ID
$quotaIDs += (Get-AzsKeyVaultQuota @kvParams)

New-AzureRmResourceGroup -Name $RGName -Location $Location
$plan = New-AzsPlan -Name $PlanName -DisplayName $PlanName -ArmLocation $Location -ResourceGroupName $RGName -QuotaIds $QuotaIDs
New-AzsOffer -Name $OfferName -DisplayName $OfferName -State Public -BasePlanIds $plan.Id -ResourceGroupName $RGName -ArmLocation $Location

# Install useful ASDK Host Apps via Chocolatey
Set-ExecutionPolicy Unrestricted -Force
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Enable Choco Global Confirmation
Write-host "Enabling global confirmation to streamline installs"
choco feature enable -n allowGlobalConfirmation

# Visual Studio Code
Write-host "Installing VS Code with Chocolatey"
choco install visualstudiocode

# Putty
Write-host "Installing Putty with Chocolatey"
choco install putty.install

# WinSCP
Write-host "Installing WinSCP with Chocolatey"
choco install winscp.install 

# Chrome
Write-host "Installing Chrome with Chocolatey"
choco install googlechrome

# Azure CLI
Write-host "Installing latest version of Azure CLI"
invoke-webrequest https://aka.ms/InstallAzureCliWindows -OutFile C:\AzureCLI.msi
msiexec.exe /qb-! /i C:\AzureCli.msi

Write-host "Setting Execution Policy back to RemoteSigned"
Set-ExecutionPolicy RemoteSigned -Confirm:$false -Force
