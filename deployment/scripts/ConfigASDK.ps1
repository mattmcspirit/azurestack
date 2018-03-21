
<#

.SYNOPSYS

    The purpose of this script is to automate as much as possible post deployment tasks in Azure Stack Development Kit
    This include :
        - Set password expiration
        - Disable Windows Update on all infrastructures VMs and ASDK host
        - Tools installation (git, azstools, Azure Stack PS module)
        - Windows Server 2016 and Ubuntu 16.04-LTS images installation
        - Creates VM scale set gallery item
        - MySQL Resource Provider Installation
        - SQL Resource Provider Installation
        - Deployment of a MySQL 5.7 hosting Server on Windows Server 2016 Core (with latest CU Updates)
        - Deployment of a SQL 2014 hosting server on Windows Server 2016 (with latest CU Updates)
        - AppService prerequisites installation (SQL Server and Standalone File Server)
        - AppService Resource Provider sources download and certificates generation
        - Set new default Quotas for Compute, Network, Storage and Key Vault

.VERSION

    3.0  major update for ASDK release 20180302.1
    2.0  update for release 1.0.280917.3 
    1.0: small bug fixes and adding quotas/plan/offer creation
    0.5: add SQL 2014 VM deployment
    0.4: add Windows update disable
    0.3: Bug fix (SQL Provider prompting for tenantdirectoryID)
    0.2: Bug Fix (AZStools download)

.AUTHOR

    Matt McSpirit
    Blog: http://www.mattmcspirit.com
    Email: matt.mcspirit@microsoft.com 
    Twitter: @mattmcspirit

.PARAMETERS

    -ASDK (Specify this is for an ASDK deployment - this switch may be expanded in future to include Multinode deployments)
    -azureDirectoryTenantName - (Name of your AAD Tenant which your Azure subscription is a part of. This parameter is mandatory)
    -authenticationType - (Either AzureAd or ADFS - which one that is entered will determine which ARM endpoints are used)
	-rppassword -  ("yourpassword" this will be the administrator password for every virtual machine deployed to support PaaS Services)
	-ISOPath ("c:\xxxx\xxx.iso" specify the path to your Windows Server 2016 Datacenter Evaluation ISO)

.EXAMPLE

	ConfigASDK.ps1 -azureDirectoryTenantName "contoso.onmicrosoft.com" -authenticationType "AzureAD" -rppassword "yourpassword" -ISOPath "c:\mywin2016eval.iso" -verbose

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

    # For ASDK deployment - this switch may be expanded in future for Multinode deployments
    [switch]$ASDK,

    [Parameter(Mandatory = $true)]
    [String] $azureDirectoryTenantName,

    [Parameter(Mandatory = $true)]
    [ValidateSet("AzureAd", "ADFS")]
    [String] $authenticationType,

    # Provide Local Administrator password for App Service, MySQL and SQL VMs.
    #[parameter(Mandatory = $true)]
    #[Security.SecureString]$rppassword,

    # Path to Windows Server 2016 Datacenter evaluation iso
    [parameter(Mandatory = $true)]
    [string]$ISOPath

)

function Select-Folder {
    [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $browse = New-Object System.Windows.Forms.FolderBrowserDialog
    $browse.SelectedPath = "C:\"
    $browse.ShowNewFolderButton = $True
    $browse.Description = "Select a directory to store your downloads - You must have administrative permission to store files in this location"

    $loop = $true
    while ($loop) {
        if ($browse.ShowDialog() -eq "OK") {
            $loop = $false
        }
        else {
            $res = [System.Windows.Forms.MessageBox]::Show("You clicked Cancel. Would you like to try again or exit?", "Select a location", [System.Windows.Forms.MessageBoxButtons]::RetryCancel)
            if ($res -eq "Cancel") {
                return
            }
        }
    }
    $browse.SelectedPath
    $browse.Dispose()
}

$VerbosePreference = "SilentlyContinue"
$ErrorActionPreference = 'Stop'

##############################################################################################################################################################
##############################################################################################################################################################

### DISPLAY INTRO TEXT AND DELAY ###

Write-Host "`n`nWELCOME TO THE AZURE STACK ASDK CONFIGURATOR`nVersion: 3.0.0" -ForegroundColor Green
Write-Host "`nThis script can be used to automate (mostly) the setup a Proof of Concept (POC) environment containing an
SQL Server, MySQL Server and the core PaaS Services, such as the Azure App Service and Azure Functions on Azure Stack.`r`n
This Configurator will perform the following tasks:`n"
Write-Host "1) Download the appropriate Azure Stack Tools and PowerShell Modules for Administration
2) Securely login to your Azure Stack environment, through either ADFS or Azure AD credentials
3) TBC
4) TBC
`n" -ForegroundColor White

Pause

### CLEAR SCREEN ###
Clear-Host

### GET START TIME ###
$Time1 = Get-Date -format HH:mm:ss

### SET LOCATION ###
$ScriptLocation = Get-Location

### DOWNLOAD & EXTRACT TOOLS ###
# Change directory to the root directory 
Set-Location C:\

### Gather Credentials ###
Write-Host "You will now be asked to supply a number of credentials, used throughout the deployment"
Start-Sleep -Seconds 3
$vmLocalAdminPass = Read-Host "Provide a password for the SQL Server, MySQL Server and App Service Virtual Machines" -AsSecureString
$DeploymentUsername = "AzureStack\AzureStackAdmin"
$DeploymentPassword = Read-Host "Provide the password for the AzureStack\AzureStackAdmin account, used when you deployed the Azure Stack Development Kit" -AsSecureString
$DeploymentCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DeploymentUsername,$DeploymentPassword 

if ($authenticationType.ToString() -like "AzureAd") {
    $ServiceAdminUsername = Read-Host "Provide the Azure Stack Service Administrator username, in the form username@<mydirectorytenant>.onmicrosoft.com"
    $ServiceAdminPassword = Read-Host "Provide the password for the Azure Stack Service Administrator account" -AsSecureString
    $AzureAdCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ServiceAdminUsername,$ServiceAdminPassword 
}

# Download the tools archive
Write-Host "Downloading Azure Stack Tools to ensure you have the latest versions.`nThis may take a few minutes, depending on your connection speed."
Start-Sleep -Seconds 5
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
invoke-webrequest https://github.com/Azure/AzureStack-Tools/archive/master.zip -OutFile master.zip -ErrorAction Stop

# Expand the downloaded files
Write-Host "Expanding Archive"
Start-Sleep -Seconds 3
expand-archive master.zip -DestinationPath . -Force
Write-Host "Archive expanded. Cleaning up."
Remove-Item master.zip -ErrorAction Stop
Start-Sleep -Seconds 3

# Change to the tools directory
Write-Host "Changing Directory"
Set-Location C:\AzureStack-Tools-master

# Import the Azure Stack Connect and Compute Modules
Import-Module .\Connect\AzureStack.Connect.psm1
Import-Module .\ComputeAdmin\AzureStack.ComputeAdmin.psm1
Disable-AzureRmDataCollection -WarningAction SilentlyContinue
Write-Host "Azure Stack Connect and Compute modules imported successfully"

# Variables that should not be changed (for ASDK)
$ERCSip = "192.168.200.225"

### CONFIGURE THE AZURE STACK HOST & INFRA VIRTUAL MACHINES ###

# Set password expiration to 180 days
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
    Get-Service -Name wuauserv | Format-List StartType, Status
}
foreach ($vm in $AZSvms) {
    Invoke-Command -VMName $vm.name -ScriptBlock $scriptblock -Credential $DeploymentCreds
}
sc.exe config wuauserv start=disabled

# Disable DNS Server on host
Write-Host "Disabling DNS Server on ASDK Host"
Stop-Service -Name DNS -Force -Confirm:$false
Set-Service -Name DNS -startuptype disabled -Confirm:$false

Write-Host "Host configuration is now complete. Starting Services configuration"
Start-Sleep -Seconds 3

### CONNECT TO AZURE STACK ###
# Register an AzureRM environment that targets your administrative Azure Stack instance

Write-Host "You will now be prompted to log in to your Azure Stack environment"
Start-Sleep -Seconds 3
$ArmEndpoint = "https://adminmanagement.local.azurestack.external"
Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop

# Add GraphEndpointResourceId value for Azure AD or ADFS and obtain Tenant ID, then login to Azure Stack
if ($authenticationType.ToString() -like "AzureAd") {
    Write-Host ("Azure Active Directory selected by Administrator")
    Set-AzureRmEnvironment -Name "AzureStackAdmin" -GraphAudience "https://graph.windows.net/" -ErrorAction Stop
    Write-Host ("Setting GraphEndpointResourceId value for Azure AD")
    Write-Host ("Getting Tenant ID for Login to Azure Stack")
    $TenantID = Get-AzsDirectoryTenantId -AADTenantName $azureDirectoryTenantName -EnvironmentName "AzureStackAdmin"
    Write-Host "Logging in with your Azure Stack Administrator Account used with Azure Active Directory"
    Start-Sleep -Seconds 3
    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $AzureADCreds -ErrorAction Stop
}
elseif ($authenticationType.ToString() -like "ADFS") {
    Write-Host ("Active Directory Federation Services selected by Administrator")
    $AZScredential = $AZDCredential
    Set-AzureRmEnvironment -Name "AzureStackAdmin" -GraphAudience "https://graph.local.azurestack.external/" -EnableAdfsAuthentication:$true
    Write-Host ("Setting GraphEndpointResourceId value for ADFS")
    Write-Host ("Getting Tenant ID for Login to Azure Stack")
    $TenantID = Get-AzsDirectoryTenantId -ADFS -EnvironmentName "AzureStackAdmin"
    Write-Host "Logging in with your Azure Stack Administrator Account used with ADFS"
    Start-Sleep -Seconds 3
    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $DeploymentCreds -ErrorAction Stop
}
else {
    Write-Host ("No valid authentication types specified - please use AzureAd or ADFS") -ForegroundColor Red -ErrorAction Stop
}

##############################################################################################################################################################
##############################################################################################################################################################

### HOST CONFIGURATION COMPLETED ###

# Query existing Platform Image Repository for Compatible Ubuntu Server 16.04 LTS Image
# If existing image is in place, use the existing image, otherwise, download from Ubuntu and upload into the Platform Image Repository

Write-Host "Checking to see if an Ubuntu Server 16.04-LTS VM Image is present in your Azure Stack Platform Image Repository"
Start-Sleep -Seconds 5

$platformImage = Get-AzureRmVMImage -Location "local" -PublisherName Canonical -Offer UbuntuServer -Skus "16.04-LTS" -ErrorAction SilentlyContinue
$platformImageTable = $platformImage | Sort-Object Version
$platformImageTableTop1 = $platformImageTable | Select-Object -Last 1

if ($platformImage -ne $null -and $platformImage.StatusCode -eq "OK") {
    Write-Host "There appears to be at least 1 suitable Ubuntu Server 16.04-LTS VM image within your Platform Image Repository `nwhich we will use for the DevOps Toolkit. Here are the details:" -ForegroundColor Green
    Start-Sleep -Seconds 1
    Write-Output $platformImageTable | Format-Table location, Offer, PublisherName, Skus, Version
    Start-Sleep -Seconds 1
    Write-Host "The DevOps Toolkit will automatically use the latest Ubuntu Server 16.04-LTS version from this list, which will be:"
    Write-Output $platformImageTableTop1 | Format-Table location, Offer, PublisherName, Skus, Version
    Start-Sleep -Seconds 1
    Write-Host "The DevOps Toolkit is now ready to begin uploading packages for DevOps tools to the Azure Stack Marketplace"
    Start-Sleep -Seconds 5
    Write-Host "Select a folder to store your Azure Stack Marketplace packages"
    Start-Sleep -Seconds 5
}
else {
    Write-Host "No existing suitable Ubuntu Server 1604-LTS VM image exists." -ForegroundColor Red
    Start-Sleep -Seconds 2
    Write-Host "The Ubuntu Server VM Image in the Azure Stack Platform Image Repository must have the following properties:"
    Write-Host "Publisher Name = Canonical"
    Write-Host "Offer = UbuntuServer"
    Write-Host "SKU = 16.04-LTS"
    Start-Sleep -Seconds 2
    Write-Host "Unfortunately, no image was found with these properties. Beginning download of Ubuntu Server VHD Zip file`n"
    Start-Sleep -Seconds 3
    Write-Host "Downloading Ubuntu Server 16.04-LTS - Select a Download Folder. Note, the dialog bvox may appear behind the PowerShell console window."
    Start-Sleep -Seconds 3
        
    # Execute the Find-Folders function to obtain a desired storage location from the user
    $SetFilePath = Select-Folder
    if (!$SetFilePath) {
        Write-Host "No valid folder path was selected. Please select a valid folder to store the VHD"
        $SetFilePath = Select-Folder
        if (!$SetFilePath) {
            Write-Host "No valid folder path was selected again. Exiting process..." -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    else {
        # Check if ASDK Configurator folder needs creating or not
        Write-Host "Checking to see if the ASDKconfig folder exists"
        Start-Sleep -Seconds 5
        if (-not (test-path "$SetFilePath\ASDKconfig")) {
            # Create the ASDK Configurator folder.
            Write-Host "ASDK Configurator folder doesn't exist, creating it"
            mkdir "$SetFilePath\ASDKconfig" -Force 
            $UpdatedFilePath = "$SetFilePath\ASDKconfig"
        }
        elseif (test-path "$SetFilePath\ASDKconfig") {
            # No need to create the ASDK Configurator folder as it already exists. Set $UpdatedFilePath to the new location.
            Write-Host "ASDK Configurator folder exists, no need to create it"
            Start-Sleep -Seconds 1
            Write-Host "ASDK Configurator folder is within $SetFilePath"
            Start-Sleep -Seconds 1
            $UpdatedFilePath = Set-Location -Path "$SetFilePath\ASDKconfig" -PassThru
            Write-Host "ASDK Configurator folder full path is $UpdatedFilePath"
        }
        # Check if VHD exists that matches previously extracted VHD in the ASDK Configurator folder.
        Write-Host "Checking to see if the Ubuntu Server VHD already exists in ASDK Configurator folder"
        Start-Sleep -Seconds 5
        if (Test-Path "$UpdatedFilePath\UbuntuServer.vhd") {
            # If VHD exists, update the $UbuntuServerVHD variable with the correct name and path.
            Write-Host "Located Ubuntu Server VHD in this folder. No need to download again..."
            Start-Sleep -Seconds 3
            $UbuntuServerVHD = Get-ChildItem -Path "$UpdatedFilePath\UbuntuServer.vhd"
            Start-Sleep -Seconds 3
            Write-Host "Ubuntu Server VHD located at $UbuntuServerVHD"
        }
        elseif (Test-Path "$UpdatedFilePath\UbuntuServer.zip") {
            # If VHD exists, update the $UbuntuServerVHD variable with the correct name and path.
            Write-Host "Cannot find a previously extracted Ubuntu Server VHD with name UbuntuServer.vhd"
            Write-Host "Checking to see if the Ubuntu Server ZIP already exists in ASDK Configurator folder"
            Start-Sleep -Seconds 3
            $UbuntuServerZIP = Get-ChildItem -Path "$UpdatedFilePath\UbuntuServer.zip"
            Start-Sleep -Seconds 3
            Write-Host "Ubuntu Server ZIP located at $UbuntuServerZIP"
            Expand-Archive -Path "$UpdatedFilePath\UbuntuServer.zip" -DestinationPath $UpdatedFilePath -Force -ErrorAction Stop
            $UbuntuServerVHD = Get-ChildItem -Path "$UpdatedFilePath" -Filter *.vhd | Rename-Item -NewName UbuntuServer.vhd -PassThru -Force -ErrorAction Stop
        }
        else {
            # No existing Ubuntu Server VHD or Zip exists that matches the name (i.e. that has previously been extracted and renamed) so a fresh one will be
            # downloaded, extracted and the variable $UbuntuServerVHD updated accordingly.
            Write-Host "Cannot find a previously extracted Ubuntu Server download"
            Write-Host "Begin download of correct Ubuntu Server ZIP and extraction of VHD"
            Start-Sleep -Seconds 5
            Invoke-Webrequest http://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip -OutFile "$UpdatedFilePath\UbuntuServer.zip" -ErrorAction Stop
            Expand-Archive -Path "$UpdatedFilePath\UbuntuServer.zip" -DestinationPath $UpdatedFilePath -Force -ErrorAction Stop
            $UbuntuServerVHD = Get-ChildItem -Path "$UpdatedFilePath" -Filter *.vhd | Rename-Item -NewName UbuntuServer.vhd -PassThru -Force -ErrorAction Stop
        }
        # Upload the image to the Azure Stack Platform Image Repository

        Write-Host "Extraction Complete. Beginning upload of VHD to Platform Image Repository"
        Start-Sleep -Seconds 5
        Add-AzsVMImage -publisher Canonical -offer UbuntuServer -sku 16.04-LTS -version 1.0.0 -osType Linux -osDiskLocalPath "$UbuntuServerVHD" -CreateGalleryItem $False -ErrorAction Stop
        $platformImage = Get-AzureRmVMImage -Location "local" -PublisherName Canonical -Offer UbuntuServer -Skus "16.04-LTS" -ErrorAction SilentlyContinue
        if ($platformImage -ne $null -and $platformImage.StatusCode -eq "OK") {
            Write-Host "Ubuntu Server image successfully uploaded to the Platform Image Repository."
            Write-Host "Cleaning up local hard drive space - deleting VHD file, but keeping ZIP "
            Remove-Item *.vhd -Force
            Write-Host "Now ready to begin uploading packages to the Azure Stack Marketplace"
        }
        Start-Sleep -Seconds 5
    }
}

# Create Ubuntu Server Gallery Item
$UbuntuGalleryItemURI = 'https://mystorageaccount.blob.local.azurestack.external/cont1/Microsoft.WindowsServer2016DatacenterServerCore-ARM.1.0.2.azpkg'
$UbuntuUpload = Add-AzsGalleryItem -GalleryItemUri $UbuntuGalleryItemURI -Verbose
Start-Sleep 5
$Retries = 0
# Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
While ($UbuntuUpload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
    Write-Host "Ubuntu Server 16.04 LTS wasn't added to the gallery successfully. Retry Attempt #$Retries" -ForegroundColor Yellow
    $UbuntuUpload = Add-AzsGalleryItem -GalleryItemUri $UbuntuGalleryItemURI
    Start-Sleep 5
}
Write-Host "Successfully added Ubuntu Server 16.04 LTS to the Azure Stack Marketplace Gallery" -ForegroundColor Green

# Create Windows Server 2016 Images
Write-host "Installing Windows Server 2016 Datacenter full and Core images"
$UpdateUri = 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/03/windows10.0-kb4088787-x64_76e9d6684e0a004f51ea7373e4ea6217193c1b5e.msu'
New-AzsServer2016VMImage -ISOPath $ISOPath -Version Both -CUUri $UpdateUri -Net35 $true -CreateGalleryItem $true
Remove-Item *.vhd -Force
Remove-Item *.msu -Force
Remove-Item *.cab -Force

# Create Windows Server 2016 Full Gallery Item
$WSGalleryItemURI = 'https://mystorageaccount.blob.local.azurestack.external/cont1/Microsoft.WindowsServer2016DatacenterServerCore-ARM.1.0.2.azpkg'
$WSUpload = Add-AzsGalleryItem -GalleryItemUri $WSGalleryItemURI -Verbose
Start-Sleep 5
$Retries = 0
# Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
While ($WSUpload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
    Write-Host "Windows Server 2016 wasn't added to the gallery successfully. Retry Attempt #$Retries" -ForegroundColor Yellow
    $WSUpload = Add-AzsGalleryItem -GalleryItemUri $WSGalleryItemURI
    Start-Sleep 5
}
Write-Host "Successfully added Windows Server 2016 to the Azure Stack Marketplace Gallery" -ForegroundColor Green

# Create Windows Server 2016 Core Gallery Item
$WSCoreGalleryItemURI = 'https://mystorageaccount.blob.local.azurestack.external/cont1/Microsoft.WindowsServer2016DatacenterServerCore-ARM.1.0.2.azpkg'
$WSCoreUpload = Add-AzsGalleryItem -GalleryItemUri $WSCoreGalleryItemURI -Verbose
Start-Sleep 5
$Retries = 0
# Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
While ($WSCoreUpload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
    Write-Host "Windows Server 2016 Core wasn't added to the gallery successfully. Retry Attempt #$Retries" -ForegroundColor Yellow
    $WSCoreUpload = Add-AzsGalleryItem -GalleryItemUri $WSCoreGalleryItemURI
    Start-Sleep 5
}
Write-Host "Successfully added Windows Server 2016 Core to the Azure Stack Marketplace Gallery" -ForegroundColor Green

# Create VM Scale Set marketplatce item
Write-host "Creating VM Scale Set Marketplace Item"
Add-AzsVMSSGalleryItem -Location local

##############################################################################################################################################################
##############################################################################################################################################################

### BASE VM IMAGES COMPLETED ###

# Install MySQL Resource Provider
Write-host "Downloading and installing MySQL resource provider"
Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $Azscredential
Invoke-WebRequest https://aka.ms/azurestackmysqlrp -OutFile "c:\temp\MySql.zip"
Set-Location C:\Temp
expand-archive c:\temp\MySql.zip -DestinationPath .\MySQL -Force
Set-Location C:\Temp\MySQL
$vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("cloudadmin", $vmLocalAdminPass)
$PfxPass = ConvertTo-SecureString "$rppassword" -AsPlainText -Force
.\DeployMySQLProvider.ps1 -AzCredential $Azscredential -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $AZDCredential -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $PfxPass -AcceptLicense

# Install SQL Resource Provider
Write-host "downloading and installing SQL resource provider"
Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $Azscredential
Set-Location C:\Temp
Invoke-WebRequest https://aka.ms/azurestacksqlrp -OutFile "c:\Temp\sql.zip"
expand-archive c:\temp\Sql.zip -DestinationPath .\SQL -Force
Set-Location C:\Temp\SQL
$vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("cloudadmin", $vmLocalAdminPass)
$PfxPass = ConvertTo-SecureString "$rppassword" -AsPlainText -Force
.\DeploySQLProvider.ps1 -AzCredential $Azscredential -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $AZDCredential -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $PfxPass

# Register resources providers
foreach ($s in (Get-AzureRmSubscription)) {
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
Set-Location C:\Temp
Invoke-WebRequest https://aka.ms/appsvconmashelpers -OutFile "c:\temp\appservicehelper.zip"
Expand-Archive C:\Temp\appservicehelper.zip -DestinationPath .\AppService\ -Force
Invoke-WebRequest http://aka.ms/appsvconmasrc1installer -OutFile "c:\temp\AppService\appservice.exe"
Write-Host "generating certificates"
Set-Location C:\Temp\AppService
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
    Name                 = "computedefault"
    CoresLimit           = 200
    AvailabilitySetCount = 20
    VirtualMachineCount  = 100
    VmScaleSetCount      = 20
    Location             = $Location
}

$netParams = @{
    Name                          = "netdefault"
    PublicIpsPerSubscription      = 500
    VNetsPerSubscription          = 500
    GatewaysPerSubscription       = 10
    ConnectionsPerSubscription    = 20
    LoadBalancersPerSubscription  = 500
    NicsPerSubscription           = 1000
    SecurityGroupsPerSubscription = 500
    Location                      = $Location
}

$storageParams = @{
    Name                    = "storagedefault"
    NumberOfStorageAccounts = 200
    CapacityInGB            = 2048
    Location                = $Location
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
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

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
