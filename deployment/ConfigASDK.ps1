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
param (
    # For ASDK deployment - this switch may be expanded in future for Multinode deployments
    [switch]$ASDK,

    [Parameter(Mandatory = $true)]
    [String] $azureDirectoryTenantName,

    [Parameter(Mandatory = $true)]
    [ValidateSet("AzureAd", "ADFS")]
    [String] $authenticationType,

    # Path to store downloaded files
    [parameter(Mandatory = $true)]
    [String]$downloadPath,

    # Path to Windows Server 2016 Datacenter Evaluation ISO file
    [parameter(Mandatory = $true)]
    [String]$ISOPath,

    # Password used for deployment of the ASDK.
    [parameter(Mandatory = $false)]
    [String]$azureStackAdminPwd,

    # Provide Local Administrator password for App Service, MySQL and SQL VMs.
    [parameter(Mandatory = $false)]
    [String]$VMpwd,

    # Username for Azure AD Login - username@<directoryname>.onmicrosoft.com
    [parameter(Mandatory = $false)]
    [string]$azureAdUsername,

    # Password for Azure AD login
    [parameter(Mandatory = $false)]
    [string]$azureAdPwd,

    # If you want the script to register the ASDK for you, use this flag
    [switch]$registerASDK,

    # If you want to use the same Azure AD creds that you used to deploy Azure Stack, to register it, set this flag
    [switch]$useAzureCredsForRegistration,

    # Username for Azure Subscription Login for registering Azure Stack - username@<directoryname>.onmicrosoft.com
    [parameter(Mandatory = $false)]
    [string]$azureRegUsername,
    
    # Password for Azure Subscription Login for registering Azure Stack
    [parameter(Mandatory = $false)]
    [string]$azureRegPwd,

    # Password for Azure Subscription Login for registering Azure Stack
    [parameter(Mandatory = $false)]
    [string]$azureRegSubId
)

$VerbosePreference = "Continue"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

### GET START TIME ###
$startTime = Get-Date -format HH:mm:ss

### SET LOCATION ###
$ScriptLocation = Get-Location

### SET ERCS IP Address - same for all default ASDKs ###
$ERCSip = "192.168.200.225"

# Define Regex for Password Complexity - needs to be at least 8 characters, with at least 1 upper case, 1 lower case and 1 special character
$regex = @"
^.*(?=.{8,})(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&£*\-_+=[\]{}|\\:',?/`~"();!]).*$
"@

$emailRegex = @"
(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])
"@

### PARAMATER VALIDATION #####################################################################################################################################
##############################################################################################################################################################

### Validate Download Path ###

Clear-Host
Write-Verbose "Selected identity provider is $authenticationType"
Write-Verbose "Checking to see if the Download Path exists"

$validDownloadPath = [System.IO.Directory]::Exists($downloadPath)
If ($validDownloadPath -eq $true) {
    Write-Verbose "Download path exists and is valid" 
    Write-Verbose "Files will be stored at $downloadPath" 
    $downloadPath = Set-Location -Path "$downloadPath" -PassThru
}
elseif ($validDownloadPath -eq $false) {
    $downloadPath = Read-Host "Download path is invalid - please enter a valid path to store your downloads"
    $validDownloadPath = [System.IO.Directory]::Exists($downloadPath)
    if ($validDownloadPath -eq $false) {
        Write-Verbose "No valid folder path was entered again. Exiting process..." -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
    elseif ($validDownloadPath -eq $true) {
        Write-Verbose "Download path exists and is valid" 
        Write-Verbose "Files will be stored at $downloadPath" 
        $downloadPath = Set-Location -Path "$downloadPath" -PassThru
    }
}

### Validate path to ISO File ###

Write-Verbose "Checking to see if the path to the ISO exists"

$validISOPath = [System.IO.File]::Exists($ISOPath)
$validISOfile = [System.IO.Path]::GetExtension("$ISOPath")

If ($validISOPath -eq $true -and $validISOfile -eq ".iso") {
    Write-Verbose "Found path to valid ISO file" 
    $ISOPath = [System.IO.Path]::GetFullPath($ISOPath)
    Write-Verbose "The Windows Server 2016 Eval found at $ISOPath will be used" 
}
elseif ($validISOPath -eq $false -or $validISOfile -ne ".iso") {
    $ISOPath = Read-Host "ISO path is invalid - please enter a valid path to the Windows Server 2016 ISO"
    $validISOPath = [System.IO.File]::Exists($ISOPath)
    $validISOfile = [System.IO.Path]::GetExtension("$ISOPath")
    if ($validISOPath -eq $false -or $validISOfile -ne ".iso") {
        Write-Verbose "No valid path to a Windows Server 2016 ISO was entered again. Exiting process..." -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
    elseif ($validISOPath -eq $true -and $validISOfile -eq ".iso") {
        Write-Verbose "Found path to valid ISO file" 
        $ISOPath = [System.IO.Path]::GetFullPath($ISOPath)
        Write-Verbose "The Windows Server 2016 Eval found at $ISOPath will be used" 
    }
}

### Validate Virtual Machine (To be created) Password ###

if ([string]::IsNullOrEmpty($VMpwd)) {
    Write-Verbose "You didn't enter a password for the virtual machines that the ASDK configurator will create." 
    $secureVMpwd = Read-Host "Please enter a password for the virtual machines that will be created during this process" -AsSecureString -ErrorAction Stop
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureVMpwd)            
    $VMpwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
}

Write-Verbose "Checking to see if Virtual Machine password is strong..."

if ($VMpwd -cmatch $regex -eq $true) {
    Write-Verbose "Virtual Machine password meets desired complexity level" 
    # Convert plain text password to a secure string
    $secureVMpwd = ConvertTo-SecureString -AsPlainText $VMpwd -Force
}

elseif ($VMpwd -cmatch $regex -eq $false) {
    Write-Verbose "Virtual Machine password doesn't meet complexity requirements, it needs to be at least 8 characters, with at least 1 upper case, 1 lower case and 1 special character " 
    # Obtain new password and store as a secure string
    $secureVMpwd = Read-Host -AsSecureString "Enter VM password again"
    # Convert to plain text to test regex complexity
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureVMpwd)            
    $VMpwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
    if ($VMpwd -cmatch $regex -eq $true) {
        Write-Verbose "Virtual Machine password matches desired complexity" 
        # Convert plain text password to a secure string
        $secureVMpwd = ConvertTo-SecureString -AsPlainText $VMpwd -Force
        # Clean up unused variable
        Remove-Variable -Name VMpwd -ErrorAction SilentlyContinue
    }
    else {
        Write-Verbose "No valid password was entered again. Exiting process..." -ErrorAction Stop 
        Set-Location $ScriptLocation
        return
    }
}

### Validate Azure Stack Development Kit Deployment Credentials ###

if ([string]::IsNullOrEmpty($azureStackAdminPwd)) {
    Write-Verbose "You didn't enter the Azure Stack Development Kit Deployment password." 
    $secureAzureStackAdminPwd = Read-Host "Please enter the password used for the Azure Stack Development Kit Deployment, for account AzureStack\AzureStackAdmin" -AsSecureString -ErrorAction Stop
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureStackAdminPwd)            
    $azureStackAdminPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
}

Write-Verbose "Checking to see Azure Stack Admin password is strong..."

$azureStackAdminUsername = "AzureStack\AzureStackAdmin"
if ($azureStackAdminPwd -cmatch $regex -eq $true) {
    Write-Verbose "Azure Stack Development Kit Deployment password for AzureStack\AzureStackAdmin, meets desired complexity level" 
    # Convert plain text password to a secure string
    $secureAzureStackAdminPwd = ConvertTo-SecureString -AsPlainText $azureStackAdminPwd -Force
    $azureStackAdminCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $azureStackAdminUsername, $secureAzureStackAdminPwd -ErrorAction Stop
}

elseif ($azureStackAdminPwd -cmatch $regex -eq $false) {
    Write-Verbose "Azure Stack Development Kit Deployment password doesn't meet complexity requirements, it needs to be at least 8 characters, with at least 1 upper case, 1 lower case and 1 special character " 
    # Obtain new password and store as a secure string
    $secureAzureStackAdminPwd = Read-Host -AsSecureString "Enter Azure Stack Development Kit Deployment password again"
    # Convert to plain text to test regex complexity
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureStackAdminPwd)            
    $azureStackAdminPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
    if ($azureStackAdminPwd -cmatch $regex -eq $true) {
        Write-Verbose "Azure Stack Development Kit Deployment password for AzureStack\AzureStackAdmin, meets desired complexity level" 
        # Convert plain text password to a secure string
        $secureAzureStackAdminPwd = ConvertTo-SecureString -AsPlainText $azureStackAdminPwd -Force
        # Clean up unused variable
        Remove-Variable -Name azureStackAdminPwd -ErrorAction SilentlyContinue
        $azureStackAdminCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $azureStackAdminUsername, $secureAzureStackAdminPwd -ErrorAction Stop
    }
    else {
        Write-Verbose "No Azure Stack Development Kit Deployment password was entered again. Exiting process..." -ErrorAction Stop 
        Set-Location $ScriptLocation
        return
    }
}

### Validate Azure Stack Development Kit Service Administrator Credentials (AZURE AD ONLY) ###

if ($authenticationType.ToString() -like "AzureAd") {

    ### Validate Azure Stack Development Kit Service Administrator Username ###

    if ([string]::IsNullOrEmpty($azureAdUsername)) {
        Write-Verbose "You didn't enter a username for the Azure AD login." 
        $azureAdUsername = Read-Host "Please enter a username in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" -ErrorAction Stop
    }

    Write-Verbose "Checking to see if Azure Stack Development Kit Service Administrator username is correctly formatted..."

    if ($azureAdUsername -cmatch $emailRegex -eq $true) {
        Write-Verbose "Azure Stack Development Kit Service Administrator username is correctly formatted." 
        Write-Verbose "$azureAdUsername will be used to connect to Azure." 
    }

    elseif ($azureAdUsername -cmatch $emailRegex -eq $false) {
        Write-Verbose "Azure Stack Development Kit Service Administrator username isn't correctly formatted. It should be entered in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" 
        # Obtain new username
        $azureAdUsername = Read-Host "Enter Azure Stack Development Kit Service Administrator username again"
        if ($azureAdUsername -cmatch $emailRegex -eq $true) {
            Write-Verbose "Azure Stack Development Kit Service Administrator username is correctly formatted." 
            Write-Verbose "$azureAdUsername will be used to connect to Azure." 
        }
        else {
            Write-Verbose "No valid Azure Stack Development Kit Service Administrator username was entered again. Exiting process..." -ErrorAction Stop 
            Set-Location $ScriptLocation
            return
        }
    }

    ### Validate Azure Stack Development Kit Service Administrator Password ###

    if ([string]::IsNullOrEmpty($azureAdPwd)) {
        Write-Verbose "You didn't enter the Azure Stack Development Kit Service Administrator password." 
        $secureAzureAdPwd = Read-Host "Please enter the Azure Stack Development Kit Service Administrator password. It should be at least 8 characters, with at least 1 upper case, 1 lower case and 1 special character." -AsSecureString -ErrorAction Stop
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureAdPwd)            
        $azureAdPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
    }

    Write-Verbose "Checking to see if Azure Stack Development Kit Service Administrator password is strong..."

    if ($azureAdPwd -cmatch $regex -eq $true) {
        Write-Verbose "Azure Stack Development Kit Service Administrator password meets desired complexity level" 
        # Convert plain text password to a secure string
        $secureAzureAdPwd = ConvertTo-SecureString -AsPlainText $azureAdPwd -Force
        $azureAdCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureAdUsername, $secureAzureAdPwd) -ErrorAction Stop
    }

    elseif ($azureAdPwd -cmatch $regex -eq $false) {
        Write-Verbose "Azure Stack Development Kit Service Administrator password doesn't meet complexity requirements, it needs to be at least 8 characters, with at least 1 upper case, 1 lower case and 1 special character." 
        # Obtain new password and store as a secure string
        $secureAzureAdPwd = Read-Host -AsSecureString "Enter Azure Stack Development Kit Service Administrator password again"
        # Convert to plain text to test regex complexity
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureAdPwd)            
        $azureAdPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
        if ($azureAdPwd -cmatch $regex -eq $true) {
            Write-Verbose "Azure Stack Development Kit Service Administrator meets desired complexity level" 
            # Convert plain text password to a secure string
            $secureAzureAdPwd = ConvertTo-SecureString -AsPlainText $azureAdPwd -Force
            # Clean up unused variable
            Remove-Variable -Name plainazureAdPwd -ErrorAction SilentlyContinue
            $azureAdCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureAdUsername, $secureAzureAdPwd) -ErrorAction Stop
        }
        else {
            Write-Verbose "No valid Azure Stack Development Kit Service Administrator password was entered again. Exiting process..." -ErrorAction Stop 
            Set-Location $ScriptLocation
            return
        }
    }

    $asdkCreds = $azureAdCreds

    if ($useAzureCredsForRegistration -and $registerASDK) {
        $azureRegCreds = $asdkCreds
    }

    elseif (!$useAzureCredsForRegistration -and $registerASDK) {
        
        if ([string]::IsNullOrEmpty($azureRegUsername)) {
            Write-Verbose "You didn't enter a username for Azure account you'll use to register the Azure Stack to." 
            $azureRegUsername = Read-Host "Please enter a username in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" -ErrorAction Stop
        }
    
        Write-Verbose "Checking to see if the Azure AD username is correctly formatted..."
    
        if ($azureRegUsername -cmatch $emailRegex -eq $true) {
            Write-Verbose "Azure AD username is correctly formatted." 
            Write-Verbose "$azureRegUsername will be used to connect to Azure." 
        }
    
        elseif ($azureRegUsername -cmatch $emailRegex -eq $false) {
            Write-Verbose "Azure AD username isn't correctly formatted. It should be entered in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" 
            # Obtain new username
            $azureRegUsername = Read-Host "Enter Azure AD username again"
            if ($azureRegUsername -cmatch $emailRegex -eq $true) {
                Write-Verbose "Azure AD username is correctly formatted." 
                Write-Verbose "$azureRegUsername will be used to connect to Azure." 
            }
            else {
                Write-Verbose "No valid Azure AD username was entered again. Exiting process..." -ErrorAction Stop 
                Set-Location $ScriptLocation
                return
            }
        }
    
        ### Validate Azure AD Registration Password ###
    
        if ([string]::IsNullOrEmpty($azureRegPwd)) {
            Write-Verbose "You didn't enter the Azure AD password." 
            $secureAzureRegPwd = Read-Host "Please enter the Azure AD password. It should be at least 8 characters, with at least 1 upper case, 1 lower case and 1 special character." -AsSecureString -ErrorAction Stop
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureRegPwd)            
            $azureRegPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
        }
    
        Write-Verbose "Checking to see if Azure AD password is strong..."
    
        if ($azureRegPwd -cmatch $regex -eq $true) {
            Write-Verbose "Azure AD password meets desired complexity level" 
            # Convert plain text password to a secure string
            $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
            $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
        }
    
        elseif ($azureRegPwd -cmatch $regex -eq $false) {
            Write-Verbose "Azure AD password doesn't meet complexity requirements, it needs to be at least 8 characters, with at least 1 upper case, 1 lower case and 1 special character." 
            # Obtain new password and store as a secure string
            $secureAzureRegPwd = Read-Host -AsSecureString "Enter Azure AD password again"
            # Convert to plain text to test regex complexity
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureRegPwd)            
            $azureRegPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
            if ($azureRegPwd -cmatch $regex -eq $true) {
                Write-Verbose "Azure AD password meets desired complexity level" 
                # Convert plain text password to a secure string
                $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
                # Clean up unused variable
                Remove-Variable -Name azureRegPwd -ErrorAction SilentlyContinue
                $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
            }
            else {
                Write-Verbose "No valid Azure AD password was entered again. Exiting process..." -ErrorAction Stop 
                Set-Location $ScriptLocation
                return
            }
        }
    }
}

if ($authenticationType.ToString() -like "ADFS") {
    $asdkCreds = $azureStackAdminCreds
}

if ($authenticationType.ToString() -like "ADFS" -and $registerASDK) {

    Remove-Variable -Name azureAdPwd -Force -ErrorAction SilentlyContinue
    Remove-Variable -Name azureAdUsername -Force -ErrorAction SilentlyContinue

    Write-Verbose "Checking for an Azure AD username - this account will be used to register the ADFS-based ASDK to Azure..."
            
    if ([string]::IsNullOrEmpty($azureRegUsername)) {
        Write-Verbose "You didn't enter a username for Azure account you'll use to register the Azure Stack to." 
        $azureRegUsername = Read-Host "Please enter a username in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" -ErrorAction Stop
    }
    else {
        Write-Verbose "Found an Azure AD username that will be used for registering this ADFS-based Azure Stack to Azure" 
        Write-Verbose "Account username is $azureRegUsername"
    }
        
    Write-Verbose "Checking to see if the Azure AD username, that will be used for Azure Stack registration to Azure, is correctly formatted..."
        
    if ($azureRegUsername -cmatch $emailRegex -eq $true) {
        Write-Verbose "Azure AD username is correctly formatted."
        Write-Verbose "$azureRegUsername will be used to register this ADFS-based Azure Stack to Azure."
    }
        
    elseif ($azureRegUsername -cmatch $emailRegex -eq $false) {
        Write-Verbose "Azure AD username isn't correctly formatted. It should be entered in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" 
        # Obtain new username
        $azureRegUsername = Read-Host "Enter Azure AD username again"
        if ($azureRegUsername -cmatch $emailRegex -eq $true) {
            Write-Verbose "Azure AD username is correctly formatted."
            Write-Verbose "$azureRegUsername will be used to register this ADFS-based Azure Stack to Azure."
        }
        else {
            Write-Verbose "No valid Azure AD username was entered again. Exiting process..." -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
        
    ### Validate Azure AD Registration Password ADFS-based Azure Stack ###

    Write-Verbose "Checking for an Azure AD password - this account will be used to register the ADFS-based ASDK to Azure..."
        
    if ([string]::IsNullOrEmpty($azureRegPwd)) {
        Write-Verbose "You didn't enter the Azure AD password."
        $secureAzureRegPwd = Read-Host "Please enter the Azure AD password. It should be at least 8 characters, with at least 1 upper case, 1 lower case and 1 special character." -AsSecureString -ErrorAction Stop
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureRegPwd)            
        $azureRegPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
    }
        
    Write-Verbose "Checking to see if Azure AD password is strong..."
        
    if ($azureRegPwd -cmatch $regex -eq $true) {
        Write-Verbose "Azure AD password meets desired complexity level"
        # Convert plain text password to a secure string
        $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
        $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
    }
        
    elseif ($azureRegPwd -cmatch $regex -eq $false) {
        Write-Verbose "Azure AD password doesn't meet complexity requirements, it needs to be at least 8 characters, with at least 1 upper case, 1 lower case and 1 special character."
        # Obtain new password and store as a secure string
        $secureAzureRegPwd = Read-Host -AsSecureString "Enter Azure AD password again"
        # Convert to plain text to test regex complexity
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureRegPwd)            
        $azureRegPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
        if ($azureRegPwd -cmatch $regex -eq $true) {
            Write-Verbose "Azure AD password meets desired complexity level"
            # Convert plain text password to a secure string
            $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
            # Clean up unused variable
            Remove-Variable -Name azureRegPwd -ErrorAction SilentlyContinue
            $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
        }
        else {
            Write-Verbose "No valid Azure AD password was entered again. Exiting process..." -ErrorAction Stop 
            Set-Location $ScriptLocation
            return
        }
    }
}

if ($registerASDK) {

    Write-Verbose "Checking for a valid Azure subscription ID that will be used to register the Azure Stack to Azure"

    ### Validate Azure Subscription ID for Registration ###
    
    if ([string]::IsNullOrEmpty($azureRegSubId)) {
        Write-Verbose "You didn't enter a subscription ID for registering your Azure Stack in Azure."
        $azureRegSubId = Read-Host "Please enter a valid Azure subscription ID" -ErrorAction Stop
    }
            
    if ($azureRegSubId) {
        Write-Verbose "Azure subscription ID has been provided."
        Write-Verbose "$azureRegSubId will be used to register this Azure Stack with Azure."
        Write-Verbose "Testing Azure Login..."
        #Test Azure Login
        try {
            Login-AzureRmAccount -SubscriptionId $azureRegSubId -Credential $azureRegCreds
            Write-Verbose "Azure Login Succeeded - this account will be used for registration of your Azure Stack:" 
            Get-AzureRmSubscription
        }
        catch {
            Write-Verbose $_.Exception.Message -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
        
    elseif ([string]::IsNullOrEmpty($azureRegSubId)) {
        Write-Verbose "No valid Azure subscription ID was entered again. Exiting process..." -ErrorAction Stop
        Set-Location $ScriptLocation
        return    
    }
}

### DOWNLOAD TOOLS #####################################################################################################################################
########################################################################################################################################################

### CREATE ASDK FOLDER ###

$ASDKpath = [System.IO.Directory]::Exists("$downloadPath\ASDK")
If ($ASDKpath -eq $true) {
    Write-Verbose "ASDK folder exists at $downloadPath - no need to create it."
    Write-Verbose "Download files will be placed in $downloadPath\ASDK"
    $ASDKpath = "$downloadPath\ASDK"
    Write-Verbose "ASDK folder full path is $ASDKpath"
}
elseif ($ASDKpath -eq $false) {
    # Create the ASDK folder.
    Write-Verbose "ASDK folder doesn't exist within $downloadPath, creating it"
    mkdir "$downloadPath\ASDK" -Force | Out-Null
    $ASDKpath = "$downloadPath\ASDK"
    Write-Verbose "ASDK folder full path is $ASDKpath"
}

### DOWNLOAD & EXTRACT TOOLS ###

# Download the tools archive using a function incase the download fails or is interrupted.
$toolsURI = "https://github.com/Azure/AzureStack-Tools/archive/master.zip"
$toolsDownloadLocation = "$ASDKpath\master.zip"
function DownloadWithRetry([string] $toolsURI, [string] $toolsDownloadLocation, [int] $retries) {
    while ($true) {
        try {
            Invoke-WebRequest $toolsURI -OutFile "$toolsDownloadLocation"
            break
        }
        catch {
            $exceptionMessage = $_.Exception.Message
            Write-Verbose "Failed to download '$toolsURI': $exceptionMessage"
            if ($retries -gt 0) {
                $retries--
                Write-Verbose "Waiting 10 seconds before retrying. Retries left: $retries"
                Start-Sleep -Seconds 10
 
            }
            else {
                $exception = $_.Exception
                throw $exception
            }
        }
    }
}

Write-Verbose "Downloading Azure Stack Tools to ensure you have the latest versions. This may take a few minutes, depending on your connection speed."
Write-Verbose "The download will be stored in $ASDKpath."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
DownloadWithRetry -toolsURI "$toolsURI" -toolsDownloadLocation "$toolsDownloadLocation" -retries 3

# Expand the downloaded files
Write-Verbose "Expanding Archive"
expand-archive "$toolsDownloadLocation" -DestinationPath "C:\" -Force
Write-Verbose "Archive expanded. Cleaning up."
Remove-Item "$toolsDownloadLocation" -Force -ErrorAction Stop

# Change to the tools directory
Write-Verbose "Changing Directory"
$modulePath = "C:\AzureStack-Tools-master"
Set-Location $modulePath

# Import the Azure Stack Connect and Compute Modules
Import-Module .\Connect\AzureStack.Connect.psm1
Import-Module .\ComputeAdmin\AzureStack.ComputeAdmin.psm1
Disable-AzureRmDataCollection -WarningAction SilentlyContinue
Write-Verbose "Azure Stack Connect and Compute modules imported successfully" 

### CONFIGURE THE AZURE STACK HOST & INFRA VIRTUAL MACHINES ############################################################################################
########################################################################################################################################################

# Set password expiration to 180 days
Write-Verbose "Configuring password expiration policy"
Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 180.00:00:00 -Identity azurestack.local
Get-ADDefaultDomainPasswordPolicy

# Disable Server Manager at Logon
Write-Verbose "Disabling Server Manager at logon..."
Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask -Verbose

# Disable IE ESC
Write-Verbose "Disabling IE Enhanced Security Configuration (ESC)."
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
Stop-Process -Name explorer -Force
Write-Verbose "IE Enhanced Security Configuration (ESC) has been disabled."

# Set Power Policy
Write-Verbose "Optimizing power policy for high performance"
POWERCFG.EXE /S SCHEME_MIN

# Disable Windows update on infrastructure VMs and host
Write-Verbose "Disabling Windows Update on Infrastructure VMs and ASDK Host"
$AZSvms = get-vm -Name AZS*
$scriptblock = {
    sc.exe config wuauserv start=disabled
    Get-Service -Name wuauserv | Format-List StartType, Status
}
foreach ($vm in $AZSvms) {
    Invoke-Command -VMName $vm.name -ScriptBlock $scriptblock -Credential $azureStackAdminCreds
}
sc.exe config wuauserv start=disabled

# Disable DNS Server on host
Write-Verbose "Disabling DNS Server on ASDK Host"
Stop-Service -Name DNS -Force -Confirm:$false
Set-Service -Name DNS -startuptype disabled -Confirm:$false

Write-Verbose "Host configuration is now complete. Starting Azure Stack registration to Azure"

### REGISTER AZURE STACK TO AZURE ############################################################################################################################
##############################################################################################################################################################

if ($registerASDK) {

    try {
        # Add the Azure cloud subscription environment name. Supported environment names are AzureCloud or, if using a China Azure Subscription, AzureChinaCloud.
        Add-AzureRmAccount -EnvironmentName "AzureCloud" -Credential $azureRegCreds
        # Register the Azure Stack resource provider in your Azure subscription
        Register-AzureRmResourceProvider -ProviderNamespace Microsoft.AzureStack
        # Import the registration module that was downloaded with the GitHub tools
        Import-Module $modulePath\Registration\RegisterWithAzure.psm1
        #Register Azure Stack
        $AzureContext = Get-AzureRmContext
        $cloudAdminUsername = "AzureStack\CloudAdmin"
        $cloudAdminCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $cloudAdminUsername, $secureAzureStackAdminPwd -ErrorAction Stop
        Set-AzsRegistration -CloudAdminCredential $cloudAdminCreds -PrivilegedEndpoint AzS-ERCS01 -BillingModel Development -ErrorAction Stop
    }
    catch {
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}

### CONNECT TO AZURE STACK #############################################################################################################################
########################################################################################################################################################

# Register an AzureRM environment that targets your administrative Azure Stack instance
$ArmEndpoint = "https://adminmanagement.local.azurestack.external"
Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop

# Add GraphEndpointResourceId value for Azure AD or ADFS and obtain Tenant ID, then login to Azure Stack
if ($authenticationType.ToString() -like "AzureAd") {
    Write-Verbose ("Azure Active Directory selected by Administrator")
    Set-AzureRmEnvironment -Name "AzureStackAdmin" -GraphAudience "https://graph.windows.net/" -ErrorAction Stop
    Write-Verbose ("Setting GraphEndpointResourceId value for Azure AD")
    Write-Verbose ("Getting Tenant ID for Login to Azure Stack")
    $TenantID = Get-AzsDirectoryTenantId -AADTenantName $azureDirectoryTenantName -EnvironmentName "AzureStackAdmin"
    Write-Verbose "Logging in with your Azure Stack Administrator Account used with Azure Active Directory"
    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop
}
elseif ($authenticationType.ToString() -like "ADFS") {
    Write-Verbose ("Active Directory Federation Services selected by Administrator")
    Set-AzureRmEnvironment -Name "AzureStackAdmin" -GraphAudience "https://graph.local.azurestack.external/" -EnableAdfsAuthentication:$true
    Write-Verbose ("Setting GraphEndpointResourceId value for ADFS")
    Write-Verbose ("Getting Tenant ID for Login to Azure Stack")
    $TenantID = Get-AzsDirectoryTenantId -ADFS -EnvironmentName "AzureStackAdmin"
    Write-Verbose "Logging in with your Azure Stack Administrator Account used with ADFS"
    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop
}
else {
    Write-Verbose ("No valid authentication types specified - please use AzureAd or ADFS")  -ErrorAction Stop
}

### ADD UBUNTU PLATFORM IMAGE ################################################################################################################################
##############################################################################################################################################################

if ($registerASDK) {

    ### Login to Azure to get all the details about the syndicated Ubuntu Server 16.04 marketplace offering ###
    Import-Module C:\AzureStack-Tools-master\Syndication\AzureStack.MarketplaceSyndication.psm1
    Login-AzureRmAccount -EnvironmentName "AzureCloud" -Credential $AzureADCreds -ErrorAction Stop | Out-Null
    $sub = Get-AzureRmSubscription
    $sub = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
    $AzureContext = Get-AzureRmContext
    $subID = $AzureContext.Subscription.Id

    $azureAccount = Add-AzureRmAccount -subscriptionid $AzureContext.Subscription.Id -TenantId $AzureContext.Tenant.TenantId -Credential $AzureAdCreds
    $azureEnvironment = Get-AzureRmEnvironment -Name AzureCloud
    $resources = Get-AzureRmResource
    $resource = $resources.resourcename
    $registrations = $resource | Where-Object {$_ -like "AzureStack*"}
    $registration = $registrations[0]

    # Retrieve the access token
    $token = $null
    $tokens = $null
    $tokens = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems()
    $token = $tokens | Where-Object Resource -EQ $azureEnvironment.ActiveDirectoryServiceEndpointResourceId | Where-Object DisplayableId -EQ $azureAccount.Context.Account.Id | Sort-Object ExpiresOn | Select-Object -Last 1 -ErrorAction Stop

    # Define variables and create an array to store all information
    $package = "*Canonical.UbuntuServer1604LTS*"
    $azpkg = $null
    $azpkg = @{
        id         = ""
        publisher  = ""
        sku        = ""
        offer      = ""
        azpkgPath  = ""
        name       = ""
        type       = ""
        vhdPath    = ""
        vhdVersion = ""
        osVersion  = ""
    }

    ### Get the package information ###
    $uri1 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($subID.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$($Registration.ToString())/products?api-version=2016-01-01"
    $Headers = @{ 'authorization' = "Bearer $($Token.AccessToken)"} 
    $product = (Invoke-RestMethod -Method GET -Uri $uri1 -Headers $Headers).value | Where-Object {$_.name -like "$package"} | Sort-Object Name | Select-Object -Last 1

    $azpkg.id = $product.name.Split('/')[-1]
    $azpkg.type = $product.properties.productKind
    $azpkg.publisher = $product.properties.publisherDisplayName
    $azpkg.sku = $product.properties.sku
    $azpkg.offer = $product.properties.offer

    # Get product info
    $uri2 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($subID.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products/$($azpkg.id)?api-version=2016-01-01"
    $Headers = @{ 'authorization' = "Bearer $($Token.AccessToken)"} 
    $productDetails = Invoke-RestMethod -Method GET -Uri $uri2 -Headers $Headers
    $azpkg.name = $productDetails.properties.galleryItemIdentity

    # Get download location for Ubuntu Server 16.04 LTS AZPKG file
    $uri3 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($subID.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products/$($azpkg.id)/listDetails?api-version=2016-01-01"
    $downloadDetails = Invoke-RestMethod -Method POST -Uri $uri3 -Headers $Headers
    $azpkg.azpkgPath = $downloadDetails.galleryPackageBlobSasUri

    # Display Legal Terms
    $legalTerms = $productDetails.properties.description
    $legalDisplay = $legalTerms -replace '<.*?>', ''
    Write-Host "$legalDisplay" -ForegroundColor Yellow

    # Get download information for Ubuntu Server 16.04 LTS VHD file
    $azpkg.vhdPath = $downloadDetails.properties.osDiskImage.sourceBlobSasUri
    $azpkg.vhdVersion = $downloadDetails.properties.version
    $azpkg.osVersion = $downloadDetails.properties.osDiskImage.operatingSystem

}

elseif (!$registerASDK) {
    $azpkg = $null
    $azpkg = @{
        publisher  = "Canonical"
        sku        = "16.04-LTS"
        offer      = "UbuntuServer"
        vhdVersion = "1.0.0"
        osVersion  = "Linux"
        name       = "Canonical.UbuntuServer16-04-LTS.1.0.0"
    }
}

### Log back into Azure Stack to check for existing images and push new ones if required ###
Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

Write-Verbose "Checking to see if an Ubuntu Server 16.04-LTS VM Image is present in your Azure Stack Platform Image Repository"
if ($(Get-AzsVMImage -Location "local" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).Properties.ProvisioningState -eq 'Succeeded') {
    Write-Verbose "There appears to be at least 1 suitable Ubuntu Server 16.04-LTS VM image within your Platform Image Repository which we will use for the ASDK Configurator. Here are the details:"
    Write-Verbose -Message ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}".' -f $azpkg.publisher, $azpkg.offer, $azpkg.sku, $azpkg.vhdVersion) -ErrorAction SilentlyContinue
}

else {
    Write-Verbose "No existing suitable Ubuntu Server 1604-LTS VM image exists." 
    Write-Verbose "The Ubuntu Server VM Image in the Azure Stack Platform Image Repository must have the following properties:"
    Write-Verbose "Publisher Name = $($azpkg.publisher)"
    Write-Verbose "Offer = $($azpkg.offer)"
    Write-Verbose "SKU = $($azpkg.sku)"
    Write-Verbose "Version = $($azpkg.vhdVersion)"
    Write-Verbose "Unfortunately, no image was found with these properties."
    Write-Verbose "Checking to see if the Ubuntu Server VHD already exists in ASDK Configurator folder"

    $validDownloadPathVHD = [System.IO.File]::Exists("$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).vhd")
    $validDownloadPathZIP = [System.IO.File]::Exists("$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip")

    if ($validDownloadPathVHD -eq $true) {
        Write-Verbose "Located Ubuntu Server VHD in this folder. No need to download again..."
        $UbuntuServerVHD = Get-ChildItem -Path "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).vhd"
        Write-Verbose "Ubuntu Server VHD located at $UbuntuServerVHD"
    }
    elseif ($validDownloadPathZIP -eq $true) {
        Write-Verbose "Cannot find a previously extracted Ubuntu Server VHD with name $($azpkg.offer)$($azpkg.vhdVersion).vhd"
        Write-Verbose "Checking to see if the Ubuntu Server ZIP already exists in ASDK Configurator folder"
        $UbuntuServerZIP = Get-ChildItem -Path "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip"
        Write-Verbose "Ubuntu Server ZIP located at $UbuntuServerZIP"
        Expand-Archive -Path $UbuntuServerZIP -DestinationPath $ASDKpath -Force -ErrorAction Stop
        $UbuntuServerVHD = Get-ChildItem -Path "$ASDKpath" -Filter *.vhd | Rename-Item -NewName "$($azpkg.offer)$($azpkg.vhdVersion).vhd" -PassThru -Force -ErrorAction Stop
    }
    else {
        # No existing Ubuntu Server VHD or Zip exists that matches the name (i.e. that has previously been extracted and renamed) so a fresh one will be
        # downloaded, extracted and the variable $UbuntuServerVHD updated accordingly.
        Write-Verbose "Cannot find a previously extracted Ubuntu Server download or ZIP file"
        Write-Verbose "Begin download of correct Ubuntu Server ZIP and extraction of VHD into $ASDKpath"

        # If registerASDK is true, the script will grab the properties of the gallery item from the syndicated marketplace and construct a replica from this info

        if ($registerASDK) {

            $ubuntuBuild = $azpkg.vhdVersion
            $ubuntuBuild = $ubuntuBuild.Substring(0, $ubuntuBuild.Length - 1)
            $ubuntuBuild = $ubuntuBuild.split('.')[2]
            Invoke-Webrequest "https://cloud-images.ubuntu.com/releases/16.04/release-$ubuntuBuild/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip" -OutFile "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip" -ErrorAction Stop
        }

        # Otherwise, it will just use 1.0.0 as specified earlier

        else {
            $ubuntuBuild = $azpkg.vhdVersion
            Invoke-Webrequest "https://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip" -OutFile "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip" -ErrorAction Stop
        }
       
        Expand-Archive -Path "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip" -DestinationPath $ASDKpath -Force -ErrorAction Stop
        $UbuntuServerVHD = Get-ChildItem -Path "$ASDKpath" -Filter *.vhd | Rename-Item -NewName "$($azpkg.offer)$($azpkg.vhdVersion).vhd" -PassThru -Force -ErrorAction Stop
    }

    # Upload the image to the Azure Stack Platform Image Repository
    Write-Verbose "Extraction Complete. Beginning upload of VHD to Platform Image Repository"

    # If the user has chosen to register the ASDK, the script will NOT create a gallery item as part of the image upload

    if ($registerASDK) {
        Add-AzsVMImage -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -osType $azpkg.osVersion -osDiskLocalPath "$UbuntuServerVHD" -CreateGalleryItem $False -ErrorAction Stop
    }
    else {
        Add-AzsVMImage -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -osType $azpkg.osVersion -osDiskLocalPath "$UbuntuServerVHD" -ErrorAction Stop
    }
    if ($(Get-AzsVMImage -Location "local" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).Properties.ProvisioningState -eq 'Succeeded') {
        Write-Verbose -Message ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" successfully uploaded.' -f $azpkg.publisher, $azpkg.offer, $azpkg.sku, $azpkg.vhdVersion) -ErrorAction SilentlyContinue
        Write-Verbose "Cleaning up local hard drive space - deleting VHD file, but keeping ZIP "
        Get-ChildItem -Path "$ASDKpath" -Filter *.vhd | Remove-Item -Force
    }
}

### If the user has chosen to register the ASDK as part of the process, the script will side load an AZPKG from the Azure Stack Marketplace ###

if ($registerASDK) {
    # Upload AZPKG package
    Write-Verbose "Checking for the following packages: $($azpkg.name)"
    if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$($azpkg.name)*"}) {
        Write-Verbose "Found the following existing package in your Gallery: $($azpkg.name). No need to upload a new one"
    }
    else {
        Write-Verbose "Didn't find this package: $($azpkg.name)"
        Write-Verbose "Will need to side load it in to the gallery"
        Write-Verbose "Uploading $($azpkg.name) with the ID: $($azpkg.id) from $($azpkg.azpkgPath)"
        $Upload = Add-AzsGalleryItem -GalleryItemUri $($azpkg.azpkgPath)
        Start-Sleep -Seconds 5
        $Retries = 0
        # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
        While ($Upload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
            Write-Verbose "$($azpkg.name) wasn't added to the gallery successfully. Retry Attempt #$Retries"
            Write-Verbose "Uploading $($azpkg.name) from $($azpkg.azpkgPath)"
            $Upload = Add-AzsGalleryItem -GalleryItemUri $($azpkg.azpkgPath)
            Start-Sleep -Seconds 5
        }
    }
}

### ADD WINDOWS SERVER 2016 PLATFORM IMAGES ##################################################################################################################
##############################################################################################################################################################

### Log back into Azure Stack to check for existing images and push new ones if required ###
Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

Write-Verbose "Checking to see if a Windows Server 2016 image is present in your Azure Stack Platform Image Repository"
# Pre-validate that the Windows Server 2016 Server Core VM Image is not already available

Remove-Variable -Name platformImageCore -Force -ErrorAction SilentlyContinue
$sku = "2016-Datacenter-Server-Core"
$platformImageCore = Get-AzsVMImage -Location "local" -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -Version "1.0.0" -ErrorAction SilentlyContinue
$serverCoreVMImageAlreadyAvailable = $false

if ($platformImageCore -ne $null -and $platformImageCore.Properties.ProvisioningState -eq 'Succeeded') {
    Write-Verbose "There appears to be at least 1 suitable Windows Server $sku image within your Platform Image Repository which we will use for the ASDK Configurator." 
    Write-Output "Insert details here"
    $serverCoreVMImageAlreadyAvailable = $true
}

# Pre-validate that the Windows Server 2016 Full Image is not already available
Remove-Variable -Name platformImageFull -Force -ErrorAction SilentlyContinue
$sku = "2016-Datacenter"
$platformImageFull = Get-AzsVMImage -Location "local" -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -Version "1.0.0" -ErrorAction SilentlyContinue
$serverFullVMImageAlreadyAvailable = $false

if ($platformImageFull -ne $null -and $platformImageFull.Properties.ProvisioningState -eq 'Succeeded') {
    Write-Verbose "There appears to be at least 1 suitable Windows Server $sku image within your Platform Image Repository which we will use for the ASDK Configurator." 
    Write-Output "Insert details here"
    $serverFullVMImageAlreadyAvailable = $true
}

if ($serverCoreVMImageAlreadyAvailable -eq $false) {
    $downloadCURequired = $true
    Write-Verbose "You're missing the Windows Server 2016 Datacenter Server Core image in your Platform Image Repository."
}

if ($serverFullVMImageAlreadyAvailable -eq $false) {
    $downloadCURequired = $true
    Write-Verbose "You're missing the Windows Server 2016 Datacenter Full image in your Platform Image Repository."
}

if (($serverCoreVMImageAlreadyAvailable -eq $true) -and ($serverFullVMImageAlreadyAvailable -eq $true)) {
    $downloadCURequired = $false
    Write-Verbose "Windows Server 2016 Datacenter Full and Core Images already exist in your Platform Image Repository"
}

### Download the latest Cumulative Update for Windows Server 2016 - Existing Azure Stack Tools module doesn't work ###

if ($downloadCURequired -eq $true) {
    Write-Verbose "You're missing at least one of the Windows Server 2016 Datacenter images, so we'll first download the latest Cumulative Update."
    # Define parameters
    $StartKB = 'https://support.microsoft.com/app/content/api/content/asset/en-us/4000816'
    $Build = '14393'
    $SearchString = 'Cumulative.*Server.*x64'

    # Find the KB Article Number for the latest Windows Server 2016 (Build 14393) Cumulative Update
    Write-Verbose "Downloading $StartKB to retrieve the list of updates."
    $kbID = (Invoke-WebRequest -Uri $StartKB).Content | ConvertFrom-Json | Select-Object -ExpandProperty Links | Where-Object level -eq 2 | Where-Object text -match $Build | Select-Object -First 1

    # Get Download Link for the corresponding Cumulative Update
    Write-Verbose "Found ID: KB$($kbID.articleID)"
    $kbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$($kbID.articleID)"
    $Available_kbIDs = $kbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
    $Available_kbIDs | Out-String | Write-Verbose
    $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object innerText -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }

    # If innerHTML is empty or does not exist, use outerHTML instead
    If ($kbIDs -eq $Null) {
        $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }
    }

    $Urls = @()

    ForEach ( $kbID in $kbIDs ) {
        Write-Verbose "KB ID: $kbID"
        $Post = @{ size = 0; updateID = $kbID; uidInfo = $kbID } | ConvertTo-Json -Compress
        $PostBody = @{ updateIDs = "[$Post]" } 
        $Urls += Invoke-WebRequest -Uri 'http://www.catalog.update.microsoft.com/DownloadDialog.aspx' -Method Post -Body $postBody | Select-Object -ExpandProperty Content | Select-String -AllMatches -Pattern "(http[s]?\://download\.windowsupdate\.com\/[^\'\""]*)" | ForEach-Object { $_.matches.value }
    }

    # Download the corresponding Windows Server 2016 (Build 14393) Cumulative Update
    ForEach ( $Url in $Urls ) {
        $filename = $Url.Substring($Url.LastIndexOf("/") + 1)
        $target = "$((Get-Item $ASDKpath).FullName)\$filename"
        Write-Verbose "Windows Server 2016 Cumulative Update will be stored at $target"
        Write-Verbose "These are generally larger than 1GB, so may take a few minutes."
        If (!(Test-Path -Path $target)) {
            Invoke-WebRequest -Uri $Url -OutFile $target
        }
        Else {
            Write-Verbose "File exists: $target. Skipping download."
        }
    }
    Write-Verbose "Creating Windows Server 2016 Evaluation images..."

    # In this try/catch, if the user has chosen to register the ASDK as part of the script, the New-AzsServer2016VMImage will NOT create
    # the gallery item, and instead, the azpkg files will be pulled from the marketplace later
    # If the user chose not to register the ASDK, the New-AzsServer2016VMImage will create a default gallery item
    try {
        if ($registerASDK) {
            New-AzsServer2016VMImage -Version Both -ISOPath $ISOpath -CreateGalleryItem $false -Net35 $true -CUPath $target -VHDSizeInMB "40960" -Location "local"
        }
        elseif (!$registerASDK) {
            New-AzsServer2016VMImage -Version Both -ISOPath $ISOpath -Net35 $true -CUPath $target -VHDSizeInMB "40960" -Location "local"
        }
        # Cleanup the VHD, MSU and Cab files
        $computeAdminPath = "$modulePath\ComputeAdmin"
        Get-ChildItem -Path "$computeAdminPath" -Filter *.vhd | Remove-Item -Force
        Get-ChildItem -Path "$ASDKpath\*" -Include *.msu, *.cab | Remove-Item -Force
    }
    Catch {
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}

### Now check for and create (if required) AZPKG files for sideloading ###
# If the user chose not to register the ASDK, the previous step should have created default gallery items, but this section of the script
# ensures that if they are missing, they will be recreated
if (!$registerASDK) {

    $packageArray = @()
    $packageArray.Clear()
    $packageArray = "*WindowsServer2016-Datacenter.*", "*WindowsServer2016-Datacenter-Server-Core.*"
    Write-Verbose "You chose not to register your Azure Stack to Azure. Your default AZPKG packages should have already been created when your Windows Server images were added to the PIR. Checking:"

    foreach ($package in $packageArray) {
        $wsPackage = $null
        $wsPackage = (Get-AzsGalleryItem | Where-Object {$_.name -like "$package"})
        if ($wsPackage) {
            Write-Verbose "Found the following existing package in your gallery: $($wsPackage.Name) - No need to upload a new one"
        }
        else {
            $wsPackage = $package -replace '[*.]', ''
            Write-Verbose "Didn't find this package: $wsPackage"
            Write-Verbose "Will need to sideload it in to the gallery"
            if ($wsPackage -eq "WindowsServer2016-Datacenter") {
                New-AzsServer2016VMImage -Version Full -ISOPath $ISOpath -Location "local"
            }
            elseif ($wsPackage -eq "WindowsServer2016-Datacenter-Server-Core") {
                New-AzsServer2016VMImage -Version Core -ISOPath $ISOpath -Location "local"
            }
        }
    }
}

# If the user chose to register the ASDK as part of the script, this section will log into Azure, scrape the marketplace items and get the properties of
# the gallery items, and the azpkg files, and side-load them into the Azure Stack marketplace.
elseif ($registerASDK) {

    ### Login to Azure to get all the details about the syndicated Windows Server 2016 marketplace offering ###
    Import-Module C:\AzureStack-Tools-master\Syndication\AzureStack.MarketplaceSyndication.psm1
    Login-AzureRmAccount -EnvironmentName "AzureCloud" -Credential $AzureADCreds -ErrorAction Stop | Out-Null
    $sub = Get-AzureRmSubscription
    $sub = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
    $AzureContext = Get-AzureRmContext
    $subID = $AzureContext.Subscription.Id

    $azureAccount = Add-AzureRmAccount -subscriptionid $AzureContext.Subscription.Id -TenantId $AzureContext.Tenant.TenantId -Credential $AzureAdCreds
    $azureEnvironment = Get-AzureRmEnvironment -Name AzureCloud
    $resources = Get-AzureRmResource
    $resource = $resources.resourcename
    $registrations = $resource | Where-Object {$_ -like "AzureStack*"}
    $registration = $registrations[0]

    # Retrieve the access token
    $token = $null
    $tokens = $null
    $tokens = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems()
    $token = $tokens | Where-Object Resource -EQ $azureEnvironment.ActiveDirectoryServiceEndpointResourceId | Where-Object DisplayableId -EQ $azureAccount.Context.Account.Id | Sort-Object ExpiresOn | Select-Object -Last 1 -ErrorAction Stop

    # Define variables and create arrays to store all information
    $packageArray = @()
    $packageArray.Clear()
    $packageArray = "*Microsoft.WindowsServer2016Datacenter-ARM*", "*Microsoft.WindowsServer2016DatacenterServerCore-ARM*"
    $azpkgArray = @()
    $azpkgArray.Clear()

    foreach ($package in $packageArray) {

        $azpkg = $null
        $azpkg = @{
            id        = ""
            publisher = ""
            sku       = ""
            offer     = ""
            azpkgPath = ""
            name      = ""
            type      = ""
        }

        # Get the package information
        $uri1 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($subID.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$($Registration.ToString())/products?api-version=2016-01-01"
        $Headers = @{ 'authorization' = "Bearer $($Token.AccessToken)"} 
        $product = (Invoke-RestMethod -Method GET -Uri $uri1 -Headers $Headers).value | Where-Object {$_.name -like "$package"} | Sort-Object Name | Select-Object -Last 1

        $azpkg.id = $product.name.Split('/')[-1]
        $azpkg.type = $product.properties.productKind
        $azpkg.publisher = $product.properties.publisherDisplayName
        $azpkg.sku = $product.properties.sku
        $azpkg.offer = $product.properties.offer

        # Get product info
        $uri2 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($subID.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products/$($azpkg.id)?api-version=2016-01-01"
        $Headers = @{ 'authorization' = "Bearer $($Token.AccessToken)"} 
        $productDetails = Invoke-RestMethod -Method GET -Uri $uri2 -Headers $Headers
        $azpkg.name = $productDetails.properties.galleryItemIdentity

        # Get download location for AZPKG file
        $uri3 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($subID.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products/$($azpkg.id)/listDetails?api-version=2016-01-01"
        $downloadDetails = Invoke-RestMethod -Method POST -Uri $uri3 -Headers $Headers
        $azpkg.azpkgPath = $downloadDetails.galleryPackageBlobSasUri

        # Display Legal Terms
        $legalTerms = $productDetails.properties.description
        $legalDisplay = $legalTerms -replace '<.*?>', ''
        Write-Host "$legalDisplay" -ForegroundColor Yellow

        # Add to the array
        $azpkgArray += , $azpkg

    }

    ### With all the information stored in the arrays, log back into Azure Stack to check for existing images and push new ones if required ###
    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

    foreach ($azpkg in $azpkgArray) {

        Write-Verbose "Checking for the following packages: $($azpkg.name)"
        if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$($azpkg.name)*"}) {
            Write-Verbose "Found the following existing package in your Gallery: $($azpkg.name). No need to upload a new one"
        }
        else {
            Write-Verbose "Didn't find this package: $($azpkg.name)"
            Write-Verbose "Will need to side load it in to the gallery"
            Write-Verbose "Uploading $($azpkg.name) with the ID: $($azpkg.id) from $($azpkg.azpkgPath)"
            $Upload = Add-AzsGalleryItem -GalleryItemUri $($azpkg.azpkgPath)
            Start-Sleep -Seconds 5
            $Retries = 0
            # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
            While ($Upload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
                Write-Verbose "$($azpkg.name) wasn't added to the gallery successfully. Retry Attempt #$Retries"
                Write-Verbose "Uploading $($azpkg.name) from $($azpkg.azpkgPath)"
                $Upload = Add-AzsGalleryItem -GalleryItemUri $($azpkg.azpkgPath)
                Start-Sleep -Seconds 5
            }
        }
    }
}

### ADD VM SCALE SET GALLERY ITEM ############################################################################################################################
##############################################################################################################################################################

# Create VM Scale Set Marketplace item
Write-Verbose "Creating VM Scale Set Marketplace Item"
Add-AzsVMSSGalleryItem -Location local

### ADD MYSQL GALLERY ITEM ###################################################################################################################################
##############################################################################################################################################################

### Login to Azure Stack, then confirm if the MySQL Gallery Item is already present ###
Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
$mySQLPackageName = ""
Write-Verbose "Checking for the MySQL gallery item"
if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$mySQLPackageName*"}) {
    Write-Verbose "Found a suitable MySQL Gallery Item in your Azure Stack Marketplace. No need to upload a new one"
}
else {
    Write-Verbose "Didn't find this package: $($azpkg.name)"
    Write-Verbose "Will need to side load it in to the gallery"
    Write-Verbose "Uploading $($azpkg.name) with the ID: $($azpkg.id) from $($azpkg.azpkgPath)"
    $Upload = Add-AzsGalleryItem -GalleryItemUri $($azpkg.azpkgPath)
    Start-Sleep -Seconds 5
    $Retries = 0
    # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
    While ($Upload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
        Write-Verbose "$($azpkg.name) wasn't added to the gallery successfully. Retry Attempt #$Retries"
        Write-Verbose "Uploading $($azpkg.name) from $($azpkg.azpkgPath)"
        $Upload = Add-AzsGalleryItem -GalleryItemUri $($azpkg.azpkgPath)
        Start-Sleep -Seconds 5
    }
}

#### INSTALL MYSQL RESOURCE PROVIDER #########################################################################################################################
##############################################################################################################################################################

# Login to Azure Stack
Write-Verbose "Downloading and installing MySQL Resource Provider"
Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

# Download and Expand the MySQL RP files
Invoke-WebRequest https://aka.ms/azurestackmysqlrp -OutFile "$ASDKpath\MySQL.zip" -ErrorAction Stop
Set-Location $ASDKpath
Expand-Archive "$ASDKpath\MySql.zip" -DestinationPath .\MySQL -Force -ErrorAction Stop
Set-Location "$ASDKpath\MySQL"

# Define the additional credentials for the local virtual machine username/password and certificates password
$vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("mysqlrpadmin", $secureVMpwd)
.\DeployMySQLProvider.ps1 -AzCredential $asdkCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $cloudAdminCreds -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureVMpwd -AcceptLicense

#### INSTALL SQL SERVER RESOURCE PROVIDER ####################################################################################################################
##############################################################################################################################################################

# Login to Azure Stack
Write-Verbose "Downloading and installing SQL Server Resource Provider"
Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

# Download and Expand the SQL Server RP files
Invoke-WebRequest https://aka.ms/azurestacksqlrp -OutFile "$ASDKpath\SQL.zip" -ErrorAction Stop
Set-Location $ASDKpath
Expand-Archive "$ASDKpath\SQL.zip" -DestinationPath .\SQL -Force -ErrorAction Stop
Set-Location "$ASDKpath\SQL"

# Define the additional credentials for the local virtual machine username/password and certificates password
$vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("sqlrpadmin", $secureVMpwd)
.\DeploySQLProvider.ps1 -AzCredential $asdkCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $cloudAdminCreds -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureVMpwd

#### REGISTER NEW RESOURCE PROVIDERS #########################################################################################################################
##############################################################################################################################################################

# Register resources providers
foreach ($s in (Get-AzureRmSubscription)) {
    Select-AzureRmSubscription -SubscriptionId $s.SubscriptionId | Out-Null
    Write-Progress $($s.SubscriptionId + " : " + $s.SubscriptionName)
    Get-AzureRmResourceProvider -ListAvailable | Register-AzureRmResourceProvider
}

#### DEPLOY VMS TO HOST USER DATABASES #######################################################################################################################
##############################################################################################################################################################

Write-Verbose "Creating a dedicated Resource Group for all database hosting assets"
New-AzureRmResourceGroup -Name "azurestack-dbhosting" -Location local

# Deploy a MySQL VM for hosting tenant db
Write-Verbose "Creating a dedicated MySQL host VM for database hosting"
New-AzureRmResourceGroupDeployment -Name "MySQLHost" -ResourceGroupName "azurestack-dbhosting" -TemplateUri https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/MySQL/azuredeploy.json -vmName "mysqlhost" -adminUsername "mysqladmin" -adminPassword $secureVMpwd -vmSize Standard_A2 -windowsOSVersion '2016-Datacenter' -mode Incremental -Verbose

# Create SKU and add host server to mysql RP - requires fix
#Write-Verbose "Attaching MySQL hosting server to MySQL resource provider"
#New-AzureRmResourceGroupDeployment -ResourceGroupName mysql-host -TemplateUri https://raw.githubusercontent.com/alainv-msft/Azure-Stack/master/Templates/mysqladapter-add-hosting-server/azuredeploy.json -username "mysqlrpadmin" -password $vmLocalAdminPass -totalSpaceMB 10240 -skuName MySQL57 -Mode Incremental -Verbose

# Deploy a SQL 2014 VM for hosting tenant db
Write-Verbose "Creating a dedicated SQL 2014 host for database hosting"
New-AzureRmResourceGroup -Name SQL-Host -Location local
New-AzureRmResourceGroupDeployment -Name sqlhost1 -ResourceGroupName SQL-Host -TemplateUri https://raw.githubusercontent.com/alainv-msft/Azure-Stack/master/Templates/SQL2014/azuredeploy.json -adminPassword $vmlocaladminpass -adminUsername "cloudadmin" -windowsOSVersion "2016-Datacenter" -Mode Incremental -Verbose

# Create SKU and add host server to sql RP - requires fix
#Write-Verbose "Attaching SQL hosting server to SQL resource provider"
#New-AzureRmResourceGroupDeployment -ResourceGroupName sql-host -TemplateUri https://raw.githubusercontent.com/alainv-msft/Azure-Stack/master/Templates/sqladapter-add-hosting-server/azuredeploy.json -hostingServerSQLLoginName "sa" -hostingServerSQLLoginPassword $vmLocalAdminPass -totalSpaceMB 10240 -skuName SQL2014 -Mode Incremental -Verbose

# deploy prerequisites for app service
Write-Verbose "deploying file server"
New-AzureRmResourceGroup -Name appservice-fileshare -Location local
New-AzureRmResourceGroupDeployment -Name fileshareserver -ResourceGroupName appservice-fileshare -TemplateUri https://raw.githubusercontent.com/alainv-msft/Azure-Stack/master/Templates/appservice-fileserver-standalone/azuredeploy.json -adminPassword $vmLocalAdminPass -fileShareOwnerPassword $vmLocalAdminPass -fileShareUserPassword $vmLocalAdminPass -Mode Incremental -Verbose 
Write-Verbose "deploying sql server for appservice"
New-AzureRmResourceGroup -Name appservice-sql -Location local
New-AzureRmResourceGroupDeployment -Name sqlapp -ResourceGroupName appservice-sql -TemplateUri https://raw.githubusercontent.com/alainv-msft/Azure-Stack/master/Templates/SQL2014/azuredeploy.json -adminPassword $vmlocaladminpass -adminUsername "cloudadmin" -windowsOSVersion "2016-Datacenter" -vmName "sqlapp" -dnsNameForPublicIP "sqlapp" -Mode Incremental -Verbose

# install App Service To be added
Write-Verbose "downloading appservice installer"
Set-Location C:\Temp
Invoke-WebRequest https://aka.ms/appsvconmashelpers -OutFile "c:\temp\appservicehelper.zip"
Expand-Archive C:\Temp\appservicehelper.zip -DestinationPath .\AppService\ -Force
Invoke-WebRequest http://aka.ms/appsvconmasrc1installer -OutFile "c:\temp\AppService\appservice.exe"
Write-Verbose "generating certificates"
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
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Enable Choco Global Confirmation
Write-Verbose "Enabling global confirmation to streamline installs"
choco feature enable -n allowGlobalConfirmation

# Visual Studio Code
Write-Verbose "Installing VS Code with Chocolatey"
choco install visualstudiocode

# Putty
Write-Verbose "Installing Putty with Chocolatey"
choco install putty.install

# WinSCP
Write-Verbose "Installing WinSCP with Chocolatey"
choco install winscp.install 

# Chrome
Write-Verbose "Installing Chrome with Chocolatey"
choco install googlechrome

# WinDirStat
Write-Verbose "Installing WinDirStat with Chocolatey"
choco install windirstat

# Azure CLI
Write-Verbose "Installing latest version of Azure CLI"
invoke-webrequest https://aka.ms/InstallAzureCliWindows -OutFile C:\AzureCLI.msi
msiexec.exe /qb-! /i C:\AzureCli.msi

Write-Verbose "Setting Execution Policy back to RemoteSigned"
Set-ExecutionPolicy RemoteSigned -Confirm:$false -Force

# Calculate completion time
$endTime = Get-Date -format HH:mm:ss
$timeDiff = New-TimeSpan $startTime $endTime
if ($timeDiff.Seconds -lt 0) {
    $Hrs = ($timeDiff.Hours) + 23
    $Mins = ($timeDiff.Minutes) + 59
    $Secs = ($timeDiff.Seconds) + 59 
}
else {
    $Hrs = $timeDiff.Hours
    $Mins = $timeDiff.Minutes
    $Secs = $timeDiff.Seconds 
}
$difference = '{0:00}h:{1:00}m:{2:00}s' -f $Hrs, $Mins, $Secs
Start-Sleep -Seconds 2
Write-Verbose "`r`nASDK Configurator setup completed successfully, taking $difference."
Start-Sleep -Seconds 2