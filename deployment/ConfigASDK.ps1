<#

.SYNOPSYS

    The purpose of this script is to automate as much as possible post deployment tasks in Azure Stack Development Kit
    This includes:
        * Validates all input parameters
        * Ensures password for VMs meets complexity required for App Service installation
        * Updated password expiration (180 days)
        * Disable Windows Update on all infrastructures VMs and ASDK host (To avoid the temptation to apply the patches...)
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
        * Set new default Quotas for MySQL, SQL Server, Compute, Network, Storage and Key Vault
        * App Service prerequisites installation (SQL Server and Standalone File Server)
        * App Service Resource Provider sources download and certificates generation
        * App Service Service Principal Created (for Azure AD and ADFS)
        * Grants App Service Service Principal Admin Consent (for Azure AD)
        * Automates deployment of the App Service using dynamically constructed JSON
        * MySQL, SQL, App Service and Host Customization can be optionally skipped
        * Cleans up download folder to ensure clean future runs
        * Transcript Log for errors and troubleshooting
        * Progress Tracking and rerun reliability with ConfigASDkProgress.csv file
        * Stores script output in a ConfigASDKOutput.txt, for future reference

.VERSION

    1805 updated with improvements to Azure account verification, ability to skip RP deployment, run counters and bug fixes
    1804 Updated with support for ASDK 1804 and PowerShell 1.3.0, bug fixes, reduced number of modules imported from GitHub tools repo
    3.1  Update added App Service automation, bug fixes, MySQL Root account fix.
    3.0  major update for ASDK release 20180329.1
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

.CREDITS

    Jon LaBelle - https://jonlabelle.com/snippets/view/powershell/download-remote-file-with-retry-support
    Alain Vetier - https://github.com/esache/Azure-Stack
    Ned Ballavance - https://github.com/ned1313/AzureStack-VM-PoC 

.GUIDANCE

    Please refer to the Readme.md (https://github.com/mattmcspirit/azurestack/blob/master/deployment/README.md) for recommended
    deployment parameter usage and instructions.

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
    [Parameter(Mandatory = $false)]
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

    # Azure Subscription to be used for registering Azure Stack 
    [parameter(Mandatory = $false)]
    [string]$azureRegSubId,

    # If you don't want to install the MySQL Resource Provider and Hosting Server set this flag
    [switch]$skipMySQL,

    # If you don't want to install the SQL Server Resource Provider and Hosting Server set this flag
    [switch]$skipMSSQL,

    # If you don't want to install the App Service and pre-requisites set this flag
    [switch]$skipAppService,

    # If you don't want to customize the ASDK host with useful apps such as Chrome, Azure CLI, VS Code etc. set this flag
    [switch]$skipCustomizeHost,

    # Offline installation package path for all key components
    [parameter(Mandatory = $false)]
    [string]$configAsdkOfflinePath
)

$VerbosePreference = "Continue"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {Stop-Transcript | Out-Null} catch {}
$scriptStep = ""

### CUSTOM VERBOSE FUNCTION #################################################################################################################################
#############################################################################################################################################################
function Write-CustomVerbose {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string]$Message = ''
    )
    begin {}
    process {
        $verboseTime = (Get-Date).ToShortTimeString()
        # Function for displaying formatted log messages.  Also displays time in minutes since the script was started
        Write-Verbose -Message "[$verboseTime]::[$scriptStep]:: $Message"
    }
    end {}
}

#############################################################################################################################################################
#############################################################################################################################################################

$scriptStep = "VALIDATION"
Write-CustomVerbose -Message "Validating if running under Admin Privileges"
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-CustomVerbose -Message "User is not administrator - please ensure you're running as Administrator (right-click, Run as administrator)" 
    exit
}

### GET START TIME ###
$startTime = Get-Date -Format g
$sw = [Diagnostics.Stopwatch]::StartNew()

### SET LOCATION ###
$ScriptLocation = Get-Location

### SET ERCS IP Address - same for all default ASDKs ###
$ERCSip = "AzS-ERCS01"

# Define Regex for Password Complexity - needs to be at least 12 characters, with at least 1 upper case, 1 lower case, 1 number and 1 special character
$regex = @"
(?=^.{12,123}$)((?=.*\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[^A-Za-z0-9])(?=.*[a-z])|(?=.*[^A-Za-z0-9])(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9]))^.*
"@

$emailRegex = @"
(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])
"@

### PARAMATER VALIDATION #####################################################################################################################################
##############################################################################################################################################################

### Validate Download Path ###

Clear-Host
Write-CustomVerbose -Message "Selected identity provider is $authenticationType"
Write-CustomVerbose -Message "Checking to see if the Download Path exists"

$validDownloadPath = [System.IO.Directory]::Exists($downloadPath)
If ($validDownloadPath -eq $true) {
    Write-CustomVerbose -Message "Download path exists and is valid" 
    Write-CustomVerbose -Message "Files will be stored at $downloadPath" 
    $downloadPath = Set-Location -Path "$downloadPath" -PassThru
}
elseif ($validDownloadPath -eq $false) {
    $downloadPath = Read-Host "Download path is invalid - please enter a valid path to store your downloads"
    $validDownloadPath = [System.IO.Directory]::Exists($downloadPath)
    if ($validDownloadPath -eq $false) {
        Write-CustomVerbose -Message "No valid folder path was entered again. Exiting process..." -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
    elseif ($validDownloadPath -eq $true) {
        Write-CustomVerbose -Message "Download path exists and is valid" 
        Write-CustomVerbose -Message "Files will be stored at $downloadPath" 
        $downloadPath = Set-Location -Path "$downloadPath" -PassThru
    }
}

### Start Logging ###
$logTime = $(Get-Date).ToString("MMdd-HHmmss")
$logStart = Start-Transcript -Path "$downloadPath\ConfigASDKLog$logTime.txt" -Append
Write-CustomVerbose -Message $logStart

### Check if ConfigASDKProgressLog.csv exists ###
$ConfigASDKProgressLogPath = "$downloadPath\ConfigASDKProgressLog.csv"
$validConfigASDKProgressLogPath = [System.IO.File]::Exists($ConfigASDKProgressLogPath)
If ($validConfigASDKProgressLogPath -eq $true) {
    Write-CustomVerbose -Message "ConfigASDkProgressLog.csv exists - this must be a rerun"
    Write-CustomVerbose -Message "Starting from previous failed step`r`n"
    $progress = Import-Csv $ConfigASDKProgressLogPath
    Write-Output $progress | Out-Host
}
elseif ($validConfigASDKProgressLogPath -eq $false) {
    Write-CustomVerbose -Message "No ConfigASDkProgressLog.csv exists - this must be a fresh deployment"
    Write-CustomVerbose -Message "Creating ConfigASDKProgressLog.csv`r`n"
    Add-Content -Path $ConfigASDKProgressLogPath -Value '"Stage","Status"' -Force -Confirm:$false
    $ConfigASDKprogress = @(
        '"DownloadTools","Incomplete"'
        '"HostConfiguration","Incomplete"'
        '"Registration","Incomplete"'
        '"UbuntuImage","Incomplete"'
        '"WindowsImage","Incomplete"'
        '"ScaleSetGalleryItem","Incomplete"'
        '"MySQLGalleryItem","Incomplete"'
        '"SQLServerGalleryItem","Incomplete"'
        '"MySQLRP","Incomplete"'
        '"SQLServerRP","Incomplete"'
        '"RegisterNewRPs","Incomplete"'
        '"MySQLSKUQuota","Incomplete"'
        '"SQLServerSKUQuota","Incomplete"'
        '"MySQLDBVM","Incomplete"'
        '"SQLServerDBVM","Incomplete"'
        '"MySQLAddHosting","Incomplete"'
        '"SQLServerAddHosting","Incomplete"'
        '"CreatePlansOffers","Incomplete"'
        '"AppServiceFileServer","Incomplete"'
        '"AppServiceSQLServer","Incomplete"'
        '"DownloadAppService","Incomplete"'
        '"GenerateAppServiceCerts","Incomplete"'
        '"CreateServicePrincipal","Incomplete"'
        '"GrantAzureADAppPermissions","Incomplete"'
        '"InstallAppService","Incomplete"'
        '"InstallHostApps","Incomplete"'
        '"CreateOutput","Incomplete"'
    )
    $ConfigASDKprogress | ForEach-Object { Add-Content -Path $ConfigASDKProgressLogPath -Value $_ }
    $progress = Import-Csv -Path $ConfigASDKProgressLogPath
    Write-Output $progress | Out-Host
}

### Validate path to ISO File ###

Write-CustomVerbose -Message "Checking to see if the path to the ISO exists"

$validISOPath = [System.IO.File]::Exists($ISOPath)
$validISOfile = [System.IO.Path]::GetExtension("$ISOPath")

If ($validISOPath -eq $true -and $validISOfile -eq ".iso") {
    Write-CustomVerbose -Message "Found path to valid ISO file" 
    $ISOPath = [System.IO.Path]::GetFullPath($ISOPath)
    Write-CustomVerbose -Message "The Windows Server 2016 Eval found at $ISOPath will be used" 
}
elseif ($validISOPath -eq $false -or $validISOfile -ne ".iso") {
    $ISOPath = Read-Host "ISO path is invalid - please enter a valid path to the Windows Server 2016 ISO"
    $validISOPath = [System.IO.File]::Exists($ISOPath)
    $validISOfile = [System.IO.Path]::GetExtension("$ISOPath")
    if ($validISOPath -eq $false -or $validISOfile -ne ".iso") {
        Write-CustomVerbose -Message "No valid path to a Windows Server 2016 ISO was entered again. Exiting process..." -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
    elseif ($validISOPath -eq $true -and $validISOfile -eq ".iso") {
        Write-CustomVerbose -Message "Found path to valid ISO file" 
        $ISOPath = [System.IO.Path]::GetFullPath($ISOPath)
        Write-CustomVerbose -Message "The Windows Server 2016 Eval found at $ISOPath will be used" 
    }
}

### Validate Virtual Machine (To be created) Password ###

if ([string]::IsNullOrEmpty($VMpwd)) {
    Write-CustomVerbose -Message "You didn't enter a password for the virtual machines that the ASDK configurator will create." 
    $secureVMpwd = Read-Host "Please enter a password for the virtual machines that will be created during this process" -AsSecureString -ErrorAction Stop
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureVMpwd)            
    $VMpwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
}

Write-CustomVerbose -Message "Checking to see if Virtual Machine password is strong..."

if ($VMpwd -cmatch $regex -eq $true) {
    Write-CustomVerbose -Message "Virtual Machine password meets desired complexity level" 
    # Convert plain text password to a secure string
    $secureVMpwd = ConvertTo-SecureString -AsPlainText $VMpwd -Force
}

elseif ($VMpwd -cmatch $regex -eq $false) {
    Write-CustomVerbose -Message "Virtual Machine password doesn't meet complexity requirements, it needs to be at least 12 characters in length."
    Write-CustomVerbose -Message "Your password should also have at least 3 of the following 4 options: 1 upper case, 1 lower case, 1 number, 1 special character."
    Write-CustomVerbose -Message "The App Service installation requires a password of this strength. An Example would be p@ssw0rd123!" 
    # Obtain new password and store as a secure string
    $secureVMpwd = Read-Host -AsSecureString "Enter VM password again"
    # Convert to plain text to test regex complexity
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureVMpwd)            
    $VMpwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
    if ($VMpwd -cmatch $regex -eq $true) {
        Write-CustomVerbose -Message "Virtual Machine password matches desired complexity" 
        # Convert plain text password to a secure string
        $secureVMpwd = ConvertTo-SecureString -AsPlainText $VMpwd -Force
        # Clean up unused variable
        Remove-Variable -Name VMpwd -ErrorAction SilentlyContinue
    }
    else {
        Write-CustomVerbose -Message "No valid password was entered again. Exiting process..." -ErrorAction Stop 
        Set-Location $ScriptLocation
        return
    }
}

### Validate Azure Stack Development Kit Deployment Credentials ###

if ([string]::IsNullOrEmpty($azureStackAdminPwd)) {
    Write-CustomVerbose -Message "You didn't enter the Azure Stack Development Kit Deployment password." 
    $secureAzureStackAdminPwd = Read-Host "Please enter the password used for the Azure Stack Development Kit Deployment, for account AzureStack\AzureStackAdmin" -AsSecureString -ErrorAction Stop
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureStackAdminPwd)            
    $azureStackAdminPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
}

Write-CustomVerbose -Message "Checking to see Azure Stack Admin password is strong..."

$azureStackAdminUsername = "AzureStack\AzureStackAdmin"
if ($azureStackAdminPwd -cmatch $regex -eq $true) {
    Write-CustomVerbose -Message "Azure Stack Development Kit Deployment password for AzureStack\AzureStackAdmin, meets desired complexity level" 
    # Convert plain text password to a secure string
    $secureAzureStackAdminPwd = ConvertTo-SecureString -AsPlainText $azureStackAdminPwd -Force
    $azureStackAdminCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $azureStackAdminUsername, $secureAzureStackAdminPwd -ErrorAction Stop
}

elseif ($azureStackAdminPwd -cmatch $regex -eq $false) {
    Write-Host "`r`nAzure Stack Admin (AzureStack\AzureStackAdmin) password is not a strong password.`nIt should ideally be at least 8 characters, with at least 1 upper case, 1 lower case, and 1 special character.`nPlease consider a stronger password in the future.`r`n" -ForegroundColor Cyan
    Start-Sleep -Seconds 10
    # Convert plain text password to a secure string
    $secureAzureStackAdminPwd = ConvertTo-SecureString -AsPlainText $azureStackAdminPwd -Force
    $azureStackAdminCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $azureStackAdminUsername, $secureAzureStackAdminPwd -ErrorAction Stop
}

<### Credentials Recap ###
$azureStackAdminUsername = "AzureStack\AzureStackAdmin" | Used to log into the local ASDK Host
azureStackAdminPwd (and $secureAzureStackAdminPwd) | Used to log into the local ASDK Host
$azureStackAdminCreds | Used to log into the local ASDK Host
#>

### Validate Azure Stack Development Kit Service Administrator Credentials (AZURE AD ONLY) ###

if ($authenticationType.ToString() -like "AzureAd") {

    ### Validate Azure AD Service Administrator Username (Used for ASDK Deployment) ###

    if ([string]::IsNullOrEmpty($azureAdUsername)) {
        Write-CustomVerbose -Message "You didn't enter a username for the Azure AD login." 
        $azureAdUsername = Read-Host "Please enter a username in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" -ErrorAction Stop
    }

    Write-CustomVerbose -Message "Checking to see if Azure AD Service Administrator (Used for ASDK Deployment) username is correctly formatted..."

    if ($azureAdUsername.ToLower() -cmatch $emailRegex -eq $true) {
        Write-CustomVerbose -Message "Azure AD Service Administrator username (Used for ASDK Deployment) is correctly formatted."
        $azureAdUsername = $azureAdUsername.ToLower()
        Write-CustomVerbose -Message "$azureAdUsername will be used to connect to Azure." 
    }

    elseif ($azureAdUsername.ToLower() -cmatch $emailRegex -eq $false) {
        Write-CustomVerbose -Message "Azure AD Service Administrator Username (Used for ASDK Deployment) isn't correctly formatted. It should be entered in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" 
        # Obtain new username
        $azureAdUsername = Read-Host "Enter Azure AD Service Administrator Username (Used for ASDK Deployment) again" -ErrorAction Stop
        if ($azureAdUsername.ToLower() -cmatch $emailRegex -eq $true) {
            $azureAdUsername = $azureAdUsername.ToLower()
            Write-CustomVerbose -Message "Azure AD Service Administrator Username (Used for ASDK Deployment) is correctly formatted." 
            Write-CustomVerbose -Message "$azureAdUsername will be used to connect to Azure." 
        }
        else {
            Write-CustomVerbose -Message "No valid Azure AD Service Administrator Username (Used for ASDK Deployment) was entered again. Exiting process..." -ErrorAction Stop 
            Set-Location $ScriptLocation
            return
        }
    }

    ### Validate Azure AD Service Administrator (Used for ASDK Deployment) Password ###

    if ([string]::IsNullOrEmpty($azureAdPwd)) {
        Write-CustomVerbose -Message "You didn't enter the Azure AD Service Administrator account (Used for ASDK Deployment) password." 
        $secureAzureAdPwd = Read-Host "Please enter the password for the Azure AD Service Administrator account used to deploy the ASDK. It should be at least 8 characters, with at least 1 upper case and 1 special character." -AsSecureString -ErrorAction Stop
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureAdPwd)            
        $azureAdPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
    }

    Write-CustomVerbose -Message "Checking to see if password for the Azure AD Service Administrator used to deploy the ASDK, is strong..."

    if ($azureAdPwd -cmatch $regex -eq $true) {
        Write-CustomVerbose -Message "Password for the Azure AD Service Administrator account used to deploy the ASDK meets desired complexity level" 
        # Convert plain text password to a secure string
        $secureAzureAdPwd = ConvertTo-SecureString -AsPlainText $azureAdPwd -Force
        $azureAdCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureAdUsername, $secureAzureAdPwd) -ErrorAction Stop
    }

    elseif ($azureAdPwd -cmatch $regex -eq $false) {
        Write-Host "`r`nAzure AD Service Administrator account password is not a strong password.`nIt should ideally be at least 8 characters, with at least 1 upper case, 1 lower case, and 1 special character.`nPlease consider a stronger password in the future.`r`n" -ForegroundColor Cyan
        Start-Sleep -Seconds 10
        $secureAzureAdPwd = ConvertTo-SecureString -AsPlainText $azureAdPwd -Force
        $azureAdCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureAdUsername, $secureAzureAdPwd) -ErrorAction Stop
    }

    $asdkCreds = $azureAdCreds

    <### Credentials Recap ###
$azureAdUsername | Used for Azure AD athentication to log into Azure/Azure Stack portals
$azureAdPwd (and $secureAzureAdPwd) | Used to log into Azure/Azure Stack portals
$azureAdCreds | Combined credentials, used to log into Azure/Azure Stack portals
$asdkCreds | New variable to represent the $azureAdCreds (if Azure AD) or the $azureStackAdminCreds (if ADFS)
#>

    if ($useAzureCredsForRegistration -and $registerASDK) {
        $azureRegCreds = $azureAdCreds
    }

    elseif (!$useAzureCredsForRegistration -and $registerASDK) {
        
        if ([string]::IsNullOrEmpty($azureRegUsername)) {
            Write-CustomVerbose -Message "You didn't enter a username for Azure account you'll use to register the Azure Stack to." 
            $azureRegUsername = Read-Host "Please enter a username in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" -ErrorAction Stop
        }
    
        Write-CustomVerbose -Message "Checking to see if the Azure AD username is correctly formatted..."
    
        if ($azureRegUsername -cmatch $emailRegex -eq $true) {
            Write-CustomVerbose -Message "Azure AD username is correctly formatted." 
            Write-CustomVerbose -Message "$azureRegUsername will be used to connect to Azure." 
        }
    
        elseif ($azureRegUsername -cmatch $emailRegex -eq $false) {
            Write-CustomVerbose -Message "Azure AD username isn't correctly formatted. It should be entered in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" 
            # Obtain new username
            $azureRegUsername = Read-Host "Enter Azure AD username again"
            if ($azureRegUsername -cmatch $emailRegex -eq $true) {
                Write-CustomVerbose -Message "Azure AD username is correctly formatted." 
                Write-CustomVerbose -Message "$azureRegUsername will be used to connect to Azure." 
            }
            else {
                Write-CustomVerbose -Message "No valid Azure AD username was entered again. Exiting process..." -ErrorAction Stop 
                Set-Location $ScriptLocation
                return
            }
        }
    
        ### Validate Azure AD Registration Password ###
    
        if ([string]::IsNullOrEmpty($azureRegPwd)) {
            Write-CustomVerbose -Message "You didn't enter the Azure AD password that you want to use for registration." 
            $secureAzureRegPwd = Read-Host "Please enter the Azure AD password you wish to use for registration. It should ideally be at least 8 characters, with at least 1 upper case and 1 special character." -AsSecureString -ErrorAction Stop
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureRegPwd)            
            $azureRegPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
        }
    
        Write-CustomVerbose -Message "Checking to see if Azure AD password is strong..."
    
        if ($azureRegPwd -cmatch $regex -eq $true) {
            Write-CustomVerbose -Message "Azure AD password meets desired complexity level" 
            # Convert plain text password to a secure string
            $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
            $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
        }
    
        elseif ($azureRegPwd -cmatch $regex -eq $false) {
            Write-Host "`r`nAzure AD password for registration is not a strong password.`nIt should ideally be at least 8 characters, with at least 1 upper case, 1 lower case, and 1 special character.`nPlease consider a stronger password in the future.`r`n" -ForegroundColor Cyan
            Start-Sleep -Seconds 10
            $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
            $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
        }
    }
}

### Create Cloud Admin Creds ###
$cloudAdminUsername = "azurestack\cloudadmin"
$cloudAdminCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $cloudAdminUsername, $secureAzureStackAdminPwd -ErrorAction Stop

<### Credentials Recap ###
$azureRegUsername | Used for Azure AD authentication to register the ASDK if NOT using same Azure AD Creds as deployment
$azureRegPwd (and $secureAzureRegPwd) | Used for Azure AD authentication to register the ASDK if NOT using same Azure AD Creds as deployment
$azureRegCreds | Combined credentials, used for Azure AD authentication to register the ASDK if NOT using same Azure AD Creds as deployment
$cloudAdminCreds | Used for ADFS login (azurestackadmin not used) and also MySQL/SQL RP deployment
#>

if ($authenticationType.ToString() -like "ADFS") {
    $asdkCreds = $cloudAdminCreds
}

<### Credentials Recap ###
$asdkCreds | If deployment is using ADFS, $asdkCreds will be set to match $azureStackAdminCreds, which should be azurestack\azurestackadmin and accompanying password
#>

if ($authenticationType.ToString() -like "ADFS" -and $registerASDK) {

    # If the user has chosen ADFS authentication, they will need to be prompted to provide some additional Azure credentials to register the ASDK.
    # This If statement captures those credentials

    Remove-Variable -Name azureAdPwd -Force -ErrorAction SilentlyContinue
    Remove-Variable -Name azureAdUsername -Force -ErrorAction SilentlyContinue

    Write-CustomVerbose -Message "Checking for an Azure AD username - this account will be used to register the ADFS-based ASDK to Azure..."
            
    if ([string]::IsNullOrEmpty($azureRegUsername)) {
        Write-CustomVerbose -Message "You didn't enter a username for Azure account you'll use to register the Azure Stack to." 
        $azureRegUsername = Read-Host "Please enter a username in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" -ErrorAction Stop
    }
    else {
        Write-CustomVerbose -Message "Found an Azure AD username that will be used for registering this ADFS-based Azure Stack to Azure" 
        Write-CustomVerbose -Message "Account username is $azureRegUsername"
    }
        
    Write-CustomVerbose -Message "Checking to see if the Azure AD username, that will be used for Azure Stack registration to Azure, is correctly formatted..."
        
    if ($azureRegUsername -cmatch $emailRegex -eq $true) {
        Write-CustomVerbose -Message "Azure AD username is correctly formatted."
        Write-CustomVerbose -Message "$azureRegUsername will be used to register this ADFS-based Azure Stack to Azure."
    }
        
    elseif ($azureRegUsername -cmatch $emailRegex -eq $false) {
        Write-CustomVerbose -Message "Azure AD username isn't correctly formatted. It should be entered in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" 
        # Obtain new username
        $azureRegUsername = Read-Host "Enter Azure AD username again"
        if ($azureRegUsername -cmatch $emailRegex -eq $true) {
            Write-CustomVerbose -Message "Azure AD username is correctly formatted."
            Write-CustomVerbose -Message "$azureRegUsername will be used to register this ADFS-based Azure Stack to Azure."
        }
        else {
            Write-CustomVerbose -Message "No valid Azure AD username was entered again. Exiting process..." -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
        
    ### Validate Azure AD Registration Password ADFS-based Azure Stack ###

    Write-CustomVerbose -Message "Checking for an Azure AD password - this account will be used to register the ADFS-based ASDK to Azure..."
        
    if ([string]::IsNullOrEmpty($azureRegPwd)) {
        Write-CustomVerbose -Message "You didn't enter the Azure AD password that you want to use for registration." 
        $secureAzureRegPwd = Read-Host "Please enter the Azure AD password you wish to use for registration. It should ideally be at least 8 characters, with at least 1 upper case and 1 special character." -AsSecureString -ErrorAction Stop
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureRegPwd)            
        $azureRegPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
    }

    Write-CustomVerbose -Message "Checking to see if Azure AD password for registration is strong..."

    if ($azureRegPwd -cmatch $regex -eq $true) {
        Write-CustomVerbose -Message "Azure AD password meets desired complexity level" 
        # Convert plain text password to a secure string
        $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
        $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
    }

    elseif ($azureRegPwd -cmatch $regex -eq $false) {
        Write-Host "`r`nAzure AD password for registration is not a strong password.`nIt should ideally be at least 8 characters, with at least 1 upper case, 1 lower case, and 1 special character.`nPlease consider a stronger password in the future.`r`n" -ForegroundColor Cyan
        Start-Sleep -Seconds 10
        $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
        $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
    }
}

if ($registerASDK) {

    Write-CustomVerbose -Message "Checking for a valid Azure subscription ID that will be used to register the Azure Stack to Azure"
    ### Validate Azure Subscription ID for Registration ###
    if ([string]::IsNullOrEmpty($azureRegSubId)) {
        Write-CustomVerbose -Message "You didn't enter a subscription ID for registering your Azure Stack in Azure."
        $azureRegSubId = Read-Host "Please enter a valid Azure subscription ID" -ErrorAction Stop
    }      
    if ($azureRegSubId) {
        Write-CustomVerbose -Message "Azure subscription ID has been provided."
        Write-CustomVerbose -Message "$azureRegSubId will be used to register this Azure Stack with Azure."
    }   
    elseif ([string]::IsNullOrEmpty($azureRegSubId)) {
        Write-CustomVerbose -Message "No valid Azure subscription ID was entered again. Exiting process..." -ErrorAction Stop
        Set-Location $ScriptLocation
        return    
    }
}

### TEST ALL LOGINS #########################################################################################################################################
#############################################################################################################################################################

$scriptStep = "TEST LOGINS"

# Clear all logins
Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
Clear-AzureRmContext -Scope CurrentUser -Force

# Register an AzureRM environment that targets your administrative Azure Stack instance
Write-CustomVerbose -Message "ASDK Configurator will now test all logins"
$ArmEndpoint = "https://adminmanagement.local.azurestack.external"
Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
$ADauth = (Get-AzureRmEnvironment -Name "AzureStackAdmin").ActiveDirectoryAuthority

if ($authenticationType.ToString() -like "AzureAd") {
    try {
        ### TEST AZURE LOGIN - Login to Azure Cloud (used for App Service App creation)
        Write-CustomVerbose -Message "Testing Azure login with Azure Active Directory`r`n"
        Login-AzureRmAccount -EnvironmentName "AzureCloud" -TenantId "$azureDirectoryTenantName" -Credential $asdkCreds -ErrorAction Stop | Out-Null
        $testAzureSub = Get-AzureRmContext | Out-Null
        Write-CustomVerbose -Message "Selected Azure Subscription is:`r`n`r`n"
        Write-Output $testAzureSub
        Start-Sleep -Seconds 5
        # Clear Azure login
        Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
        Clear-AzureRmContext -Scope CurrentUser -Force

        ### TEST AZURE STACK LOGIN - Login to Azure Stack
        Write-CustomVerbose -Message "Testing Azure Stack login with Azure Active Directory"
        Write-CustomVerbose -Message "Setting GraphEndpointResourceId value for Azure AD`r`n`r`n"
        Set-AzureRmEnvironment -Name "AzureStackAdmin" -GraphAudience "https://graph.windows.net/" -ErrorAction Stop
        Write-CustomVerbose -Message "Getting Tenant ID for Login to Azure Stack"
        $endpt = "{0}{1}/.well-known/openid-configuration" -f $ADauth, $azureDirectoryTenantName
        $OauthMetadata = (Invoke-WebRequest -UseBasicParsing $endpt).Content | ConvertFrom-Json
        $TenantID = $OauthMetadata.Issuer.Split('/')[3]
        Write-CustomVerbose -Message "Logging into the Default Provider Subscription with your Azure Stack Administrator Account used with Azure Active Directory`r`n`r`n"
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Subscription "Default Provider Subscription" -Credential $asdkCreds -ErrorAction Stop | Out-Null
        # Clear Azure login
        Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
        Clear-AzureRmContext -Scope CurrentUser -Force
    }
    catch {
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($authenticationType.ToString() -like "ADFS") {
    try {
        ### TEST AZURE STACK LOGIN with ADFS - Login to Azure Stack
        Write-CustomVerbose -Message "Testing Azure Stack login with ADFS"
        Write-CustomVerbose -Message "Setting GraphEndpointResourceId value for ADFS`r`n`r`n"
        Set-AzureRmEnvironment -Name "AzureStackAdmin" -GraphAudience "https://graph.local.azurestack.external/" -EnableAdfsAuthentication:$true
        Write-CustomVerbose -Message "Getting Tenant ID for Login to Azure Stack"
        $TenantID = $(Invoke-RestMethod $("{0}/.well-known/openid-configuration" -f $ADauth.TrimEnd('/'))).issuer.TrimEnd('/').Split('/')[-1]
        Write-CustomVerbose -Message "Logging in with your Azure Stack Administrator Account used with ADFS`r`n`r`n"
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Subscription "Default Provider Subscription" -Credential $asdkCreds -ErrorAction Stop | Out-Null
        # Clean up current logins
        Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
        Clear-AzureRmContext -Scope CurrentUser -Force
    }
    catch {
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
if ($registerASDK) {
    try {
        ### OPTIONAL - TEST AZURE REGISTRATION CREDS
        Write-CustomVerbose -Message "Testing Azure login for registration with Azure Active Directory`r`n"
        Login-AzureRmAccount -EnvironmentName "AzureCloud" -SubscriptionId $azureRegSubId -Credential $azureRegCreds -ErrorAction Stop | Out-Null
        $testAzureRegSub = Get-AzureRmContext | Out-Null
        Write-CustomVerbose -Message "Selected Azure Subscription used for registration is:`r`n`r`n"
        Write-Output $testAzureRegSub
        Start-Sleep -Seconds 5
        # Clear Azure login
        Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
        Clear-AzureRmContext -Scope CurrentUser -Force
    }
    catch {
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif (!$registerASDK) {
    Write-CustomVerbose -Message "User has chosen to not register the ASDK with Azure"
    Write-CustomVerbose -Message "No need to test login for registration"
}

# Clean up current logins
Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
Clear-AzureRmContext -Scope CurrentUser -Force

### Run Counter #############################################################################################################################################
#############################################################################################################################################################

# Once logins have been successfully tested, increment run counter to track usage
# This is used to understand how many times the ConfigASDK.ps1 script has been run
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "http://bit.ly/asdkcounter" -UseBasicParsing -ErrorAction SilentlyContinue -DisableKeepAlive | Out-Null

### DOWNLOADER FUNCTION #####################################################################################################################################
#############################################################################################################################################################
function DownloadWithRetry([string] $downloadURI, [string] $downloadLocation, [int] $retries) {
    while ($true) {
        try {
            (New-Object System.Net.WebClient).DownloadFile($downloadURI, $downloadLocation)
            break
        }
        catch {
            $exceptionMessage = $_.Exception.Message
            Write-CustomVerbose -Message "Failed to download '$downloadURI': $exceptionMessage"
            if ($retries -gt 0) {
                $retries--
                Write-CustomVerbose -Message "Waiting 10 seconds before retrying. Retries left: $retries"
                Start-Sleep -Seconds 10
            }
            else {
                $exception = $_.Exception
                throw $exception
            }
        }
    }
}

### DOWNLOAD TOOLS #####################################################################################################################################
########################################################################################################################################################

### CREATE ASDK FOLDER ###

$ASDKpath = [System.IO.Directory]::Exists("$downloadPath\ASDK")
If ($ASDKpath -eq $true) {
    Write-CustomVerbose -Message "ASDK folder exists at $downloadPath - no need to create it."
    Write-CustomVerbose -Message "Download files will be placed in $downloadPath\ASDK"
    $ASDKpath = "$downloadPath\ASDK"
    Write-CustomVerbose -Message "ASDK folder full path is $ASDKpath"
}
elseif ($ASDKpath -eq $false) {
    # Create the ASDK folder.
    Write-CustomVerbose -Message "ASDK folder doesn't exist within $downloadPath, creating it"
    mkdir "$downloadPath\ASDK" -Force | Out-Null
    $ASDKpath = "$downloadPath\ASDK"
    Write-CustomVerbose -Message "ASDK folder full path is $ASDKpath"
}

$progress = Import-Csv -Path $ConfigASDKProgressLogPath
$RowIndex = [array]::IndexOf($progress.Stage, "DownloadTools")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()

if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {

    try {
        ### DOWNLOAD & EXTRACT TOOLS ###
        # Download the tools archive using a function incase the download fails or is interrupted.
        $toolsURI = "https://github.com/Azure/AzureStack-Tools/archive/master.zip"
        $toolsDownloadLocation = "$ASDKpath\master.zip"
        Write-CustomVerbose -Message "Downloading Azure Stack Tools to ensure you have the latest versions. This may take a few minutes, depending on your connection speed."
        Write-CustomVerbose -Message "The download will be stored in $ASDKpath."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        DownloadWithRetry -downloadURI "$toolsURI" -downloadLocation "$toolsDownloadLocation" -retries 10

        # Expand the downloaded files
        Write-CustomVerbose -Message "Expanding Archive"
        Expand-Archive "$toolsDownloadLocation" -DestinationPath "C:\" -Force
        Write-CustomVerbose -Message "Archive expanded. Cleaning up."
        Remove-Item "$toolsDownloadLocation" -Force -ErrorAction Stop

        # Update the ConfigASDKProgressLog.csv file with successful completion
        Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
    }
    catch {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return        
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

# Change to the tools directory
Write-CustomVerbose -Message "Changing Directory"
$modulePath = "C:\AzureStack-Tools-master"
Set-Location $modulePath
Disable-AzureRmDataCollection -WarningAction SilentlyContinue

### CONFIGURE THE AZURE STACK HOST & INFRA VIRTUAL MACHINES ############################################################################################
########################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "HostConfiguration")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Set password expiration to 180 days
        Write-CustomVerbose -Message "Configuring password expiration policy"
        Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 180.00:00:00 -Identity azurestack.local
        Get-ADDefaultDomainPasswordPolicy

        # Set Power Policy
        Write-CustomVerbose -Message "Optimizing power policy for high performance"
        POWERCFG.EXE /S SCHEME_MIN

        # Disable Windows Update on infrastructure VMs
        Write-CustomVerbose -Message "Disabling Windows Update on Infrastructure VMs and ASDK Host`r`n"
        $AZSvms = Get-VM -Name AZS*
        $scriptblock = {
            Get-Service -Name wuauserv | Stop-Service -Force -PassThru | Set-Service -StartupType disabled -Confirm:$false
        }
        foreach ($vm in $AZSvms) {
            Invoke-Command -VMName $vm.name -ScriptBlock $scriptblock -Credential $azureStackAdminCreds
        }

        # Disable Windows Update and DNS Server on Host - using foreach loop as ASDK on Azure solution doesn't have DNS Server.
        $serviceArray = @()
        $serviceArray.Clear()
        $serviceArray = "wuauserv", "DNS"
        foreach ($service in $serviceArray) {
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                Write-CustomVerbose -Message "Stopping Service: $service"
                Stop-Service -Name $service -Force -PassThru
                Write-CustomVerbose -Message "Disabling Service: $service at startup"
                Set-Service -Name $service -StartupType disabled -Confirm:$false
            }
            else {
                Write-CustomVerbose -Message "Service: $service not found, continuing process..."
            }
        }

        # Update the ConfigASDKProgressLog.csv file with successful completion
        Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        Write-CustomVerbose -Message "Host configuration is now complete."
    }
    Catch {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

### REGISTER AZURE STACK TO AZURE ############################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "Registration")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if ($registerASDK) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            Write-CustomVerbose -Message "Starting Azure Stack registration to Azure"
            # Add the Azure cloud subscription environment name. Supported environment names are AzureCloud or, if using a China Azure Subscription, AzureChinaCloud.
            Login-AzureRmAccount -EnvironmentName "AzureCloud" -SubscriptionId $azureRegSubId -Credential $azureRegCreds -ErrorAction Stop | Out-Null
            # Register the Azure Stack resource provider in your Azure subscription
            Register-AzureRmResourceProvider -ProviderNamespace Microsoft.AzureStack
            # Import the registration module that was downloaded with the GitHub tools
            Import-Module $modulePath\Registration\RegisterWithAzure.psm1 -Force -Verbose
            #Register Azure Stack
            $AzureContext = Get-AzureRmContext
            Set-AzsRegistration -PrivilegedEndpointCredential $cloudAdminCreds -PrivilegedEndpoint AzS-ERCS01 -BillingModel Development -ErrorAction Stop
            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif (!$registerASDK) {
    Write-CustomVerbose -Message "Skipping Azure Stack registration to Azure`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

### CONNECT TO AZURE STACK #############################################################################################################################
########################################################################################################################################################
$scriptStep = "CONNECTING"
# Add GraphEndpointResourceId value for Azure AD or ADFS and obtain Tenant ID, then login to Azure Stack
if ($authenticationType.ToString() -like "AzureAd") {
    Write-CustomVerbose -Message "Azure Active Directory selected by Administrator"
    Write-CustomVerbose -Message "Setting GraphEndpointResourceId value for Azure AD"
    Set-AzureRmEnvironment -Name "AzureStackAdmin" -GraphAudience "https://graph.windows.net/" -ErrorAction Stop
    Write-CustomVerbose -Message "Getting Tenant ID for Login to Azure Stack"
    $endpt = "{0}{1}/.well-known/openid-configuration" -f $ADauth, $azureDirectoryTenantName
    $OauthMetadata = (Invoke-WebRequest -UseBasicParsing $endpt).Content | ConvertFrom-Json
    $TenantID = $OauthMetadata.Issuer.Split('/')[3]
    Write-CustomVerbose -Message "Logging into the Default Provider Subscription with your Azure Stack Administrator Account used with Azure Active Directory"
    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Subscription "Default Provider Subscription" -Credential $asdkCreds -ErrorAction Stop
}
elseif ($authenticationType.ToString() -like "ADFS") {
    Write-CustomVerbose -Message "Active Directory Federation Services selected by Administrator"
    Write-CustomVerbose -Message "Setting GraphEndpointResourceId value for ADFS"
    Set-AzureRmEnvironment -Name "AzureStackAdmin" -GraphAudience "https://graph.local.azurestack.external/" -EnableAdfsAuthentication:$true
    Write-CustomVerbose -Message "Getting Tenant ID for Login to Azure Stack"
    $TenantID = $(Invoke-RestMethod $("{0}/.well-known/openid-configuration" -f $ADauth.TrimEnd('/'))).issuer.TrimEnd('/').Split('/')[-1]
    Write-CustomVerbose -Message "Logging in with your Azure Stack Administrator Account used with ADFS"
    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Subscription "Default Provider Subscription" -Credential $asdkCreds -ErrorAction Stop
}
else {
    Write-CustomVerbose -Message ("No valid authentication types specified - please use AzureAd or ADFS")  -ErrorAction Stop
}

# Get Azure Stack location
$azsLocation = (Get-AzsLocation).Name

### ADD UBUNTU PLATFORM IMAGE ################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "UbuntuImage")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()

# Create RG
$asdkImagesRGName = "azurestack-images"
$asdkImagesStorageAccountName = "asdkimagesstor"
$asdkImagesContainerName = "asdkimagescontainer"

if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {

        # Test/Create RG
        if (-not (Get-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -ErrorAction SilentlyContinue)) {
            New-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
        }

        # Test/Create Storage
        $asdkStorageAccount = Get-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName -ErrorAction SilentlyContinue
        if (-not ($asdkStorageAccount)) {
            $asdkStorageAccount = New-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -Location $azsLocation -ResourceGroupName $asdkImagesRGName -Type Standard_LRS -ErrorAction Stop
        }
        Set-AzureRmCurrentStorageAccount -StorageAccountName $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName 

        # Test/Create Container
        $asdkContainer = Get-AzureStorageContainer -Name $asdkImagesContainerName -ErrorAction SilentlyContinue
        if (-not ($asdkContainer)) {
            $asdkContainer = New-AzureStorageContainer -Name $asdkImagesContainerName -Permission Blob -Context $asdkStorageAccount.Context -ErrorAction Stop
        }       
        if ($registerASDK) {
            # Logout to clean up
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
            Clear-AzureRmContext -Scope CurrentUser -Force

            ### Login to Azure to get all the details about the syndicated Ubuntu Server 16.04 marketplace offering ###
            Import-Module "$modulePath\Syndication\AzureStack.MarketplaceSyndication.psm1"
            Login-AzureRmAccount -EnvironmentName "AzureCloud" -SubscriptionId $azureRegSubId -Credential $azureRegCreds -ErrorAction Stop | Out-Null
            $sub = Get-AzureRmSubscription -SubscriptionId $azureRegSubId | Select-AzureRmSubscription
            $AzureContext = Get-AzureRmContext
            $subID = $AzureContext.Subscription.Id
            $azureAccount = Add-AzureRmAccount -subscriptionid $AzureContext.Subscription.Id -TenantId $AzureContext.Tenant.TenantId -Credential $azureRegCreds
            $azureEnvironment = Get-AzureRmEnvironment -Name AzureCloud
            $resources = Get-AzureRmResource
            $resource = $resources.resourcename
            $registrations = @($resource | Where-Object {$_ -like "AzureStack*"})
            if ($registrations.count -gt 1) {
                $Registration = $registrations[0]
            }
            else {
                $Registration = $registrations
            }

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
            $uri1 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($subID.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products?api-version=2016-01-01"
            $Headers = @{ 'authorization' = "Bearer $($Token.AccessToken)"} 
            $product = (Invoke-RestMethod -Method GET -Uri $uri1 -Headers $Headers).value | Where-Object {$_.name -like "$package"} | Sort-Object Name | Select-Object -Last 1 -ErrorAction Stop

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
                name       = "Canonical.UbuntuServer1604LTS-ARM.1.0.0"
            }
        }

        ### Log back into Azure Stack to check for existing images and push new ones if required ###
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

        Write-CustomVerbose -Message "Checking to see if an Ubuntu Server 16.04-LTS VM Image is present in your Azure Stack Platform Image Repository"
        if ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
            Write-CustomVerbose -Message "There appears to be at least 1 suitable Ubuntu Server 16.04-LTS VM image within your Platform Image Repository which we will use for the ASDK Configurator. Here are the details:"
            Write-CustomVerbose -Message ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}".' -f $azpkg.publisher, $azpkg.offer, $azpkg.sku, $azpkg.vhdVersion) -ErrorAction SilentlyContinue
        }

        else {
            Write-CustomVerbose -Message "No existing suitable Ubuntu Server 1604-LTS VM image exists." 
            Write-CustomVerbose -Message "The Ubuntu Server VM Image in the Azure Stack Platform Image Repository must have the following properties:"
            Write-CustomVerbose -Message "Publisher Name = $($azpkg.publisher)"
            Write-CustomVerbose -Message "Offer = $($azpkg.offer)"
            Write-CustomVerbose -Message "SKU = $($azpkg.sku)"
            Write-CustomVerbose -Message "Version = $($azpkg.vhdVersion)"
            Write-CustomVerbose -Message "Unfortunately, no image was found with these properties."
            Write-CustomVerbose -Message "Checking to see if the Ubuntu Server VHD already exists in ASDK Configurator folder"

            $validDownloadPathVHD = [System.IO.File]::Exists("$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).vhd")
            $validDownloadPathZIP = [System.IO.File]::Exists("$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip")

            if ($validDownloadPathVHD -eq $true) {
                Write-CustomVerbose -Message "Located Ubuntu Server VHD in this folder. No need to download again..."
                $UbuntuServerVHD = Get-ChildItem -Path "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).vhd"
                Write-CustomVerbose -Message "Ubuntu Server VHD located at $UbuntuServerVHD"
            }
            elseif ($validDownloadPathZIP -eq $true) {
                Write-CustomVerbose -Message "Cannot find a previously extracted Ubuntu Server VHD with name $($azpkg.offer)$($azpkg.vhdVersion).vhd"
                Write-CustomVerbose -Message "Checking to see if the Ubuntu Server ZIP already exists in ASDK Configurator folder"
                $UbuntuServerZIP = Get-ChildItem -Path "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip"
                Write-CustomVerbose -Message "Ubuntu Server ZIP located at $UbuntuServerZIP"
                Expand-Archive -Path $UbuntuServerZIP -DestinationPath $ASDKpath -Force -ErrorAction Stop
                $UbuntuServerVHD = Get-ChildItem -Path "$ASDKpath" -Filter *.vhd | Rename-Item -NewName "$($azpkg.offer)$($azpkg.vhdVersion).vhd" -PassThru -Force -ErrorAction Stop
            }
            else {
                # No existing Ubuntu Server VHD or Zip exists that matches the name (i.e. that has previously been extracted and renamed) so a fresh one will be
                # downloaded, extracted and the variable $UbuntuServerVHD updated accordingly.
                Write-CustomVerbose -Message "Cannot find a previously extracted Ubuntu Server download or ZIP file"
                Write-CustomVerbose -Message "Begin download of correct Ubuntu Server ZIP and extraction of VHD into $ASDKpath"

                if ($registerASDK) {
                    $ubuntuBuild = $azpkg.vhdVersion
                    $ubuntuBuild = $ubuntuBuild.Substring(0, $ubuntuBuild.Length - 1)
                    $ubuntuBuild = $ubuntuBuild.split('.')[2]
                    $ubuntuURI = "https://cloud-images.ubuntu.com/releases/16.04/release-$ubuntuBuild/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"

                }
                else {
                    $ubuntuURI = "https://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"
                }
                $ubuntuDownloadLocation = "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip"
                DownloadWithRetry -downloadURI "$ubuntuURI" -downloadLocation "$ubuntuDownloadLocation" -retries 10
       
                Expand-Archive -Path "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip" -DestinationPath $ASDKpath -Force -ErrorAction Stop
                $UbuntuServerVHD = Get-ChildItem -Path "$ASDKpath" -Filter *disk1.vhd | Rename-Item -NewName "$($azpkg.offer)$($azpkg.vhdVersion).vhd" -PassThru -Force -ErrorAction Stop
            }

            # Upload the image to the Azure Stack Platform Image Repository
            Write-CustomVerbose -Message "Extraction Complete. Beginning upload of VHD to Platform Image Repository"

            # If the user has chosen to register the ASDK, the script will NOT create a gallery item as part of the image upload
            
            # Upload VHD to Storage Account
            $asdkStorageAccount.PrimaryEndpoints.Blob
            $ubuntuServerURI = '{0}{1}/{2}' -f $asdkStorageAccount.PrimaryEndpoints.Blob.AbsoluteUri, $asdkImagesContainerName, $UbuntuServerVHD.Name

            # Check there's not a VHD already uploaded to storage
            if ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $UbuntuServerVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and ($ubuntuUploadSuccess)) {
                Write-CustomVerbose -Message "You already have an upload of $($UbuntuServerVHD.Name) within your Storage Account. No need to re-upload."
            }
            elseif ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $UbuntuServerVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$ubuntuUploadSuccess)) {
                Try {
                    # Logging in again to ensure login hasn't timed out
                    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    Add-AzureRmVhd -Destination $ubuntuServerURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $UbuntuServerVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                    $ubuntuUploadSuccess = $true
                }
                catch {
                    $ubuntuUploadSuccess = $false
                    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
                    Set-Location $ScriptLocation
                    return
                }
            }
            else {
                Try {
                    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                    Add-AzureRmVhd -Destination $ubuntuServerURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $UbuntuServerVHD.FullName -Verbose -ErrorAction Stop
                    $ubuntuUploadSuccess = $true
                }
                catch {
                    $ubuntuUploadSuccess = $false
                    Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
                    Set-Location $ScriptLocation
                    return
                }
            }

            if ($registerASDK) {
                Add-AzsPlatformImage -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -OsType $azpkg.osVersion -OsUri "$ubuntuServerURI" -Force -Confirm: $false
            }
            else {
                Add-AzsPlatformImage -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -OsType $azpkg.osVersion -OsUri "$ubuntuServerURI" -Force -Confirm: $false
            }
            if ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
                Write-CustomVerbose -Message ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" successfully uploaded.' -f $azpkg.publisher, $azpkg.offer, $azpkg.sku, $azpkg.vhdVersion) -ErrorAction SilentlyContinue
                Write-CustomVerbose -Message "Cleaning up local hard drive space - deleting VHD file, but keeping ZIP"
                Get-ChildItem -Path "$ASDKpath" -Filter *.vhd | Remove-Item -Force
                Write-CustomVerbose -Message "Cleaning up VHD from storage account"
                Remove-AzureStorageBlob -Blob $UbuntuServerVHD.Name -Container $asdkImagesContainerName -Context $asdkStorageAccount.Context -Force
            }
            elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Failed') {
                throw "Adding VM image failed"
            }
            elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -ErrorAction SilentlyContinue).ProvisioningState -eq 'Canceled') {
                throw "Adding VM image was canceled"
            }
        }

        ### If the user has chosen to register the ASDK as part of the process, the script will side load an AZPKG from the Azure Stack Marketplace ###
        
        # Upload AZPKG package
        Write-CustomVerbose -Message "Checking for the following packages: $($azpkg.name)"
        if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$($azpkg.name)*"}) {
            Write-CustomVerbose -Message "Found the following existing package in your Gallery: $($azpkg.name). No need to upload a new one"
        }
        else {
            Write-CustomVerbose -Message "Didn't find this package: $($azpkg.name)"
            Write-CustomVerbose -Message "Will need to side load it in to the gallery"
                
            if ($registerASDK) {
                $galleryItemUri = $($azpkg.azpkgPath)
                Write-CustomVerbose -Message "Uploading $($azpkg.name) with the ID: $($azpkg.id) from $($azpkg.azpkgPath)"
                $galleryItemUri = $($azpkg.azpkgPath)
            }
            else {
                $galleryItemUri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/Ubuntu/Canonical.UbuntuServer1604LTS-ARM.1.0.0.azpkg"
                Write-CustomVerbose -Message "Uploading $($azpkg.name) from $galleryItemUri"
            }
            $Upload = Add-AzsGalleryItem -GalleryItemUri $galleryItemUri -Force -Confirm:$false -ErrorAction Stop
            Start-Sleep -Seconds 5
            $Retries = 0
            # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
            While ($Upload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
                Write-CustomVerbose -Message "$($azpkg.name) wasn't added to the gallery successfully. Retry Attempt #$Retries"
                Write-CustomVerbose -Message "Uploading $($azpkg.name) from $galleryItemUri"
                $Upload = Add-AzsGalleryItem -GalleryItemUri $galleryItemUri -Force -Confirm:$false -ErrorAction Stop
                Start-Sleep -Seconds 5
            }
        }
        Remove-Variable $ubuntuUploadSuccess -Force -ErrorAction SilentlyContinue
        # Update the ConfigASDKProgressLog.csv file with successful completion
        Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
    }
    catch {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

### ADD WINDOWS SERVER 2016 PLATFORM IMAGES ##################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "WindowsImage")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        ### Log back into Azure Stack to check for existing images and push new ones if required ###
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

        Write-CustomVerbose -Message "Checking to see if a Windows Server 2016 image is present in your Azure Stack Platform Image Repository"
        # Pre-validate that the Windows Server 2016 Server Core VM Image is not already available

        Remove-Variable -Name platformImageCore -Force -ErrorAction SilentlyContinue
        $sku = "2016-Datacenter-Server-Core"
        $platformImageCore = Get-AzsPlatformImage -Location "$azsLocation" -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -Version "1.0.0" -ErrorAction SilentlyContinue
        $serverCoreVMImageAlreadyAvailable = $false

        if ($platformImageCore -ne $null -and $platformImageCore.ProvisioningState -eq 'Succeeded') {
            Write-CustomVerbose -Message "There appears to be at least 1 suitable Windows Server $sku image within your Platform Image Repository which we will use for the ASDK Configurator." 
            $serverCoreVMImageAlreadyAvailable = $true
        }

        # Pre-validate that the Windows Server 2016 Full Image is not already available
        Remove-Variable -Name platformImageFull -Force -ErrorAction SilentlyContinue
        $sku = "2016-Datacenter"
        $platformImageFull = Get-AzsPlatformImage -Location "$azsLocation" -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -Version "1.0.0" -ErrorAction SilentlyContinue
        $serverFullVMImageAlreadyAvailable = $false

        if ($platformImageFull -ne $null -and $platformImageFull.ProvisioningState -eq 'Succeeded') {
            Write-CustomVerbose -Message "There appears to be at least 1 suitable Windows Server $sku image within your Platform Image Repository which we will use for the ASDK Configurator." 
            $serverFullVMImageAlreadyAvailable = $true
        }

        if ($serverCoreVMImageAlreadyAvailable -eq $false) {
            $downloadCURequired = $true
            Write-CustomVerbose -Message "You're missing the Windows Server 2016 Datacenter Server Core image in your Platform Image Repository."
        }

        if ($serverFullVMImageAlreadyAvailable -eq $false) {
            $downloadCURequired = $true
            Write-CustomVerbose -Message "You're missing the Windows Server 2016 Datacenter Full image in your Platform Image Repository."
        }

        if (($serverCoreVMImageAlreadyAvailable -eq $true) -and ($serverFullVMImageAlreadyAvailable -eq $true)) {
            $downloadCURequired = $false
            Write-CustomVerbose -Message "Windows Server 2016 Datacenter Full and Core Images already exist in your Platform Image Repository"
        }

        ### Download the latest Cumulative Update for Windows Server 2016 - Existing Azure Stack Tools module doesn't work ###

        if ($downloadCURequired -eq $true) {

            # Mount the ISO, check the image for the version, then dismount
            Remove-Variable -Name buildVersion -ErrorAction SilentlyContinue
            $isoMountForVersion = Mount-DiskImage -ImagePath $ISOPath -StorageType ISO -PassThru
            $isoDriveLetterForVersion = ($isoMountForVersion | Get-Volume).DriveLetter
            $wimPath = "$IsoDriveLetterForVersion`:\sources\install.wim"
            $buildVersion = (dism.exe /Get-WimInfo /WimFile:$wimPath /index:1 | Select-String "Version ").ToString().Split(".")[2].Trim()
            Dismount-DiskImage -ImagePath $ISOPath

            Write-CustomVerbose -Message "You're missing at least one of the Windows Server 2016 Datacenter images, so we'll first download the latest Cumulative Update."
            # Define parameters
            $StartKB = 'https://support.microsoft.com/app/content/api/content/asset/en-us/4000816'
            $Build = $buildVersion
            $SearchString = 'Cumulative.*Server.*x64'

            # Find the KB Article Number for the latest Windows Server 2016 (Build 14393) Cumulative Update
            Write-CustomVerbose -Message "Downloading $StartKB to retrieve the list of updates."
            $kbID = (Invoke-WebRequest -Uri $StartKB -UseBasicParsing).Content | ConvertFrom-Json | Select-Object -ExpandProperty Links | Where-Object level -eq 2 | Where-Object text -match $Build | Select-Object -First 1

            # Get Download Link for the corresponding Cumulative Update
            Write-CustomVerbose -Message "Found ID: KB$($kbID.articleID)"
            $kbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$($kbID.articleID)" -UseBasicParsing
            $Available_kbIDs = $kbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
            $Available_kbIDs | Out-String | Write-Verbose
            $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object innerText -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }

            # If innerHTML is empty or does not exist, use outerHTML instead
            If ($kbIDs -eq $Null) {
                $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }
            }

            $Urls = @()

            ForEach ( $kbID in $kbIDs ) {
                Write-CustomVerbose -Message "KB ID: $kbID"
                $Post = @{ size = 0; updateID = $kbID; uidInfo = $kbID } | ConvertTo-Json -Compress
                $PostBody = @{ updateIDs = "[$Post]" } 
                $Urls += Invoke-WebRequest -Uri 'http://www.catalog.update.microsoft.com/DownloadDialog.aspx' -UseBasicParsing -Method Post -Body $postBody | Select-Object -ExpandProperty Content | Select-String -AllMatches -Pattern "(http[s]?\://download\.windowsupdate\.com\/[^\'\""]*)" | ForEach-Object { $_.matches.value }
            }

            # Download the corresponding Windows Server 2016 Cumulative Update
            ForEach ( $Url in $Urls ) {
                $filename = $Url.Substring($Url.LastIndexOf("/") + 1)
                $target = "$((Get-Item $ASDKpath).FullName)\$filename"
                Write-CustomVerbose -Message "Windows Server 2016 Cumulative Update will be stored at $target"
                Write-CustomVerbose -Message "These are generally larger than 1GB, so may take a few minutes."
                If (!(Test-Path -Path $target)) {
                    DownloadWithRetry -downloadURI "$Url" -downloadLocation "$target" -retries 10
                }
                Else {
                    Write-CustomVerbose -Message "File exists: $target. Skipping download."
                }
            }
            Write-CustomVerbose -Message "Creating Windows Server 2016 Evaluation images..."

            try {
                # Download Convert-WindowsImage.ps1
                $convertWindowsURI = "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/scripts/Convert-WindowsImage.ps1"
                $convertWindowsDownloadLocation = "$ASDKpath\Convert-WindowsImage.ps1"
                Write-CustomVerbose -Message "Downloading Convert-WindowsImage.ps1 to create the VHD from the ISO"
                Write-CustomVerbose -Message "The download will be stored in $ASDKpath."
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                DownloadWithRetry -downloadURI "$convertWindowsURI" -downloadLocation "$convertWindowsDownloadLocation" -retries 10
                Set-Location $ASDKpath

                # Test/Create RG
                if (-not (Get-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -ErrorAction SilentlyContinue)) {
                    New-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -Force -Confirm:$false -ErrorAction Stop
                }

                # Test/Create Storage
                $asdkStorageAccount = Get-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName -ErrorAction SilentlyContinue
                if (-not ($asdkStorageAccount)) {
                    $asdkStorageAccount = New-AzureRmStorageAccount -Name $asdkImagesStorageAccountName -Location $azsLocation -ResourceGroupName $asdkImagesRGName -Type Standard_LRS -ErrorAction Stop
                }
                Set-AzureRmCurrentStorageAccount -StorageAccountName $asdkImagesStorageAccountName -ResourceGroupName $asdkImagesRGName 

                # Test/Create Container
                $asdkContainer = Get-AzureStorageContainer -Name $asdkImagesContainerName -ErrorAction SilentlyContinue
                if (-not ($asdkContainer)) {
                    $asdkContainer = New-AzureStorageContainer -Name $asdkImagesContainerName -Permission Blob -Context $asdkStorageAccount.Context -ErrorAction Stop
                }

                ### If required, build the Server Core Image ###

                if ($serverCoreVMImageAlreadyAvailable -eq $false) {
                    $CoreEdition = 'Windows Server 2016 SERVERDATACENTERCORE'
                    $VHD = .\Convert-WindowsImage.ps1 -SourcePath $ISOpath -WorkingDirectory $ASDKpath -SizeBytes 40GB -Edition "$CoreEdition" -VHDPath "$ASDKpath\ServerCore.vhd" `
                        -VHDFormat VHD -VHDType Fixed -VHDPartitionStyle MBR -Feature "NetFx3" -Package $target -Passthru -Verbose

                    $serverCoreVHD = Get-ChildItem -Path "$ASDKpath" -Filter "*ServerCore.vhd"

                    # Upload VHD to Storage Account
                    $asdkStorageAccount.PrimaryEndpoints.Blob
                    $serverCoreURI = '{0}{1}/{2}' -f $asdkStorageAccount.PrimaryEndpoints.Blob.AbsoluteUri, $asdkImagesContainerName, $serverCoreVHD.Name

                    # Check there's not a VHD already uploaded to storage
                    if ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $serverCoreVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and ($serverCoreUploadSuccess)) {
                        Write-CustomVerbose -Message "You already have an upload of $($serverCoreVHD.Name) within your Storage Account. No need to re-upload."
                    }
                    elseif ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $serverCoreVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$serverCoreUploadSuccess)) {
                        Try {
                            # Log back into Azure Stack to ensure login hasn't timed out
                            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                            Add-AzureRmVhd -Destination $serverCoreURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $serverCoreVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                            $serverCoreUploadSuccess = $true
                        }
                        catch {
                            $serverCoreUploadSuccess = $false
                            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
                            Set-Location $ScriptLocation
                            return
                        }
                    }
                    else {
                        Try {
                            # Log back into Azure Stack to ensure login hasn't timed out
                            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                            Add-AzureRmVhd -Destination $serverCoreURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $serverCoreVHD.FullName -Verbose -ErrorAction Stop
                            $serverCoreUploadSuccess = $true
                        }
                        catch {
                            $serverCoreUploadSuccess = $false
                            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
                            Set-Location $ScriptLocation
                            return
                        }
                    }
                    Add-AzsPlatformImage -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter-Server-Core" -Version "1.0.0" -OsType "Windows" -OsUri "$serverCoreURI" -Force -Confirm: $false

                    if ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter-Server-Core" -Version "1.0.0" -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
                        Write-CustomVerbose -Message ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" successfully uploaded.' -f "MicrosoftWindowsServer", "WindowsServer", "2016-Datacenter-Server-Core", "1.0.0") -ErrorAction SilentlyContinue
                        Write-CustomVerbose -Message "Cleaning up local hard drive space - deleting VHD file, but keeping ZIP"
                        Get-ChildItem -Path "$ASDKpath" -Filter *ServerCore.vhd | Remove-Item -Force
                        Write-CustomVerbose -Message "Cleaning up VHD from storage account"
                        Remove-AzureStorageBlob -Blob $serverCoreVHD.Name -Container $asdkImagesContainerName -Context $asdkStorageAccount.Context -Force
                    }
                    elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter-Server-Core" -Version "1.0.0" -ErrorAction SilentlyContinue).ProvisioningState -eq 'Failed') {
                        throw "Adding VM image failed"
                    }
                    elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter-Server-Core" -Version "1.0.0" -ErrorAction SilentlyContinue).ProvisioningState -eq 'Canceled') {
                        throw "Adding VM image was canceled"
                    }
                }

                ### If required, build the Server Full Image ###

                if ($serverFullVMImageAlreadyAvailable -eq $false) {
                    $FullEdition = 'Windows Server 2016 SERVERDATACENTER'
                    $VHD = .\Convert-WindowsImage.ps1 -SourcePath $ISOpath -WorkingDirectory $ASDKpath -SizeBytes 40GB -Edition "$FullEdition" -VHDPath "$ASDKpath\ServerFull.vhd" `
                        -VHDFormat VHD -VHDType Fixed -VHDPartitionStyle MBR -Feature "NetFx3" -Package $target -Passthru -Verbose

                    $serverFullVHD = Get-ChildItem -Path "$ASDKpath" -Filter "*ServerFull.vhd"

                    # Upload VHD to Storage Account
                    $asdkStorageAccount.PrimaryEndpoints.Blob
                    $serverFullURI = '{0}{1}/{2}' -f $asdkStorageAccount.PrimaryEndpoints.Blob.AbsoluteUri, $asdkImagesContainerName, $serverFullVHD.Name

                    # Check there's not a VHD already uploaded to storage
                    if ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $serverFullVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and ($serverFullUploadSuccess)) {
                        Write-CustomVerbose -Message "You already have an upload of $($serverFullVHD.Name) within your Storage Account. No need to re-upload."
                    }
                    elseif ($(Get-AzureStorageBlob -Container $asdkImagesContainerName -Blob $serverFullVHD.Name -Context $asdkStorageAccount.Context -ErrorAction SilentlyContinue) -and (!$serverFullUploadSuccess)) {
                        Try {
                            # Log back into Azure Stack to ensure login hasn't timed out
                            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                            Add-AzureRmVhd -Destination $serverFullURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $serverFullVHD.FullName -OverWrite -Verbose -ErrorAction Stop
                            $serverFullUploadSuccess = $true
                        }
                        catch {
                            $serverFullUploadSuccess = $false
                            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
                            Set-Location $ScriptLocation
                            return
                        }
                    }
                    else {
                        Try {
                            # Log back into Azure Stack to ensure login hasn't timed out
                            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                            Add-AzureRmVhd -Destination $serverFullURI -ResourceGroupName $asdkImagesRGName -LocalFilePath $serverFullVHD.FullName -Verbose -ErrorAction Stop
                            $serverFullUploadSuccess = $true
                        }
                        catch {
                            $serverFullUploadSuccess = $false
                            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
                            Set-Location $ScriptLocation
                            return
                        }
                    }
                    Add-AzsPlatformImage -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter" -Version "1.0.0" -OsType "Windows" -OsUri "$serverFullURI" -Force -Confirm: $false

                    if ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter" -Version "1.0.0" -ErrorAction SilentlyContinue).ProvisioningState -eq 'Succeeded') {
                        Write-CustomVerbose -Message ('VM Image with publisher "{0}", offer "{1}", sku "{2}", version "{3}" successfully uploaded.' -f "MicrosoftWindowsServer", "WindowsServer", "2016-Datacenter", "1.0.0") -ErrorAction SilentlyContinue
                        Write-CustomVerbose -Message "Cleaning up local hard drive space - deleting VHD file, but keeping ZIP"
                        Get-ChildItem -Path "$ASDKpath" -Filter *ServerFull.vhd | Remove-Item -Force
                        Write-CustomVerbose -Message "Cleaning up VHD from storage account"
                        Remove-AzureStorageBlob -Blob $serverFullVHD.Name -Container $asdkImagesContainerName -Context $asdkStorageAccount.Context -Force
                    }
                    elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter" -Version "1.0.0" -ErrorAction SilentlyContinue).ProvisioningState -eq 'Failed') {
                        throw "Adding VM image failed"
                    }
                    elseif ($(Get-AzsPlatformImage -Location "$azsLocation" -Publisher "MicrosoftWindowsServer" -Offer "WindowsServer" -Sku "2016-Datacenter" -Version "1.0.0" -ErrorAction SilentlyContinue).ProvisioningState -eq 'Canceled') {
                        throw "Adding VM image was canceled"
                    }
                }

                Get-ChildItem -Path "$ASDKpath\*" -Include *.msu, *.cab | Remove-Item -Force
            }
            Catch {
                Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
                Set-Location $ScriptLocation
                return
            }
        }

        ### PACKAGES ###
        # Now check for and create (if required) AZPKG files for sideloading
        # If the user chose not to register the ASDK, the step below will grab an azpkg file from Github
        if (!$registerASDK) {
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

            $packageArray = @()
            $packageArray.Clear()
            $packageArray = "*WindowsServer2016Datacenter-ARM*", "*WindowsServer2016DatacenterServerCore-ARM*"
            Write-CustomVerbose -Message "You chose not to register your Azure Stack to Azure. Checking for existing Windows Server gallery items"

            foreach ($package in $packageArray) {
                $wsPackage = $null
                $wsPackage = (Get-AzsGalleryItem | Where-Object {$_.name -like "$package"} | Sort-Object CreatedTime -Descending | Select-Object -First 1)
                if ($wsPackage) {
                    Write-CustomVerbose -Message "Found the following existing package in your gallery: $($wsPackage.Identity) - No need to upload a new one"
                }
                else {
                    $wsPackage = $package -replace '[*.]', ''
                    Write-CustomVerbose -Message "Didn't find this package: $wsPackage"
                    Write-CustomVerbose -Message "Will need to sideload it in to the gallery"
                    $galleryItemUri = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/WindowsServer/Microsoft.$wsPackage.1.0.0.azpkg"
                    Write-CustomVerbose -Message "Uploading $wsPackage from $galleryItemUri"
                }
                $Upload = Add-AzsGalleryItem -GalleryItemUri $galleryItemUri -Force -Confirm:$false -ErrorAction Stop
                Start-Sleep -Seconds 5
                $Retries = 0
                # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
                While ($Upload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
                    Write-CustomVerbose -Message "$($wsPackage.ItemName) wasn't added to the gallery successfully. Retry Attempt #$Retries"
                    Write-CustomVerbose -Message "Uploading $($wsPackage.Identity) from $galleryItemUri"
                    $Upload = Add-AzsGalleryItem -GalleryItemUri $galleryItemUri -Force -Confirm:$false -ErrorAction Stop
                    Start-Sleep -Seconds 5
                }    
            }
        }

        # If the user chose to register the ASDK as part of the script, this section will log into Azure, scrape the marketplace items and get the properties of
        # the gallery items, and the azpkg files, and side-load them into the Azure Stack marketplace.
        elseif ($registerASDK) {

            ### Login to Azure to get all the details about the syndicated Windows Server 2016 marketplace offering ###
            Import-Module "$modulePath\Syndication\AzureStack.MarketplaceSyndication.psm1"
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
            Clear-AzureRmContext -Scope CurrentUser -Force
            Login-AzureRmAccount -EnvironmentName "AzureCloud" -SubscriptionId $azureRegSubId -Credential $azureRegCreds -ErrorAction Stop | Out-Null
            $sub = Get-AzureRmSubscription -SubscriptionId $azureRegSubId | Select-AzureRmSubscription
            $AzureContext = Get-AzureRmContext
            $subID = $AzureContext.Subscription.Id
            $azureAccount = Add-AzureRmAccount -subscriptionid $AzureContext.Subscription.Id -TenantId $AzureContext.Tenant.TenantId -Credential $azureRegCreds
            $azureEnvironment = Get-AzureRmEnvironment -Name AzureCloud
            $resources = Get-AzureRmResource
            $resource = $resources.resourcename
            $registrations = @($resource | Where-Object {$_ -like "AzureStack*"})
            if ($registrations.count -gt 1) {
                $Registration = $registrations[0]
            }
            else {
                $Registration = $registrations
            }

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

                $products = @()
                $products.Clear()
                $product = $null

                # Get the package information
                $uri1 = "$($azureEnvironment.ResourceManagerUrl.ToString().TrimEnd('/'))/subscriptions/$($subID.ToString())/resourceGroups/azurestack/providers/Microsoft.AzureStack/registrations/$Registration/products?api-version=2016-01-01"
                $Headers = @{ 'authorization' = "Bearer $($Token.AccessToken)"} 
                $products = (Invoke-RestMethod -Method GET -Uri $uri1 -Headers $Headers).value | Where-Object {$_.name -like "$package"} | Sort-Object Name | Select-Object -Last 1

                foreach ($product in $products) {

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
            }

            ### With all the information stored in the arrays, log back into Azure Stack to check for existing gallery items and push new ones if required ###
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

            foreach ($azpkg in $azpkgArray) {

                Write-CustomVerbose -Message "Checking for the following packages: $($azpkg.name)"
                if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$($azpkg.name)*"}) {
                    Write-CustomVerbose -Message "Found the following existing package in your Gallery: $($azpkg.name). No need to upload a new one"
                }
                else {
                    Write-CustomVerbose -Message "Didn't find this package: $($azpkg.name)"
                    Write-CustomVerbose -Message "Will need to side load it in to the gallery"
                    Write-CustomVerbose -Message "Uploading $($azpkg.name) with the ID: $($azpkg.id) from $($azpkg.azpkgPath)"
                    $Upload = Add-AzsGalleryItem -GalleryItemUri $($azpkg.azpkgPath) -Force -Confirm:$false -ErrorAction Stop
                    Start-Sleep -Seconds 5
                    $Retries = 0
                    # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
                    While ($Upload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
                        Write-CustomVerbose -Message "$($azpkg.name) wasn't added to the gallery successfully. Retry Attempt #$Retries"
                        Write-CustomVerbose -Message "Uploading $($azpkg.name) from $($azpkg.azpkgPath)"
                        $Upload = Add-AzsGalleryItem -GalleryItemUri $($azpkg.azpkgPath) -Force -Confirm:$false -ErrorAction Stop
                        Start-Sleep -Seconds 5
                    }
                }
            }
        }
        # Update the ConfigASDKProgressLog.csv file with successful completion
        Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
    }
    catch {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

### ADD VM SCALE SET GALLERY ITEM ############################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "ScaleSetGalleryItem")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        ### Login to Azure Stack, then confirm if the VM Scale Set Gallery Item is already present ###
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        $VMSSPackageName = "microsoft.vmss.1.3.6"
        $VMSSPackageURL = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/VMSS/microsoft.vmss.1.3.6.azpkg"
        Write-CustomVerbose -Message "Checking for the VM Scale Set gallery item"
        if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$VMSSPackageName*"}) {
            Write-CustomVerbose -Message "Found a suitable VM Scale Set Gallery Item in your Azure Stack Marketplace. No need to upload a new one"
        }
        else {
            Write-CustomVerbose -Message "Didn't find this package: $VMSSPackageName"
            Write-CustomVerbose -Message "Will need to side load it in to the gallery"
            Write-CustomVerbose -Message "Uploading $VMSSPackageName"
            $Upload = Add-AzsGalleryItem -GalleryItemUri $VMSSPackageURL -Force -Confirm:$false -ErrorAction Stop
            Start-Sleep -Seconds 5
            $Retries = 0
            # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
            While ($Upload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
                Write-CustomVerbose -Message "$VMSSPackageName wasn't added to the gallery successfully. Retry Attempt #$Retries"
                Write-CustomVerbose -Message "Uploading $VMSSPackageName from $VMSSPackageURL"
                $Upload = Add-AzsGalleryItem -GalleryItemUri $VMSSPackageURL -Force -Confirm:$false -ErrorAction Stop
                Start-Sleep -Seconds 5
            }
        }
        # Update the ConfigASDKProgressLog.csv file with successful completion
        Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
    }
    Catch {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

### ADD MYSQL GALLERY ITEM ###################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "MySQLGalleryItem")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        ### Login to Azure Stack, then confirm if the MySQL Gallery Item is already present ###
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        $mySQLPackageName = "ASDK.MySQL.1.0.0"
        $mySQLPackageURL = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/MySQL/ASDK.MySQL.1.0.0.azpkg"
        Write-CustomVerbose -Message "Checking for the MySQL gallery item"
        if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$mySQLPackageName*"}) {
            Write-CustomVerbose -Message "Found a suitable MySQL Gallery Item in your Azure Stack Marketplace. No need to upload a new one"
        }
        else {
            Write-CustomVerbose -Message "Didn't find this package: $mySQLPackageName"
            Write-CustomVerbose -Message "Will need to side load it in to the gallery"
            Write-CustomVerbose -Message "Uploading $mySQLPackageName"
            $Upload = Add-AzsGalleryItem -GalleryItemUri $mySQLPackageURL -Force -Confirm:$false -ErrorAction Stop
            Start-Sleep -Seconds 5
            $Retries = 0
            # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
            While ($Upload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
                Write-CustomVerbose -Message "$mySQLPackageName wasn't added to the gallery successfully. Retry Attempt #$Retries"
                Write-CustomVerbose -Message "Uploading $mySQLPackageName from $mySQLPackageURL"
                $Upload = Add-AzsGalleryItem -GalleryItemUri $mySQLPackageURL -Force -Confirm:$false -ErrorAction Stop
                Start-Sleep -Seconds 5
            }
        }
        # Update the ConfigASDKProgressLog.csv file with successful completion
        Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
    }
    catch {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

### ADD SQL SERVER GALLERY ITEM ##############################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "SQLServerGalleryItem")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        ### Login to Azure Stack, then confirm if the SQL Server 2017 Gallery Item is already present ###
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        $MSSQLPackageName = "ASDK.MSSQL.1.0.0"
        $MSSQLPackageURL = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/MSSQL/ASDK.MSSQL.1.0.0.azpkg"
        Write-CustomVerbose -Message "Checking for the SQL Server 2017 gallery item"
        if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$MSSQLPackageName*"}) {
            Write-CustomVerbose -Message "Found a suitable SQL Server 2017 Gallery Item in your Azure Stack Marketplace. No need to upload a new one"
        }
        else {
            Write-CustomVerbose -Message "Didn't find this package: $MSSQLPackageName"
            Write-CustomVerbose -Message "Will need to side load it in to the gallery"
            Write-CustomVerbose -Message "Uploading $MSSQLPackageName"
            $Upload = Add-AzsGalleryItem -GalleryItemUri $MSSQLPackageURL -Force -Confirm:$false -ErrorAction Stop
            Start-Sleep -Seconds 5
            $Retries = 0
            # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
            While ($Upload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
                Write-CustomVerbose -Message "$MSSQLPackageName wasn't added to the gallery successfully. Retry Attempt #$Retries"
                Write-CustomVerbose -Message "Uploading $MSSQLPackageName from $MSSQLPackageURL"
                $Upload = Add-AzsGalleryItem -GalleryItemUri $MSSQLPackageURL -Force -Confirm:$false -ErrorAction Stop
                Start-Sleep -Seconds 5
            }
        }
        # Update the ConfigASDKProgressLog.csv file with successful completion
        Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
    }
    catch {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### INSTALL MYSQL RESOURCE PROVIDER #########################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "MySQLRP")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipMySQL) {
    # We first need to check if in a previous run, this section was skipped, but now, the user wants to add this, so we need to reset the progress.
    if ($progress[$RowIndex].Status -eq "Skipped") {
        Write-CustomVerbose -Message "Operator previously skipped this step, but now wants to perform this step. Updating ConfigASDKProgressLog.csv file to Incomplete."
        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Incomplete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        $RowIndex = [array]::IndexOf($progress.Stage, "MySQLRP")
    }
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Login to Azure Stack
            Write-CustomVerbose -Message "Downloading and installing MySQL Resource Provider"
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

            # Cleanup old folder
            Remove-Item "$asdkPath\MySQL" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
            # Download and Expand the MySQL RP files
            $mySqlRpURI = "https://aka.ms/azurestackmysqlrp1804"
            $mySqlRpDownloadLocation = "$ASDKpath\MySQL.zip"
            DownloadWithRetry -downloadURI "$mySqlRpURI" -downloadLocation "$mySqlRpDownloadLocation" -retries 10
            Set-Location $ASDKpath
            Expand-Archive "$ASDKpath\MySql.zip" -DestinationPath .\MySQL -Force -ErrorAction Stop
            Set-Location "$ASDKpath\MySQL"

            # Define the additional credentials for the local virtual machine username/password and certificates password
            $vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("mysqlrpadmin", $secureVMpwd)
            .\DeployMySQLProvider.ps1 -AzCredential $asdkCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $cloudAdminCreds -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureVMpwd -AcceptLicense

            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipMySQL) {
    Write-CustomVerbose -Message "Operator chose to skip MySQL Resource Provider Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### INSTALL SQL SERVER RESOURCE PROVIDER ####################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "SQLServerRP")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipMSSQL) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Login to Azure Stack
            Write-CustomVerbose -Message "Downloading and installing SQL Server Resource Provider"
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

            # Download and Expand the SQL Server RP files
            $sqlRpURI = "https://aka.ms/azurestacksqlrp1804"
            $sqlRpDownloadLocation = "$ASDKpath\SQL.zip"
            DownloadWithRetry -downloadURI "$sqlRpURI" -downloadLocation "$sqlRpDownloadLocation" -retries 10
            Set-Location $ASDKpath
            Expand-Archive "$ASDKpath\SQL.zip" -DestinationPath .\SQL -Force -ErrorAction Stop
            Set-Location "$ASDKpath\SQL"

            # Define the additional credentials for the local virtual machine username/password and certificates password
            $vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("sqlrpadmin", $secureVMpwd)
            .\DeploySQLProvider.ps1 -AzCredential $asdkCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $cloudAdminCreds -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureVMpwd

            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipMSSQL -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip SQL Server Resource Provider Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### REGISTER NEW RESOURCE PROVIDERS #########################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "RegisterNewRPs")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Register resource providers
        foreach ($s in (Get-AzureRmSubscription)) {
            Select-AzureRmSubscription -SubscriptionId $s.SubscriptionId | Out-Null
            Write-Progress $($s.SubscriptionId + " : " + $s.SubscriptionName)
            Get-AzureRmResourceProvider -ListAvailable | Register-AzureRmResourceProvider
        }
        # Update the ConfigASDKProgressLog.csv file with successful completion
        Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
    }
    catch {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### ADD MYSQL SKU & QUOTA ###################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "MySQLSKUQuota")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipMySQL) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Logout to clean up
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
            Clear-AzureRmContext -Scope CurrentUser -Force

            # Set the variables and gather token for creating the SKU & Quota
            $mySqlSkuFamily = "MySQL"
            $mySqlSkuName = "MySQL57"
            $mySqlSkuTier = "Standalone"
            $mySqlLocation = "$azsLocation"
            $mySqlArmEndpoint = $ArmEndpoint.TrimEnd("/", "\");
            $mySqlDatabaseAdapterNamespace = "Microsoft.MySQLAdapter.Admin"
            $mySqlApiVersion = "2017-08-28"
            $mySqlQuotaName = "mysqldefault"
            $mySqlQuotaResourceCount = "10"
            $mySqlQuotaResourceSizeMB = "1024"

            # Login to Azure Stack and populate variables
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            $sub = Get-AzureRmSubscription | Where-Object {$_.Name -eq "Default Provider Subscription"}
            $azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
            $subID = $azureContext.Subscription.Id
            $azureEnvironment = Get-AzureRmEnvironment -Name AzureStackAdmin

            # Fetch the tokens
            $mySqlToken = $null
            $mySqlTokens = $null
            $mySqlTokens = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems()
            $mySqlToken = $mySqlTokens | Where-Object Resource -EQ $azureEnvironment.ActiveDirectoryServiceEndpointResourceId | Where-Object DisplayableId -EQ $AzureContext.Account.Id | Sort-Object ExpiresOn | Select-Object -Last 1 -ErrorAction Stop

            # Build the header for authorization
            $mySqlHeaders = @{ 'authorization' = "Bearer $($mySqlToken.AccessToken)"}

            # Build the URIs
            $skuUri = ('{0}/subscriptions/{1}/providers/{2}/locations/{3}/skus/{4}?api-version={5}' -f $mySqlArmEndpoint, $subID, $mySqlDatabaseAdapterNamespace, $mySqlLocation, $mySqlSkuName, $mySqlApiVersion)
            $quotaUri = ('{0}/subscriptions/{1}/providers/{2}/locations/{3}/quotas/{4}?api-version={5}' -f $mySqlArmEndpoint, $subID, $mySqlDatabaseAdapterNamespace, $mySqlLocation, $mySqlQuotaName, $mySqlApiVersion)

            # Create the request body for SKU
            $skuTenantNamespace = $mySqlDatabaseAdapterNamespace.TrimEnd(".Admin");
            $skuResourceType = '{0}/databases' -f $skuTenantNamespace
            $skuIdForRequestBody = '/subscriptions/{0}/providers/{1}/locations/{2}/skus/{3}' -f $subID, $mySqlDatabaseAdapterNamespace, $mySqlLocation, $mySqlSkuName
            $skuRequestBody = @{
                properties = @{
                    resourceType = $skuResourceType
                    sku          = @{
                        family = $mySqlSkuFamily
                        name   = $mySqlSkuName
                        tier   = $mySqlSkuTier
                    }
                }
                id         = $skuIdForRequestBody
                name       = $mySqlSkuName
            }
            $skuRequestBodyJson = $skuRequestBody | ConvertTo-Json

            # Create the request body for Quota
            $quotaIdForRequestBody = '/subscriptions/{0}/providers/{1}/locations/{2}/quotas/{3}' -f $subID, $mySqlDatabaseAdapterNamespace, $mySqlLocation, $mySqlQuotaName
            $quotaRequestBody = @{
                properties = @{
                    resourceCount       = $mySqlQuotaResourceCount
                    totalResourceSizeMB = $mySqlQuotaResourceSizeMB
                }
                id         = $quotaIdForRequestBody
                name       = $mySqlQuotaName
            }
            $quotaRequestBodyJson = $quotaRequestBody | ConvertTo-Json

            # Create the SKU
            Write-CustomVerbose -Message "Creating new MySQL Resource Provider SKU with name: $($mySqlSkuName), adapter namespace: $($mySqlDatabaseAdapterNamespace)" -Verbose
            try {
                # Make the REST call
                $skuResponse = Invoke-WebRequest -Uri $skuUri -Method Put -Headers $mySqlHeaders -Body $skuRequestBodyJson -ContentType "application/json" -UseBasicParsing
                $skuResponse
            }
            catch {
                $message = $_.Exception.Message
                Write-Error -Message ("[New-AzureStackRmDatabaseAdapterSKU]::Failed to create MySQL Resource Provider SKU with name {0}, failed with error: {1}" -f $mySqlSkuName, $message) 
            }

            # Create the Quota
            Write-CustomVerbose -Message "Creating new MySQL Resource Provider Quota with name: $($mySqlQuotaName), adapter namespace: $($mySqlDatabaseAdapterNamespace)" -Verbose
            try {
                # Make the REST call
                $quotaResponse = Invoke-WebRequest -Uri $quotaUri -Method Put -Headers $mySqlHeaders -Body $quotaRequestBodyJson -ContentType "application/json" -UseBasicParsing
                $quotaResponse
            }
            catch {
                $message = $_.Exception.Message
                Write-Error -Message ("Failed to create MySQL Resource Provider Quota with name {0}, failed with error: {1}" -f $mySqlQuotaName, $message) 
            }
            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipMySQL -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip MySQL Quota and SKU Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### ADD SQL SERVER SKU & QUOTA ##############################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "SQLServerSKUQuota")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipMSSQL) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Logout to clean up
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
            Clear-AzureRmContext -Scope CurrentUser -Force

            # Set the variables and gather token for creating the SKU & Quota
            $sqlSkuFamily = "SQLServer"
            $sqlSkuEdition = "Evaluation"
            $sqlSkuName = "MSSQL2017"
            $sqlSkuTier = "Standalone"
            $sqlLocation = "$azsLocation"
            $sqlArmEndpoint = $ArmEndpoint.TrimEnd("/", "\");
            $sqlDatabaseAdapterNamespace = "Microsoft.SQLAdapter.Admin"
            $sqlApiVersion = "2017-08-28"
            $sqlQuotaName = "sqldefault"
            $sqlQuotaResourceCount = "10"
            $sqlQuotaResourceSizeMB = "1024"

            # Login to Azure Stack and populate variables
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            $sub = Get-AzureRmSubscription | Where-Object {$_.Name -eq "Default Provider Subscription"}
            $azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
            $subID = $azureContext.Subscription.Id
            $azureEnvironment = Get-AzureRmEnvironment -Name AzureStackAdmin

            # Fetch the tokens
            $sqlToken = $null
            $sqlTokens = $null
            $sqlTokens = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems()
            $sqlToken = $sqlTokens | Where-Object Resource -EQ $azureEnvironment.ActiveDirectoryServiceEndpointResourceId | Where-Object DisplayableId -EQ $AzureContext.Account.Id | Sort-Object ExpiresOn | Select-Object -Last 1 -ErrorAction Stop

            # Build the header for authorization
            $sqlHeaders = @{ 'authorization' = "Bearer $($sqlToken.AccessToken)"}

            # Build the URIs
            $skuUri = ('{0}/subscriptions/{1}/providers/{2}/locations/{3}/skus/{4}?api-version={5}' -f $sqlArmEndpoint, $subID, $sqlDatabaseAdapterNamespace, $sqlLocation, $sqlSkuName, $sqlApiVersion)
            $quotaUri = ('{0}/subscriptions/{1}/providers/{2}/locations/{3}/quotas/{4}?api-version={5}' -f $sqlArmEndpoint, $subID, $sqlDatabaseAdapterNamespace, $sqlLocation, $sqlQuotaName, $sqlApiVersion)

            # Create the request body for SKU
            $skuTenantNamespace = $sqlDatabaseAdapterNamespace.TrimEnd(".Admin");
            $skuResourceType = '{0}/databases' -f $skuTenantNamespace
            $skuIdForRequestBody = '/subscriptions/{0}/providers/{1}/locations/{2}/skus/{3}' -f $subID, $sqlDatabaseAdapterNamespace, $sqlLocation, $sqlSkuName
            $skuRequestBody = @{
                properties = @{
                    resourceType = $skuResourceType
                    sku          = @{
                        family = $sqlSkuFamily
                        kind   = $sqlSkuEdition
                        name   = $sqlSkuName
                        tier   = $sqlSkuTier
                    }
                }
                id         = $skuIdForRequestBody
                name       = $sqlSkuName
            }
            $skuRequestBodyJson = $skuRequestBody | ConvertTo-Json

            # Create the request body for Quota
            $quotaIdForRequestBody = '/subscriptions/{0}/providers/{1}/locations/{2}/quotas/{3}' -f $subID, $sqlDatabaseAdapterNamespace, $sqlLocation, $sqlQuotaName
            $quotaRequestBody = @{
                properties = @{
                    resourceCount       = $sqlQuotaResourceCount
                    totalResourceSizeMB = $sqlQuotaResourceSizeMB
                }
                id         = $quotaIdForRequestBody
                name       = $sqlQuotaName
            }
            $quotaRequestBodyJson = $quotaRequestBody | ConvertTo-Json

            # Create the SKU
            Write-CustomVerbose -Message "Creating new SQL Server Resource Provider SKU with name: $($sqlSkuName), adapter namespace: $($sqlDatabaseAdapterNamespace)" -Verbose
            try {
                # Make the REST call
                $skuResponse = Invoke-WebRequest -Uri $skuUri -Method Put -Headers $sqlHeaders -Body $skuRequestBodyJson -ContentType "application/json" -UseBasicParsing
                $skuResponse
            }
            catch {
                $message = $_.Exception.Message
                Write-Error -Message ("[New-AzureStackRmDatabaseAdapterSKU]::Failed to create SQL Server Resource Provider SKU with name {0}, failed with error: {1}" -f $sqlSkuName, $message) 
            }

            # Create the Quota
            Write-CustomVerbose -Message "Creating new SQL Server Resource Provider Quota with name: $($sqlQuotaName), adapter namespace: $($sqlDatabaseAdapterNamespace)" -Verbose
            try {
                # Make the REST call
                $quotaResponse = Invoke-WebRequest -Uri $quotaUri -Method Put -Headers $sqlHeaders -Body $quotaRequestBodyJson -ContentType "application/json" -UseBasicParsing
                $quotaResponse
            }
            catch {
                $message = $_.Exception.Message
                Write-Error -Message ("Failed to create SQL Server Resource Provider Quota with name {0}, failed with error: {1}" -f $sqlQuotaName, $message) 
            }
            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipMSSQL -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip SQL Server Quota and SKU Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### DEPLOY MySQL VM TO HOST USER DATABASES ##################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "MySQLDBVM")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipMySQL) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            Write-CustomVerbose -Message "Creating a dedicated Resource Group for all database hosting assets"
            New-AzureRmResourceGroup -Name "azurestack-dbhosting" -Location $azsLocation -Force

            # Deploy a MySQL VM for hosting tenant db
            Write-CustomVerbose -Message "Creating a dedicated MySQL5.7 on Ubuntu VM for database hosting"
            New-AzureRmResourceGroupDeployment -Name "MySQLHost" -ResourceGroupName "azurestack-dbhosting" -TemplateUri https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/packages/MySQL/ASDK.MySQL/DeploymentTemplates/mainTemplate.json `
                -vmName "mysqlhost" -adminUsername "mysqladmin" -adminPassword $secureVMpwd -mySQLPassword $secureVMpwd -allowRemoteConnections "Yes" `
                -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "mysqlhost" -vmSize Standard_A3 -mode Incremental -Verbose -ErrorAction Stop

            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipMySQL -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip MySQL Hosting Server Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### DEPLOY SQL SERVER VM TO HOST USER DATABASES #############################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "SQLServerDBVM")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipMSSQL) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Deploy a SQL Server 2017 on Ubuntu VM for hosting tenant db
            Write-CustomVerbose -Message "Creating a dedicated SQL Server 2017 on Ubuntu 16.04 LTS for database hosting"
            New-AzureRmResourceGroupDeployment -Name "SQLHost" -ResourceGroupName "azurestack-dbhosting" -TemplateUri https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/packages/MSSQL/ASDK.MSSQL/DeploymentTemplates/mainTemplate.json `
                -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd `
                -virtualNetworkNewOrExisting "existing" -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dbhosting_subnet" -publicIPAddressDomainNameLabel "sqlhost" -vmSize Standard_A3 -mode Incremental -Verbose -ErrorAction Stop

            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipMSSQL -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip MySQL Hosting Server Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### ADD MYSQL HOSTING SERVER ################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "MySQLAddHosting")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipMySQL) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Get the FQDN of the VM
            $mySqlFqdn = (Get-AzureRmPublicIpAddress -Name "mysql_ip" -ResourceGroupName "azurestack-dbhosting").DnsSettings.Fqdn

            # Add host server to MySQL RP
            Write-CustomVerbose -Message "Attaching MySQL hosting server to MySQL resource provider"
            New-AzureRmResourceGroupDeployment -ResourceGroupName "azurestack-dbhosting" -TemplateUri https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/MySQLHosting/azuredeploy.json `
                -username "root" -password $secureVMpwd -hostingServerName $mySqlFqdn -totalSpaceMB 10240 -skuName "MySQL57" -Mode Incremental -Verbose -ErrorAction Stop

            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        # Get the FQDN of the VM
        $mySqlFqdn = (Get-AzureRmPublicIpAddress -Name "mysql_ip" -ResourceGroupName "azurestack-dbhosting").DnsSettings.Fqdn
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipMySQL -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip MySQL Hosting Server Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### ADD SQL SERVER HOSTING SERVER ###########################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "SQLServerAddHosting")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipMSSQL) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Get the FQDN of the VM
            $sqlFqdn = (Get-AzureRmPublicIpAddress -Name "sql_ip" -ResourceGroupName "azurestack-dbhosting").DnsSettings.Fqdn

            # Add host server to SQL Server RP
            Write-CustomVerbose -Message "Attaching SQL Server 2017 hosting server to SQL Server resource provider"
            New-AzureRmResourceGroupDeployment -ResourceGroupName "azurestack-dbhosting" -TemplateUri https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/SQLHosting/azuredeploy.json `
                -hostingServerName $sqlFqdn -hostingServerSQLLoginName "sa" -hostingServerSQLLoginPassword $secureVMpwd -totalSpaceMB 10240 -skuName "MSSQL2017" -Mode Incremental -Verbose -ErrorAction Stop

            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        # Get the FQDN of the VM
        $sqlFqdn = (Get-AzureRmPublicIpAddress -Name "sql_ip" -ResourceGroupName "azurestack-dbhosting").DnsSettings.Fqdn
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipMSSQL -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip SQL Server Hosting Server Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### CREATE BASIC BASE PLANS AND OFFERS ######################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "CreatePlansOffers")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Configure a simple base plan and offer for IaaS
        Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
        Clear-AzureRmContext -Scope CurrentUser -Force
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

        # Default quotas, plan, and offer
        $PlanName = "BasePlan"
        $OfferName = "BaseOffer"
        $RGName = "azurestack-plansandoffers"

        $computeParams = $null
        $computeParams = @{
            Name                 = "compute_default"
            CoresLimit           = 200
            AvailabilitySetCount = 20
            VirtualMachineCount  = 100
            VmScaleSetCount      = 20
            Location             = $azsLocation
        }

        $netParams = $null
        $netParams = @{
            Name                                               = "network_default"
            MaxPublicIpsPerSubscription                        = 500
            MaxVNetsPerSubscription                            = 500
            MaxVirtualNetworkGatewaysPerSubscription           = 10
            MaxVirtualNetworkGatewayConnectionsPerSubscription = 20
            MaxLoadBalancersPerSubscription                    = 500
            MaxNicsPerSubscription                             = 1000
            MaxSecurityGroupsPerSubscription                   = 500
            Location                                           = $azsLocation
        }

        $storageParams = $null
        $storageParams = @{
            Name                    = "storage_default"
            NumberOfStorageAccounts = 200
            CapacityInGB            = 2048
            Location                = $azsLocation
        }

        $kvParams = $null
        $kvParams = @{
            Location = $azsLocation
        }

        $quotaIDs = $null
        $quotaIDs = @()
        $quotaIDs += (New-AzsNetworkQuota @netParams).ID
        $quotaIDs += (New-AzsComputeQuota @computeParams).ID
        $quotaIDs += (New-AzsStorageQuota @storageParams).ID
        $quotaIDs += (Get-AzsKeyVaultQuota @kvParams).ID

        New-AzureRmResourceGroup -Name $RGName -Location $azsLocation
        $plan = New-AzsPlan -Name $PlanName -DisplayName $PlanName -Location $azsLocation -ResourceGroupName $RGName -QuotaIds $QuotaIDs
        New-AzsOffer -Name $OfferName -DisplayName $OfferName -State Private -BasePlanIds $plan.Id -ResourceGroupName $RGName -Location $azsLocation
        Set-AzsOffer -Name $OfferName -DisplayName $OfferName -State Public -BasePlanIds $plan.Id -ResourceGroupName $RGName -Location $azsLocation

        # Update the ConfigASDKProgressLog.csv file with successful completion
        Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
    }
    catch {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### DEPLOY APP SERVICE FILE SERVER ##########################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "AppServiceFileServer")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipAppService) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            ### Deploy File Server ###
            Write-CustomVerbose -Message "Deploying Windows Server 2016 File Server"
            New-AzureRmResourceGroup -Name "appservice-fileshare" -Location $azsLocation -Force
            New-AzureRmResourceGroupDeployment -Name "fileshareserver" -ResourceGroupName "appservice-fileshare" -vmName "fileserver" -TemplateUri https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/FileServer/azuredeploy.json `
                -adminPassword $secureVMpwd -fileShareOwnerPassword $secureVMpwd -fileShareUserPassword $secureVMpwd -Mode Incremental -Verbose -ErrorAction Stop

            # Get the FQDN of the VM
            $fileServerFqdn = (Get-AzureRmPublicIpAddress -Name "fileserver_ip" -ResourceGroupName "appservice-fileshare").DnsSettings.Fqdn

            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        # Get the FQDN of the VM
        $fileServerFqdn = (Get-AzureRmPublicIpAddress -Name "fileserver_ip" -ResourceGroupName "appservice-fileshare").DnsSettings.Fqdn
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipAppService -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip App Service Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### DEPLOY APP SERVICE SQL SERVER ###########################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "AppServiceSQLServer")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipAppService) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Deploy a SQL Server 2017 on Ubuntu VM for App Service
            Write-CustomVerbose -Message "Creating a dedicated SQL Server 2017 on Ubuntu Server 16.04 LTS for App Service"
            New-AzureRmResourceGroup -Name "appservice-sql" -Location $azsLocation -Force
            New-AzureRmResourceGroupDeployment -Name "sqlapp" -ResourceGroupName "appservice-sql" -TemplateUri https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/packages/MSSQL/ASDK.MSSQL/DeploymentTemplates/mainTemplate.json `
                -vmName "sqlapp" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -storageAccountName "sqlappstor" `
                -publicIPAddressDomainNameLabel "sqlapp" -publicIPAddressName "sqlapp_ip" -vmSize Standard_A3 -mode Incremental -Verbose -ErrorAction Stop

            # Get the FQDN of the VM
            $sqlAppServerFqdn = (Get-AzureRmPublicIpAddress -Name "sqlapp_ip" -ResourceGroupName "appservice-sql").DnsSettings.Fqdn

            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        # Get the FQDN of the VM
        $sqlAppServerFqdn = (Get-AzureRmPublicIpAddress -Name "sqlapp_ip" -ResourceGroupName "appservice-sql").DnsSettings.Fqdn
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipAppService -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip App Service Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### DOWNLOAD APP SERVICE ####################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "DownloadAppService")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipAppService) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Install App Service To be added
            Write-CustomVerbose -Message "Downloading App Service Installer"
            Set-Location $ASDKpath
            # Clean up old App Service Path if it exists
            Remove-Item "$asdkPath\AppService" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
            $appServiceHelperURI = "https://aka.ms/appsvconmashelpers"
            $appServiceHelperDownloadLocation = "$ASDKpath\appservicehelper.zip"
            DownloadWithRetry -downloadURI "$appServiceHelperURI" -downloadLocation "$appServiceHelperDownloadLocation" -retries 10
            Expand-Archive $ASDKpath\appservicehelper.zip -DestinationPath "$ASDKpath\AppService\" -Force
            $appServiceExeURI = "https://aka.ms/appsvconmasinstaller"
            $appServiceExeDownloadLocation = "$ASDKpath\AppService\appservice.exe"
            DownloadWithRetry -downloadURI "$appServiceExeURI" -downloadLocation "$appServiceExeDownloadLocation" -retries 10

            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipAppService -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip App Service Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

$AppServicePath = "$ASDKpath\AppService"

#### GENERATE APP SERVICE CERTS ##############################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "GenerateAppServiceCerts")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipAppService) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            Write-CustomVerbose -Message "Generating Certificates"
            Set-Location "$AppServicePath"
            .\Create-AppServiceCerts.ps1 -PfxPassword $secureVMpwd -DomainName "local.azurestack.external"
            .\Get-AzureStackRootCert.ps1 -PrivilegedEndpoint $ERCSip -CloudAdminCredential $cloudAdminCreds

            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipAppService -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip App Service Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### CREATE AD SERVICE PRINCIPAL #############################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "CreateServicePrincipal")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipAppService) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Create Azure AD or ADFS Service Principal
            if ($authenticationType.ToString() -like "AzureAd") {
                # Logout to clean up
                Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
                Clear-AzureRmContext -Scope CurrentUser -Force

                # Grant permissions to Azure AD Service Principal
                Login-AzureRmAccount -EnvironmentName "AzureCloud" -TenantId "$azureDirectoryTenantName" -Credential $asdkCreds -ErrorAction Stop | Out-Null
                Set-Location "$AppServicePath"
                $appID = . .\Create-AADIdentityApp.ps1 -DirectoryTenantName "$azureDirectoryTenantName" -AdminArmEndpoint "adminmanagement.local.azurestack.external" -TenantArmEndpoint "management.local.azurestack.external" `
                    -CertificateFilePath "$AppServicePath\sso.appservice.local.azurestack.external.pfx" -CertificatePassword $secureVMpwd -AzureStackAdminCredential $asdkCreds
                $appIdPath = "$AppServicePath\ApplicationID.txt"
                $identityApplicationID = $applicationId
                New-Item $appIdPath -ItemType file -Force
                Write-Output $identityApplicationID > $appIdPath
                Start-Sleep -Seconds 20
            }
            elseif ($authenticationType.ToString() -like "ADFS") {
                Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
                Set-Location "$AppServicePath"
                $appID = .\Create-ADFSIdentityApp.ps1 -AdminArmEndpoint "adminmanagement.local.azurestack.external" -PrivilegedEndpoint $ERCSip `
                    -CertificateFilePath "$AppServicePath\sso.appservice.local.azurestack.external.pfx" -CertificatePassword $secureVMpwd -CloudAdminCredential $asdkCreds
                $appIdPath = "$AppServicePath\ApplicationID.txt"
                $identityApplicationID = $appID
                New-Item $appIdPath -ItemType file -Force
                Write-Output $identityApplicationID > $appIdPath
            }
            else {
                Write-CustomVerbose -Message ("No valid application was created, please perform this step after the script has completed") -ErrorAction SilentlyContinue
            }
            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipAppService -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip App Service Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

if (!$identityApplicationID) {
    $identityApplicationID = Get-Content -Path "$AppServicePath\ApplicationID.txt"
}

#### GRANT AZURE AD APP PERMISSION ###########################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "GrantAzureADAppPermissions")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipAppService) {
    if ($authenticationType.ToString() -like "AzureAd") {
        if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
            try {
                # Logout to clean up
                Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
                Clear-AzureRmContext -Scope CurrentUser -Force
                # Grant permissions to Azure AD Service Principal
                Login-AzureRmAccount -EnvironmentName "AzureCloud" -TenantId $azureDirectoryTenantName -Credential $asdkCreds -ErrorAction Stop | Out-Null
                $context = Get-AzureRmContext
                $tenantId = $context.Tenant.Id
                $refreshToken = $context.TokenCache.ReadItems().RefreshToken
                $body = "grant_type=refresh_token&refresh_token=$($refreshToken)&resource=74658136-14ec-4630-ad9b-26e160ff0fc6"
                $apiToken = Invoke-RestMethod "https://login.windows.net/$tenantId/oauth2/token" -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded'
                $header = @{
                    'Authorization'          = 'Bearer ' + $apiToken.access_token
                    'X-Requested-With'       = 'XMLHttpRequest'
                    'x-ms-client-request-id' = [guid]::NewGuid()
                    'x-ms-correlation-id'    = [guid]::NewGuid()
                }
                $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$identityApplicationID/Consent?onBehalfOfAll=true"
                Invoke-RestMethod –Uri $url –Headers $header –Method POST -ErrorAction SilentlyContinue
                # Update the ConfigASDKProgressLog.csv file with successful completion
                Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
                $progress[$RowIndex].Status = "Complete"
                $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
                Write-Output $progress | Out-Host
            }
            catch {
                Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
                $progress[$RowIndex].Status = "Failed"
                $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
                Write-Output $progress | Out-Host
                Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
                Set-Location $ScriptLocation
                return
            }
        }
        elseif ($progress[$RowIndex].Status -eq "Complete") {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
        }
    }
    elseif ($authenticationType.ToString() -like "ADFS") {
        Write-CustomVerbose -Message "Skipping Azure AD App Permissions, as this is an ADFS deployment`r`n"
        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Skipped"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
    }
}
elseif ($skipAppService -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip App Service Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### DEPLOY APP SERVICE ######################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "InstallAppService")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipAppService) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            Write-CustomVerbose -Message "Checking variables are present before creating JSON"
            # Check Variables #
            if (($authenticationType.ToString() -like "AzureAd") -and ($azureDirectoryTenantName -ne $null)) {
                Write-CustomVerbose -Message "Azure Directory Tenant Name is present: $azureDirectoryTenantName"
            }
            elseif ($authenticationType.ToString() -like "ADFS") {
                Write-CustomVerbose -Message "ADFS deployment, no need for Azure Directory Tenant Name"
            }
            elseif (($authenticationType.ToString() -like "AzureAd") -and ($azureDirectoryTenantName -eq $null)) {
                throw "Missing Azure Directory Tenant Name - Exiting process"
            }
            if ($fileServerFqdn -ne $null) {
                Write-CustomVerbose -Message "File Server FQDN is present: $fileServerFqdn"
            }
            else {
                throw "Missing File Server FQDN - Exiting process"
            }
            if ($VMpwd -ne $null) {
                Write-CustomVerbose -Message "Virtual Machine password is present: $VMpwd"
            }
            else {
                throw "Missing Virtual Machine password - Exiting process"
            }
            if ($sqlAppServerFqdn -ne $null) {
                Write-CustomVerbose -Message "SQL Server FQDN is present: $sqlAppServerFqdn"
            }
            else {
                throw "Missing SQL Server FQDN - Exiting process"
            }
            if ($identityApplicationID -ne $null) {
                Write-CustomVerbose -Message "Identity Application ID present: $identityApplicationID"
            }
            else {
                throw "Missing Identity Application ID - Exiting process"
            }
        
            Invoke-WebRequest "https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/appservice/AppServiceDeploymentSettings.json" -OutFile "$AppServicePath\AppServicePreDeploymentSettings.json" -UseBasicParsing -ErrorAction Stop
            $JsonConfig = Get-Content -Path "$AppServicePath\AppServicePreDeploymentSettings.json"
            #Create the JSON from deployment

            if ($authenticationType.ToString() -like "AzureAd") {
                $JsonConfig = $JsonConfig.Replace("<<AzureDirectoryTenantName>>", $azureDirectoryTenantName)
            }
            elseif ($authenticationType.ToString() -like "ADFS") {
                $JsonConfig = $JsonConfig.Replace("<<AzureDirectoryTenantName>>", "adfs")
            }

            $JsonConfig = $JsonConfig.Replace("<<FileServerDNSLabel>>", $fileServerFqdn)
            $JsonConfig = $JsonConfig.Replace("<<Password>>", $VMpwd)
            $CertPathDoubleSlash = $AppServicePath.Replace("\", "\\")
            $JsonConfig = $JsonConfig.Replace("<<CertPathDoubleSlash>>", $CertPathDoubleSlash)
            $JsonConfig = $JsonConfig.Replace("<<SQLServerName>>", $sqlAppServerFqdn)
            $SQLServerUser = "sa"
            $JsonConfig = $JsonConfig.Replace("<<SQLServerUser>>", $SQLServerUser)
            $JsonConfig = $JsonConfig.Replace("<<IdentityApplicationId>>", $identityApplicationID)
            Out-File -FilePath "$AppServicePath\AppServiceDeploymentSettings.json" -InputObject $JsonConfig

            # Deploy App Service EXE
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($asdkCreds.Password)
            $appServiceInstallPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            $appServiceLogTime = $(Get-Date).ToString("MMdd-HHmmss")
            $appServiceLogPath = "$AppServicePath\AppServiceLog$appServiceLogTime.txt"
            Set-Location "$AppServicePath"
            Write-CustomVerbose -Message "Starting deployment of the App Service"
            Start-Process -FilePath .\AppService.exe -ArgumentList "/quiet /log $appServiceLogPath Deploy UserName=$($asdkCreds.UserName) Password=$appServiceInstallPwd ParamFile=$AppServicePath\AppServiceDeploymentSettings.json" -PassThru

            while ((Get-Process AppService -ErrorAction SilentlyContinue).Responding) {
                Write-CustomVerbose -Message "App Service is deploying. Checking in 10 seconds"
                Start-Sleep -Seconds 10
            }
            
            if (!(Get-Process AppService -ErrorAction SilentlyContinue).Responding) {
                Write-CustomVerbose -Message "App Service deployment has finished executing."
            }

            $appServiceErrorCode = "Exit code: 0xffffffff"
            Write-CustomVerbose -Message "Checking App Service log file for issues"
            if ($(Select-String -Path $appServiceLogPath -Pattern "$appServiceErrorCode" -SimpleMatch -Quiet) -eq "True") {
                Write-CustomVerbose -Message "App Service install failed with $appServiceErrorCode"
                Write-CustomVerbose -Message "An error has occurred during deployment. Please check the App Service logs at $appServiceLogPath"
                throw "App Service install failed with $appServiceErrorCode. Please check the App Service logs at $appServiceLogPath"
            }
            else {
                Write-CustomVerbose -Message "App Service log file indicates successful deployment"
            }
            Write-CustomVerbose -Message "Checking App Service resource group for successful deployment"
            # Ensure logged into Azure Stack
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
            Clear-AzureRmContext -Scope CurrentUser -Force
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            $appServiceRgCheck = (Get-AzureRmResourceGroupDeployment -ResourceGroupName "appservice-infra" -Name "AppService.DeployCloud" -ErrorAction SilentlyContinue)
            if ($appServiceRgCheck.ProvisioningState -ne 'Succeeded') {
                Write-CustomVerbose -Message "An error has occurred during deployment. Please check the App Service logs at $appServiceLogPath"
                throw "$($appServiceRgCheck.DeploymentName) has $($appServiceRgCheck.ProvisioningState). Please check the App Service logs at $appServiceLogPath"
            }
            else {
                Write-CustomVerbose -Message "App Service deployment with name: $($appServiceRgCheck.DeploymentName) has $($appServiceRgCheck.ProvisioningState)"
            }

            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipAppService -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip App Service Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### CUSTOMIZE ASDK HOST #####################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "InstallHostApps")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (!$skipCustomizeHost) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Install useful ASDK Host Apps via Chocolatey
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

            # Enable Choco Global Confirmation
            Write-CustomVerbose -Message "Enabling global confirmation to streamline installs"
            choco feature enable -n allowGlobalConfirmation

            # Visual Studio Code
            Write-CustomVerbose -Message "Installing VS Code with Chocolatey"
            choco install visualstudiocode

            # Putty
            Write-CustomVerbose -Message "Installing Putty with Chocolatey"
            choco install putty.install

            # WinSCP
            Write-CustomVerbose -Message "Installing WinSCP with Chocolatey"
            choco install winscp.install 

            # Chrome
            Write-CustomVerbose -Message "Installing Chrome with Chocolatey"
            choco install googlechrome

            # WinDirStat
            Write-CustomVerbose -Message "Installing WinDirStat with Chocolatey"
            choco install windirstat

            # Azure CLI
            Write-CustomVerbose -Message "Installing latest version of Azure CLI with Chocolatey"
            choco install azure-cli

            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($skipCustomizeHost -or ($progress[$RowIndex].Status -eq "Skipped")) {
    Write-CustomVerbose -Message "Operator chose to skip ASDK Host Customization`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}

#### GENERATE OUTPUT #########################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "CreateOutput")
$scriptStep = $($progress[$RowIndex].Stage).ToString().ToUpper()
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        ### Create Output Document ###
        $txtPath = "$downloadPath\ConfigASDKOutput.txt"
        Remove-Item -Path $txtPath -Confirm:$false -Force -ErrorAction SilentlyContinue -Verbose
        New-Item "$txtPath" -ItemType file -Force

        Write-Output "`r`nThis document contains useful information for deployment of the App Service" > $txtPath
        Write-Output "`r`nYour chosen authentication type was: $authenticationType" >> $txtPath

        if ($authenticationType.ToString() -like "ADFS") {
            Write-Output "Your ASDK admin account and the Azure Stack portal use the following account for login: $azureStackAdminUsername" >> $txtPath
        }

        elseif ($authenticationType.ToString() -like "AzureAD") {
            Write-Output "Use the following username to login to your ASDK host: $azureStackAdminUsername" >> $txtPath
            Write-Output "Use the following username to login to the Azure Stack portal: $azureAdUsername" >> $txtPath
        }

        Write-Output "`r`nASDK has been registered to Azure: $($registerASDK.IsPresent)" >> $txtPath

        if ($registerASDK) {
            Write-Output "Your Azure Stack was registered to this Azure subscription: $azureRegSubId" >> $txtPath
        }

        if ($useAzureCredsForRegistration -and $registerASDK) {
            Write-Output "Your Azure Stack was registered to Azure with the following username: $azureAdUsername" >> $txtPath
        }
        elseif ($authenticationType.ToString() -like "AzureAd" -and !$useAzureCredsForRegistration -and $registerASDK) {
            Write-Output "Your Azure Stack was registered to Azure with the following username: $azureRegUsername" >> $txtPath
        }

        if ($authenticationType.ToString() -like "ADFS" -and $registerASDK) {
            Write-Output "Your Azure Stack was registered to Azure with the following username: $azureRegUsername" >> $txtPath
        }

        Write-Output "`r`nThe Azure Stack PowerShell tools have been downloaded to: $modulePath" >> $txtPath
        Write-Output "All other downloads have been stored here: $ASDKpath" >> $txtPath

        Write-Output "`r`nSQL & MySQL Resource Provider Information:" >> $txtPath
        if (!$skipMySQL) {
            Write-Output "MySQL Resource Provider VM Credentials = mysqlrpadmin | $VMpwd" >> $txtPath
            Write-Output "MySQL Database Hosting VM FQDN: $mySqlFqdn" >> $txtPath
            Write-Output "MySQL Database Hosting VM Credentials = mysqladmin | $VMpwd" >> $txtPath
        }
        if (!$skipMSSQL) {
            Write-Output "SQL Server Resource Provider VM Credentials = sqlrpadmin | $VMpwd" >> $txtPath
            Write-Output "SQL Server Database Hosting VM FQDN: $sqlFqdn" >> $txtPath
            Write-Output "SQL Server Database Hosting VM Credentials = sqladmin | $VMpwd" >> $txtPath
        }
        if (!$skipAppService) {
            Write-Output "`r`nApp Service Resource Provider Information:" >> $txtPath
            Write-Output "App Service File Server VM FQDN: $fileServerFqdn" >> $txtPath
            Write-Output "App Service File Server VM Credentials = fileshareowner or fileshareuser | $VMpwd" >> $txtPath
            Write-Output "App Service SQL Server VM FQDN: $sqlAppServerFqdn" >> $txtPath
            Write-Output "App Service SQL Server VM Credentials = sqladmin | $VMpwd" >> $txtPath
            Write-Output "App Service SQL Server SA Credentials = sa | $VMpwd" >> $txtPath

            if ($authenticationType.ToString() -like "AzureAd") {
                Write-Output "`r`nTo complete the App Service deployment, use this Application Id: $identityApplicationID" >> $txtPath
                Write-Output "Sign in to the Azure portal as Azure Active Directory Service Admin ($azureAdUsername) -> Search for Application Id and grant permissions." >> $txtPath
                Write-Output "Documented steps: https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-app-service-before-you-get-started#create-an-azure-active-directory-application" >> $txtPath
            }
            elseif ($authenticationType.ToString() -like "ADFS") {
                Write-Output "`r`nTo complete the App Service deployment, use this Application Id: $identityApplicationID" >> $txtPath
                Write-Output "Documented steps: https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-app-service-before-you-get-started#create-an-active-directory-federation-services-application" >> $txtPath
            }

            Write-Output "`r`nOther useful information for reference:" >> $txtPath
            Write-Output "`r`nAzure Stack Admin ARM Endpoint: adminmanagement.local.azurestack.external" >> $txtPath
            Write-Output "Azure Stack Tenant ARM Endpoint: management.local.azurestack.external" >> $txtPath
            Write-Output "Azure Directory Tenant Name: $azureDirectoryTenantName" >> $txtPath
            Write-Output "File Share UNC Path: \\appservicefileshare.local.cloudapp.azurestack.external\websites" >> $txtPath
            Write-Output "File Share Owner: fileshareowner" >> $txtPath
            Write-Output "File Share Owner Password: $VMpwd" >> $txtPath
            Write-Output "File Share User: fileshareuser" >> $txtPath
            Write-Output "File Share User Password: $VMpwd" >> $txtPath
            Write-Output "Identity Application ID: $identityApplicationID" >> $txtPath
            Write-Output "Identity Application Certificate file (*.pfx): $AppServicePath\sso.appservice.local.azurestack.external.pfx" >> $txtPath
            Write-Output "Identity Application Certificate (*.pfx) password: $VMpwd" >> $txtPath
            Write-Output "Azure Resource Manager (ARM) root certificate file (*.cer): $AppServicePath\AzureStackCertificationAuthority.cer" >> $txtPath
            Write-Output "App Service default SSL certificate file (*.pfx): $AppServicePath\_.appservice.local.AzureStack.external.pfx" >> $txtPath
            Write-Output "App Service default SSL certificate (*.pfx) password: $VMpwd" >> $txtPath
            Write-Output "App Service API SSL certificate file (*.pfx): $AppServicePath\api.appservice.local.AzureStack.external.pfx" >> $txtPath
            Write-Output "App Service API SSL certificate (*.pfx) password: $VMpwd" >> $txtPath
            Write-Output "App Service Publisher SSL certificate file (*.pfx): $AppServicePath\ftp.appservice.local.AzureStack.external.pfx" >> $txtPath
            Write-Output "App Service Publisher SSL certificate (*.pfx) password: $VMpwd" >> $txtPath
            Write-Output "SQL Server Name: $sqlAppServerFqdn" >> $txtPath
            Write-Output "SQL sysadmin login: sa" >> $txtPath
            Write-Output "SQL sysadmin password: $VMpwd" >> $txtPath
            Write-Output "Worker Role Virtual Machine(s) Admin: workeradmin" >> $txtPath
            Write-Output "Worker Role Virtual Machine(s) Password: $VMpwd" >> $txtPath
            Write-Output "Confirm Password: $VMpwd" >> $txtPath
            Write-Output "Other Roles Virtual Machine(s) Admin: roleadmin" >> $txtPath
            Write-Output "Other Roles Virtual Machine(s) Password: $VMpwd" >> $txtPath
            Write-Output "Confirm Password: $VMpwd" >> $txtPath
        }
        # Update the ConfigASDKProgressLog.csv file with successful completion
        Write-CustomVerbose -Message "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
    }
    catch {
        Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        Write-CustomVerbose -Message "$_.Exception.Message" -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-CustomVerbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### FINAL STEPS #############################################################################################################################################
##############################################################################################################################################################

### Clean Up ASDK Folder ###
$scriptStep = "CLEANUP"
$scriptSuccess = $progress | Where-Object {($_.Status -eq "Incomplete") -or ($_.Status -eq "Failed")}
if ([string]::IsNullOrEmpty($scriptSuccess)) {
    Write-CustomVerbose -Message "Congratulations - all steps completed successfully:`r`n"
    Write-Output $progress | Out-Host
    Write-CustomVerbose -Message "Cleaning up ASDK Folder and Progress CSV file"
    Remove-Item -Path "$asdkPath" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
    Remove-Item -Path $ConfigASDKProgressLogPath -Confirm:$false -Force -ErrorAction SilentlyContinue -Verbose
    Write-CustomVerbose -Message "Cleaning up Resource Group used for Image Upload"
    Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
    Get-AzureRmResourceGroup -Name $asdkImagesRGName -Location $azsLocation -ErrorAction SilentlyContinue | Remove-AzureRmResourceGroup -Force -ErrorAction SilentlyContinue
    # Increment run counter to track successful run
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri "http://bit.ly/asdksuccessrun" -UseBasicParsing -ErrorAction SilentlyContinue -DisableKeepAlive | Out-Null
}
else {
    Write-CustomVerbose -Message "Script hasn't completed successfully"
    Write-CustomVerbose -Message "Please rerun the script to complete the process`r`n"
    Write-Output $progress | Out-Host
}

Write-CustomVerbose -Message "Setting Execution Policy back to RemoteSigned"
Set-ExecutionPolicy RemoteSigned -Confirm:$false -Force

# Calculate completion time
$endTime = Get-Date -Format g
$sw.Stop()
$Hrs = $sw.Elapsed.Hours
$Mins = $sw.Elapsed.Minutes
$Secs = $sw.Elapsed.Seconds
$difference = '{0:00}h:{1:00}m:{2:00}s' -f $Hrs, $Mins, $Secs

Set-Location $ScriptLocation -ErrorAction SilentlyContinue
Write-Output "ASDK Configurator setup completed successfully, taking $difference." -ErrorAction SilentlyContinue
Write-Output "You started the ASDK Configurator deployment at $startTime." -ErrorAction SilentlyContinue
Write-Output "ASDK Configurator deployment completed at $endTime." -ErrorAction SilentlyContinue

### Launch browser to activate admin and user portal for Azure AD deployments
### Will launch in Chrome if Host has been customized
if ($authenticationType.ToString() -like "AzureAd") {
    Write-Output "Launching browser to activate admin and user portals"
    if (!$skipCustomizeHost) {
        [System.Diagnostics.Process]::Start("chrome.exe", "https://adminportal.local.azurestack.external/guest/signup")
        Start-Sleep -Seconds 10
        [System.Diagnostics.Process]::Start("chrome.exe", "https://portal.local.azurestack.external/guest/signup")
    }
    elseif ($skipCustomizeHost) {
        Start-Process https://adminportal.local.azurestack.external/guest/signup
        Start-Sleep -Seconds 10
        Start-Process https://portal.local.azurestack.external/guest/signup
    }
}
Stop-Transcript -ErrorAction SilentlyContinue