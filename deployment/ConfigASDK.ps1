<#

.SYNOPSYS

    The purpose of this script is to automate as much as possible post deployment tasks in Azure Stack Development Kit
    This includes:
        - Set password expiration
        - Disable Windows Update on all infrastructures VMs and ASDK host
        - Tools installation (Azure Stack Tools)
        - Registration of the ASDK to Azure (Optional)
        - Windows Server 2016 Datacenter Full & Core and Ubuntu 16.04-LTS images installation
        - Creates VM Scale Set gallery item
        - MySQL Resource Provider Installation
        - SQL Server Resource Provider Installation
        - Deployment of a MySQL 5.7 hosting Server on Ubuntu Server 16.04 LTS
        - Deployment of a SQL Server 2017 hosting server on Ubuntu Server 16.04 LTS
        - Adding SQL Server & MySQL Hosting Servers to Resource Providers inc. SKU/Quotas
        - AppService prerequisites installation (SQL Server and Standalone File Server)
        - AppService Resource Provider sources download and certificates generation
        - Set new default Quotas for MySQL, SQL Server, Compute, Network, Storage and Key Vault
        - Generate output text file for use in the next steps of configuration.

.VERSION

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
    # For ASDK deployment - this switch may be expanded in future for Multinode deployments
    [switch]$ASDK,

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

    # Password for Azure Subscription Login for registering Azure Stack
    [parameter(Mandatory = $false)]
    [string]$azureRegSubId
)

$VerbosePreference = "Continue"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {Stop-Transcript | Out-Null} catch {}

### GET START TIME ###
$startTime = $(Get-Date).ToLocalTime()
$sw = [Diagnostics.Stopwatch]::StartNew()

### SET LOCATION ###
$ScriptLocation = Get-Location

### SET ERCS IP Address - same for all default ASDKs ###
$ERCSip = "192.168.200.225"

# Define Regex for Password Complexity - needs to be at least 8 characters, with at least 1 upper case and 1 special character
$regex = @"
^.*(?=.{8,})(?=.*[A-Z])(?=.*[@#$%^&£*\-_+=[\]{}|\\:',?/`~"();!]).*$
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

### Start Logging ###
Start-Transcript -Path "$downloadPath\ConfigASDKLog.txt" -Append

### Check if ConfigASDKProgressLog.csv exists ###
$ConfigASDKProgressLogPath = "$downloadPath\ConfigASDKProgressLog.csv"
$validConfigASDKProgressLogPath = [System.IO.File]::Exists($ConfigASDKProgressLogPath)
If ($validConfigASDKProgressLogPath -eq $true) {
    Write-Verbose "ConfigASDkProgressLog.csv exists - this must be a rerun"
    Write-Verbose "Starting from previous failed step"
    $progress = Import-Csv $ConfigASDKProgressLogPath
    Write-Output $progress
}
elseif ($validConfigASDKProgressLogPath -eq $false) {
    Write-Verbose "No ConfigASDkProgressLog.csv exists - this must be a fresh deployment"
    Write-Verbose "Creating ConfigASDKProgressLog.csv"
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
        '"AppServiceFileServer","Incomplete"'
        '"AppServiceSQLServer","Incomplete"'
        '"DownloadAppService","Incomplete"'
        '"GenerateAppServiceCerts","Incomplete"'
        '"CreateServicePrincipal","Incomplete"'
        '"GrantAzureADAppPermissions","Incomplete"'
        '"CreatePlansOffers","Incomplete"'
        '"InstallAppService","Incomplete"'
        '"InstallHostApps","Incomplete"'
        '"CreateOutput","Incomplete"'
    )
    $ConfigASDKprogress | ForEach-Object { Add-Content -Path $ConfigASDKProgressLogPath -Value $_ }
    $progress = Import-Csv -Path $ConfigASDKProgressLogPath
    Write-Output $progress
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
    Write-Host "`r`n
    ______________________________________________________________________________________________________________
    
    Virtual Machine password is not a strong password.
    It should ideally be at least 8 characters, with at least 1 upper case, 1 lower case, and 1 special character.
    Please consider a stronger password in the future.
    ______________________________________________________________________________________________________________
    `r`n" -ForegroundColor Cyan
    Start-Sleep -Seconds 10
    $secureVMpwd = ConvertTo-SecureString -AsPlainText $VMpwd -Force
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
    Write-Host "`r`n
    ______________________________________________________________________________________________________________
    
    Azure Stack Admin (AzureStack\AzureStackAdmin) password is not a strong password.
    It should ideally be at least 8 characters, with at least 1 upper case, 1 lower case, and 1 special character.
    Please consider a stronger password in the future.
    ______________________________________________________________________________________________________________
    `r`n" -ForegroundColor Cyan
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
        Write-Verbose "You didn't enter a username for the Azure AD login." 
        $azureAdUsername = Read-Host "Please enter a username in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" -ErrorAction Stop
    }

    Write-Verbose "Checking to see if Azure AD Service Administrator (Used for ASDK Deployment) username is correctly formatted..."

    if ($azureAdUsername -cmatch $emailRegex -eq $true) {
        Write-Verbose "Azure AD Service Administrator username (Used for ASDK Deployment) is correctly formatted." 
        Write-Verbose "$azureAdUsername will be used to connect to Azure." 
    }

    elseif ($azureAdUsername -cmatch $emailRegex -eq $false) {
        Write-Verbose "Azure AD Service Administrator Username (Used for ASDK Deployment) isn't correctly formatted. It should be entered in the format username@<directoryname>.onmicrosoft.com, or your own custom domain, for example username@contoso.com" 
        # Obtain new username
        $azureAdUsername = Read-Host "Enter Azure AD Service Administrator Username (Used for ASDK Deployment) again"
        if ($azureAdUsername -cmatch $emailRegex -eq $true) {
            Write-Verbose "Azure AD Service Administrator Username (Used for ASDK Deployment) is correctly formatted." 
            Write-Verbose "$azureAdUsername will be used to connect to Azure." 
        }
        else {
            Write-Verbose "No valid Azure AD Service Administrator Username (Used for ASDK Deployment) was entered again. Exiting process..." -ErrorAction Stop 
            Set-Location $ScriptLocation
            return
        }
    }

    ### Validate Azure AD Service Administrator (Used for ASDK Deployment) Password ###

    if ([string]::IsNullOrEmpty($azureAdPwd)) {
        Write-Verbose "You didn't enter the Azure AD Service Administrator account (Used for ASDK Deployment) password." 
        $secureAzureAdPwd = Read-Host "Please enter the password for the Azure AD Service Administrator account used to deploy the ASDK. It should be at least 8 characters, with at least 1 upper case and 1 special character." -AsSecureString -ErrorAction Stop
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureAdPwd)            
        $azureAdPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
    }

    Write-Verbose "Checking to see if password for the Azure AD Service Administrator used to deploy the ASDK, is strong..."

    if ($azureAdPwd -cmatch $regex -eq $true) {
        Write-Verbose "Password for the Azure AD Service Administrator account used to deploy the ASDK meets desired complexity level" 
        # Convert plain text password to a secure string
        $secureAzureAdPwd = ConvertTo-SecureString -AsPlainText $azureAdPwd -Force
        $azureAdCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureAdUsername, $secureAzureAdPwd) -ErrorAction Stop
    }

    elseif ($azureAdPwd -cmatch $regex -eq $false) {
        Write-Host "`r`n
        ______________________________________________________________________________________________________________
        
        Azure AD Service Administrator account password is not a strong password.
        It should ideally be at least 8 characters, with at least 1 upper case, 1 lower case, and 1 special character.
        Please consider a stronger password in the future.
        ______________________________________________________________________________________________________________
        `r`n" -ForegroundColor Cyan
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
            Write-Verbose "You didn't enter the Azure AD password that you want to use for registration." 
            $secureAzureRegPwd = Read-Host "Please enter the Azure AD password you wish to use for registration. It should ideally be at least 8 characters, with at least 1 upper case and 1 special character." -AsSecureString -ErrorAction Stop
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
            Write-Host "`r`n
            ______________________________________________________________________________________________________________
            
            Azure AD password for registration is not a strong password.
            It should ideally be at least 8 characters, with at least 1 upper case, 1 lower case, and 1 special character.
            Please consider a stronger password in the future.
            ______________________________________________________________________________________________________________
            `r`n" -ForegroundColor Cyan
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
        Write-Verbose "You didn't enter the Azure AD password that you want to use for registration." 
        $secureAzureRegPwd = Read-Host "Please enter the Azure AD password you wish to use for registration. It should ideally be at least 8 characters, with at least 1 upper case and 1 special character." -AsSecureString -ErrorAction Stop
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzureRegPwd)            
        $azureRegPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  
    }

    Write-Verbose "Checking to see if Azure AD password for registration is strong..."

    if ($azureRegPwd -cmatch $regex -eq $true) {
        Write-Verbose "Azure AD password meets desired complexity level" 
        # Convert plain text password to a secure string
        $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
        $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
    }

    elseif ($azureRegPwd -cmatch $regex -eq $false) {
        Write-Host "`r`n
        ______________________________________________________________________________________________________________
        
        Azure AD password for registration is not a strong password.
        It should ideally be at least 8 characters, with at least 1 upper case, 1 lower case, and 1 special character.
        Please consider a stronger password in the future.
        ______________________________________________________________________________________________________________
        `r`n" -ForegroundColor Cyan
        Start-Sleep -Seconds 10
        $secureAzureRegPwd = ConvertTo-SecureString -AsPlainText $azureRegPwd -Force
        $azureRegCreds = New-Object -TypeName System.Management.Automation.PSCredential ($azureRegUsername, $secureAzureRegPwd) -ErrorAction Stop
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
            Write-Verbose "Failed to download '$downloadURI': $exceptionMessage"
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

$progress = Import-Csv -Path $ConfigASDKProgressLogPath
$RowIndex = [array]::IndexOf($progress.Stage, "DownloadTools")

if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {

    try {
        ### DOWNLOAD & EXTRACT TOOLS ###
        # Download the tools archive using a function incase the download fails or is interrupted.
        # Download points to my fork of the tools, to ensure compatibility - this will be updated accordingly.
        $toolsURI = "https://github.com/mattmcspirit/AzureStack-Tools/archive/master.zip"
        $toolsDownloadLocation = "$ASDKpath\master.zip"
        Write-Verbose "Downloading Azure Stack Tools to ensure you have the latest versions. This may take a few minutes, depending on your connection speed."
        Write-Verbose "The download will be stored in $ASDKpath."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        DownloadWithRetry -downloadURI "$toolsURI" -downloadLocation "$toolsDownloadLocation" -retries 10

        # Expand the downloaded files
        Write-Verbose "Expanding Archive"
        expand-archive "$toolsDownloadLocation" -DestinationPath "C:\" -Force
        Write-Verbose "Archive expanded. Cleaning up."
        Remove-Item "$toolsDownloadLocation" -Force -ErrorAction Stop

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return        
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

# Change to the tools directory
Write-Verbose "Changing Directory"
$modulePath = "C:\AzureStack-Tools-master"
Set-Location $modulePath

# Import the Azure Stack Connect and Compute Modules
Import-Module $modulePath\Connect\AzureStack.Connect.psm1
Import-Module $modulePath\ComputeAdmin\AzureStack.ComputeAdmin.psm1
Disable-AzureRmDataCollection -WarningAction SilentlyContinue
Write-Verbose "Azure Stack Connect and Compute modules imported successfully" 

### CONFIGURE THE AZURE STACK HOST & INFRA VIRTUAL MACHINES ############################################################################################
########################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "HostConfiguration")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Set password expiration to 180 days
        Write-Verbose "Configuring password expiration policy"
        Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 180.00:00:00 -Identity azurestack.local
        Get-ADDefaultDomainPasswordPolicy

        # Set Power Policy
        Write-Verbose "Optimizing power policy for high performance"
        POWERCFG.EXE /S SCHEME_MIN

        # Disable Windows Update on infrastructure VMs
        Write-Verbose "Disabling Windows Update on Infrastructure VMs and ASDK Host`r`n"
        $AZSvms = Get-VM -Name AZS*
        $scriptblock = {
            Get-Service -Name wuauserv | Stop-Service -Force -PassThru | Set-Service -StartupType disabled -Confirm:$false
        }
        foreach ($vm in $AZSvms) {
            Invoke-Command -VMName $vm.name -ScriptBlock $scriptblock -Credential $azureStackAdminCreds
        }
        # Disable Windows Update and DNS Server on Host
        Get-Service -Name wuauserv, DNS | Stop-Service -Force -PassThru | Set-Service -StartupType disabled -Confirm:$false

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress

        Write-Verbose "`r`nHost configuration is now complete."
    }
    Catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

### REGISTER AZURE STACK TO AZURE ############################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "Registration")
if ($registerASDK) {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            Write-Verbose "Starting Azure Stack registration to Azure"
            # Add the Azure cloud subscription environment name. Supported environment names are AzureCloud or, if using a China Azure Subscription, AzureChinaCloud.
            Add-AzureRmAccount -EnvironmentName "AzureCloud" -Credential $azureRegCreds
            # Register the Azure Stack resource provider in your Azure subscription
            Register-AzureRmResourceProvider -ProviderNamespace Microsoft.AzureStack
            # Import the registration module that was downloaded with the GitHub tools
            Import-Module $modulePath\Registration\RegisterWithAzure.psm1
            #Register Azure Stack
            $AzureContext = Get-AzureRmContext
            Set-AzsRegistration -PrivilegedEndpointCredential $cloudAdminCreds -PrivilegedEndpoint AzS-ERCS01 -BillingModel Development -ErrorAction Stop
            # Update the ConfigASDKProgressLog.csv file with successful completion
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress
        }
        catch {
            Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Verbose $_.Exception.Message -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif (!$registerASDK) {
    Write-Verbose "Skipping Azure Stack registration to Azure"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress
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

$RowIndex = [array]::IndexOf($progress.Stage, "UbuntuImage")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        if ($registerASDK) {
            # Logout to clean up
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
            Clear-AzureRmContext -Scope CurrentUser -Force

            ### Login to Azure to get all the details about the syndicated Ubuntu Server 16.04 marketplace offering ###
            Import-Module C:\AzureStack-Tools-master\Syndication\AzureStack.MarketplaceSyndication.psm1
            Login-AzureRmAccount -EnvironmentName "AzureCloud" -Credential $azureRegCreds -ErrorAction Stop | Out-Null
            $sub = Get-AzureRmSubscription
            $sub = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
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
                    #Invoke-Webrequest "https://cloud-images.ubuntu.com/releases/16.04/release-$ubuntuBuild/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip" -OutFile "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip" -ErrorAction Stop -UseBasicParsing
                    $ubuntuURI = "https://cloud-images.ubuntu.com/releases/16.04/release-$ubuntuBuild/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"
                    $ubuntuDownloadLocation = "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip"
                    DownloadWithRetry -downloadURI "$ubuntuURI" -downloadLocation "$ubuntuDownloadLocation" -retries 10
                }

                # Otherwise, it will just use 1.0.0 as specified earlier

                else {
                    $ubuntuBuild = $azpkg.vhdVersion
                    #Invoke-Webrequest "https://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip" -OutFile "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip" -ErrorAction Stop -UseBasicParsing
                    $ubuntuURI = "https://cloud-images.ubuntu.com/releases/xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.vhd.zip"
                    $ubuntuDownloadLocation = "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip"
                    DownloadWithRetry -downloadURI "$ubuntuURI" -downloadLocation "$ubuntuDownloadLocation" -retries 10
                }
       
                Expand-Archive -Path "$ASDKpath\$($azpkg.offer)$($azpkg.vhdVersion).zip" -DestinationPath $ASDKpath -Force -ErrorAction Stop
                $UbuntuServerVHD = Get-ChildItem -Path "$ASDKpath" -Filter *.vhd | Rename-Item -NewName "$($azpkg.offer)$($azpkg.vhdVersion).vhd" -PassThru -Force -ErrorAction Stop
            }

            # Upload the image to the Azure Stack Platform Image Repository
            Write-Verbose "Extraction Complete. Beginning upload of VHD to Platform Image Repository"

            # If the user has chosen to register the ASDK, the script will NOT create a gallery item as part of the image upload

            if ($registerASDK) {
                Add-AzsVMImage -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -osType $azpkg.osVersion -osDiskLocalPath "$UbuntuServerVHD" -CreateGalleryItem $False
            }
            else {
                Add-AzsVMImage -Publisher $azpkg.publisher -Offer $azpkg.offer -Sku $azpkg.sku -Version $azpkg.vhdVersion -osType $azpkg.osVersion -osDiskLocalPath "$UbuntuServerVHD"
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
        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

### ADD WINDOWS SERVER 2016 PLATFORM IMAGES ##################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "WindowsImage")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
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
            $serverCoreVMImageAlreadyAvailable = $true
        }

        # Pre-validate that the Windows Server 2016 Full Image is not already available
        Remove-Variable -Name platformImageFull -Force -ErrorAction SilentlyContinue
        $sku = "2016-Datacenter"
        $platformImageFull = Get-AzsVMImage -Location "local" -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -Version "1.0.0" -ErrorAction SilentlyContinue
        $serverFullVMImageAlreadyAvailable = $false

        if ($platformImageFull -ne $null -and $platformImageFull.Properties.ProvisioningState -eq 'Succeeded') {
            Write-Verbose "There appears to be at least 1 suitable Windows Server $sku image within your Platform Image Repository which we will use for the ASDK Configurator." 
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

            # Mount the ISO, check the image for the version, then dismount
            Remove-Variable -Name buildVersion -ErrorAction SilentlyContinue
            $isoMountForVersion = Mount-DiskImage -ImagePath $ISOPath
            $isoDriveLetterForVersion = ($isoMountForVersion | Get-Volume).DriveLetter
            $wimPath = "$IsoDriveLetterForVersion`:\sources\install.wim"
            $buildVersion = (dism.exe /Get-WimInfo /WimFile:$wimPath /index:1 | Select-String "Version").ToString().Split(".")[2].Trim()
            Dismount-DiskImage -ImagePath $ISOPath

            Write-Verbose "You're missing at least one of the Windows Server 2016 Datacenter images, so we'll first download the latest Cumulative Update."
            # Define parameters
            $StartKB = 'https://support.microsoft.com/app/content/api/content/asset/en-us/4000816'
            $Build = $buildVersion
            $SearchString = 'Cumulative.*Server.*x64'

            # Find the KB Article Number for the latest Windows Server 2016 (Build 14393) Cumulative Update
            Write-Verbose "Downloading $StartKB to retrieve the list of updates."
            $kbID = (Invoke-WebRequest -Uri $StartKB -UseBasicParsing).Content | ConvertFrom-Json | Select-Object -ExpandProperty Links | Where-Object level -eq 2 | Where-Object text -match $Build | Select-Object -First 1

            # Get Download Link for the corresponding Cumulative Update
            Write-Verbose "Found ID: KB$($kbID.articleID)"
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
                Write-Verbose "KB ID: $kbID"
                $Post = @{ size = 0; updateID = $kbID; uidInfo = $kbID } | ConvertTo-Json -Compress
                $PostBody = @{ updateIDs = "[$Post]" } 
                $Urls += Invoke-WebRequest -Uri 'http://www.catalog.update.microsoft.com/DownloadDialog.aspx' -UseBasicParsing -Method Post -Body $postBody | Select-Object -ExpandProperty Content | Select-String -AllMatches -Pattern "(http[s]?\://download\.windowsupdate\.com\/[^\'\""]*)" | ForEach-Object { $_.matches.value }
            }

            # Download the corresponding Windows Server 2016 (Build 14393) Cumulative Update
            ForEach ( $Url in $Urls ) {
                $filename = $Url.Substring($Url.LastIndexOf("/") + 1)
                $target = "$((Get-Item $ASDKpath).FullName)\$filename"
                Write-Verbose "Windows Server 2016 Cumulative Update will be stored at $target"
                Write-Verbose "These are generally larger than 1GB, so may take a few minutes."
                If (!(Test-Path -Path $target)) {
                    DownloadWithRetry -downloadURI "$Url" -downloadLocation "$target" -retries 10
                    #Invoke-WebRequest -Uri $Url -OutFile $target -UseBasicParsing
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
            Import-Module "$modulePath\Syndication\AzureStack.MarketplaceSyndication.psm1"
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
            Clear-AzureRmContext -Scope CurrentUser -Force
            Login-AzureRmAccount -EnvironmentName "AzureCloud" -Credential $azureRegCreds -ErrorAction Stop | Out-Null
            $sub = Get-AzureRmSubscription
            $sub = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
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
        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

### ADD VM SCALE SET GALLERY ITEM ############################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "ScaleSetGalleryItem")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Create VM Scale Set Marketplace item
        Write-Verbose "Creating VM Scale Set Marketplace Item"
        Add-AzsVMSSGalleryItem -Location local
        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    Catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

### ADD MYSQL GALLERY ITEM ###################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "MySQLGalleryItem")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        ### Login to Azure Stack, then confirm if the MySQL Gallery Item is already present ###
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        $mySQLPackageName = "ASDK.MySQL.1.0.0"
        $mySQLPackageURL = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/MySQL/ASDK.MySQL.1.0.0.azpkg"
        Write-Verbose "Checking for the MySQL gallery item"
        if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$mySQLPackageName*"}) {
            Write-Verbose "Found a suitable MySQL Gallery Item in your Azure Stack Marketplace. No need to upload a new one"
        }
        else {
            Write-Verbose "Didn't find this package: $mySQLPackageName"
            Write-Verbose "Will need to side load it in to the gallery"
            Write-Verbose "Uploading $mySQLPackageName"
            $Upload = Add-AzsGalleryItem -GalleryItemUri $mySQLPackageURL
            Start-Sleep -Seconds 5
            $Retries = 0
            # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
            While ($Upload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
                Write-Verbose "$mySQLPackageName wasn't added to the gallery successfully. Retry Attempt #$Retries"
                Write-Verbose "Uploading $mySQLPackageName from $mySQLPackageURL"
                $Upload = Add-AzsGalleryItem -GalleryItemUri $mySQLPackageURL
                Start-Sleep -Seconds 5
            }
        }
        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

### ADD SQL SERVER GALLERY ITEM ##############################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "SQLServerGalleryItem")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        ### Login to Azure Stack, then confirm if the SQL Server 2017 Gallery Item is already present ###
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        $MSSQLPackageName = "ASDK.MSSQL.1.0.0"
        $MSSQLPackageURL = "https://github.com/mattmcspirit/azurestack/raw/master/deployment/packages/MSSQL/ASDK.MSSQL.1.0.0.azpkg"
        Write-Verbose "Checking for the SQL Server 2017 gallery item"
        if (Get-AzsGalleryItem | Where-Object {$_.Name -like "*$MSSQLPackageName*"}) {
            Write-Verbose "Found a suitable SQL Server 2017 Gallery Item in your Azure Stack Marketplace. No need to upload a new one"
        }
        else {
            Write-Verbose "Didn't find this package: $MSSQLPackageName"
            Write-Verbose "Will need to side load it in to the gallery"
            Write-Verbose "Uploading $MSSQLPackageName"
            $Upload = Add-AzsGalleryItem -GalleryItemUri $MSSQLPackageURL
            Start-Sleep -Seconds 5
            $Retries = 0
            # Sometimes the gallery item doesn't get added, so perform checks and reupload if necessary
            While ($Upload.StatusCode -match "OK" -and ($Retries++ -lt 20)) {
                Write-Verbose "$MSSQLPackageName wasn't added to the gallery successfully. Retry Attempt #$Retries"
                Write-Verbose "Uploading $MSSQLPackageName from $MSSQLPackageURL"
                $Upload = Add-AzsGalleryItem -GalleryItemUri $MSSQLPackageURL
                Start-Sleep -Seconds 5
            }
        }
        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### INSTALL MYSQL RESOURCE PROVIDER #########################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "MySQLRP")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Login to Azure Stack
        Write-Verbose "Downloading and installing MySQL Resource Provider"
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

        # Download and Expand the MySQL RP files
        $mySqlRpURI = "https://aka.ms/azurestackmysqlrp"
        $mySqlRpDownloadLocation = "$ASDKpath\MySQL.zip"
        DownloadWithRetry -downloadURI "$mySqlRpURI" -downloadLocation "$mySqlRpDownloadLocation" -retries 10
        #Invoke-WebRequest https://aka.ms/azurestackmysqlrp -OutFile "$ASDKpath\MySQL.zip" -ErrorAction Stop -UseBasicParsing
        Set-Location $ASDKpath
        Expand-Archive "$ASDKpath\MySql.zip" -DestinationPath .\MySQL -Force -ErrorAction Stop
        Set-Location "$ASDKpath\MySQL"

        # Define the additional credentials for the local virtual machine username/password and certificates password
        $vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("mysqlrpadmin", $secureVMpwd)
        .\DeployMySQLProvider.ps1 -AzCredential $asdkCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $cloudAdminCreds -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureVMpwd -AcceptLicense

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### INSTALL SQL SERVER RESOURCE PROVIDER ####################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "SQLServerRP")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Login to Azure Stack
        Write-Verbose "Downloading and installing SQL Server Resource Provider"
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

        # Download and Expand the SQL Server RP files
        $sqlRpURI = "https://aka.ms/azurestacksqlrp"
        $sqlRpDownloadLocation = "$ASDKpath\SQL.zip"
        DownloadWithRetry -downloadURI "$sqlRpURI" -downloadLocation "$sqlRpDownloadLocation" -retries 10
        #Invoke-WebRequest https://aka.ms/azurestacksqlrp -OutFile "$ASDKpath\SQL.zip" -ErrorAction Stop -UseBasicParsing
        Set-Location $ASDKpath
        Expand-Archive "$ASDKpath\SQL.zip" -DestinationPath .\SQL -Force -ErrorAction Stop
        Set-Location "$ASDKpath\SQL"

        # Define the additional credentials for the local virtual machine username/password and certificates password
        $vmLocalAdminCreds = New-Object System.Management.Automation.PSCredential ("sqlrpadmin", $secureVMpwd)
        .\DeploySQLProvider.ps1 -AzCredential $asdkCreds -VMLocalCredential $vmLocalAdminCreds -CloudAdminCredential $cloudAdminCreds -PrivilegedEndpoint $ERCSip -DefaultSSLCertificatePassword $secureVMpwd

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### REGISTER NEW RESOURCE PROVIDERS #########################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "RegisterNewRPs")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Register resource providers
        foreach ($s in (Get-AzureRmSubscription)) {
            Select-AzureRmSubscription -SubscriptionId $s.SubscriptionId | Out-Null
            Write-Progress $($s.SubscriptionId + " : " + $s.SubscriptionName)
            Get-AzureRmResourceProvider -ListAvailable | Register-AzureRmResourceProvider
        }
        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### ADD MYSQL SKU & QUOTA ###################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "MySQLSKUQuota")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Logout to clean up
        Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
        Clear-AzureRmContext -Scope CurrentUser -Force

        # Set the variables and gather token for creating the SKU & Quota
        $mySqlSkuFamily = "MySQL"
        $mySqlSkuName = "MySQL57"
        $mySqlSkuTier = "Standalone"
        $mySqlLocation = "local"
        $mySqlArmEndpoint = $ArmEndpoint.TrimEnd("/", "\");
        $mySqlDatabaseAdapterNamespace = "Microsoft.MySQLAdapter.Admin"
        $mySqlApiVersion = "2017-08-28"
        $mySqlQuotaName = "mysqldefault"
        $mySqlQuotaResourceCount = "10"
        $mySqlQuotaResourceSizeMB = "1024"

        # Login to Azure Stack and populate variables
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        $sub = Get-AzureRmSubscription
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
        Write-Verbose -Message "Creating new MySQL Resource Provider SKU with name: $($mySqlSkuName), adapter namespace: $($mySqlDatabaseAdapterNamespace)" -Verbose
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
        Write-Verbose -Message "Creating new MySQL Resource Provider Quota with name: $($mySqlQuotaName), adapter namespace: $($mySqlDatabaseAdapterNamespace)" -Verbose
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
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### ADD SQL SERVER SKU & QUOTA ##############################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "SQLServerSKUQuota")
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
        $sqlLocation = "local"
        $sqlArmEndpoint = $ArmEndpoint.TrimEnd("/", "\");
        $sqlDatabaseAdapterNamespace = "Microsoft.SQLAdapter.Admin"
        $sqlApiVersion = "2017-08-28"
        $sqlQuotaName = "sqldefault"
        $sqlQuotaResourceCount = "10"
        $sqlQuotaResourceSizeMB = "1024"

        # Login to Azure Stack and populate variables
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        $sub = Get-AzureRmSubscription
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
        Write-Verbose -Message "Creating new SQL Server Resource Provider SKU with name: $($sqlSkuName), adapter namespace: $($sqlDatabaseAdapterNamespace)" -Verbose
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
        Write-Verbose -Message "Creating new SQL Server Resource Provider Quota with name: $($sqlQuotaName), adapter namespace: $($sqlDatabaseAdapterNamespace)" -Verbose
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
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### DEPLOY MySQL VM TO HOST USER DATABASES ##################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "MySQLDBVM")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        Write-Verbose "Creating a dedicated Resource Group for all database hosting assets"
        New-AzureRmResourceGroup -Name "azurestack-dbhosting" -Location local -Force

        # Deploy a MySQL VM for hosting tenant db
        Write-Verbose "Creating a dedicated MySQL5.7 on Ubuntu VM for database hosting"
        New-AzureRmResourceGroupDeployment -Name "MySQLHost" -ResourceGroupName "azurestack-dbhosting" -TemplateUri https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/packages/MySQL/ASDK.MySQL/DeploymentTemplates/mainTemplate.json `
            -vmName "mysqlhost" -adminUsername "mysqladmin" -adminPassword $secureVMpwd -mySQLPassword $secureVMpwd -allowRemoteConnections "Yes" `
            -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dhosting_subnet" -publicIPAddressDomainNameLabel "mysqlhost" -vmSize Standard_A3 -mode Incremental -Verbose -ErrorAction Stop

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### DEPLOY SQL SERVER VM TO HOST USER DATABASES #############################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "SQLServerDBVM")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Deploy a SQL Server 2017 on Ubuntu VM for hosting tenant db
        Write-Verbose "Creating a dedicated SQL Server 2017 on Ubuntu 16.04 LTS for database hosting"
        New-AzureRmResourceGroupDeployment -Name "SQLHost" -ResourceGroupName "azurestack-dbhosting" -TemplateUri https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/packages/MSSQL/ASDK.MSSQL/DeploymentTemplates/mainTemplate.json `
            -vmName "sqlhost" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd `
            -virtualNetworkNewOrExisting "existing" -virtualNetworkName "dbhosting_vnet" -virtualNetworkSubnetName "dhosting_subnet" -publicIPAddressDomainNameLabel "sqlhost" -vmSize Standard_A3 -mode Incremental -Verbose -ErrorAction Stop

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### ADD MYSQL HOSTING SERVER ################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "MySQLAddHosting")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Get the FQDN of the VM
        $mySqlFqdn = (Get-AzureRmPublicIpAddress -Name "mysql_ip" -ResourceGroupName "azurestack-dbhosting").DnsSettings.Fqdn

        # Add host server to MySQL RP
        Write-Verbose "Attaching MySQL hosting server to MySQL resource provider"
        New-AzureRmResourceGroupDeployment -ResourceGroupName "azurestack-dbhosting" -TemplateUri https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/MySQLHosting/azuredeploy.json `
            -username "root" -password $secureVMpwd -hostingServerName $mySqlFqdn -totalSpaceMB 10240 -skuName "MySQL57" -Mode Incremental -Verbose -ErrorAction Stop

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    # Get the FQDN of the VM
    $mySqlFqdn = (Get-AzureRmPublicIpAddress -Name "mysql_ip" -ResourceGroupName "azurestack-dbhosting").DnsSettings.Fqdn
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### ADD SQL SERVER HOSTING SERVER ###########################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "SQLServerAddHosting")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Get the FQDN of the VM
        $sqlFqdn = (Get-AzureRmPublicIpAddress -Name "sql_ip" -ResourceGroupName "azurestack-dbhosting").DnsSettings.Fqdn

        # Add host server to SQL Server RP
        Write-Verbose "Attaching SQL Server 2017 hosting server to SQL Server resource provider"
        New-AzureRmResourceGroupDeployment -ResourceGroupName "azurestack-dbhosting" -TemplateUri https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/SQLHosting/azuredeploy.json `
            -hostingServerName $sqlFqdn -hostingServerSQLLoginName "sa" -hostingServerSQLLoginPassword $secureVMpwd -totalSpaceMB 10240 -skuName "MSSQL2017" -Mode Incremental -Verbose -ErrorAction Stop

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    # Get the FQDN of the VM
    $sqlFqdn = (Get-AzureRmPublicIpAddress -Name "sql_ip" -ResourceGroupName "azurestack-dbhosting").DnsSettings.Fqdn
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### DEPLOY APP SERVICE FILE SERVER ##########################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "AppServiceFileServer")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        ### Deploy File Server ###
        Write-Verbose "Deploying Windows Server 2016 File Server"
        New-AzureRmResourceGroup -Name "appservice-fileshare" -Location local -Force
        New-AzureRmResourceGroupDeployment -Name "fileshareserver" -ResourceGroupName "appservice-fileshare" -vmName "fileserver" -TemplateUri https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/templates/FileServer/azuredeploy.json `
            -adminPassword $secureVMpwd -fileShareOwnerPassword $secureVMpwd -fileShareUserPassword $secureVMpwd -Mode Incremental -Verbose -ErrorAction Stop

        # Get the FQDN of the VM
        $fileServerFqdn = (Get-AzureRmPublicIpAddress -Name "fileserver_ip" -ResourceGroupName "appservice-fileshare").DnsSettings.Fqdn

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    # Get the FQDN of the VM
    $fileServerFqdn = (Get-AzureRmPublicIpAddress -Name "fileserver_ip" -ResourceGroupName "appservice-fileshare").DnsSettings.Fqdn
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### DEPLOY APP SERVICE SQL SERVER ###########################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "AppServiceSQLServer")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Deploy a SQL Server 2017 on Ubuntu VM for App Service
        Write-Verbose "Creating a dedicated SQL Server 2017 on Ubuntu Server 16.04 LTS for App Service"
        New-AzureRmResourceGroup -Name "appservice-sql" -Location local -Force
        New-AzureRmResourceGroupDeployment -Name "sqlapp" -ResourceGroupName "appservice-sql" -TemplateUri https://raw.githubusercontent.com/mattmcspirit/azurestack/master/deployment/packages/MSSQL/ASDK.MSSQL/DeploymentTemplates/mainTemplate.json `
            -vmName "sqlapp" -adminUsername "sqladmin" -adminPassword $secureVMpwd -msSQLPassword $secureVMpwd -storageAccountName "sqlappstor" `
            -publicIPAddressDomainNameLabel "sqlapp" -publicIPAddressName "sqlapp_ip" -vmSize Standard_A3 -mode Incremental -Verbose -ErrorAction Stop

        # Get the FQDN of the VM
        $sqlAppServerFqdn = (Get-AzureRmPublicIpAddress -Name "sqlapp_ip" -ResourceGroupName "appservice-sql").DnsSettings.Fqdn

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    # Get the FQDN of the VM
    $sqlAppServerFqdn = (Get-AzureRmPublicIpAddress -Name "sqlapp_ip" -ResourceGroupName "appservice-sql").DnsSettings.Fqdn
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### DOWNLOAD APP SERVICE ####################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "DownloadAppService")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Install App Service To be added
        Write-Verbose "Downloading App Service Installer"
        Set-Location $ASDKpath
        $appServiceHelperURI = "https://aka.ms/appsvconmashelpers"
        $appServiceHelperDownloadLocation = "$ASDKpath\appservicehelper.zip"
        DownloadWithRetry -downloadURI "$appServiceHelperURI" -downloadLocation "$appServiceHelperDownloadLocation" -retries 10
        Expand-Archive $ASDKpath\appservicehelper.zip -DestinationPath "$ASDKpath\AppService\" -Force
        $appServiceExeURI = "https://aka.ms/appsvconmasinstaller"
        $appServiceExeDownloadLocation = "$ASDKpath\AppService\appservice.exe"
        DownloadWithRetry -downloadURI "$appServiceExeURI" -downloadLocation "$appServiceExeDownloadLocation" -retries 10

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### GENERATE APP SERVICE CERTS ##############################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "GenerateAppServiceCerts")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        Write-Verbose "Generating Certificates"
        $AppServicePath = "$ASDKpath\AppService"
        Set-Location "$AppServicePath"
        .\Create-AppServiceCerts.ps1 -PfxPassword $secureVMpwd -DomainName "local.azurestack.external"
        .\Get-AzureStackRootCert.ps1 -PrivilegedEndpoint $ERCSip -CloudAdminCredential $cloudAdminCreds

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### CREATE AD SERVICE PRINCIPAL #############################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "CreateServicePrincipal")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        # Create Azure AD or ADFS Service Principal
        if ($authenticationType.ToString() -like "AzureAd") {
            # Logout to clean up
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
            Clear-AzureRmContext -Scope CurrentUser -Force

            # Grant permissions to Azure AD Service Principal
            Login-AzureRmAccount -EnvironmentName "AzureCloud" -Credential $asdkCreds -ErrorAction Stop | Out-Null
            Set-Location "$AppServicePath"
            $appID = .\Create-AADIdentityApp.ps1 -DirectoryTenantName "$azureDirectoryTenantName" -AdminArmEndpoint "adminmanagement.local.azurestack.external" -TenantArmEndpoint "management.local.azurestack.external" `
                -CertificateFilePath "$AppServicePath\sso.appservice.local.azurestack.external.pfx" -CertificatePassword $secureVMpwd -AzureStackAdminCredential $asdkCreds
            $appIdPath = "$AppServicePath\ApplicationID.txt"
            $deploymentIdPath = "$AppServicePath\DeploymentID.txt"
            $deploymentID = $appID[0]
            $identityApplicationID = $appID[1]
            New-Item $appIdPath -ItemType file -Force
            New-Item $deploymentIdPath -ItemType file -Force
            Write-Output $identityApplicationID > $appIdPath
            Write-Output $deploymentID > $appIdPath
            Start-Sleep -Seconds 20
        }
        elseif ($authenticationType.ToString() -like "ADFS") {
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            Set-Location "$AppServicePath"
            $appID = .\Create-ADFSIdentityApp.ps1 -AdminArmEndpoint "adminmanagement.local.azurestack.external" -PrivilegedEndpoint $ERCSip `
                -CertificateFilePath "$AppServicePath\sso.appservice.local.azurestack.external.pfx" -CertificatePassword $secureVMpwd -CloudAdminCredential $asdkCreds
            $appIdPath = "$AppServicePath\ApplicationID.txt"
            $deploymentID = $appID[0]
            $identityApplicationID = $appID[1]
            New-Item $appIdPath -ItemType file -Force
            Write-Output $identityApplicationID > $appIdPath
        }
        else {
            Write-Verbose ("No valid application was created, please perform this step after the script has completed")  -ErrorAction SilentlyContinue
        }
        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### GRANT AZURE AD APP PERMISSION ###########################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "GrantAzureADAppPermissions")
if ($authenticationType.ToString() -like "AzureAd") {
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {

        try {
            # Logout to clean up
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
            Clear-AzureRmContext -Scope CurrentUser -Force
            # Grant permissions to Azure AD Service Principal
            Login-AzureRmAccount -EnvironmentName "AzureCloud" -Credential $asdkCreds -ErrorAction Stop | Out-Null
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
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress
        }
        catch {
            Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Verbose $_.Exception.Message -ErrorAction Stop
            Set-Location $ScriptLocation
            return
        }
    }
    elseif ($progress[$RowIndex].Status -eq "Complete") {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
    }
}
elseif ($authenticationType.ToString() -like "ADFS") {
    Write-Verbose "Skipping Azure AD App Permissions, as this is an ADFS deployment"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress
}

#### CREATE BASIC BASE PLANS AND OFFERS ######################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "CreatePlansOffers")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        # Configure a simple base plan and offer for IaaS
        Import-Module "$modulePath\Connect\AzureStack.Connect.psm1"
        Import-Module "$modulePath\ServiceAdmin\AzureStack.ServiceAdmin.psm1"

        Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount
        Clear-AzureRmContext -Scope CurrentUser -Force
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

        # Default quotas, plan, and offer
        $PlanName = "BasePlan"
        $OfferName = "BaseOffer"
        $RGName = "azurestack-plansandoffers"
        $Location = (Get-AzsLocation).Name

        $computeParams = @{
            Name                 = "compute_default"
            CoresLimit           = 200
            AvailabilitySetCount = 20
            VirtualMachineCount  = 100
            VmScaleSetCount      = 20
            Location             = $Location
        }

        $netParams = @{
            Name                          = "network_default"
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
            Name                    = "storage_default"
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

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### DEPLOY APP SERVICE ######################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "InstallAppService")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        Invoke-WebRequest "https://raw.githubusercontent.com/mattmcspirit/azurestack/AppServiceAutomate/deployment/appservice/AppServiceDeploymentSettings.json" -OutFile "$AppServicePath\AppServicePreDeploymentSettings.json"
        $JsonConfig = Get-Content -Path "$AppServicePath\AppServicePreDeploymentSettings.json"
        #Create the JSON from deployment
        $JsonConfig = $JsonConfig.Replace("<<AzureDirectoryTenantName>>", $azureDirectoryTenantName)
        $JsonConfig = $JsonConfig.Replace("<<DeploymentId>>", $deploymentID)
        $TenantArmAppIDObj = Get-AzureRmADApplication -IdentifierUri "https://management.$azureDirectoryTenantName/$($appID[0])"
        $TenantArmApplicationId = $TenantArmAppIDObj.ApplicationId
        $JsonConfig = $JsonConfig.Replace("<<TenantArmApplicationId>>", $TenantArmApplicationId)
        $sub = Get-AzureRmSubscription
        $subscriptionId = $sub.Id
        $JsonConfig = $JsonConfig.Replace("<<subscriptionId>>", $subscriptionId)
        $TenantId = $sub.TenantId
        $JsonConfig = $JsonConfig.Replace("<<TenantId>>", $TenantId)
        $JsonConfig = $JsonConfig.Replace("<<FileServerDNSLabel>>", $fileServerFqdn)
        $JsonPassword = $VMPwd
        $JsonConfig = $JsonConfig.Replace("<<Password>>", $JsonPassword)
        $JsonConfig = $JsonConfig.Replace("<<IdentityApplicationId>>", $identityApplicationID)
        $ServicePrincipalObjectId = (Get-AzureRmADServicePrincipal -ServicePrincipalName $IdentityApplicationId).Id.Guid
        $JsonConfig = $JsonConfig.Replace("<<ServicePrincipalObjectId>>", $ServicePrincipalObjectId)
        $CertPathDoubleSlash = $AppServicePath.Replace("\", "\\")
        $JsonConfig = $JsonConfig.Replace("<<CertPathDoubleSlash>>", $CertPathDoubleSlash)
        $JsonConfig = $JsonConfig.Replace("<<SQLServerName>>", $sqlAppServerFqdn)
        $SQLServerUser = "sa"
        $JsonConfig = $JsonConfig.Replace("<<SQLServerUser>>", $SQLServerUser)
        Out-File -FilePath "$AppServicePath\AppServiceDeploymentSettings.json" -InputObject $JsonConfig

        # Deploy App Service EXE
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($asdkCreds.Password)
        $appServiceInstallPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        Set-Location "$AppServicePath"
        Write-Verbose "Starting deployment of the App Service"
        .\AppService.exe /quiet Deploy UserName=$($asdkCreds.UserName) Password=$appServiceInstallPwd ParamFile="$AppServicePath\AppServiceDeploymentSettings.json"

        while ((Get-Process AppService -ErrorAction SilentlyContinue).Responding) {
            Write-Verbose "App Service is Deploying. Checking in 10 seconds"
            Start-Sleep -Seconds 10
        }
            
        if (!(Get-Process AppService -ErrorAction SilentlyContinue).Responding) {
            Write-Verbose "App Service Deployment Completed."
        }

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### CUSTOMIZE ASDK HOST #####################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "InstallHostApps")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
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
        Write-Verbose "Installing latest version of Azure CLI with Chocolatey"
        choco install azure-cli

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### GENERATE OUTPUT #########################################################################################################################################
##############################################################################################################################################################

$RowIndex = [array]::IndexOf($progress.Stage, "CreateOutput")
if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        Write-Host -ForegroundColor Green "The ASDK configuration is complete....well, almost"
        Write-Host -ForegroundColor Green "Please copy the following application ID: $identityApplicationID and review the documentation to finish the process"

        ### Create Output Document ###

        $txtPath = "$downloadPath\ConfigASDKOutput.txt"
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
        elseif (!$useAzureCredsForRegistration -and $registerASDK) {
            Write-Output "Your Azure Stack was registered to Azure with the following username: $azureRegUsername" >> $txtPath
        }

        if ($authenticationType.ToString() -like "ADFS" -and $registerASDK) {
            Write-Output "Your Azure Stack was registered to Azure with the following username: $azureRegUsername" >> $txtPath
        }

        Write-Output "`r`nThe Azure Stack PowerShell tools have been downloaded to: $modulePath" >> $txtPath
        Write-Output "All other downloads have been stored here: $ASDKpath" >> $txtPath
        Write-Output "`r`nSQL & MySQL Resource Provider Information:" >> $txtPath
        Write-Output "MySQL Resource Provider VM Credentials = mysqlrpadmin | $VMpwd" >> $txtPath
        Write-Output "MySQL Database Hosting VM FQDN: $mySqlFqdn" >> $txtPath
        Write-Output "MySQL Database Hosting VM Credentials = mysqladmin | $VMpwd" >> $txtPath
        Write-Output "SQL Server Resource Provider VM Credentials = sqlrpadmin | $VMpwd" >> $txtPath
        Write-Output "SQL Server Database Hosting VM FQDN: $sqlFqdn" >> $txtPath
        Write-Output "SQL Server Database Hosting VM Credentials = sqladmin | $VMpwd" >> $txtPath
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

        Write-Output "`r`nYou'll now need to run the appservice.exe located in your $AppServicePath folder" >> $txtPath
        Write-Output "Documentation can be found here: https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-app-service-deploy" >> $txtPath
        Write-Output "Use the following values to populate the wizard:" >> $txtPath
        Write-Output "`r`nAzure Stack Admin ARM Endpoint: adminmanagement.local.azurestack.external" >> $txtPath
        Write-Output "Azure Stack Tenant ARM Endpoint: management.local.azurestack.external" >> $txtPath
        Write-Output "Azure Directory Tenant Name: $azureDirectoryTenantName" >> $txtPath
        Write-Output "`r`nOn the next screen, click Connect, login, and then choose your subscription and location (local)" >> $txtPath
        Write-Output "`r`nOn the next screen, replace your Resource Group Name with appservice-infra" >> $txtPath
        Write-Output "`r`nOn the next screen, input the following info:" >> $txtPath
        Write-Output "File Share UNC Path: \\appservicefileshare.local.cloudapp.azurestack.external\websites" >> $txtPath
        Write-Output "File Share Owner: fileshareowner" >> $txtPath
        Write-Output "File Share Owner Password: $VMpwd" >> $txtPath
        Write-Output "File Share User: fileshareuser" >> $txtPath
        Write-Output "File Share User Password: $VMpwd" >> $txtPath
        Write-Output "`r`nOn the next screen, input the following info:" >> $txtPath
        Write-Output "Identity Application ID: $identityApplicationID" >> $txtPath
        Write-Output "Identity Application Certificate file (*.pfx): $AppServicePath\sso.appservice.local.azurestack.external.pfx" >> $txtPath
        Write-Output "Identity Application Certificate (*.pfx) password: $VMpwd" >> $txtPath
        Write-Output "Azure Resource Manager (ARM) root certificate file (*.cer): $AppServicePath\AzureStackCertificationAuthority.cer" >> $txtPath
        Write-Output "`r`nOn the next screen, input the following info:" >> $txtPath
        Write-Output "App Service default SSL certificate file (*.pfx): $AppServicePath\_.appservice.local.AzureStack.external.pfx" >> $txtPath
        Write-Output "App Service default SSL certificate (*.pfx) password: $VMpwd" >> $txtPath
        Write-Output "App Service API SSL certificate file (*.pfx): $AppServicePath\api.appservice.local.AzureStack.external.pfx" >> $txtPath
        Write-Output "App Service API SSL certificate (*.pfx) password: $VMpwd" >> $txtPath
        Write-Output "App Service Publisher SSL certificate file (*.pfx): $AppServicePath\ftp.appservice.local.AzureStack.external.pfx" >> $txtPath
        Write-Output "App Service Publisher SSL certificate (*.pfx) password: $VMpwd" >> $txtPath
        Write-Output "`r`nOn the next screen, input the following info:" >> $txtPath
        Write-Output "SQL Server Name: $sqlAppServerFqdn" >> $txtPath
        Write-Output "SQL sysadmin login: sa" >> $txtPath
        Write-Output "SQL sysadmin password: $VMpwd" >> $txtPath
        Write-Output "`r`nOn the next screen, accept the defaults for the instances and click Next:" >> $txtPath
        Write-Output "`r`nOn the next screen, accept the default for the Platform Image and click Next:" >> $txtPath
        Write-Output "`r`nOn the next screen, input the following info:" >> $txtPath
        Write-Output "Worker Role Virtual Machine(s) Admin: workeradmin" >> $txtPath
        Write-Output "Worker Role Virtual Machine(s) Password: $VMpwd" >> $txtPath
        Write-Output "Confirm Password: $VMpwd" >> $txtPath
        Write-Output "Other Roles Virtual Machine(s) Admin: roleadmin" >> $txtPath
        Write-Output "Other Roles Virtual Machine(s) Password: $VMpwd" >> $txtPath
        Write-Output "Confirm Password: $VMpwd" >> $txtPath

        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed"
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Verbose $_.Exception.Message -ErrorAction Stop
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}

#### FINAL STEPS #############################################################################################################################################
##############################################################################################################################################################

### Clean Up ASDK Folder ###
$scriptSuccess = $progress | Where-Object {($_.Status -eq "Incomplete") -or ($_.Status -eq "Failed")}
if ([string]::IsNullOrEmpty($scriptSuccess)) {
    Write-Verbose "Congratulations - all steps completed successfully:`r`n"
    $progress
    Write-Verbose "Cleaning up ASDK Folder and Progress CSV file"
    Get-ChildItem -Path "$asdkPath\*" | Where-Object {($_.Extension -eq ".zip")} | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item "$asdkPath\MySQL" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item "$asdkPath\SQL" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$asdkPath\AppService\*" -Recurse | Where-Object {($_.Extension -ne ".exe") -and ($_.Extension -ne ".pfx") -and ($_.Extension -ne ".cer")} | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path $ConfigASDKProgressLogPath -Confirm:$false -Force -ErrorAction SilentlyContinue
}
else {
    Write-Verbose "Script hasn't completed successfully"
    Write-Verbose "Please rerun the script to complete the process"
    $progress
}

Write-Verbose "Setting Execution Policy back to RemoteSigned"
Set-ExecutionPolicy RemoteSigned -Confirm:$false -Force

# Calculate completion time
$endTime = $(Get-Date).ToLocalTime()
$sw.Stop()
$Hrs = $sw.Elapsed.Hours
$Mins = $sw.Elapsed.Minutes
$Secs = $sw.Elapsed.Seconds
$difference = '{0:00}h:{1:00}m:{2:00}s' -f $Hrs, $Mins, $Secs

Write-Output "`r`nOpening your ConfigASDKOutput.txt file that you'll use for the App Service deployment..."
Start-Sleep -Seconds 5
Notepad "$downloadPath\ConfigASDKOutput.txt"
Set-Location $ScriptLocation -ErrorAction SilentlyContinue
Write-Output "ASDK Configurator setup completed successfully, taking $difference." -ErrorAction SilentlyContinue
Write-Output "You started the ASDK Configurator deployment at $startTime." -ErrorAction SilentlyContinue
Write-Output "ASDK Configurator deployment completed at $endTime." -ErrorAction SilentlyContinue

### Launch browser to activate admin and user portal for Azure AD deployments
if ($authenticationType.ToString() -like "AzureAd") {
    Write-Output "Launching browser to activate admin and user portals"
    [System.Diagnostics.Process]::Start("chrome.exe", "https://adminportal.local.azurestack.external/guest/signup")
    Start-Sleep -Seconds 10
    [System.Diagnostics.Process]::Start("chrome.exe", "https://portal.local.azurestack.external/guest/signup")
}

Stop-Transcript -ErrorAction SilentlyContinue