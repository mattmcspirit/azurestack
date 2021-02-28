# Copyright (c) Microsoft Corporation. All rights reserved.
# Common.psm1 1.1.93.1 2020-12-16 23:32:43

# AzureStack-Services-SqlServer released/1.1.93 retail-amd64

<#
.SYNOPSIS
    Initializes the Azure PowerShell environment for use with an Azure Stack Environment.
#>
Import-Module -Name "$PSScriptRoot\..\..\Telemetry\Microsoft.AzureStack.Deploy.Telemetry.dll" -ErrorAction Stop -Verbose:$false # Telemetry

function Trace-Step {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Message to be displayed in the trace")]
        [string]$Message
    )
    $TitleChar = "*"
    $FormattedOutput = @()
    $TitleBar = ""
    for ($i = 0; $i -lt ($Message.Length) + 2; $i++) {
        $TitleBar += $TitleChar
    }
    $FormattedOutput = @("", $TitleBar, "$TitleChar$Message$TitleChar", $TitleBar)
    $FormattedOutput = $FormattedOutput | ForEach-Object { (Get-Date).ToLongTimeString() + " : " + $_ }
    $FormattedOutput | Write-Verbose -Verbose
}

function Test-DeploymentMachineOSVersion {
    $osVersionInfo = [Environment]::OSVersion.Version
    if (-not ($osVersionInfo.Major -ge 10)) {
        Write-Host -ForegroundColor Red "RP deployment must be run from a machine running Windows 2016 or newer, please retry from a machine running the supported OS version."
        throw
    }
}

function Test-DeploymentMachineNETFramework {
    $requiredNETVersion = 4.6
    if (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP') {
        $ndpReg = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\' -Recurse
        $netVersions = $ndpReg | Get-ItemProperty -Name Version -ErrorAction Ignore
        $result = $netVersions.Version -ge $requiredNETVersion
        if ( -not ($result)) {
            Write-Host -ForegroundColor Red "RP deployment must be run from a machine with .NET framework 4.6 or newer, please install the required version of the .NET framework and retry RP deployment"
            throw
        }
    }
    else {
        Write-Host -ForegroundColor Red "RP deployment must be run from a machine with .NET framework 4.6 or newer, please install the required version of the .NET framework and retry RP deployment"
        throw
    }
}

function Import-AzurePshModules {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Azure Powershell install location")]
        [string]$AzPshInstallLocation
    )

    Write-Host "Loading azure powershell modules from location $AzPshInstallLocation"
    Import-Module $AzPshInstallLocation\Az.Accounts -Scope Global
    Import-Module $AzPshInstallLocation\Az.Resources -Scope Global
    Import-Module $AzPshInstallLocation\Az.Storage -Scope Global
    Import-Module $AzPshInstallLocation\Az.Keyvault -Scope Global
    Import-Module $AzPshInstallLocation\Az.Compute -Scope Global
    Import-Module $AzPshInstallLocation\Az.Network -Scope Global
    Import-Module $AzPshInstallLocation\Az.Dns -Scope Global
}

function Test-AzureStackPowerShell {
    $AzPshInstallFolder = "WindowsPowerShell\Modules"
    $AzPshInstallLocation = "$Env:ProgramFiles\$AzPshInstallFolder"

    # add this path to the system $env:PSModulePath to make sure it can find the modules.
    $modulePaths = $env:PSModulePath -split ";"
    if (-NOT ($modulePaths -contains $AzPshInstallLocation)) {
        $env:PSModulePath = $env:PSModulePath + ";" + $AzPshInstallLocation 
    }

    $AzPsVersion = "0.10.0"
    $ProgressPreference = "SilentlyContinue"

    $packageProvider = Get-PackageProvider -Name Nuget
    if ($packageProvider -eq $null) {
        Write-Host "Nuget Package provider not found. Installing .... "
        Install-PackageProvider -Name "Nuget" -MinimumVersion 2.8.5.201
    }
    else {
        Write-Host "Nuget Package provider found."
    }

    # Check if the AzureRm.Profile module is already loaded into the session, 
    # if it is already loaded, make sure that it is loaded from the needed location
    # Az.Accounts is loaded into the session for any azure powershell modules as all the modules have dependency on this
    $moduleName = "Az.Accounts"
    $moduleLoaded = Get-Module -Name $moduleName
    $isModuleLoaded = $moduleLoaded -ne $null
    $isLoadedFromNeededLocation = $isModuleLoaded -and $moduleLoaded.Path.ToLower().Contains($AzPshInstallFolder.ToLower())
    
    if ($isModuleLoaded -and $isLoadedFromNeededLocation) {
        # Make sure all the needed modules are loaded. if already loaded, import-module statement is no-op
        Import-AzurePshModules -AzPshInstallLocation $AzPshInstallLocation
    }
    elseif ($isModuleLoaded -and (-Not $isLoadedFromNeededLocation)) {
        Write-Host "$moduleName expected load location: $AzPshInstallLocation, actual location: $($moduleLoaded.Path)"
        Write-Host -ForegroundColor Red "Please open a new powershell session to run the deployment, as this powershell session has azure powershell modules loaded from a location other than $AzPshInstallLocation"
        throw
    }

    $isModuleInstalled = Test-Path -Path $AzPshInstallLocation\Az -PathType Container
    $isCorrectVersion = Test-Path -Path $AzPshInstallLocation\Az\$AzPsVersion -PathType Container

    if ($isModuleInstalled -and $isCorrectVersion) {
        Write-Host "Azure powershell version $AzPsVersion found at $AzPshInstallLocation"
        # Make sure all the needed modules are loaded. if already loaded, import-module statement is no-op
        Import-AzurePshModules -AzPshInstallLocation $AzPshInstallLocation
    } 
    elseif ($isModuleInstalled -and -Not $isCorrectVersion) {
        Write-Host -ForegroundColor Red "Incorrect azure powershell version installed in $AzPshInstallLocation, Please delete the folder contents and rerun the script"
        throw
    }
    else {
        # Module is not installed 
        $isConnectedEnv = Test-NetConnection www.powershellgallery.com -Port 443 -InformationLevel Quiet

        if ($isConnectedEnv) {
            # in this case azure powershell modules are not found in $AzPshInstallLocation
            Write-Host "Installing the azure powershell modules at the location $AzPshInstallLocation."
            Install-Module -Name Az.BootStrapper -Force -AllowPrerelease
            Install-AzProfile -Profile 2019-03-01-hybrid -Force
            Write-Host "Successfully installed the azure powershell modules."
            Import-AzurePshModules -AzPshInstallLocation $AzPshInstallLocation
        }
        else {
            # disconnected environment, powershell modules are not installed in $AzPshInstallLocation
            # Trying to find the required version in the locally registered repositories
            $repos = Get-PSRepository 
            $modulesSaved = $false
    
            foreach ($repo in $repos) {
                Write-Host "Trying to find the AzureRM module version $AzPsVersion in the registered repo $($repo.Name)"
                $mod = Find-Module -Name Az -RequiredVersion $AzPsVersion -Repository $repo.Name -ErrorAction SilentlyContinue
                if ($mod -ne $null) {
                    Write-Host "Installing the AzureRM module version $AzPsVersion from the regsitered repo $($repo.Name) to the location $AzPshInstallLocation"
                    Install-Module Az -Repository $RepoName -RequiredVersion 0.10.0-preview -AllowPrerelease -Scope AllUsers -Force -ErrorAction Stop -Verbose
                    Write-Host "Successfully installed the azure powershell modules."
                    $modulesSaved = $true;
                    break;
                }
            }
            if (-Not $modulesSaved) {
                Write-Host -ForegroundColor Red "Azure powershell modules not found in $AzPshInstallLocation, Please do Save-Module AzureRM -RequiredVersion $AzureRMVersion -Path $AzPshInstallLocation -Force specifying the value for -Repository param"
                throw
            }
        }
    }
}

function Test-AzureStackVersion {
    param(
        [Parameter(Mandatory = $false, HelpMessage = "Minimum Azure Stack Version")]
        [System.Version]$MinAzureStackVersion = "1.0.0.0",
        [Parameter(Mandatory = $false, HelpMessage = "Maximal Azure Stack Version")]
        [System.Version]$MaxAzureStackVersion = "2.0.0.0",
        [Parameter(Mandatory = $true, HelpMessage = "Current Azure Stack Version")]
        [System.Version]$CurrentAzureStackVersion        
    )
    
    if (-not (($CurrentAzureStackVersion -ge $MinAzureStackVersion) -and ($CurrentAzureStackVersion -le $MaxAzureStackVersion))) {
        if ($MinAzureStackVersion -eq $MaxAzureStackVersion) {
            Write-Error -Message ("The current azure stack version {0} does not meet the requirement. The expected azure stack version is {1}" -f $CurrentAzureStackVersion, $MinAzureStackVersion)
        }
        else {
            Write-Error -Message ("The current azure stack version {0} does not meet the requirement. The expected minimum azure stack version is {1}, The expected maximal azure stack version is {2}, " `
                    -f $CurrentAzureStackVersion, $MinAzureStackVersion, $MaxAzureStackVersion)
        }
        throw          
    }
}

function Test-DataAdapterUpdateVersion {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Supported Data Adapter Version")]
        [System.Version]$SupportedDataAdapterUpdateVersion,
        [Parameter(Mandatory = $true, HelpMessage = "Current Data Adapter Version")]
        [System.Version]$CurrentDataAdapterVersion        
    )
    
    if (($CurrentDataAdapterVersion.CompareTo($SupportedDataAdapterUpdateVersion) -lt 0) -and ($SupportedDataAdapterUpdateVersion -ne "0.0.0.0")) {
        Write-Error -Message ("The current Data Adapter version {0} does not meet the requirement. The expected version is {1}" `
                -f $CurrentDataAdapterVersion, $SupportedDataAdapterUpdateVersion)
        throw 
    }
}

function Get-AzureStackEnvironment {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $false, HelpMessage = "Friendly name of Azure stack")]
        [string]$EnvironmentName = "AzureStack",
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Arm Endpoint")]
        [string]$ArmEndpoint        
    )
    $azEnvironment = Get-AzureRmEnvironment $EnvironmentName -ErrorAction SilentlyContinue
    if ($azEnvironment -ne $null) {
        Remove-AzureRmEnvironment -Name $EnvironmentName | Out-Null
    }
    $armEndpoint = $ArmEndpoint;
    $DomainName = ""
    try {
        $temp = ""
        $DomainNameSplit = $ArmEndpoint.Split(".")
        for ($i = 1; $i -le $DomainNameSplit.Count - 1; $i++) {
            $temp += $DomainNameSplit[$i] + "."
        }
        $DomainName = $temp.TrimEnd(".").Split(":")[0] 
    }
    catch {
        Write-Error "The specified ARM endpoint was invalid"
    }   
    $endpoints = Invoke-RestMethod "${armEndpoint}/metadata/endpoints?api-version=2015-01-01"
    Write-Verbose -Message "Endpoints: $(ConvertTo-Json $endpoints)" -Verbose
    
    $keyVault = "vault"
    if ($ArmEndpoint.Contains("adminmanagement")) {
        $keyVault = "adminvault"
    }
    $keyVaultDnsSuffix = $keyVault + "." + $DomainName
    $keyVaultEndpoint = "https://" + $keyVaultDnsSuffix


    $azureEnvironmentParams = @{
        Name                                     = $EnvironmentName
        ActiveDirectoryEndpoint                  = $endpoints.authentication.loginEndpoint.TrimEnd('/') + "/"
        ActiveDirectoryServiceEndpointResourceId = $endpoints.authentication.audiences[0]
        AdTenant                                 = $DirectoryTenantId
        ResourceManagerEndpoint                  = $ArmEndpoint
        GalleryEndpoint                          = $endpoints.galleryEndpoint
        GraphEndpoint                            = $endpoints.graphEndpoint
        GraphAudience                            = $endpoints.graphEndpoint
        EnableAdfsAuthentication                 = $true
        ManagementPortalUrl                      = $endpoints.portalEndpoint
        AzureKeyVaultDnsSuffix                   = $keyVaultDnsSuffix
        AzureKeyVaultServiceEndpointResourceId   = $keyVaultEndpoint
        StorageEndpoint                          = $DomainName
    }
    $azEnvironment = Add-AzureRMEnvironment @azureEnvironmentParams
    $azEnvironment = Get-AzureRmEnvironment $EnvironmentName
    return $azEnvironment
}

function Add-AzureStackAccount {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Credential object of Azure Stack")]
        [PSCredential]$azCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Azure stack environment Name")]
        [string]$azEnvironmentName,
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID

    )
    
    try {
        # the cmdlet still report error with SilentlyContinue, so use try and catch here.
        $context = Get-AzureRmContext -ErrorAction SilentlyContinue
    }
    catch {
    }
    
    $initialized = $false
    if ($context -and $context.Account -and $context.Account.Id -and $context.Subscription -and ($context.Subscription.Name -eq "Default Provider Subscription") -and ($context.Environment.AzureKeyVaultDnsSuffix -like "adminvault*")) {
        Write-Verbose -Verbose "Reused the existing context"
        $azAccount = $context.Account
        $initialized = $true
    }
    else {
        Write-Verbose -Verbose "Initializing a new AzureRm context"
        $usePassedCredential = $true
        $retries = 5
        # clean up the existing logged account. https://docs.microsoft.com/en-us/azure-stack/operator/azure-stack-powershell-configure-admin?view=azs-2008&tabs=azurerm1%2Caz2%2Caz3
        Remove-AzureRmAccount -Scope Process -ErrorAction SilentlyContinue | Out-Null
        for ($i = 0; $i -lt $retries; $i++) {
            if ($usePassedCredential) {
                Add-AzureRmAccount -EnvironmentName $azEnvironmentName -Credential $azCredential -TenantId $DirectoryTenantID -ErrorAction SilentlyContinue | Out-Null
            }
            else {
                Add-AzureRmAccount `
                    -EnvironmentName $azEnvironmentName `
                    -TenantId $DirectoryTenantID -ErrorAction SilentlyContinue | Out-Null
            }
            
            try {
                # the cmdlet still report error with SilentlyContinue, so use try and catch here.
                $context = Get-AzureRmContext -ErrorAction SilentlyContinue
            }
            catch {}
            
            if ($context -and $context.Account -and $context.Account.Id -and $context.Subscription -and ($context.Subscription.Name -eq "Default Provider Subscription") -and ($context.Environment.AzureKeyVaultDnsSuffix -like "adminvault*")) {
                Write-Verbose -Verbose "Initialized a new AzureRm context"
                $azAccount = $context.Account
                $initialized = $true
                break;
            }
            else {
                $usePassedCredential = $false
                Write-Verbose -Verbose "The initialized AzureRm context is not as expected, the account Id or subscription or AzureKeyVaultDnsSuffix is not correct."
                if (($i + 1) -lt $retries) {
                    Clear-AzureRmContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }
    }

    if (-not $initialized) {
        Write-Verbose -Verbose "Print the Azure Rm Context and Environment Info"
        Write-Verbose -Verbose ">>>>>>>>>>>>>>>>>>>>>>>>> Get all environments >>>>>>>>>>>>>>>>>>>>>>>>>>>"
        Write-Verbose -Verbose (Get-AzureRmEnvironment | Format-List * -Force | Out-String)
        Write-Verbose -Verbose ">>>>>>>>>>>>>>>>>>>>>>>>> Get AzureRm Context >>>>>>>>>>>>>>>>>>>>>>>>>>>"
        Write-Verbose -Verbose (Get-AzureRmContext | Format-Table -Force | Out-String)
        Write-Verbose -Verbose ">>>>>>>>>>>>>>>>>>>>>>>>> Get the environment associated with AzureRm Context >>>>>>>>>>>>>>>>>>>>>>>>>>>"
        Write-Verbose -Verbose ((Get-AzureRmContext).Environment | Format-List * -Force | Out-String)
        Write-Verbose -Verbose ">>>>>>>>>>>>>>>>>>>>>>>>> Get Modules >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
        Write-Verbose -Verbose (Get-Module | Format-Table -Force | Out-String)
        throw "Could not login in"
    }
    $azAccount
}

function Initialize-AzureStackEnvironment {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $false, HelpMessage = "Friendly name of Azure stack")]
        [string]$EnvironmentName = "AzureStack",
        [Parameter(Mandatory = $true, HelpMessage = "Credential object of Azure Stack")]
        [PSCredential]$azCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Admin Arm Endpoint")]
        [string]$ArmEndpoint
    )
    $azEnvironment = Get-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -EnvironmentName $EnvironmentName -ArmEndpoint $ArmEndpoint
    $azAccount = Add-AzureStackAccount -azCredential $azCredential -azEnvironmentName $azEnvironment.Name -DirectoryTenantID $DirectoryTenantID
    $azAccount
}

function Get-AzureStackDeploymentId {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Azure stack Tenant Arm endpoint")]
        [string]$TenantArmEndpoint
    )
    $deploymentId = ""

    try {
        $TenantArmEndpoint = $TenantArmEndpoint.Trim("\", "/")
        $endpoint = Invoke-RestMethod "$TenantArmEndpoint/metadata/endpoints?api-version=1.0"
        $deploymentId = $endpoint.authentication.audiences[0].Split("/")[-1]
    }
    catch {
        Write-Error -Message "Please verify the Tenant Arm Endpoint: $TenantArmEndpoint is correct "
    }
    return $deploymentId
}

function New-GraphApplicationOnADFS {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "the Privileged endpoint")]
        [string]$Privilegedendpoint,
        [Parameter(Mandatory = $true, HelpMessage = "Azure Stack cloudsadmin domain account credential.")]
        [PSCredential]$CloudAdminCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Key Vault Integration Cert")]
        [Object]$KeyVaultIntegrationCert,
        [Parameter(Mandatory = $true, HelpMessage = "The type of RP being deployed.")]
        [string]$TraceName
    )
    Set-TrustedHosts -PrivilegedEndpoint $Privilegedendpoint
    $domainAdminSession = New-PSSession -ComputerName $Privilegedendpoint -Credential $CloudAdminCredential -configurationname privilegedendpoint  -Verbose 
    $applicationGroup = Invoke-Command -Session $domainAdminSession -Verbose -ErrorAction Stop  -ScriptBlock { New-GraphApplication -Name "$using:TraceName" -ClientCertificates $using:KeyVaultIntegrationCert } 
    Remove-PSSession -Session $domainAdminSession
    return $applicationGroup;
}

function Invoke-GivenCommand {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Command to be run")]
        [string]$Command,
        [Parameter(Mandatory = $false, HelpMessage = "Parameters for the command")]
        [hashtable]$Parameters,
        [Parameter(Mandatory = $false, HelpMessage = "Max Retry Count")]
        [int]$MaxRetryCount = 3,
        [Parameter(Mandatory = $false, HelpMessage = "Retry duration")]
        [int]$RetryDuration = 300
    )

    $ErrorActionPreference = 'Stop'

    $currentRetry = 0;
    $success = $false;
    do {
        try {
            Write-Verbose -Message ("Started to execute [$Command] at {0} time(s) " -f ($currentRetry + 1))
            if ($Parameters -ne $null -and $Parameters.Count -gt 0) {
                & $Command @parameters
            }
            else {
                & $Command
            }
            $success = $true;
            Write-Verbose -Message ("Completed execution of [$Command] at {0} time(s) " -f ($currentRetry + 1))
        }
        catch [System.Exception] {
            Write-Verbose -Message ("Failed to execute [$Command] at {0} time(s) " -f ($currentRetry + 1))
            if ($currentRetry -ge $MaxRetryCount) {
                $message = "Can not execute [$Command] command. The error: " + $_.Exception.ToString();
                throw $message;
            }
            else {
                $message = ("Can not execute [$Command] command at {0} time(s). Will retry. The error: " -f ($currentRetry + 1)) + $_.Exception.ToString();
                Write-Warning -Message $message
                Start-Sleep -s $RetryDuration;
            }
            $currentRetry++;
        }

    } while (!$success);
}

function Invoke-GivenCommandWithReturnValue {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Command to be run")]
        [string]$Command,
        [Parameter(Mandatory = $false, HelpMessage = "Parameters for the command")]
        [hashtable]$Parameters,
        [Parameter(Mandatory = $false, HelpMessage = "Max Retry Count")]
        [int]$MaxRetryCount = 3,
        [Parameter(Mandatory = $false, HelpMessage = "Retry duration")]
        [int]$RetryDuration = 300
    )
    $currentRetry = 0;
    $success = $false;
    do {
        try {
            Write-Host ("Started to execute [$Command] at {0} time(s) " -f ($currentRetry + 1))
            if ($Parameters -ne $null -and $Parameters.Count -gt 0) {
                $returnVal = & $Command @parameters
            }
            else {
                $returnVal = & $Command
            }
            $success = $true;
            Write-Host ("Completed execution of [$Command] at {0} time(s) " -f ($currentRetry + 1))
        }
        catch [System.Exception] {
            Write-Host ("Failed to execute [$Command] at {0} time(s) " -f ($currentRetry + 1))
            if ($currentRetry -ge $MaxRetryCount) {
                $message = "Can not execute [$Command] command. The error: " + $_.Exception.ToString();
                throw $message;
            }
            else {
                $message = ("Can not execute [$Command] command at {0} time(s). Will retry. The error: " -f ($currentRetry + 1)) + $_.Exception.ToString();
                Write-Warning -Message $message
                Start-Sleep -s $RetryDuration;
            }
            $currentRetry++;
        }

    } while (!$success);

    return $returnVal
}

function Test-AzurestackAdminCredential {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $true, HelpMessage = "Credential object of Azure Stack")]
        [PSCredential]$azCredential = "AzureStack",
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Admin Arm Endpoint")]
        [string]$ArmEndpoint
    )
    $success = $false
    try {
        Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -azCredential $azCredential -ArmEndpoint $ArmEndpoint | Out-Null
        try {
            # the cmdlet still report error with SilentlyContinue, so use try and catch here.
            $subscription = Get-AzureRmSubscription -SubscriptionName "Default Provider Subscription" -ErrorAction SilentlyContinue
        }
        catch {
        }
        
        if ($subscription -and $subscription.SubscriptionId) {
            $success = $true
        }
        else {
            Write-Verbose -Message ("Login successful. Looks like there is no Subscription for account: {0}. Using {1} Admin 
            URL and {2} DirectoryTenantID  " -f $azCredential.UserName, $ArmEndpoint, $DirectoryTenantID) -Verbose
        }
    }
    catch {
        Write-Verbose -Message ("Cannot login with account: {0}. Using {1} Admin URL and {2} DirectoryTenantID" `
                -f $azCredential.UserName, $ArmEndpoint, $DirectoryTenantID) -Verbose
        Write-Verbose -Message ("Errors are " + $_.ToString()) -Verbose
        $success = $false
    }
    return $success
}

function Test-PIRImage {
    param(
        [parameter(Mandatory = $true)]
        [string]$location,
        [parameter(Mandatory = $true)]
        [string]$publisherName,
        [parameter(Mandatory = $true)]
        [string]$offer,
        [parameter(Mandatory = $true)]
        [string]$skus,
        [parameter(Mandatory = $false)]
        [string]$version,
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Deployment Credentials")]
        [System.Management.Automation.PSCredential]$AzCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack ArmEndpoint")]
        [string]$ArmEndpoint        
    )
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -azCredential $AzCredential -ArmEndpoint $ArmEndpoint | Out-Null
    $images = Get-AzureRmVMImage -Location $location -PublisherName $publisherName -Offer $offer -Skus $skus -ErrorAction SilentlyContinue
    
    if ( -not ([string]::IsNullOrEmpty($version) -or $version -eq "latest")) {
        $images = $images | Where-Object Version -eq $version
    }
    $images.Count -gt 0
}


function Test-NamespaceExistance {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $true, HelpMessage = "Credential object of Azure Stack")]
        [PSCredential]$azCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Namespace of the Azure provider")]
        [string]$namespace,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Admin Arm Endpoint")]
        [string]$ArmEndpoint        
    )
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -azCredential $azCredential -ArmEndpoint $ArmEndpoint | Out-Null
    $providernamespace = Get-AzureRMResourceProvider -ListAvailable | Where-Object { $_.ProviderNamespace -eq $namespace }
    if ($providernamespace) {
        return $true
    }
    else {
        return $false
    }
}

function Trace-DeploymentInternal {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Deployment GUID")]
        [string]$DeploymentGUID,
        [Parameter(Mandatory = $true, HelpMessage = "Start time")]
        [System.DateTimeOffset]$StartTime,
        [Parameter(Mandatory = $false, HelpMessage = "End time")]
        [System.DateTimeOffset]$EndTime = [System.DateTimeOffset]::Now,
        [Parameter(Mandatory = $true, HelpMessage = "Status")]
        [string]$Status,
        [Parameter(Mandatory = $true, HelpMessage = "Step")]
        [string]$Step,
        [Parameter(Mandatory = $true, HelpMessage = "Filter to select files from path")]
        [string]$LogMessage,
        [Parameter(Mandatory = $false, HelpMessage = "Trace level")]
        $TraceLevel = 'Info',
        [Parameter(Mandatory = $false, HelpMessage = "Trace level")]
        $TraceName
    )
    Trace-Deployment -DeploymentGUID $deploymentGUID -Type "ARM" -RoleName $($TraceName + "Provider") -Step $step `
        -TraceLevel $TraceLevel -StartTime $StartTime -EndTime $EndTime -Status $Status -LogMessage $LogMessage
}

function Send-FilesToBlobStorage {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Path of files to upload")]
        [string]$path,
        [Parameter(Mandatory = $true, HelpMessage = "Resource group name")]
        [string]$resourceGroupName,
        [Parameter(Mandatory = $true, HelpMessage = "Storage account name")]
        [string]$storageAccountName,
        [Parameter(Mandatory = $true, HelpMessage = "Storage container name")]
        [string]$storageContainerName,
        [Parameter(Mandatory = $false, HelpMessage = "Filter to select files from path")]
        [string]$filter = "*",
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String] $ArmEndpoint,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string] $DirectoryTenantID,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [pscredential] $AzCredential
    )
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $azCredential | Out-Null

    $blobs = @()

    # Resource group
    $location = (Get-AzureRMLocation)[0].Location        
    $resourceGroup = Get-AzureRmResourceGroup -Name $resourceGroupName -Location $location
    Write-Verbose -Message "Resource Group: $($resourceGroup.ResourceGroupName)" -Verbose
    $StorageObject = Get-AzureRmResource -ResourceType "Microsoft.Storage/storageAccounts" -Name $storageAccountName
    if ( !$StorageObject ) {
        $storageAccount = New-AzureRmStorageAccount -ResourceGroupName $resourceGroupName -StorageAccountName $storageAccountName -Location $location -Type Standard_LRS
        Write-Verbose -Message "New Storage account: $($storageAccount.StorageAccountName) created" -Verbose
    }
    Write-Verbose -Message "Using Storage account: $storageAccountName" -Verbose

    Set-AzureRmCurrentStorageAccount -ResourceGroupName $resourceGroupName -StorageAccountName $storageAccountName | Out-Null

    # Blob storage container
    $storageContainer = Get-AzureStorageContainer -Name $storageContainerName -ErrorAction SilentlyContinue
    if (-not $storageContainer) {
        $storageContainer = New-AzureStorageContainer -Name $storageContainerName -Permission Container -ErrorAction Stop
    }
    Write-Verbose -Message "Storage container: $($storageContainer.Name)" -Verbose

    $sourceFiles = Get-ChildItem -Path $path -Filter $filter -File -Recurse
    foreach ($sourceFile in $sourceFiles) {
        Write-Verbose -Message "Uploading file $sourceFile to storage container $($storageContainer.Name)" -Verbose
        $blob = Set-AzureStorageBlobContent -File $sourceFile.FullName -Container $storageContainerName -Force
        $blobs += $blob
    }

    return $blobs
}

function Remove-FilesToBlobStorageContainer {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Resource group name")]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, HelpMessage = "Storage account name")]
        [string]$StorageAccountName,
        [Parameter(Mandatory = $true, HelpMessage = "Storage container name")]
        [string]$StorageContainerName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String] $ArmEndpoint,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string] $DirectoryTenantID,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [pscredential] $AzCredential
    )
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $azCredential | Out-Null
    $storageAccount = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ErrorAction SilentlyContinue
    if ($storageAccount) {
        Set-AzureRmCurrentStorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName | Out-Null
        Get-AzureStorageContainer -Name $StorageContainerName -ErrorAction SilentlyContinue | Remove-AzureStorageContainer -Force 
    }
}

function Test-TemplateFile {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Template file path to be tested")]
        [string]$path
    )
    try {
        Get-Content -Path $path -Raw | ConvertFrom-Json | Out-Null
    }
    catch {
        $err = "Cannot parse JSON template file '$path'.Verify ANSI encoding, no /*comments*/, and valid JSON syntax.`r`nException: $($_.Exception.Message)"
        throw New-Object System.ArgumentException($err, $_.Exception)
    }
}

function Register-ResourceProviderNamespace {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Provider Namespace")]
        [string]$namespace
    )

    $maxRetryCount = 60
    $currentRetryCount = 0
    $duration = 20
    $registrationSuccess = $false   
    Write-Verbose -Verbose -Message "Register resource provider: $namespace"    
    while ($currentRetryCount -lt $maxRetryCount) {
        # workaround for ARM cache refresh
        try {
            Register-AzureRmResourceProvider -ProviderNamespace $namespace
            if ((Get-AzureRmResourceProvider -ListAvailable | Where-Object { $_.ProviderNamespace -eq $namespace }).RegistrationState -ieq "Registered") {
                Write-Verbose -Verbose -Message  "Resource Provider for $namespace is registered"
                $registrationSuccess = $true
                break;
            }
            else {
                Start-Sleep -Seconds $duration
                Write-Warning -Message ("Waiting for current state {0} of Resource Provider {1} to Registered for {2} seconds" -f ($(Get-AzureRmResourceProvider -ListAvailable | Where-Object { $_.ProviderNamespace -eq $namespace }).RegistrationState, $namespace, (($currentRetryCount + 1) * $duration)))
            }
        }
        catch {
            $cacheWaitTime = 60
            Write-Warning "Register resource provider: $namespace Error:$($_.Exception.Message) .Waiting for $cacheWaitTime and retrying..."
            Start-Sleep -Seconds $cacheWaitTime
           
        }             
        $currentRetryCount++
    }
    if (-not $registrationSuccess) {
        throw "Resource Provider for $namespace cannot be registered"
    }
}

function Get-AzureRmProviderRegistrationInfo {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Resource Provider path")]
        $azResourceProvider
    )
    $rpInfo = [PSCustomObject]@{
        Name                = $azResourceProvider.Name
        DisplayName         = $azResourceProvider.Properties.DisplayName
        ManifestEndpointUri = $azResourceProvider.Properties.ManifestEndpoint.EndpointUri
        Location            = $azResourceProvider.Location
        Enabled             = $azResourceProvider.Properties.Enabled
    }
    return $rpInfo
}

function Read-InputBoxDialog {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Message to be displayed on the Text box")]
        [string]$Message,
        [Parameter(Mandatory = $true, HelpMessage = "Title of the text box")]
        [string]$WindowTitle,
        [Parameter(Mandatory = $false, HelpMessage = "Any default Text to be filled in the text box")]
        [string]$DefaultText
    )
    Add-Type -AssemblyName Microsoft.VisualBasic
    return [Microsoft.VisualBasic.Interaction]::InputBox($Message, $WindowTitle, $DefaultText)
}

function Test-Credential {
    param(
        [parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Management.Automation.PSCredential]$credential
    )
    begin {
        $context = 'Domain'
        Add-Type -assemblyname system.DirectoryServices.accountmanagement
        $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::$context)
    }
    process {
        $value = $DS.ValidateCredentials($credential.UserName, $credential.GetNetworkCredential().password, [System.DirectoryServices.AccountManagement.ContextOptions]::SimpleBind)
        return [bool]$value
    }
}

Function Test-VMCredential {

    param(
        [parameter(Mandatory = $true)]
        [string]$UserName,
        [parameter(Mandatory = $true)]
        [string]$Password
    )

    if ($UserName -match '[^a-zA-Z0-9]' -or $UserName.length -gt 64 -or $UserName.length -lt 2) {
        $s = "Given Username $UserName does not meet the requirements of:" + [Environment]::NewLine + "1) Having only numbers or upper and lower case letters." + [Environment]::NewLine + "2) Length between 2 and 64 characters"
        Write-Verbose $s -Verbose
        return $false
    }

    $upper = [regex]"[A-Z]"
    $lower = [regex]"[a-z]"
    $number = [regex]"[0-9]"
    #Special is "none of the above"
    $special = [regex]"[^a-zA-Z0-9]"
    [bool]$return = $true
    # Check the length.
    if ($Password.length -lt 8) {
        $return = $false
    }

    # Check for minimum number of occurrences.
    $checks = 0
    $checks += If ($upper.Matches($Password).Count -gt 0 ) { 1 } Else { 0 }
    $checks += If ($lower.Matches($Password).Count -gt 0) { 1 } Else { 0 }
    $checks += If ($number.Matches($Password).Count -gt 0) { 1 } Else { 0 }
    $checks += If ($special.Matches($Password).Count -gt 0) { 1 } Else { 0 }
    if ($checks -lt 3) {
        $return = $false
    }

    # Passed all checks.
    if (!$return) {
        $s = "Given Password does not meet the requirements of" + [Environment]::NewLine + "1) Having at least one upper case letter, one lower case letter, one number and one special character." + [Environment]::NewLine + "2) Length between 8 and 64 characters"
        Write-Verbose $s -Verbose
        return $false
    }
    $true
}

function Test-DependencyFilesLocalPath {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Path to dependency files")]
        [string]$Path
    )

    if (!$Path) {
        return $true
    }
    $valid = Test-Path $Path
    if (!$valid) {
        $s = "The provided local path to the dependency files does not exist."
        Write-Verbose $s -Verbose
        return $false
    }
    return $true
}


function Remove-ResourceProvider {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "ResourceGroupName")]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, HelpMessage = "Adapter TraceName")]
        [string]$TraceName,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Deployment ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Deployment Credentials")]
        [System.Management.Automation.PSCredential]$AzCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack ArmEndpoint")]
        [string]$ArmEndpoint,
        [Parameter(Mandatory = $false, HelpMessage = "Whether the last action of removing resource group will be run as a job.")]
        [Switch]$AsJob
    )
    
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -azCredential $AzCredential -ArmEndpoint $ArmEndpoint | Out-Null

    # Cleanup DNS record before removing the resource group    
    $VmName = $TraceName
    $DBAdapterDNSZoneNamePrefix = "dbadapter"
    $Location = (Get-AzureRMLocation)[0].Location       
    $DBAdapterDNSZoneResourceGroupName = Get-DNSZoneResourceGroupName -Location $Location -DBAdapterDNSZoneNamePrefix $DBAdapterDNSZoneNamePrefix
    $DBAdapterDNSZoneResourceGroup = Get-AzureRmResourceGroup -Name $DBAdapterDNSZoneResourceGroupName -ErrorAction SilentlyContinue
    if ($DBAdapterDNSZoneResourceGroup) {
        Write-Verbose "$DBAdapterDNSZoneResourceGroupName ResourceGroup is found. Cleaning up $TraceName DNS Entries." -Verbose
        $zone = Get-AzureRmDnsZone -ResourceGroupName $DBAdapterDNSZoneResourceGroupName | Where-Object { $_.Name -like "$DBAdapterDNSZoneNamePrefix.*" }
        if ($zone) {
            $dnsRecord = Get-AzureRmDnsRecordSet -Name $VmName -ResourceGroupName $DBAdapterDNSZoneResourceGroupName -ZoneName $zone.Name `
                -RecordType A -ErrorAction SilentlyContinue
            if ($dnsRecord) {
                Remove-AzureRmDnsRecordSet -Name $VmName -ResourceGroupName $DBAdapterDNSZoneResourceGroupName -ZoneName $zone.Name -RecordType A
            }

            # Check remaining record sets (ignoring default '@' sets)
            $remainingSets = Get-AzureRmDnsRecordSet -ResourceGroupName $DBAdapterDNSZoneResourceGroupName `
                -ZoneName $zone.Name -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "@" }
            if (-not $remainingSets) {
                Write-Verbose "No DNS entries remain under $DBAdapterDNSZoneResourceGroupName. Hence deleting the DNS Zone and Resource Group." -Verbose
                # No remaining record sets, clean up resource group
                Remove-AzureRmResourceGroup -Force -Verbose -Name $DBAdapterDNSZoneResourceGroupName
            }
        }
    }
    $rg = Get-AzureRmResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
    if (!$rg) {
        Write-Verbose "$TraceName RP ResourceGroup $ResourceGroupName is not found." -Verbose
        return
    }
    Write-Verbose "$TraceName RP ResourceGroup $ResourceGroupName is found. Attempting to remove it. Immutable logs storage account can be removed after 1 day." -Verbose
    if ($AsJob) {
        Remove-AzureRmResourceGroup -Force -Verbose -Name $ResourceGroupName -AsJob
    }
    else {
        Remove-AzureRmResourceGroup -Force -Verbose -Name $ResourceGroupName
    }

    Delete-RegistrationToHRP -DirectoryTenantID $DirectoryTenantID -ServiceAdminCredential $AzCredential -ArmEndpoint $ArmEndpoint -DBAdapterName $TraceName
}

function Get-DatabaseAdapterDNSZoneName {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "The AzureStack deployment domain name")]
        [string]$DomainName,

        [Parameter(Mandatory = $true, HelpMessage = "Location of resource group")]
        [string]$Location,

        [Parameter(Mandatory = $true, HelpMessage = "DBAdapter DNS Zone prefix")]
        [string]$DBAdapterDNSZoneNamePrefix
    )

    ("{0}.{1}.{2}") -f $DBAdapterDNSZoneNamePrefix.ToLower(), $Location, $DomainName
}

function Get-DatabaseAdapterDNSZone {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "The AzureStack deployment domain name")]
        [string]$DomainName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String] $ArmEndpoint,
        [Parameter(Mandatory = $true, HelpMessage = "location name for the resource group")]
        [string]$Location,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string] $DirectoryTenantID,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [pscredential] $AzCredential,
        [Parameter(Mandatory = $true, HelpMessage = "DBAdapter DNS Zone prefix")]
        [string]$DBAdapterDNSZoneNamePrefix,
        [Parameter(Mandatory = $true, HelpMessage = "DBAdapter DNS Zone Resource Group Name")]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, HelpMessage = "Tags for resource group")]
        [hashtable]$Tags
    )
    
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $AzCredential | Out-Null 
    #Create DNS zone and record for registration
    if (-not (Get-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction SilentlyContinue)) {
        New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -Tag $Tags | Out-Null
    }

    $rg = Get-AzureRmResourceGroup -Name $ResourceGroupName
    $zoneName = Get-DatabaseAdapterDNSZoneName -DomainName $DomainName -Location $rg.Location -DBAdapterDNSZoneNamePrefix $DBAdapterDNSZoneNamePrefix
    
    if (-not (Get-AzureRmDnsZone -ResourceGroupName $ResourceGroupName -Name $zoneName -ErrorAction SilentlyContinue)) {
        $zone = New-AzureRmDnsZone -ResourceGroupName $ResourceGroupName -Name $zoneName
    }
    $zone = Get-AzureRmDnsZone -ResourceGroupName $ResourceGroupName -Name $zoneName

    return $zone
}

function Get-AzureStackAdminSubTokenHeader {
    param (
        [parameter(mandatory = $true, HelpMessage = "Name of the Azure Stack Environment")]
        [string] $EnvironmentName,
	
        [parameter(mandatory = $true, HelpMessage = "TenantID of Identity Tenant")]
        [string] $tenantID,

        [parameter(HelpMessage = "Credentials to retrieve token header for")]
        [System.Management.Automation.PSCredential] $azureStackCredentials,

        [parameter(HelpMessage = "Name of the Administrator subscription")]
        [string] $subscriptionName = "Default Provider Subscription"
    )
    
    $azureStackEnvironment = Get-AzureRmEnvironment -Name $EnvironmentName -ErrorAction SilentlyContinue
    if ($azureStackEnvironment -ne $null) {
        $ARMEndpoint = $azureStackEnvironment.ResourceManagerUrl
    }
    else {
        Write-Error "The Azure Stack Admin environment with the name $EnvironmentName does not exist. Create one with Add-AzureRmEnvironment." -ErrorAction Stop
    }

    if (-not $azureStackCredentials) {
        $azureStackCredentials = Get-Credential
    }

    try {
        Invoke-RestMethod -Method Get -Uri "$($ARMEndpoint.ToString().TrimEnd('/'))/metadata/endpoints?api-version=2015-01-01" -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error "The specified ARM endpoint: $ArmEndpoint is not valid for this environment. Please make sure you are using the correct admin ARM endpoint for this environment." -ErrorAction Stop
    }

    $authority = $azureStackEnvironment.ActiveDirectoryAuthority
    $activeDirectoryServiceEndpointResourceId = $azureStackEnvironment.ActiveDirectoryServiceEndpointResourceId

    Login-AzureRmAccount -EnvironmentName $EnvironmentName -TenantId $tenantID -Credential $azureStackCredentials | Out-Null

    try {
        $subscription = Get-AzureRmSubscription -SubscriptionName "Default Provider Subscription" -SubscriptionName $subscriptionName 
    }
    catch {
        Write-Error "Verify that the login credentials are for the administrator and that the specified ARM endpoint: $ArmEndpoint is the valid administrator ARM endpoint for this environment." -ErrorAction Stop
    }

    $subscription | Select-AzureRmSubscription | Out-Null

    $powershellClientId = "0a7bdc5c-7b57-40be-9939-d4c5fc7cd417"

    $savedWarningPreference = $WarningPreference
    $WarningPreference = 'SilentlyContinue' 

    $adminToken = Get-AzureStackToken `
        -Authority $authority `
        -Resource $activeDirectoryServiceEndpointResourceId `
        -AadTenantId $tenantID `
        -ClientId $powershellClientId `
        -Credential $azureStackCredentials 

    $WarningPreference = $savedWarningPreference

    $headers = @{ Authorization = ("Bearer $adminToken") }
    
    return $subscription.SubscriptionId, $headers
}

function Get-ThumbprintOfRootCertOnEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String] $URL
    )

    $WebRequest = [Net.WebRequest]::CreateHttp($URL)
    $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
    #Request website
    try { $Response = $WebRequest.GetResponse() }
    catch {}
    #Creates Certificate
    $Certificate = $WebRequest.ServicePoint.Certificate.Handle
    #Build chain
    $chain.Build($Certificate) | Out-Null
    $rootThumbprint = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint
    $s = "The thumbprint of root cert on $URL is $rootThumbprint"
    Write-Verbose $s -Verbose

    return $rootThumbprint
}

function Test-SSLCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CertificatePath,
        [Parameter(Mandatory = $true)]
        [SecureString]$DefaultSSLCertificatePassword,
        [Parameter(Mandatory = $true, HelpMessage = "The AzureStack deployment domain name")]
        [string]$DomainName,
        [Parameter(Mandatory = $true, HelpMessage = "Name of the RP VM")]
        [string]$RPVMName,
        [Parameter(Mandatory = $false)]
        [bool] $WarnOnSelfSigned = $true,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String] $ArmEndpoint,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string] $DirectoryTenantID,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [pscredential] $aadCredential
    )
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $aadCredential | Out-Null

    # setting KeyUsage values
    $keyUsageDS = "DigitalSignature"
    $keyUsageKE = "KeyEncipherment"

    $DBAdapterDNSZoneNamePrefix = "dbadapter"
    $Location = (Get-AzureRMLocation)[0].Location         
    $ExpectedDomainFQDN = ("{0}.{1}.{2}") -f $DBAdapterDNSZoneNamePrefix.ToLower(), $Location, $DomainName

    $pfxFile = Get-ChildItem -Path $CertificatePath -Filter '*.pfx' | ForEach-Object FullName
    if (-not $pfxFile) {
        throw "No file with .pfx extension exists in '$CertificatePath' location"
    }
    if ($pfxFile.Count -ne 1) {
        throw "More than one file with .pfx extension exists in '$CertificatePath' location"
    }

    # Check pfx file name is valid
    $alphanumericWithUnderscoreDotDashRegex = "^[a-zA-Z0-9_.-]+$"
    $pfxFileName = Get-ChildItem -Path $CertificatePath -Filter '*.pfx' | ForEach-Object Name
    if (-not ($pfxFileName -match $alphanumericWithUnderscoreDotDashRegex)) {
        throw "Invalid pfx file name, file name can contain alphanumeric characters, dot, dash, and underscore. Please rename the file and retry deployment. Saw: '$pfxFileName'"
    }

    try {
        $pfx = Get-PfxData –FilePath $pfxFile -Password $DefaultSSLCertificatePassword
    }
    catch {
        [string]$exceptionMessage = $_.Exception.Message
        # 0x8007000d error code for invalid cert data
        if ($exceptionMessage.Contains("0x8007000d")) {
            throw "'$pfxFile' contains invalid certificate data"
        }
        # 0x80070056 error code for invalid password
        elseif ($exceptionMessage.Contains("0x80070056")) {
            throw "Provided password for '$pfxFile' is invalid"
        }
        else {
            throw
        }
    }

    # Get the records between cn="<records>"
    $records = @()
    $records = $pfx.EndEntityCertificates.DnsNameList.Unicode

    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($pfxFile, $DefaultSSLCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)

        $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName

        if ($signatureAlgorithm -eq "sha1RSA") {
            throw "'$pfxFile' uses invalid security algorithm sha1RSA"
        }

        if (-not $cert.HasPrivateKey) {
            throw "'$pfxFile' contains no private key"
        }

        # Check the cert chain - https://docs.microsoft.com/en-us/azure-stack/operator/azure-stack-pki-certs?view=azs-2002#optional-paas-certificates
        # PaaS cert requirement: The certificates that you use for resource providers must have the same root authority as those used for the global Azure Stack Hub endpoints.
        # Check if the cert is issued by Azure Stack Root Cert
        # Create a new chain to store the certificate chain
        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        # Build the certificate chain from the file certificate
        $chain.Build($cert) | Out-Null
        # Return the list of certificates in the chain (the root will be the last one)
        $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint
        Write-Verbose "The thumbprint of root cert on $pfxFile is $root" -Verbose
        # Check if the root cert is the same as global endpoint
        $rootGlobal = Get-ThumbprintOfRootCertOnEndpoint -URL $ArmEndpoint
        if ($root -ne $rootGlobal) {
            Write-Warning -Message "$pfxFile is NOT using the root cert of Global Azure Stack Hub Endpoint" -Verbose
        }
        else {
            Write-Verbose -Message "$pfxFile is using the root cert of Global Azure Stack Hub Endpoint" -Verbose
        }
    }
    finally {
        $cert.Dispose()
    }

    # Check for Self Signed Certs and chain of trust 
    # TODO: Add validation for intermediate authorities
    if (-not $pfx.OtherCertificates) {
        if ($pfx.EndEntityCertificates.Issuer -eq $pfx.EndEntityCertificates.Subject) {
            if ($WarnOnSelfSigned) {
                Write-Warning "Warning: '$pfxFile' is self-signed" -Verbose
            }
        }
        else {
            throw "'$pfxFile' has no chain of trust"
        }
    }

    # Validate KeyUsage should have Digital Signature and Key Encipherment.
    foreach ($extension in $pfx.EndEntityCertificates[0].Extensions) {
        if ($extension.KeyUsages) {
            $keyUsage = $extension.KeyUsages
            break
        }
    }

    if (!(($keyUsage -match $keyUsageDS) -and ($keyUsage -match $keyUsageKE))) {
        throw "'$pfxFile' has invalid key usage, expected Digital Signature and Key Encipherment usages."
    }

    # Validate certificate issue date and expiration date
    $dateNow = Get-Date
    $certIssuedDate = $pfx.EndEntityCertificates[0].NotBefore
    $certExpirationDate = $pfx.EndEntityCertificates[0].NotAfter

    # issue date has to be less than or equal to now, if issued date is greater than today this is an error
    if ($certIssuedDate.Date -gt $dateNow.Date) {
        throw "'$pfxFile' has invalid issued date, issued date has to be less than or equal to today, saw '$certIssuedDate' , now '$dateNow'"
    }

    # expiration date has to be greater than today, or if exp is less than or equal to today this is an error
    if ($certExpirationDate.Date -le $dateNow.Date) {
        throw "'$pfxFile' has expired or is close to expiration. saw: '$certExpirationDate' , now '$dateNow'"
    }

    # Check records for expected domain
    if ($ExpectedDomainFQDN -in $records) {
        Write-Verbose "Expected database provider endpoint domain '$ExpectedDomainFQDN' is included in '$pfxFile' DNS name list" -Verbose
    }
    else {
        # *.<region>.<ExternalFQDN> or *.<ExternalFQDN> or <rpvmname>.<ExternalFQDN>
        if ("*.$ExpectedDomainFQDN" -in $records -or "*$($ExpectedDomainFQDN.Substring($ExpectedDomainFQDN.IndexOf('.')))" -in $records ) {
            Write-Warning "Warning: '$pfxFile' is a wildcard certificate" -Verbose
        }
        elseif ("$RPVMName.$ExpectedDomainFQDN" -in $records) {
            Write-Verbose "'$pfxFile' is a single site or multiple site certificate" -Verbose
        }
        else {
            throw "Expected database provider endpoint domain '$ExpectedDomainFQDN' is not included in '$pfxFile' DNS name list"
        }
    }
}

function Set-TrustedHosts {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "The Ip of privileged endpoint")]
        [string]$PrivilegedEndpoint
    )
    $currentTrustedRoot = (Get-Item wsman:\localhost\Client\TrustedHosts).Value
    if ([string]::IsNullOrEmpty($currentTrustedRoot) -or (-not $currentTrustedRoot.Contains($PrivilegedEndpoint))) {
        Write-Verbose -Message "Current trusted root: $currentTrustedRoot" -Verbose
        $allowAllHost = $false;
        foreach ($trustHost in $currentTrustedRoot.Split(",")) {
            if ($trustHost -eq "*") {
                $allowAllHost = $true;
                break;
            }
        }

        if (-not $allowAllHost) {
            Set-Item wsman:\localhost\Client\TrustedHosts -Value "$currentTrustedRoot, $PrivilegedEndpoint" -Force
        }
    }
}

function Get-AzureStackStampInfo {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "The Ip of privileged endpoint")]
        [string]$PrivilegedEndpoint,

        [Parameter(Mandatory = $true, HelpMessage = "Azure Stack cloudsadmin domain account credential.")]
        [PSCredential]$CloudAdminCredential
    )

    Set-TrustedHosts -PrivilegedEndpoint $PrivilegedEndpoint
    try {
        $domainAdminSession = New-PSSession -ComputerName $PrivilegedEndpoint -Credential $CloudAdminCredential -configurationname privilegedendpoint  -Verbose -ErrorAction Stop
        if ($domainAdminSession -ne $null) {
            Invoke-Command -Session $domainAdminSession -Verbose -ErrorAction Stop  -ScriptBlock { Get-AzureStackStampInformation } 
        }
    }
    catch {
        throw "Issue in connecting to the privilegedEndpoint $PrivilegedEndpoint with $($CloudAdminCredential.UserName). $($_.Exception.Message)"
    }
    finally {
        if ($domainAdminSession -ne $null) {
            Remove-PSSession $domainAdminSession -Verbose
        }
    }
}

function Test-AzureStackStampInfo {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "The Ip of privileged endpoint")]
        [string]$PrivilegedEndpoint,

        [Parameter(Mandatory = $true, HelpMessage = "Azure Stack cloudsadmin domain account credential.")]
        [PSCredential]$CloudAdminCredential
    )
    try {
        $info = Get-AzureStackStampInfo -PrivilegedEndpoint $PrivilegedEndpoint -CloudAdminCredential $CloudAdminCredential        
        return ( -not [String]::IsNullOrEmpty($info.AADTenantID))
    }
    catch {
        return $false
    }
}

function Initialize-ClientCertificate([string] $Subject) {
    $params = @{
        CertStoreLocation = 'Cert:\LocalMachine\My'
        DnsName           = $Subject
        FriendlyName      = "$Subject"
        KeyLength         = 2048
        KeyUsageProperty  = 'All'
        KeyExportPolicy   = 'Exportable'
        Provider          = 'Microsoft Enhanced Cryptographic Provider v1.0'
        HashAlgorithm     = 'SHA256'
    }

    $cert = New-SelfSignedCertificate @params -ErrorAction Stop
    Write-Verbose "Generated new certificate '$($cert.Subject)' ($($cert.Thumbprint))." -Verbose
    return $cert
}
function New-ResourceProviderResourceGroup {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Resource group name for Resource provider")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true, HelpMessage = "Region name for the resource group")]
        [string]$RegionName,

        [Parameter(Mandatory = $true, HelpMessage = "Tags for resource group")]
        [hashtable]$Tags
    )

    # New the resource group
    $resourceGroupObj = Get-AzureRmResourceGroup -Name $ResourceGroupName -Location $RegionName -ErrorAction SilentlyContinue
    if ($resourceGroupObj) {
        Write-Verbose "RP ResourceGroup $ResourceGroupName is found. Attempting to remove it." -Verbose
        Remove-AzureRmResourceGroup -Force -Verbose -Name $ResourceGroupName
    }
    
    New-AzureRmResourceGroup -Name $ResourceGroupName -Location $RegionName -Force -Tag $Tags    
}

# Return True if a new resource group needs to be created.
# Return False if there is a existing resource group that will be reused (for the restore operation)
# Throw an error if the exisiting resource group cannot be re-used.
function Test-ResourceProviderResourceGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Resource group name for Resource provider")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true, HelpMessage = "Region name for the resource group")]
        [string]$RegionName,

        [Parameter(Mandatory = $true, HelpMessage = "Tags for resource group")]
        [hashtable]$Tags
    )

    # Get the resource group
    $resourceGroupObj = Get-AzureRmResourceGroup -Name $ResourceGroupName -Location $RegionName -ErrorAction SilentlyContinue
    if (-not $resourceGroupObj) {
        # if the reosurce group does not exist, return true.
        return $true
    }

    $currentTags = $resourceGroupObj.Tags
    if ((-not $currentTags) -or (-not $currentTags.Version) -or ($currentTags.Version -ne $Tags.Version)) {
        Write-Error -Message "There is a conflicting resource group with name $ResourceGroupName, deployment will stop."
    }
    # If the Restore tag is set, it means the resource group will be reused for restore, return false
    if ($currentTags.Restore -eq "True") {
        # remove the Restore tag
        Set-AzureRmResourceGroup -Name $ResourceGroupName -Tag $Tags | Out-Null
        return $false
    }
    else {
        $currentRpVM = Get-AzureRmVM -ResourceGroupName $ResourceGroupName | Where-Object { $_.Tags.Version -eq $currentTags.Version };
        if (-not $currentRpVM) {
            Write-Warning -Message "Could not find resource provider VM for db adapter in resource group: $ResourceGroupName , Version $($Tags.Version)" -Verbose
            return $true
        }
        Write-Error -Message "The resource provider is already deployed, please use update script to upgrade to new version."
    }
}
function Get-DNSZoneResourceGroupName {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "DBAdapter DNS Zone Name Prefix")]
        [string]$DBAdapterDNSZoneNamePrefix = "dbadapter",

        [Parameter(Mandatory = $true, HelpMessage = "location name for the resource group")]
        [string]$Location
    )

    return ("system.{0}.{1}.dns") -f $Location, $DBAdapterDNSZoneNamePrefix
}

function New-DNSZoneAndRecord {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Resource group name which contains the public Ip")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true, HelpMessage = "Domain Name")]
        [string]$DomainName,

        [Parameter(Mandatory = $true, HelpMessage = "location name for the resource group")]
        [string]$Location,

        [Parameter(Mandatory = $true, HelpMessage = "The VM name")]
        [string]$VmName,

        [Parameter(Mandatory = $true, HelpMessage = "The version")]
        [string]$Version,

        [Parameter(Mandatory = $true, HelpMessage = "The trace name")]
        [string]$TraceName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String] $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string] $DirectoryTenantID,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [pscredential] $azCredential
    )
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $AzCredential | Out-Null 

    $Tags = @{"Version" = $Version; "ProviderName" = $TraceName; "Role" = "DNSZoneResourceGroup"; "Category" = "Foundation" }
    $DBAdapterDNSZoneNamePrefix = "dbadapter"
    $DBAdapterDNSZoneResourceGroupName = Get-DNSZoneResourceGroupName -Location $Location -DBAdapterDNSZoneNamePrefix $DBAdapterDNSZoneNamePrefix
    $zone = Get-DatabaseAdapterDNSZone -DomainName $DomainName -Location $Location -Tags $Tags -ResourceGroupName $DBAdapterDNSZoneResourceGroupName -DBAdapterDNSZoneNamePrefix $DBAdapterDNSZoneNamePrefix -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $AzCredential
    
    $dnsRecord = Get-AzureRmDnsRecordSet -Name $TraceName -ResourceGroupName $DBAdapterDNSZoneResourceGroupName -ZoneName $zone.Name -RecordType A -ErrorAction SilentlyContinue
    if ($dnsRecord) {
        Remove-AzureRmDnsRecordSet -Name $TraceName -ResourceGroupName $DBAdapterDNSZoneResourceGroupName -ZoneName $zone.Name -RecordType A | Out-Null
    }

    $azPublicIpAddresses = @(Get-AzureRmPublicIpAddress -ResourceGroupName $ResourceGroupName)
    $azPublicIpAddress = $azPublicIpAddresses | Where-Object {
        $_.Tag.ProviderName -eq $TraceName -and $_.Tag.Category -eq 'NonFoundation'
    }
    $rs = New-AzureRmDnsRecordSet -Name $TraceName -RecordType A -Zone $zone -Ttl 3600
    Add-AzureRmDnsRecordConfig -RecordSet $rs -Ipv4Address $azPublicIpAddress.IpAddress -ErrorAction Stop | Out-Null
    Set-AzureRmDnsRecordSet -RecordSet $rs -ErrorAction Stop | Out-Null

    return $zone
}

function New-DNSZoneAndRecordWithRetries {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Resource group name which contains the public Ip")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true, HelpMessage = "Domain Name")]
        [string]$DomainName,

        [Parameter(Mandatory = $true, HelpMessage = "location name for the resource group")]
        [string]$Location,

        [Parameter(Mandatory = $true, HelpMessage = "The VM name")]
        [string]$VmName,

        [Parameter(Mandatory = $true, HelpMessage = "The version")]
        [string]$Version,

        [Parameter(Mandatory = $true, HelpMessage = "The trace name")]
        [string]$TraceName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String] $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string] $DirectoryTenantID,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [pscredential] $azCredential
    )
    
    $paramsNewDNSZoneAndRecord = @{
        'ResourceGroupName' = $ResourceGroupName
        'DomainName'        = $DomainName
        'Location'          = $Location
        'VmName'            = $VmName
        'Version'           = $Version
        'TraceName'         = $TraceName
        'ArmEndpoint'       = $ArmEndpoint
        'DirectoryTenantID' = $DirectoryTenantID
        'azCredential'      = $azCredential
    }
    
    return Invoke-GivenCommandWithReturnValue -Command "New-DNSZoneAndRecord" `
        -Parameters $paramsNewDNSZoneAndRecord `
        -MaxRetryCount 3 `
        -RetryDuration 10

}

function Remove-DNSRecord {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Resource group name which contains the public Ip")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true, HelpMessage = "Domain Name")]
        [string]$DomainName,

        [Parameter(Mandatory = $true, HelpMessage = "location name for the resource group")]
        [string]$Location,

        [Parameter(Mandatory = $true, HelpMessage = "The VM name")]
        [string]$VmName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String] $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string] $DirectoryTenantID,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [pscredential] $azCredential
    )
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $AzCredential | Out-Null 
    $DBAdapterDNSZoneNamePrefix = "dbadapter"
    $DBAdapterDNSZoneResourceGroupName = Get-DNSZoneResourceGroupName -Location $Location -DBAdapterDNSZoneNamePrefix $DBAdapterDNSZoneNamePrefix
    $zoneName = Get-DatabaseAdapterDNSZoneName -DomainName $DomainName -Location $Location -DBAdapterDNSZoneNamePrefix $DBAdapterDNSZoneNamePrefix
    $zone = Get-AzureRmDnsZone -ResourceGroupName $ResourceGroupName -Name $zoneName -ErrorAction SilentlyContinue
    if ($zone) {
        $dnsRecord = Get-AzureRmDnsRecordSet -Name $VmName -ResourceGroupName $DBAdapterDNSZoneResourceGroupName -ZoneName $zone.Name -RecordType A -ErrorAction SilentlyContinue
        if ($dnsRecord) {
            Remove-AzureRmDnsRecordSet -Name $VmName -ResourceGroupName $DBAdapterDNSZoneResourceGroupName -ZoneName $zone.Name -RecordType A
        }
    }
}

function Test-ResourceProviderEndpoint {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Resource Provider Endpoint FQDN")]
        [string]$ResourceProviderEndpointFQDN,

        [Parameter(Mandatory = $true, HelpMessage = "Admin Resource Provider Port")]
        [string]$AdminResourceProviderPort,

        [Parameter(Mandatory = $true, HelpMessage = "Tenant Resource Provider Port")]
        [string]$TenantResourceProviderPort,

        [Parameter(Mandatory = $false, HelpMessage = "Admin Extension Port")]
        [string]$AdminExtensionPort,

        [Parameter(Mandatory = $false, HelpMessage = "Tenant Extension Port")]
        [string]$TenantExtensionPort,

        [Parameter(Mandatory = $false, HelpMessage = "Tenant Extension for Admin Port")]
        [string]$TenantExtensionForAdminPort,

        [Parameter(Mandatory = $true, HelpMessage = "Trace name")]
        [string]$TraceName
    )

    # Check if the admin endpoint is responsive
    try {
        $adminEndpointURI = "https://{0}:{1}" -f $ResourceProviderEndpointFQDN, $AdminResourceProviderPort
        Write-Verbose -Message "Check $adminEndpointURI" -Verbose
        Invoke-WebRequest $adminEndpointURI -Headers @{"Cache-Control" = "no-cache" } | Out-Null
    }
    catch {
        $e = $_.Exception
        if ($e.Response -ne $null -and $e.Status.value__ -eq 7) {
            # Expected response received from the endpoint (WebExceptionStatus value 7 = Forbidden)
            Write-Verbose -Message "Microsoft.$TraceName.Admin endpoint is responsive" -Verbose
        }
        else {
            # Did not receive the expected response, throwing error
            Write-Error -Exception $e
            throw "Microsoft.$TraceName.Admin endpoint is not responsive"
        }
    }
    
    # Check if the tenant endpoint is responsive
    try {
        $tenantEndpointURI = "https://{0}:{1}" -f $ResourceProviderEndpointFQDN, $TenantResourceProviderPort
        Write-Verbose -Message "Check $tenantEndpointURI" -Verbose
        Invoke-WebRequest $tenantEndpointURI | Out-Null
    }
    catch {
        $e = $_.Exception
       
        if ($e.Response -ne $null -and $e.Status.value__ -eq 7) {
            # Expected response received from the endpoint (WebExceptionStatus value 7 = Forbidden)
            Write-Verbose -Message "Microsoft.$TraceName endpoint is responsive" -Verbose
        }
        else {
            # Did not receive the expected response, throwing error
            Write-Error -Exception $e
            throw "Microsoft.$TraceName endpoint is not responsive"
        }
    }

    # Check if the admin extension endpoint is responsive   
    if ($AdminExtensionPort) {
        $adminExtensionURI = "https://{0}:{1}" -f $ResourceProviderEndpointFQDN, $AdminExtensionPort
        Write-Verbose -Message "Check $adminExtensionURI" -Verbose
        $response = Invoke-WebRequest $adminExtensionURI
        if ($response -ne $null -and $response.StatusCode -eq 200) {
            Write-Verbose -Message "Microsoft.$TraceName.Admin extension endpoint is responsive" -Verbose
        }
        else {
            # Did not receive the expected response, throwing error
            Write-Error -Exception $e
            throw "Microsoft.$TraceName.Admin extension endpoint is not responsive"
        }
    }

    if ($TenantExtensionPort) {
        $tenantExtensionURI = "https://{0}:{1}" -f $ResourceProviderEndpointFQDN, $TenantExtensionPort
        Write-Verbose -Message "Check $tenantExtensionURI" -Verbose
        $response = Invoke-WebRequest $tenantExtensionURI
        if ($response -ne $null -and $response.StatusCode -eq 200) {
            Write-Verbose -Message "Microsoft.$TraceName.Tenant extension endpoint is responsive" -Verbose
        }
        else {
            # Did not receive the expected response, throwing error
            Write-Error -Exception $e
            throw "Microsoft.$TraceName.Tenant extension endpoint is not responsive"
        }
    }

    if ($TenantExtensionForAdminPort) {
        $tenantExtensionForAdminURI = "https://{0}:{1}" -f $ResourceProviderEndpointFQDN, $TenantExtensionForAdminPort
        Write-Verbose -Message "Check $tenantExtensionForAdminURI" -Verbose
        $response = Invoke-WebRequest $tenantExtensionForAdminURI
        if ($response -ne $null -and $response.StatusCode -eq 200) {
            Write-Verbose -Message "Microsoft.$TraceName.Tenant extension for Admin is responsive" -Verbose
        }
        else {
            # Did not receive the expected response, throwing error
            Write-Error -Exception $e
            throw "Microsoft.$TraceName.Tenant extension for Admin is not responsive"
        }
    }
}

function Remove-ResourceProviderResource {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Resource group name")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true, HelpMessage = "Location of resource group")]
        [string]$Location,

        [Parameter(Mandatory = $true, HelpMessage = "Version of Resource Provider")]
        [string]$Version,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String] $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string] $DirectoryTenantID,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [pscredential] $azCredential,
        
        [Parameter(Mandatory = $false, HelpMessage = "Set this switch remove publicIP")]
        [switch]$removePublicIP
    )
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $AzCredential | Out-Null 
    $resourceGroupObj = Get-AzureRmResourceGroup -ResourceGroupName $ResourceGroupName -Location $Location -ErrorAction SilentlyContinue
    $resourceGroupTagsObj = $resourceGroupObj.Tags

    $resourceProviderResource = Get-AzureRmResource -ResourceGroupName $ResourceGroupName | Where-Object { $_.Tags -ne $null } | Where-Object { $hashtable = $_.Tags; ($hashtable.Version -eq $Version) -and ($hashtable.Category -eq "NonFoundation" ) }
    
    #Remove VM
    $resourceProviderResource | Where-Object ResourceType -eq Microsoft.Compute/virtualMachines | Remove-AzureRmResource -Force -Verbose
    
    #Remove network interface
    $resourceProviderResource | Where-Object ResourceType -eq Microsoft.Network/networkInterfaces | Remove-AzureRmResource -Force -Verbose
    
    #Remove Vnet
    $resourceProviderResource | Where-Object ResourceType -eq Microsoft.Network/virtualNetworks | Remove-AzureRmResource -Force -Verbose

    #Remove security group
    $resourceProviderResource | Where-Object ResourceType -eq Microsoft.Network/networkSecurityGroups | Remove-AzureRmResource -Force -Verbose

    if ($removePublicIP) {
        $resourceProviderResource | Where-Object ResourceType -eq Microsoft.Network/publicIPAddresses | Remove-AzureRmResource -Force -Verbose
    }

    #Remove storage account
    $resourceProviderResource | Where-Object ResourceType -eq Microsoft.Storage/storageAccounts | Remove-AzureRmResource -Force -Verbose
}

function Remove-AzureRmVmExtensionsByType {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $true, HelpMessage = "Credential object of Azure Stack")]
        [PSCredential]$azCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Admin Arm Endpoint")]
        [string]$ArmEndpoint,
        [Parameter(Mandatory = $true, HelpMessage = "Resource group name")]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, HelpMessage = "VM Name")]
        [string]$VMName,
        [Parameter(Mandatory = $true, HelpMessage = "VM Extension Type")]
        [string]$VMExtensionType
    )
    $azAccount = Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -azCredential $azCredential -ArmEndpoint $ArmEndpoint
    
    $vm = Get-AzureRmVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Warning -Message "Could not find VM $VMName in resource group $ResourceGroupName" -Verbose
        return
    }

    if ($vm.Count -gt 1) {
        Write-Warning -Message "Find more than 1 VM $VMName in resource group $ResourceGroupName" -Verbose
        return
    }
    
    $findExtension = $false
    foreach ($extension in $vm.Extensions) {
        $ext = Get-AzureRmVMExtension -VMName $vm.Name -ResourceGroupName $vm.ResourceGroupName -Name $extension.Id.Split("/")[-1] -ErrorAction SilentlyContinue
        if ($ext.ExtensionType -eq $VMExtensionType) {
            $findExtension = $true
            Write-Verbose -Message ("Remove extension {0} , type {1} on VM {2}" -f $ext.Name, $ext.ExtensionType, $ext.VMName)  -Verbose
            $ext | Remove-AzureRmVMExtension -Force -Verbose  
        }
    }

    if (-not $findExtension) {
        Write-Warning -Message "Cound not find extension type $VMExtensionType on VM $VMName " -Verbose
    }
}

function Test-DbAdapterGuestOSUpdate {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $true, HelpMessage = "Credential object of Azure Stack")]
        [PSCredential]$azCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Admin Arm Endpoint")]
        [string]$ArmEndpoint,
        [Parameter(Mandatory = $true, HelpMessage = "Path of files to upload")]
        [string]$windowsUpdatePath,
        [Parameter(Mandatory = $false, HelpMessage = "Resource provider version")]
        [string]$Version,
        [ValidateSet("SQLAdapter", "MySQLAdapter")] 
        [string]$DBAdapterName
    )

    $azAccount = Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -azCredential $azCredential -ArmEndpoint $ArmEndpoint
    $azResourceGroup = Get-AzureRmResourceGroup | Where-Object { $_.Tags.ProviderName -eq $DBAdapterName -and $_.Tags.Role -eq "ResourceGroup" }

    if (-not $azResourceGroup) {
        throw "Could not find resource group for db adapter $DBAdapterName"
    }
    else {
        $resourceGroupName = $azResourceGroup.ResourceGroupName
    }

    if ($azResourceGroup.Count -gt 1) {
        $azResourceGroup
        throw "Find more than one resource group for db adapter $DBAdapterName"
    }

    if ([string]::IsNullOrEmpty($Version)) {
        $Version = $azResourceGroup.Tags.Version
        $currentRpVM = Get-AzureRmVM -ResourceGroupName $resourceGroupName | Where-Object { $_.Tags.Version -eq $Version };
        if (-not $currentRpVM) {
            throw "Could not find resource provider VM for db adapter $DBAdapterName , Version $Version"
        }
    }

    if ( -not (Test-Path $windowsUpdatePath)) {
        Write-Error -Message "Could not find the windiows udpate at $windowsUpdatePath"
    }

    $msuName = Split-path $windowsUpdatePath -leaf
    $kbIdmatch = [Regex]::Match($msuName.ToUpper(), "KB[0-9]+")
    if (-not $kbIdmatch.Success) {
        throw "Could not find the KB id in the windows update file name. The example of windows udpate file name: windowsserver-kb4034661-x64.msu"
    }
}

function ConvertFrom-KeySecureString {
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]
        $BackupEncryptionKeyBase64
    )
       
    $ptr = [System.Runtime.InteropServices.marshal]::SecureStringToGlobalAllocUnicode($BackupEncryptionKeyBase64)
    $key = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($ptr)
    return $key
}

function ConvertFrom-RegularSecureString {
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]
        $SecurePassword
    )
       
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    return $plainText
}

function UnProtect-BackupFile {
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]
        $BackupEncryptionKeyBase64,

        [Parameter(Mandatory = $true)]
        [string]
        $SourceFileName,

        [Parameter(Mandatory = $true)]
        [string]
        $DestinationFileName
    )
    $key = ConvertFrom-KeySecureString($BackupEncryptionKeyBase64)
    $symmetricFileEncryptionProvider = New-Object Microsoft.AzureStack.Common.Infrastructure.Encryption.SymmetricFileEncryptionProvider($key, $null)
    $symmetricFileEncryptionProvider.DecryptFileAsync($SourceFileName, $DestinationFileName).GetAwaiter().GetResult()
}

function Protect-BackupFile {
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]
        $BackupEncryptionKeyBase64,

        [Parameter(Mandatory = $true)]
        [string]
        $SourceFileName,

        [Parameter(Mandatory = $true)]
        [string]
        $DestinationFileName
    )
    $key = ConvertFrom-KeySecureString($BackupEncryptionKeyBase64)
    $symmetricFileEncryptionProvider = New-Object Microsoft.AzureStack.Common.Infrastructure.Encryption.SymmetricFileEncryptionProvider($key, $null)
    $symmetricFileEncryptionProvider.EncryptFileAsync($SourceFileName, $DestinationFileName).GetAwaiter().GetResult()
}

function New-DbAdapterUsageTablesAndQueues {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $true, HelpMessage = "Credential object of Azure Stack")]
        [pscredential] $azCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Admin Arm Endpoint")]
        [string]$ArmEndpoint,
        [Parameter(Mandatory = $true, HelpMessage = "Resource group name")]
        [string]$ResourceGroupName,
        [ValidateSet("SQLAdapter", "MySQLAdapter")] 
        [string]$DBAdapterName
    )
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $azCredential | Out-Null

    $usageStorageAccountName = ("{0}{1}" -f $DBAdapterName, "usageaccount").ToLower()
    $usageStorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -Name $usageStorageAccountName

    $storageContext = $usageStorageAccount.Context

    # Usage records table
    $usageTableName = "usagerecordstable"
    $usageTable = Get-AzureStorageTable -Name $usageTableName -Context $storageContext -ErrorAction SilentlyContinue
    if ($usageTable) {
        Write-Verbose -Message "$($usageTableName) already exists" -Verbose
    }
    else {
        New-AzureStorageTable -Name $usageTableName -Context $storageContext | Out-Null
    }

    # Usage errors table
    $usageErrorsTableName = "usageerrorstable"
    $usageErrorsTable = Get-AzureStorageTable -Name $usageErrorsTableName -Context $storageContext -ErrorAction SilentlyContinue
    if ($usageErrorsTable) {
        Write-Verbose -Message "$($usageErrorsTable) already exists" -Verbose
    }
    else {
        New-AzureStorageTable -Name $usageErrorsTableName -Context $storageContext | Out-Null
    }

    # Usage queue
    $usageQueueName = "usagequeue"
    $usageQueue = Get-AzureStorageQueue -Name $usageQueueName -Context $storageContext -ErrorAction SilentlyContinue
    if ($usageQueue) {
        Write-Verbose -Message "$($usageQueueName) already exists" -Verbose
    }
    else {
        New-AzureStorageQueue -Name $usageQueueName -Context $storageContext | Out-Null
    }

    # Usage errors queue
    $usageErrorsQueueName = "usageerrorsqueue"
    $usageErrorsQueue = Get-AzureStorageQueue -Name $usageErrorsQueueName -Context $storageContext -ErrorAction SilentlyContinue
    if ($usageErrorsQueue) {
        Write-Verbose -Message "$($usageErrorsQueue) already exists" -Verbose
    }
    else {
        New-AzureStorageQueue -Name $usageErrorsQueueName -Context $storageContext | Out-Null
    }
}

function Send-Request() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Endpoint,

        [Parameter(Mandatory = $true)]
        [string]
        $ArmEndpoint,

        [Parameter(ParameterSetName = 'PutRequest')]
        [switch]
        $Put,

        [Parameter(ParameterSetName = 'GetRequest')]
        [switch]
        $Get,

        [Parameter(ParameterSetName = 'DeleteRequest')]
        [switch]
        $Delete,

        
        [Parameter(ParameterSetName = 'PostRequest')]
        [switch]
        $Post,

        [Parameter(Mandatory = $true, ParameterSetName = 'PutRequest')]
        [string]
        $Body,

        [Parameter(Mandatory = $false)]
        [System.Collections.Hashtable]
        $header = @{}
    )

    $ErrorActionPreference = 'Stop'

    $tokens = @()
    $tokens += try { [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared.ReadItems() } catch { }
    $tokens += try { [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems() } catch { }
    $tokenTraceProperties = @('DisplayableId', 'GivenName', 'ClientId', 'UniqueId', 'TenantId', 'Resource', 'Authority', 'IdentityProvider', 'ExpiresOn') # FamilyName, IsMultipleResourceRefreshToken, AccessToken, RefreshToken, IdToken

    $context = Get-AzureRmContext -ErrorAction Stop -Verbose
    $azureEnvironment = Get-AzureRmEnvironment -Name $($context.Environment.Name) -ErrorAction Stop
    $token = $tokens |
    Where-Object Resource  -eq $azureEnvironment.ActiveDirectoryServiceEndpointResourceId |
    Where-Object { ($_.TenantId -eq $azureEnvironment.AdTenant) -or ($azureEnvironment.AdTenant -and ($_.Authority -like "*$($azureEnvironment.AdTenant)*")) } |
    Where-Object DisplayableId -eq $context.Account.Id |
    Sort-Object ExpiresOn |
    Select-Object -Last 1
    Write-Verbose "Using access token: $($token | Select-Object $tokenTraceProperties | Format-List | Out-String)" -Verbose

    $header['Content-Type'] = 'application\json'
    $header['Authorization'] = "Bearer " + $token.AccessToken

    $url = $Endpoint
    if (-not $Endpoint.StartsWith('http')) {
        $url = $ArmEndpoint + $Endpoint
    }

    Write-Host "Header: $($header | ConvertTo-Json)"

    if ($Get) {
        Write-Host "Get $($url)"
        return Invoke-WebRequest -Uri $url -Headers $header -Method Get -UseBasicParsing
    }
    elseif ($Put) {
        Write-Host "Put $($url)"
        Write-Host "Body: $($body)"
        return Invoke-WebRequest -Uri $url -Headers $header -Method Put -Body $body -ContentType 'application/json' -UseBasicParsing
    }
    elseif ($Delete) {
        Write-Host "Delete $($url)"
        return Invoke-WebRequest -Uri $url -Headers $header -Method Delete -UseBasicParsing
    }
    elseif ($Post) {
        Write-Host "Post $($url)"
        return Invoke-WebRequest -Uri $url -Headers $header -Method Post -UseBasicParsing
    }
}

function Wait-Operation() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]
        $OperationResponse,

        [Parameter(Mandatory = $true)]
        [string]
        $ArmEndpoint,

        [Parameter(Mandatory = $false)]
        [int]
        $TimeoutInSec = 300
    )

    $ErrorActionPreference = 'Stop'

    if ($OperationResponse.StatusCode -ge 300) {
        throw "Previous operation is failed: $OperationResponse"
    }

    $queryUrl = $OperationResponse.Headers["Azure-AsyncOperation"]
    if (-not $queryUrl) {
        $queryUrl = $OperationResponse.Headers["Location"]
    }

    $startTime = (Get-Date)

    while ($true) {
        $response = Send-Request -Endpoint $queryUrl -ArmEndpoint $ArmEndpoint -Get
        if (($response.Content | ConvertFrom-Json).Status -eq 'Succeeded') {
            return $response;
        }
        elseif (($response.Content | ConvertFrom-Json).Status -eq 'Failed') {
            $errorMessage = ($response.Content | ConvertFrom-Json).error.details.message
            throw "Wait-Operation failed due to $errorMessage"
        }
        else {
            Start-Sleep -Seconds 10
        }

        if (((Get-Date) - $startTime).TotalSeconds -gt $TimeoutInSec) {
            throw "Timeout while waiting for operation: $OperationResponse"
        }
    }
}

function Invoke-AzureRestCall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Endpoint,

        [Parameter(Mandatory = $true)]
        [string]
        $ArmEndpoint,

        [Parameter(ParameterSetName = 'PutRequest')]
        [switch]
        $Put,

        [Parameter(ParameterSetName = 'GetRequest')]
        [switch]
        $Get,

        [Parameter(ParameterSetName = 'DeleteRequest')]
        [switch]
        $Delete,

        [Parameter(ParameterSetName = 'PostRequest')]
        [switch]
        $Post,

        [Parameter(Mandatory = $true, ParameterSetName = 'PutRequest')]
        [string]
        $Body,

        [Parameter(Mandatory = $false)]
        [System.Collections.Hashtable]
        $header = @{},

        [Parameter(Mandatory = $false)]
        [int]
        $TimeoutInSec = 300
    )
    
    $ErrorActionPreference = 'Stop'

    if ($Put) {
        $response = Send-Request -Endpoint $Endpoint -ArmEndpoint $ArmEndpoint -Put -Body $Body -header $header
    }
    elseif ($Get) {
        $response = Send-Request -Endpoint $Endpoint -ArmEndpoint $ArmEndpoint -Get -header $header
    }
    elseif ($Delete) {
        $response = Send-Request -Endpoint $Endpoint -ArmEndpoint $ArmEndpoint -Delete -header $header
    }
    elseif ($Post) {
        $response = Send-Request -Endpoint $Endpoint -ArmEndpoint $ArmEndpoint -Post -header $header
    }

    if ((($response.StatusCode -eq 201) -or ($response.StatusCode -eq 202)) -and ($response.Headers["Azure-AsyncOperation"] -or $response.Headers["Location"])) {
        # Indicate an async operation
        return Wait-Operation -OperationResponse $response -ArmEndpoint $ArmEndpoint -TimeoutInSec $TimeoutInSec
    }
    else {
        return $response
    }
}

function Get-ImmutablePolicy() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [string]
        $SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]
        $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]
        $StorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]
        $ContainerName
    )

    $ErrorActionPreference = 'Stop'

    $Endpoint = "/subscriptions/$($SubscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.Storage/storageaccounts/$($StorageAccountName)/blobServices/default/containers/$($ContainerName)/immutabilityPolicies/default?api-version=2018-02-01"

    return Invoke-AzureRestCall -EndPoint $Endpoint -ArmEndpoint $ArmEndpoint -Get
}

function Delete-ImmutablePolicy() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [string]
        $SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]
        $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]
        $StorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]
        $ContainerName,

        [Parameter(Mandatory = $true)]
        [string]
        $Etag
    )

    $ErrorActionPreference = 'Stop'

    $Endpoint = "/subscriptions/$($SubscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.Storage/storageaccounts/$($StorageAccountName)/blobServices/default/containers/$($ContainerName)/immutabilityPolicies/default?api-version=2018-02-01"

    return Invoke-AzureRestCall -EndPoint $Endpoint -ArmEndpoint $ArmEndpoint -Delete -header @{'If-Match' = $Etag }
}

function Set-ImmutablePolicy() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [string]
        $SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]
        $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]
        $StorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]
        $ContainerName
    )

    $ErrorActionPreference = 'Stop'

    $body = '{"properties":{"immutabilityPeriodSinceCreationInDays":1}}'
    
    $Endpoint = "/subscriptions/$($SubscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.Storage/storageaccounts/$($StorageAccountName)/blobServices/default/containers/$($ContainerName)/immutabilityPolicies/default?api-version=2018-02-01"

    return Invoke-AzureRestCall -EndPoint $Endpoint -ArmEndpoint $ArmEndpoint -Body $body -Put
}

function Get-ImmutablePolicy() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [string]
        $SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]
        $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]
        $StorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]
        $ContainerName
    )

    $ErrorActionPreference = 'Stop'

    $Endpoint = "/subscriptions/$($SubscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.Storage/storageaccounts/$($StorageAccountName)/blobServices/default/containers/$($ContainerName)/immutabilityPolicies/default?api-version=2018-02-01"

    return Invoke-AzureRestCall -EndPoint $Endpoint -ArmEndpoint $ArmEndpoint -Get
}

function Set-LockToImmutablePolicy() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [string]
        $SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]
        $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]
        $StorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]
        $ContainerName,

        [Parameter(Mandatory = $true)]
        [string]
        $Etag
    )

    $ErrorActionPreference = 'Stop'
    
    $Endpoint = "/subscriptions/$($SubscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.Storage/storageaccounts/$($StorageAccountName)/blobServices/default/containers/$($ContainerName)/immutabilityPolicies/default/lock?api-version=2018-02-01"

    return Invoke-AzureRestCall -EndPoint $Endpoint -ArmEndpoint $ArmEndpoint -Post -header @{'If-Match' = $Etag }
}

function Remove-ImmutableContainer() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [string]
        $SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]
        $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]
        $StorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]
        $ContainerName
    )

    $ErrorActionPreference = 'Stop'
    
    $Endpoint = "/subscriptions/$($SubscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.Storage/storageaccounts/$($StorageAccountName)/blobServices/default/containers/$($ContainerName)?api-version=2018-02-01"

    return Invoke-AzureRestCall -EndPoint $Endpoint -ArmEndpoint $ArmEndpoint -Delete
}

function Set-ImmutableStorageAccountForAuditingLog {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $true, HelpMessage = "Credential object of Azure Stack")]
        [pscredential] $ServiceAdminCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Admin Arm Endpoint")]
        [string]$ArmEndpoint,
        [ValidateSet("SQLAdapter", "MySQLAdapter")] 
        [string]$DBAdapterName
    )

    $ErrorActionPreference = 'Stop'
    
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $ServiceAdminCredential | Out-Null
    $subscription = Get-AzureRmSubscription -SubscriptionName "Default Provider Subscription" -ErrorAction SilentlyContinue
    $location = $ArmEndpoint.Split(".")[1]

    $ResourceGroupName = ("system.{0}.{1}" -f $location, $DBAdapterName).ToLowerInvariant();

    $StorageAccount = 'sqladapterdiagaccount'
    if ($DBAdapterName -eq "MySQLAdapter") {
        $StorageAccount = 'mysqladapterdiagaccount'
    }

    # Step 1: Get the immutable policy
    Write-Host "Get immutable policy to check the status."
    $response = Get-ImmutablePolicy -ArmEndpoint $ArmEndpoint -SubscriptionId $subscription.SubscriptionId -ResourceGroupName $ResourceGroupName -ContainerName 'wadwindowseventlogs' -StorageAccountName $StorageAccount
    Write-Host $response

    if ($response.StatusCode -eq '200') {
        Write-Host "Get immutable policy success."
    }
    else {
        throw "Failed to get immutable policy."
    }

    $content = ConvertFrom-Json $response.Content

    # Step 2: Set the immutable policy if not exist
    if (-not $content.etag) {
        Write-Host "Set immutable policy."
        $response = Set-ImmutablePolicy -ArmEndpoint $ArmEndpoint -SubscriptionId $subscription.SubscriptionId -ResourceGroupName $ResourceGroupName -ContainerName 'wadwindowseventlogs' -StorageAccountName $StorageAccount
        Write-Host $response
    
        if ($response.StatusCode -eq '200') {
            Write-Host "Set immutable policy success."
        }
        else {
            throw "Failed to set immutable policy."
        }

        $content = ConvertFrom-Json $response.Content
    }

    # Step 3: Set the immutable policy lock
    if ($content.properties.state -ne "Locked") {
        $etag = $content.etag
        Write-Host "Set immutable policy lock."
        $response = Set-LockToImmutablePolicy -ArmEndpoint $ArmEndpoint -SubscriptionId $subscription.SubscriptionId -ResourceGroupName $ResourceGroupName -ContainerName 'wadwindowseventlogs' -StorageAccountName $StorageAccount -Etag $etag
        Write-Host $response
        if ($response.StatusCode -eq '200') {
            Write-Host "Set lock to immutable policy success."
        }
        else {
            throw "Failed to set lock to immutable policy."
        }
    }
}

function Remove-RPProvider {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $true, HelpMessage = "Credential object of Azure Stack")]
        [pscredential] $ServiceAdminCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Admin Arm Endpoint")]
        [string]$ArmEndpoint,
        [ValidateSet("SQLAdapter", "MySQLAdapter")] 
        [string]$DBAdapterName
    )

    $ErrorActionPreference = 'Stop'

    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $ServiceAdminCredential | Out-Null
    $subscription = Get-AzureRmSubscription -SubscriptionName "Default Provider Subscription" -ErrorAction SilentlyContinue
    $location = $ArmEndpoint.Split(".")[1]

    $ResourceGroupName = ("system.{0}.{1}" -f $location, $DBAdapterName).ToLowerInvariant();

    $StorageAccount = 'sqladapterdiagaccount'
    if ($DBAdapterName -eq "MySQLAdapter") {
        $StorageAccount = 'mysqladapterdiagaccount'
    }
    $ContainerName = 'wadwindowseventlogs'

    $isAzureStackWithoutImmutableBlob = $false
    try {
        $response = Get-ImmutablePolicy -ArmEndpoint $ArmEndpoint -SubscriptionId $subscription.SubscriptionId -ResourceGroupName $ResourceGroupName -ContainerName $ContainerName -StorageAccountName $StorageAccount
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response.StatusCode -eq 400) {
            $isAzureStackWithoutImmutableBlob = $true
        }
        else {
            throw $_.Exception
        }
    }

    if (-not $isAzureStackWithoutImmutableBlob) {
        Write-Host $response

        if ($response.StatusCode -eq '200') {
            Write-Host "Get immutable policy success."
        }
        else {
            throw "Failed to get immutable policy."
        }

        $content = ConvertFrom-Json $response.Content
    }

    if ($isAzureStackWithoutImmutableBlob -or (-not $content.etag)) {
        Remove-ResourceProvider -ResourceGroupName $ResourceGroupName `
            -TraceName $DBAdapterName `
            -DirectoryTenantID $DirectoryTenantID `
            -azCredential $ServiceAdminCredential `
            -ArmEndpoint $ArmEndpoint
    }
    else {
        # Remove the RP as job so it would not block here.
        Remove-ResourceProvider -ResourceGroupName $ResourceGroupName `
            -TraceName $DBAdapterName `
            -DirectoryTenantID $DirectoryTenantID `
            -azCredential $ServiceAdminCredential `
            -ArmEndpoint $ArmEndpoint `
            -AsJob

        Write-Host "Detect immutable policy exist. You may want to rerun the script one day later if you don't want to wait for one day."

        while ($true) {
            try {
                Set-AzureRmCurrentStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccount
                Get-AzureStorageBlob -Container $ContainerName | Remove-AzureStorageBlob -Force
                $response = Remove-ImmutableContainer -ArmEndpoint $ArmEndpoint -ResourceGroupName $ResourceGroupName -ContainerName $ContainerName -SubscriptionId $subscription.SubscriptionId -StorageAccountName $StorageAccount
                if ($response.StatusCode -ne 200) {
                    throw $response.StatusCode
                }
            }
            catch {
                Write-Host "Failed to remove immutable storage account. Will retry 10 minutes later. $($_.Exception.Message)"
                Start-Sleep -Seconds 600
                continue
            }

            break
        }

        # Remove the RP again so that all resources get clean up
        Remove-ResourceProvider -ResourceGroupName $ResourceGroupName `
            -TraceName $DBAdapterName `
            -DirectoryTenantID $DirectoryTenantID `
            -azCredential $ServiceAdminCredential `
            -ArmEndpoint $ArmEndpoint
        Write-Host "Uninstall successed."
    }
}

function Set-DiagnosticAccountToHRP {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $true, HelpMessage = "Credential object of Azure Stack")]
        [pscredential] $ServiceAdminCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Admin Arm Endpoint")]
        [string]$ArmEndpoint,
        [Parameter(Mandatory = $true, HelpMessage = "DB Adapter Name")]
        [ValidateSet("SQLAdapter", "MySQLAdapter")] 
        [string]$DBAdapterName,
        [Parameter(Mandatory = $true, HelpMessage = "Deploy version")]
        [string]$Version,
        [Parameter(Mandatory = $true, HelpMessage = "Identity management solution: AzureAD or ADFS")]
        [ValidateSet("AzureAD", "ADFS")] 
        [string]$IdentityManagementSolution
    )

    $ErrorActionPreference = 'Stop'

    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -EnvironmentName "AzureStack" -azCredential $ServiceAdminCredential -ArmEndpoint $ArmEndpoint | Out-Null

    # NOTE: Select default subscription if the account contains multiple subscriptions.
    $azSubscription = Get-AzureRmSubscription -SubscriptionName "Default Provider Subscription" -ErrorAction Stop
    $azSubscription | Select-AzureRmSubscription | Out-Null
    Write-Verbose -Message "Using Subscription: '$($azSubscription.Name)'" -Verbose

    $location = $ArmEndpoint.Split(".")[1]
    $resourceGroupName = ("system.{0}.{1}" -f $location, $DBAdapterName).ToLowerInvariant();
    $StorageAccount = 'sqladapterdiagaccount'
    if ($DBAdapterName -eq "MySQLAdapter") {
        $StorageAccount = 'mysqladapterdiagaccount'
    }

    # Step 1: create a new vault inside the resource group
    $Tags = @{"Version" = $Version; "ProviderName" = $DBAdapterName; "Role" = "KeyVaultToDiagnostic"; "Category" = "NonFoundation" }
    $keyVaultName = $DBAdapterName + 'Diagnostic'
    Write-Host "Create $keyVaultName under the resource group $resourceGroupName and $location"
    $diagnosticVault = Get-AzureRmKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName
    if (-not $diagnosticVault) {
        New-AzureRmKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -Location $location -Tag $Tags
    }

    # Step 2: Grant HRP the privileged to access the key vault
    $resourceId = "/subscriptions/$($azSubscription.SubscriptionId)/resourceGroups/system.$($location)/providers/Microsoft.Deployment.Providers/environmentVariables/default"
    Write-Host "Get Azure Rm Resource $resourceId"
    $resource = Get-AzureRmResource -ResourceId $resourceId -ApiVersion '2019-01-01'
    $objectId = $resource.Properties.systemIdentityApps.health.homeDirectoryServicePrincipalObjectId
    Write-Host "Grant $keyVaultName to HRP AD SP ID: $objectId under the resource group $resourceGroupName"
    if ($IdentityManagementSolution -eq 'ADFS') {
        Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ObjectId $objectId -PermissionsToSecrets get, list -ResourceGroupName $resourceGroupName -BypassObjectIdValidation

        # Step 2.1: If it is ADFS, need to manually grant the service admin to access the KeyVault
        $ctx = Get-AzureRmContext -Verbose
        $oids = $ctx.TokenCache.ReadItems() | Where-Object { $_.DisplayableId -eq $ctx.Account.Id } | Select-Object UniqueId | Sort-Object -Property UniqueId -Unique
        foreach ($oid in $oids.UniqueId) {
            Write-Host "Adding Key Vault access policy for $oid"
            Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ObjectId $oid -PermissionsToSecrets Get, List, Set, Delete, Recover, Backup, Restore -BypassObjectIdValidation
        }
    }
    else {
        Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ObjectId $objectId -PermissionsToSecrets get, list -ResourceGroupName $resourceGroupName
    }

    # Step 3: Store the storage account connection string to key vault
    $keys = Get-AzureRmStorageAccountKey -ResourceGroupName $resourceGroupName -Name $StorageAccount
    $storageAccount = Get-AzureRmStorageAccount -ResourceGroupName $resourceGroupName -Name $StorageAccount
    $key1 = $keys[0]
    $endpointSuffix = $ArmEndpoint.Substring($ArmEndpoint.IndexOf(".") + 1).TrimEnd("/")
    $connectionString = "DefaultEndpointsProtocol=https;AccountName=" + $StorageAccount.StorageAccountName + ";AccountKey=" + $key1.Value + ";EndpointSuffix=" + $endpointSuffix
    $secret = ConvertTo-SecureString -String $connectionString -Force -AsPlainText
    Write-Host "Set $keyVaultName with Storage Key Name $($storageAccount.StorageAccountName) and Secret $connectionString"
    Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name $storageAccount.StorageAccountName -SecretValue $secret | Out-Null

    Write-Host "Finished HRP Dependency resource creation."
}

function Delete-DiagnosticRegistration() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [string]
        $SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]
        $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]
        $ServiceHealthRegistrationName,

        [Parameter(Mandatory = $true)]
        [string]
        $DiagnosticsRegistrationName
    )

    $ErrorActionPreference = 'Stop'

    $Endpoint = "/subscriptions/$($SubscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.InfrastructureInsights.Providers/serviceRegistrations/$($ServiceHealthRegistrationName)/diagnosticsRegistrations/$($DiagnosticsRegistrationName)?api-version=2016-05-01"

    return Invoke-AzureRestCall -EndPoint $Endpoint -ArmEndpoint $ArmEndpoint -Delete
}

function Delete-HrpRegistration() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [string]
        $SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]
        $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]
        $ServiceHealthRegistrationName
    )

    $ErrorActionPreference = 'Stop'

    $Endpoint = "/subscriptions/$($SubscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.InfrastructureInsights.Providers/serviceRegistrations/$($ServiceHealthRegistrationName)?api-version=2016-05-01"

    return Invoke-AzureRestCall -EndPoint $Endpoint -ArmEndpoint $ArmEndpoint -Delete
}

function Delete-RegistrationToHRP {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $true, HelpMessage = "Credential object of Azure Stack")]
        [pscredential] $ServiceAdminCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Admin Arm Endpoint")]
        [string]$ArmEndpoint,
        [ValidateSet("SQLAdapter", "MySQLAdapter")] 
        [string]$DBAdapterName
    )

    $ErrorActionPreference = 'Stop'

    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -EnvironmentName "AzureStack" -azCredential $ServiceAdminCredential -ArmEndpoint $ArmEndpoint | Out-Null

    # NOTE: Select default subscription if the account contains multiple subscriptions.
    $azSubscription = Get-AzureRmSubscription -SubscriptionName "Default Provider Subscription" -ErrorAction Stop
    $azSubscription | Select-AzureRmSubscription | Out-Null
    Write-Verbose -Message "Using Subscription: '$($azSubscription.Name)'" -Verbose

    $location = $ArmEndpoint.Split(".")[1]
    $resourceGroupName = ("system.{0}" -f $location).ToLowerInvariant();

    $ServiceHealthRegistrationName = $DBAdapterName
    $DiagnosticsRegistrationName = "Microsoft-$($DBAdapterName)-Diagnostics"

    Write-Host "Begin to remove diagnostic registration: $DiagnosticsRegistrationName"
    # Step 1: Remove registration to HRP diagnostic
    Delete-DiagnosticRegistration -ArmEndpoint $ArmEndpoint -SubscriptionId $azSubscription.SubscriptionId -ResourceGroupName $ResourceGroupName -ServiceHealthRegistrationName $ServiceHealthRegistrationName -DiagnosticsRegistrationName $DiagnosticsRegistrationName

    Write-Host "Begin to remove service registration: $ServiceHealthRegistrationName"
    # Step 2: Remove HRP service registration
    Delete-HrpRegistration -ArmEndpoint $ArmEndpoint -SubscriptionId $azSubscription.SubscriptionId -ResourceGroupName $ResourceGroupName -ServiceHealthRegistrationName $ServiceHealthRegistrationName

    Write-Host "Finished remove the HRP registration."
}

function New-DbAdapterResourceHydrationQueue {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Tenant Directory ID")]
        [string]$DirectoryTenantID,
        [Parameter(Mandatory = $true, HelpMessage = "Credential object of Azure Stack")]
        [pscredential] $azCredential,
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Admin Arm Endpoint")]
        [string]$ArmEndpoint,
        [Parameter(Mandatory = $true, HelpMessage = "Resource group name")]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, HelpMessage = "Storage account name")]
        [string]$storageAccountName
    )
    # resource hydraton queue
    $resourceHydrationQueueName = "resourcehydration"
    Write-Verbose -Message "Creating $($resourceHydrationQueueName) queue on $storageAccountName storage account" -Verbose
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $azCredential | Out-Null
    
    $storageAccount = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -Name $storageAccountName

    $storageContext = $storageAccount.Context

    $resourceHydrationQueue = Get-AzureStorageQueue -Name $resourceHydrationQueueName -Context $storageContext -ErrorAction SilentlyContinue
    if ($resourceHydrationQueue) {
        Write-Verbose -Message "$($resourceHydrationQueueName) already exists" -Verbose
    }
    else {
        New-AzureStorageQueue -Name $resourceHydrationQueueName -Context $storageContext | Out-Null
        Write-Verbose -Message "Successfully created $($resourceHydrationQueueName) queue" -Verbose
    }
}

function Set-Settings {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "Path of the Application Exe")]
        [ValidateNotNullOrEmpty()]
        [string]$ExePath,

        [Parameter(Mandatory = $true, HelpMessage = "Hashtable of settings to update.")]
        [ValidateNotNull()]
        [System.Collections.Hashtable] $Settings
    )

    [System.Configuration.Configuration] $appConfig = [System.Configuration.ConfigurationManager]::OpenExeConfiguration($ExePath)

    $existingSettingKeys = [System.Collections.Generic.HashSet[String]]$appConfig.AppSettings.Settings.AllKeys
    $updatedSettingKeys = @()
    foreach ($keyValuePair in $Settings.GetEnumerator()) {
        $key = $keyValuePair.Key
        $newValue = $keyValuePair.Value.ToString()

        if (-not $existingSettingKeys.Contains($key)) {
            Write-Warning "Setting with key '$key' is absent in '$($config.FilePath)'. Adding this new setting." -WarningAction Continue
            $appConfig.AppSettings.Settings.Add($key, $newValue)
            $updatedSettingKeys += @(, $key)
        }
        else {
            $oldValue = $appConfig.AppSettings.Settings[$key].Value
            if ($newValue -ne $oldValue) {
                $appConfig.AppSettings.Settings[$key].Value = $newValue
                $updatedSettingKeys += @(, $key)
            }
        }
    }

    Write-Verbose -Message "Updating $($updatedSettingKeys.Count)/$($Settings.Count) changed settings ($($existingSettingKeys.Count) total) in '$($appConfig.FilePath)'." -Verbose
    if ($updatedSettingKeys.Count -gt 0) {
        $appConfig.Save([System.Configuration.ConfigurationSaveMode]::Modified)
    }
}

function Initialize-KeyvaultAccessPolicy {
    [CmdletBinding()]
    Param
    (
        # Display Name of the Service Principal
        [ValidatePattern("[a-zA-Z0-9-]{3,}")]
        [Parameter(Mandatory = $true)]
        $DisplayName,

        [Parameter(Mandatory = $false)]
        [string]
        $Privilegedendpoint,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $AdminCredential,

        [Parameter(Mandatory = $true, HelpMessage = "Identity management solution: AzureAD or ADFS")]
        [ValidateSet('AzureAD', 'ADFS')]
        [string]$IdentityManagementSolution,

        [Parameter(Mandatory = $true, HelpMessage = "KeyVault Name.")]
        [string]$keyVaultName,

        [Parameter(Mandatory = $true, HelpMessage = "Resource group name. (1-80 chars, alphanumeric, period, underscore, dash, and parenthesis)")]
        [string]$resourceGroupName
    )
    $ClientCertificate = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -Subject "CN=$DisplayName" -KeySpec KeyExchange
        
    if ($IdentityManagementSolution -ieq "AzureAD") {
        $certString = [Convert]::ToBase64String($ClientCertificate.GetRawCertData())
        $application = Get-AzureRmADApplication -IdentifierUri "http://$DisplayName" -ErrorAction SilentlyContinue
        if ($application) {
            Remove-AzureRmADApplication -ObjectId $application.ObjectId -Force | Out-Null
        }

        $spn = Get-AzureRmADServicePrincipal -ServicePrincipalName "http://$DisplayName" -ErrorAction SilentlyContinue
        if ($spn) {
            Remove-AzureRmADServicePrincipal -ObjectId $spn.ObjectId -Force | Out-Null
        }
            
        $application = New-AzureRmADServicePrincipal -DisplayName $DisplayName `
            -CertValue $certString `
            -EndDate $ClientCertificate.NotAfter.AddDays(-1) `
            -StartDate $ClientCertificate.NotBefore `
            -ErrorAction Stop `
            -Verbose
            
        #sleeps for 20 seconds to allow some time for the new service principal to propagate throughout Azure Active Directory
        Start-Sleep -Seconds 20

        Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ServicePrincipalName $application.ApplicationId -PermissionsToSecrets Get, Set, List, Delete, Backup, Restore, Recover, Purge | Out-Null
        return $application.ApplicationId, $ClientCertificate.Thumbprint, $application.ApplicationId
    }
    elseif ($IdentityManagementSolution -ieq "ADFS") {
        Set-TrustedHosts -PrivilegedEndpoint $PrivilegedEndpoint
        try {
            $domainAdminSession = New-PSSession -ComputerName $PrivilegedEndpoint -Credential $AdminCredential -configurationname privilegedendpoint  -Verbose          
                
            $ApplicationName = $DisplayName
            
            $application = Invoke-Command -Session $domainAdminSession -Verbose -ErrorAction Stop -ScriptBlock { New-GraphApplication -Name $using:ApplicationName -ClientCertificates $using:ClientCertificate }
                
            Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ObjectId $application.ApplicationIdentifier -BypassObjectIdValidation -PermissionsToKeys all -PermissionsToSecrets Get, Set, List, Delete, Backup, Restore, Recover, Purge | Out-Null 
            return $application.ClientId, $application.Thumbprint, $application.ApplicationIdentifier
        } 
        finally {
            if ($domainAdminSession -ne $null) {
                Remove-PSSession $domainAdminSession -Verbose
            }
        }
    }
}
    
function Remove-KeyvaultAccessPolicy {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        $ApplicationId,

        [Parameter(Mandatory = $true, HelpMessage = "Identity management solution: AzureAD or ADFS")]
        [ValidateSet('AzureAD', 'ADFS')]
        [string]$IdentityManagementSolution,

        [Parameter(Mandatory = $true, HelpMessage = "KeyVault Name.")]
        [string]$keyVaultName,

        [Parameter(Mandatory = $true, HelpMessage = "Resource group name. (1-80 chars, alphanumeric, period, underscore, dash, and parenthesis)")]
        [string]$resourceGroupName
    )
    if ($IdentityManagementSolution -ieq "AzureAD") {
        Remove-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ServicePrincipalName $ApplicationId -ErrorAction SilentlyContinue
    }
    elseif ($IdentityManagementSolution -ieq "ADFS") {
        Remove-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ObjectId $ApplicationId -ErrorAction SilentlyContinue
    }
}

function Backup-KeyVaultSecretsToFile {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, HelpMessage = "KeyVault Name")]
        [string]$keyVaultName,

        [Parameter(Mandatory = $true, HelpMessage = "Backup file full patch")]
        [string]$backupFile
    )
    
    $secrets = Get-AzureKeyVaultSecret -VaultName $keyVaultName
    $secretWithValues = @()
    for ($i = 0; $i -lt $secrets.Count; $i++) {
        $secretWithValues += Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $secrets[$i].Name
    }

    $secretWithValues | ConvertTo-Json | Set-Content -Path $backupFile -Encoding UTF8 -Force
}

function Clear-KeyVaultSecrets {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, HelpMessage = "KeyVault Name")]
        [string]$keyVaultName
    )

    $secrets = Get-AzureKeyVaultSecret -VaultName $keyVaultName
    for ($i = 0; $i -lt $secrets.Count; $i++) {
        Remove-AzureKeyVaultSecret -VaultName $keyVaultName -Name $secrets[$i].Name -Force -Confirm:$false
    }
}

function Restore-KeyVaultSecretsFromBackup {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, HelpMessage = "KeyVault Name")]
        [string]$keyVaultName,

        [Parameter(Mandatory = $true, HelpMessage = "Backup file full patch")]
        [string]$backupFile
    )
    
    $secrets = Get-Content -Path $backupFile -Encoding UTF8 | ConvertFrom-Json
    for ($i = 0; $i -lt $secrets.Count; $i++) {
        $secretValue = ConvertTo-SecureString $secrets[$i].SecretValueText -AsPlainText -Force
        Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name $secrets[$i].Name -SecretValue $secretValue
    }
}

function Get-BackupInfoXml {
    return @"
<?xml version="1.0"?>
<BackupInfo xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<BackupDataVersion></BackupDataVersion>
<BackupId></BackupId>
<RoleStatus>
<RoleOperationStatus>
    <RoleName></RoleName>
    <Status></Status>
</RoleOperationStatus>
<RoleOperationStatus>
    <RoleName></RoleName>
    <Status></Status>
</RoleOperationStatus>
<RoleOperationStatus>
    <RoleName></RoleName>
    <Status></Status>
</RoleOperationStatus>
</RoleStatus>
<Status></Status>
<CreatedDateTime></CreatedDateTime>
<TimeTakenToCreate></TimeTakenToCreate>
<StampVersion></StampVersion>
<OemVersion></OemVersion>
<DeploymentID></DeploymentID>
</BackupInfo>
"@
}