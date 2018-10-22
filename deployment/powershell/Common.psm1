# Copyright (c) Microsoft Corporation. All rights reserved.
# Common.psm1 1.1.24.0 2018-05-22 01:17:30

# AzureStack-Services-SqlServer release retail-amd64

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
    $FormattedOutput = $FormattedOutput | ForEach-Object {(Get-Date).ToLongTimeString() + " : " + $_}
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

function Test-AzureStackPowerShell {
    
    # Install the powershell module if
    $packageProvider = Get-PackageProvider -Name Nuget
    if ($packageProvider -eq $null) {
        Write-Host "Nuget Package provider not found. Installing .... "
        Install-PackageProvider -Name "Nuget" -MinimumVersion 2.8.5.201
    }
    else {
        Write-Host "Nuget Package provider found."
    }
    $azureRMModule = Get-Module -ListAvailable -Name "AzureRM" | Where-Object {$_.Version -eq "1.2.11"}
    if ($azureRMModule -eq $null) {
        Write-Host -ForegroundColor Red "Azure Powershell not found. Need Azure powershell compatible with stack. Use ArmProfile 2017-03-09-profile. Please install the current version and rerun the RP setup"
        throw
    }
    elseif (($azureRMModule.Version.Major -eq "1") -and ($azureRMModule.Version.Minor -eq "2") -and ($azureRMModule.Version.Build -ge "11")) {
        Write-Host "Azure Powershell Module with $($azureRMModule.Version) version found. Continuing ...."
    }
    else {
        Write-Host -ForegroundColor Red "Azure Powershell Module with $($azureRMModule.Version) version found. Need Azure powershell compatible with stack. Use ArmProfile 2017-03-09-profile. Please uninstall the current version and rerun the RP setup"
        throw
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
        [Parameter(Mandatory = $true, HelpMessage = "Azurestack Admin Arm Endpoint")]
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
    $endpoints = Invoke-RestMethod "${armEndpoint}/metadata/endpoints?api-version=2015-01-01";
    $authorityEndpoint = $endpoints.authentication.loginEndpoint

    $azEnvironment = Add-AzureRMEnvironment `
        -Name $EnvironmentName `
        -ArmEndpoint $armEndpoint
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
    
    if ($context -and $context.Account -and $context.Account.Id -and $context.Subscription -and ($context.Subscription.Name -eq "Default Provider Subscription")) {
        $azAccount = $context.Account
    }
    else {
        $azAccount = Add-AzureRmAccount -EnvironmentName $azEnvironmentName -Credential $azCredential -TenantId $DirectoryTenantID -ErrorAction SilentlyContinue
        for ($i = 0; $i -lt 5; $i++) {
            try {
                # the cmdlet still report error with SilentlyContinue, so use try and catch here.
                $context = Get-AzureRmContext -ErrorAction SilentlyContinue
            }
            catch {}
            
            if ($context -and $context.Account -and $context.Account.Id -and $context.Subscription -and ($context.Subscription.Name -eq "Default Provider Subscription")) {
                break;
            }
            $azAccount = Add-AzureRmAccount `
                -EnvironmentName $azEnvironmentName `
                -TenantId $DirectoryTenantID -ErrorAction SilentlyContinue
        }
    }

    if (-not $azAccount) {
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
    $providernamespace = Get-AzureRMResourceProvider -ListAvailable | Where-Object {$_.ProviderNamespace -eq $namespace}
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
    <# Turning off deployment telemetry
    Trace-Deployment -DeploymentGUID $deploymentGUID -Type "ARM" -RoleName $($TraceName +"Provider") -Step $step `
        -TraceLevel $TraceLevel -StartTime $StartTime -EndTime $EndTime -Status $Status -LogMessage $LogMessage #>
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
    $location = (Get-AzsLocation)[0].Name         
    $resourceGroup = Get-AzureRmResourceGroup -Name $resourceGroupName -Location $location
    Write-Verbose -Message "Resource Group: $($resourceGroup.ResourceGroupName)" -Verbose
    $StorageObject = Find-AzureRmResource -ResourceType "Microsoft.Storage/storageAccounts" | Where-Object {$_.Name -eq $storageAccountName}        
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
    Register-AzureRmResourceProvider -ProviderNamespace $namespace
    while ($currentRetryCount -lt $maxRetryCount) {
        if ((Get-AzureRmResourceProvider -ListAvailable | Where-Object {$_.ProviderNamespace -eq $namespace}).RegistrationState -ieq "Registered") {
            Write-Verbose -Verbose -Message  "Resource Provider for $namespace is registered"
            $registrationSuccess = $true
            break;
        }
        else {
            Start-Sleep -Seconds $duration
            Write-Warning -Message ("Waiting for current state {0} of Resource Provider {1} to Registered for {2} seconds" -f ($(Get-AzureRmResourceProvider -ListAvailable | Where-Objecthere-Objecthere-Object {$_.ProviderNamespace -eq $namespace}).RegistrationState, $namespace, (($currentRetryCount + 1) * $duration)))
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
    ����Add-Type -AssemblyName Microsoft.VisualBasic
    ����return [Microsoft.VisualBasic.Interaction]::InputBox($Message, $WindowTitle, $DefaultText)
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
    $checks += If ($upper.Matches($Password).Count -gt 0 ) {1} Else {0}
    $checks += If ($lower.Matches($Password).Count -gt 0) {1} Else {0}
    $checks += If ($number.Matches($Password).Count -gt 0) {1} Else {0}
    $checks += If ($special.Matches($Password).Count -gt 0) {1} Else {0}
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
        [string]$ArmEndpoint        
    )
    
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -azCredential $AzCredential -ArmEndpoint $ArmEndpoint | Out-Null

    # Cleanup DNS record before removing the resource group
    $rg = Get-AzureRmResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
    if (!$rg) {
        Write-Verbose "$TraceName RP ResourceGroup $ResourceGroupName is not found." -Verbose
        return
    }
    $VmName = $TraceName
    $DBAdapterDNSZoneNamePrefix = "dbadapter"
    $Location = (Get-AzsLocation)[0].Name         
    $DBAdapterDNSZoneResourceGroupName = Get-DNSZoneResourceGroupName -Location $Location -DBAdapterDNSZoneNamePrefix $DBAdapterDNSZoneNamePrefix
    $DBAdapterDNSZoneResourceGroup = Get-AzureRmResourceGroup -Name $DBAdapterDNSZoneResourceGroupName -ErrorAction SilentlyContinue
    if ($DBAdapterDNSZoneResourceGroup) {
        Write-Verbose "$DBAdapterDNSZoneResourceGroupName ResourceGroup is found. Cleaning up $TraceName DNS Entries." -Verbose
        $zone = Get-AzureRmDnsZone -ResourceGroupName $DBAdapterDNSZoneResourceGroupName | Where-Object {$_.Name -like "$DBAdapterDNSZoneNamePrefix.*"}
        if ($zone) {
            $dnsRecord = Get-AzureRmDnsRecordSet -Name $VmName -ResourceGroupName $DBAdapterDNSZoneResourceGroupName -ZoneName $zone.Name `
                -RecordType A -ErrorAction SilentlyContinue
            if ($dnsRecord) {
                Remove-AzureRmDnsRecordSet -Name $VmName -ResourceGroupName $DBAdapterDNSZoneResourceGroupName -ZoneName $zone.Name -RecordType A
            }

            # Check remaining record sets (ignoring default '@' sets)
            $remainingSets = Get-AzureRmDnsRecordSet -ResourceGroupName $DBAdapterDNSZoneResourceGroupName `
                -ZoneName $zone.Name -ErrorAction SilentlyContinue | Where-Object {$_.Name -ne "@"}
            if (-not $remainingSets) {
                Write-Verbose "No DNS entries remain under $DBAdapterDNSZoneResourceGroupName. Hence deleting the DNS Zone and Resource Group." -Verbose
                # No remaining record sets, clean up resource group
                Remove-AzureRmResourceGroup -Force -Verbose -Name $DBAdapterDNSZoneResourceGroupName
            }
        }
    }
    Write-Verbose "$TraceName RP ResourceGroup $ResourceGroupName is found. Attempting to remove it." -Verbose
    Remove-AzureRmResourceGroup -Force -Verbose -Name $ResourceGroupName
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

Function Get-AzureStackRmDatabaseAdapterQuota {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String] $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string] $DirectoryTenantID,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [pscredential] $aadCredential,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Microsoft.SQLAdapter.Admin", "Microsoft.MySQLAdapter.Admin")]
        $databaseAdapterNamespace
    )
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $aadCredential
    try {
        $location = (Get-AzsLocation)[0].Name         
    }
    catch {}
    $environmentName = (Get-AzureRmContext).Environment.Name
    $sub, $header = Get-AzureStackAdminSubTokenHeader -EnvironmentName $environmentName -tenantID $DirectoryTenantID -azureStackCredential $aadCredential
    $apiVersion = '2017-08-28'
    $ArmEndpoint = $ArmEndpoint.TrimEnd("/", "\");
    $uri = ('{0}/subscriptions/{1}/providers/{2}/locations/{3}/quotas?api-version={4}' -f $ArmEndpoint, (Get-AzureRmContext).Subscription.SubscriptionId, $databaseAdapterNamespace, $location, $apiVersion )   
    
    # Make the REST call
    $response = Invoke-RestMethod -Method 'Get' -Headers $header -Uri $uri -Body $requestBodyJson -ContentType 'application/json'
    Write-Verbose -Message $response | ConvertTo-Json -Verbose
    return $response
}

Function New-AzureStackRmDatabaseAdapterQuota {
    Param(
        [ValidateNotNullorEmpty()]
        [String] $location = 'local',

        [ValidateNotNullorEmpty()]
        [String] $ArmEndpoint = 'https://api.local.azurestack.external',

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary] $requestHeaders,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string] $quotaName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [int] $quotaResourceCount,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [int] $quotaResourceSizeMB,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Microsoft.SQLAdapter.Admin", "Microsoft.MySQLAdapter.Admin")]
        $databaseAdapterNamespace,

        [ValidateNotNullorEmpty()]
        [string] $apiVersion = '2017-08-28'
    )

    $ArmEndpoint = $ArmEndpoint.TrimEnd("/", "\");
    $uri = ('{0}/subscriptions/{1}/providers/{2}/locations/{3}/quotas/{4}?api-version={5}' -f $ArmEndpoint, (Get-AzureRmContext).Subscription.SubscriptionId, $databaseAdapterNamespace, $location, $quotaName, $apiVersion )   
    
    # Create the request body
    $idForRequestBody = '/subscriptions/{0}/providers/{1}/locations/{2}/quotas/{3}' -f (Get-AzureRmContext).Subscription.SubscriptionId, $databaseAdapterNamespace, $location, $quotaName

    $requestBody = @{
        properties = @{
            resourceCount       = $quotaResourceCount
            totalResourceSizeMB = $quotaResourceSizeMB
        }
        id         = $idForRequestBody
        name       = $quotaName
    }
    $requestBodyJson = $requestBody | ConvertTo-Json
    
    Write-Verbose -Message "[New-AzureStackRmDatabaseAdapterQuota]::Creating new database adapter Quota with name $($quotaName), adapter namespace: $($databaseAdapterNamespace)" -Verbose
    try {
        # Make the REST call
        $response = Invoke-RestMethod -Method 'PUT' -Headers $requestHeaders -Uri $uri -Body $requestBodyJson -ContentType 'application/json'
        return $response
    }
    catch {
        $message = $_.Exception.Message
        Write-Error -Message ("[New-AzureStackRmDatabaseAdapterQuota]::Failed to create database adapter Quota with name {0}, failed with error: {1}" -f $quotaName, $message)
        throw $_.Exception
    }
}

Function Remove-AzureStackRmDatabaseAdapterQuota {
    Param(
        [ValidateNotNullorEmpty()]
        [String] $location = 'local',

        [ValidateNotNullorEmpty()]
        [String] $ArmEndpoint = 'https://api.local.azurestack.external',

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary] $requestHeaders,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string] $quotaName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Microsoft.SQLAdapter.Admin", "Microsoft.MySqlAdapter.Admin")]
        $databaseAdapterNamespace,

        [ValidateNotNullorEmpty()]
        [string] $apiVersion = '2017-08-28'
    )

    $ArmEndpoint = $ArmEndpoint.TrimEnd("/", "\");
    $uri = ('{0}/subscriptions/{1}/providers/{2}/locations/{3}/quotas/{4}?api-version={5}' -f $ArmEndpoint, (Get-AzureRmContext).Subscription.SubscriptionId, $databaseAdapterNamespace, $location, $quotaName, $apiVersion)

    Write-Verbose -Message "[Remove-AzureStackRmDatabaseAdapterQuota]::Deleting database adapter Quota with name: $($quotaName), adapter namespace: $($databaseAdapterNamespace)" -Verbose
    try {
        # Make the REST call
        $response = Invoke-RestMethod -Method 'DELETE' -Headers $requestHeaders -Uri $uri
        return $response
    }
    catch {
        $message = $_.Exception.Message
        Write-Error -Message ("[Remove-AzureStackRmDatabaseAdapterQuota]::Failed to delete Quota with name {0}, failed with error: {1}" -f $quotaName, $message)
        throw $_.Exception
    }
}

Function Test-DbAdapterDeployment {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String] $ArmEndpoint,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string] $DirectoryTenantID,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [pscredential] $aadCredential,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Microsoft.SQLAdapter.Admin", "Microsoft.MySQLAdapter.Admin")]
        $databaseAdapterNamespace
    )
    Initialize-AzureStackEnvironment -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $aadCredential | Out-Null
    $location = (Get-AzsLocation)[0].Name         
    $environmentName = (Get-AzureRmContext).Environment.Name
    $sub, $header = Get-AzureStackAdminSubTokenHeader -EnvironmentName $environmentName -tenantID $DirectoryTenantID -azureStackCredential $aadCredential
    New-AzureStackRmDatabaseAdapterQuota -location $location -ArmEndpoint $ArmEndpoint -requestHeaders $header -quotaName "TestQuota" -quotaResourceCount 20 -quotaResourceSizeMB 2048 -databaseAdapterNamespace $databaseAdapterNamespace
    Remove-AzureStackRmDatabaseAdapterQuota -location $location -ArmEndpoint $ArmEndpoint -requestHeaders $header -quotaName "TestQuota" -databaseAdapterNamespace $databaseAdapterNamespace
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
    $Location = (Get-AzsLocation)[0].Name         
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
        $pfx = Get-PfxData �FilePath $pfxFile -Password $DefaultSSLCertificatePassword
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
        $domainAdminSession = New-PSSession -ComputerName $PrivilegedEndpoint -Credential $CloudAdminCredential -configurationname privilegedendpoint  -Verbose
        Invoke-Command -Session $domainAdminSession -Verbose -ErrorAction Stop  -ScriptBlock { Get-AzureStackStampInformation } 
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
    $info = Get-AzureStackStampInfo -PrivilegedEndpoint $PrivilegedEndpoint -CloudAdminCredential $CloudAdminCredential
    return ( -not [String]::IsNullOrEmpty($info.AADTenantID))
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
    if (-not $resourceGroupObj) {
        New-AzureRmResourceGroup -Name $ResourceGroupName -Location $RegionName -Force -Tag $Tags
    }
}
function Test-ResourceProviderResourceGroup {
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
    if (-not $resourceGroupObj) {
        # if the reosurce group does not exist, return true.
        return $true
    }

    $currentTags = $resourceGroupObj.Tags
    if ($currentTags.Version -eq $Tags.Version) {
        # if the version tag is the same, return true
        return $true
    }
    else {
        # if the version tag is not the same return false
        return $false
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

    $Tags = @{"Version" = $Version; "ProviderName" = $TraceName; "Role" = "DNSZoneResourceGroup"; "Category" = "Foundation"}
    $DBAdapterDNSZoneNamePrefix = "dbadapter"
    $DBAdapterDNSZoneResourceGroupName = Get-DNSZoneResourceGroupName -Location $Location -DBAdapterDNSZoneNamePrefix $DBAdapterDNSZoneNamePrefix
    $zone = Get-DatabaseAdapterDNSZone -DomainName $DomainName -Location $Location -Tags $Tags -ResourceGroupName $DBAdapterDNSZoneResourceGroupName -DBAdapterDNSZoneNamePrefix $DBAdapterDNSZoneNamePrefix -DirectoryTenantID $DirectoryTenantID -ArmEndpoint $ArmEndpoint -azCredential $AzCredential
    
    $dnsRecord = Get-AzureRmDnsRecordSet -Name $TraceName -ResourceGroupName $DBAdapterDNSZoneResourceGroupName -ZoneName $zone.Name -RecordType A -ErrorAction SilentlyContinue
    if ($dnsRecord) {
        Remove-AzureRmDnsRecordSet -Name $TraceName -ResourceGroupName $DBAdapterDNSZoneResourceGroupName -ZoneName $zone.Name -RecordType A | Out-Null
    }
    $azPublicIpAddresses = Get-AzureRmPublicIpAddress -ResourceGroupName $ResourceGroupName
    $rs = New-AzureRmDnsRecordSet -Name $TraceName -RecordType A -Zone $zone -Ttl 3600
    Add-AzureRmDnsRecordConfig -RecordSet $rs -Ipv4Address $azPublicIpAddresses.IpAddress | Out-Null
    Set-AzureRmDnsRecordSet -RecordSet $rs | Out-Null
    return $zone
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
        Invoke-WebRequest $adminEndpointURI | Out-Null
    }
    catch {
        $e = $_.Exception
        if ($e.Response -ne $null -and $e.Status.value__ -eq 7) {
            # Expected response received from the endpoint (WebExceptionStatus value 7 = Forbidden)
            Write-Verbose -Message "Microsoft.$TraceName.Admin endpoint is responsive" -Verbose
        }
        else {
            # Did not receive the expected response, throwing error
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

    $resourceProviderResource = Find-AzureRmResource -ResourceGroupNameContains $ResourceGroupName | Where-Object {$_.Tags -ne $null} | Where-Object { $hashtable = $_.Tags; ($hashtable.Version -eq $Version) -and ($hashtable.Category -eq "NonFoundation" )}
    
    #Remove VM
    $resourceProviderResource | Where-Object ResourceType -eq Microsoft.Compute/virtualMachines | Remove-AzureRmResource -Force -Verbose
    
    #Remove network interface
    $resourceProviderResource | Where-Object ResourceType -eq Microsoft.Network/networkInterfaces | Remove-AzureRmResource -Force -Verbose
    
    #Remove Vnet
    $resourceProviderResource | Where-Object ResourceType -eq Microsoft.Network/virtualNetworks   | Remove-AzureRmResource -Force -Verbose

    #Remove security group
    $resourceProviderResource | Where-Object ResourceType -eq Microsoft.Network/networkSecurityGroups   | Remove-AzureRmResource -Force -Verbose

    if ($removePublicIP) {
        $resourceProviderResource | Where-Object ResourceType -eq Microsoft.Network/publicIPAddresses   | Remove-AzureRmResource -Force -Verbose
    }

    #Remove storage account
    $resourceProviderResource | Where-Object ResourceType -eq Microsoft.Storage/storageAccounts   | Remove-AzureRmResource -Force -Verbose
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
    $azResourceGroup = Get-AzureRmResourceGroup | Where-Object {$_.Tags.ProviderName -eq $DBAdapterName -and $_.Tags.Role -eq "ResourceGroup" }

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
        $currentRpVM = Get-AzureRmVM -ResourceGroupName $resourceGroupName | Where-Object {$_.Tags.Version -eq $Version };
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
        Write-Verbose -Message "$($usageTableName) already exists"
    }
    else {
        New-AzureStorageTable -Name $usageTableName -Context $storageContext | Out-Null
    }

    # Usage errors table
    $usageErrorsTableName = "usageerrorstable"
    $usageErrorsTable = Get-AzureStorageTable -Name $usageErrorsTableName -Context $storageContext -ErrorAction SilentlyContinue
    if ($usageErrorsTable) {
        Write-Verbose -Message "$($usageErrorsTable) already exists"
    }
    else {
        New-AzureStorageTable -Name $usageErrorsTableName -Context $storageContext | Out-Null
    }

    # Usage queue
    $usageQueueName = "usagequeue"
    $usageQueue = Get-AzureStorageQueue -Name $usageQueueName -Context $storageContext -ErrorAction SilentlyContinue
    if ($usageQueue) {
        Write-Verbose -Message "$($usageQueueName) already exists"
    }
    else {
        New-AzureStorageQueue -Name $usageQueueName -Context $storageContext | Out-Null
    }

    # Usage errors queue
    $usageErrorsQueueName = "usageerrorsqueue"
    $usageErrorsQueue = Get-AzureStorageQueue -Name $usageErrorsQueueName -Context $storageContext -ErrorAction SilentlyContinue
    if ($usageErrorsQueue) {
        Write-Verbose -Message "$($usageErrorsQueue) already exists"
    }
    else {
        New-AzureStorageQueue -Name $usageErrorsQueueName -Context $storageContext | Out-Null
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

    Write-Verbose -Message "Updating $($updatedSettingKeys.Count)/$($Settings.Count) changed settings ($($existingSettingKeys.Count) total) in '$($appConfig.FilePath)'."
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
            $domainAdminSession = New-PSSession -ComputerName $PrivilegedEndpoint  -Credential $AdminCredential -configurationname privilegedendpoint  -Verbose          
                
            $ApplicationName = $DisplayName
            
            $application = Invoke-Command -Session $domainAdminSession -Verbose -ErrorAction Stop -ScriptBlock { New-GraphApplication -Name $using:ApplicationName  -ClientCertificates $using:ClientCertificate }
                
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

# SIG # Begin signature block
# MIIkAQYJKoZIhvcNAQcCoIIj8jCCI+4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAHt+NySqTeTUat
# rqpvOYefNBH4xlli8yxOLsIhb+I54qCCDYMwggYBMIID6aADAgECAhMzAAAAxOmJ
# +HqBUOn/AAAAAADEMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTcwODExMjAyMDI0WhcNMTgwODExMjAyMDI0WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCIirgkwwePmoB5FfwmYPxyiCz69KOXiJZGt6PLX4kvOjMuHpF4+nypH4IBtXrL
# GrwDykbrxZn3+wQd8oUK/yJuofJnPcUnGOUoH/UElEFj7OO6FYztE5o13jhwVG87
# 7K1FCTBJwb6PMJkMy3bJ93OVFnfRi7uUxwiFIO0eqDXxccLgdABLitLckevWeP6N
# +q1giD29uR+uYpe/xYSxkK7WryvTVPs12s1xkuYe/+xxa8t/CHZ04BBRSNTxAMhI
# TKMHNeVZDf18nMjmWuOF9daaDx+OpuSEF8HWyp8dAcf9SKcTkjOXIUgy+MIkogCy
# vlPKg24pW4HvOG6A87vsEwvrAgMBAAGjggGAMIIBfDAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUy9ZihM9gOer/Z8Jc0si7q7fDE5gw
# UgYDVR0RBEswSaRHMEUxDTALBgNVBAsTBE1PUFIxNDAyBgNVBAUTKzIzMDAxMitj
# ODA0YjVlYS00OWI0LTQyMzgtODM2Mi1kODUxZmEyMjU0ZmMwHwYDVR0jBBgwFoAU
# SG5k5VAF04KqFzc3IrVtqMp1ApUwVAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljQ29kU2lnUENBMjAxMV8yMDEx
# LTA3LTA4LmNybDBhBggrBgEFBQcBAQRVMFMwUQYIKwYBBQUHMAKGRWh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljQ29kU2lnUENBMjAxMV8y
# MDExLTA3LTA4LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQAG
# Fh/bV8JQyCNPolF41+34/c291cDx+RtW7VPIaUcF1cTL7OL8mVuVXxE4KMAFRRPg
# mnmIvGar27vrAlUjtz0jeEFtrvjxAFqUmYoczAmV0JocRDCppRbHukdb9Ss0i5+P
# WDfDThyvIsoQzdiCEKk18K4iyI8kpoGL3ycc5GYdiT4u/1cDTcFug6Ay67SzL1BW
# XQaxFYzIHWO3cwzj1nomDyqWRacygz6WPldJdyOJ/rEQx4rlCBVRxStaMVs5apao
# pIhrlihv8cSu6r1FF8xiToG1VBpHjpilbcBuJ8b4Jx/I7SCpC7HxzgualOJqnWmD
# oTbXbSD+hdX/w7iXNgn+PRTBmBSpwIbM74LBq1UkQxi1SIV4htD50p0/GdkUieeN
# n2gkiGg7qceATibnCCFMY/2ckxVNM7VWYE/XSrk4jv8u3bFfpENryXjPsbtrj4Ns
# h3Kq6qX7n90a1jn8ZMltPgjlfIOxrbyjunvPllakeljLEkdi0iHv/DzEMQv3Lz5k
# pTdvYFA/t0SQT6ALi75+WPbHZ4dh256YxMiMy29H4cAulO2x9rAwbexqSajplnbI
# vQjE/jv1rnM3BrJWzxnUu/WUyocc8oBqAU+2G4Fzs9NbIj86WBjfiO5nxEmnL9wl
# iz1e0Ow0RJEdvJEMdoI+78TYLaEEAo5I+e/dAs8DojCCB3owggVioAMCAQICCmEO
# kNIAAAAAAAMwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmlj
# YXRlIEF1dGhvcml0eSAyMDExMB4XDTExMDcwODIwNTkwOVoXDTI2MDcwODIxMDkw
# OVowfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UE
# AxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAKvw+nIQHC6t2G6qghBNNLrytlghn0IbKmvpWlCq
# uAY4GgRJun/DDB7dN2vGEtgL8DjCmQawyDnVARQxQtOJDXlkh36UYCRsr55JnOlo
# XtLfm1OyCizDr9mpK656Ca/XllnKYBoF6WZ26DJSJhIv56sIUM+zRLdd2MQuA3Wr
# aPPLbfM6XKEW9Ea64DhkrG5kNXimoGMPLdNAk/jj3gcN1Vx5pUkp5w2+oBN3vpQ9
# 7/vjK1oQH01WKKJ6cuASOrdJXtjt7UORg9l7snuGG9k+sYxd6IlPhBryoS9Z5JA7
# La4zWMW3Pv4y07MDPbGyr5I4ftKdgCz1TlaRITUlwzluZH9TupwPrRkjhMv0ugOG
# jfdf8NBSv4yUh7zAIXQlXxgotswnKDglmDlKNs98sZKuHCOnqWbsYR9q4ShJnV+I
# 4iVd0yFLPlLEtVc/JAPw0XpbL9Uj43BdD1FGd7P4AOG8rAKCX9vAFbO9G9RVS+c5
# oQ/pI0m8GLhEfEXkwcNyeuBy5yTfv0aZxe/CHFfbg43sTUkwp6uO3+xbn6/83bBm
# 4sGXgXvt1u1L50kppxMopqd9Z4DmimJ4X7IvhNdXnFy/dygo8e1twyiPLI9AN0/B
# 4YVEicQJTMXUpUMvdJX3bvh4IFgsE11glZo+TzOE2rCIF96eTvSWsLxGoGyY0uDW
# iIwLAgMBAAGjggHtMIIB6TAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUSG5k
# 5VAF04KqFzc3IrVtqMp1ApUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYD
# VR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUci06AjGQQ7kU
# BU7h6qfHMdEjiTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybC5taWNyb3Nv
# ZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0MjAxMV8yMDExXzAz
# XzIyLmNybDBeBggrBgEFBQcBAQRSMFAwTgYIKwYBBQUHMAKGQmh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0MjAxMV8yMDExXzAz
# XzIyLmNydDCBnwYDVR0gBIGXMIGUMIGRBgkrBgEEAYI3LgMwgYMwPwYIKwYBBQUH
# AgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvZG9jcy9wcmltYXJ5
# Y3BzLmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBwAG8AbABpAGMA
# eQBfAHMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAZ/KG
# pZjgVHkaLtPYdGcimwuWEeFjkplCln3SeQyQwWVfLiw++MNy0W2D/r4/6ArKO79H
# qaPzadtjvyI1pZddZYSQfYtGUFXYDJJ80hpLHPM8QotS0LD9a+M+By4pm+Y9G6XU
# tR13lDni6WTJRD14eiPzE32mkHSDjfTLJgJGKsKKELukqQUMm+1o+mgulaAqPypr
# WEljHwlpblqYluSD9MCP80Yr3vw70L01724lruWvJ+3Q3fMOr5kol5hNDj0L8giJ
# 1h/DMhji8MUtzluetEk5CsYKwsatruWy2dsViFFFWDgycScaf7H0J/jeLDogaZiy
# WYlobm+nt3TDQAUGpgEqKD6CPxNNZgvAs0314Y9/HG8VfUWnduVAKmWjw11SYobD
# HWM2l4bf2vP48hahmifhzaWX0O5dY0HjWwechz4GdwbRBrF1HxS+YWG18NzGGwS+
# 30HHDiju3mUv7Jf2oVyW2ADWoUa9WfOXpQlLSBCZgB/QACnFsZulP0V3HjXG0qKi
# n3p6IvpIlR+r+0cjgPWe+L9rt0uX4ut1eBrs6jeZeRhL/9azI2h15q/6/IvrC4Dq
# aTuv/DDtBEyO3991bWORPdGdVk5Pv4BXIqF4ETIheu9BCrE/+6jMpF3BoYibV3FW
# TkhFwELJm3ZbCoBIa/15n8G9bW1qyVJzEw16UM0xghXUMIIV0AIBATCBlTB+MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNy
# b3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExAhMzAAAAxOmJ+HqBUOn/AAAAAADE
# MA0GCWCGSAFlAwQCAQUAoIHGMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCASO7hG
# dTF3/toiGHfCpo1tE9xackvU+LbKs0xR6B4WCTBaBgorBgEEAYI3AgEMMUwwSqAk
# gCIATQBpAGMAcgBvAHMAbwBmAHQAIABXAGkAbgBkAG8AdwBzoSKAIGh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS93aW5kb3dzMA0GCSqGSIb3DQEBAQUABIIBAAkDOvGS
# Xdnif9qoihq0LkiuxEhEcK6IFhHtETi4kDRdQyP2+eFdUAreSU4T7jNUBgyvYtv+
# r6fOavYZq8H0qxN3fgv4NGqd8Voj1SfNn5qL9F7az80mkCsWVEbLp65A5i9D14k0
# i+1kByY78XbZb7YDfW6ZZ8OVXZo0dLbuAOmLTsn4kK0GxdwGtUGyGt67FHUmOXqm
# oEkAjRyUS2HsxulLKPVo3gOCRc7cpvRaMORY+YHOIUJm3v2jaiWvbyf115I43hTB
# WeQuIBNZb3X8O4M+5MB0rjEGxZuhj/QuULb5ixkBoEF9e5mRsmOfJzLW+x4TN6nT
# FpoLFHrQn0XqhzyhghNGMIITQgYKKwYBBAGCNwMDATGCEzIwghMuBgkqhkiG9w0B
# BwKgghMfMIITGwIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBPAYLKoZIhvcNAQkQAQSg
# ggErBIIBJzCCASMCAQEGCisGAQQBhFkKAwEwMTANBglghkgBZQMEAgEFAAQgkzb9
# 0t6JLWrQLFy+L8FLfBAU82ojtIsSPhSJucOMI38CBlsDEwVqcBgTMjAxODA1MjIw
# ODIxMzkuMjA2WjAHAgEBgAIB9KCBuKSBtTCBsjELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEMMAoGA1UECxMDQU9DMScwJQYDVQQLEx5uQ2lwaGVy
# IERTRSBFU046MERFOC0yREM1LTNDQTkxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2Wggg7KMIIGcTCCBFmgAwIBAgIKYQmBKgAAAAAAAjANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUwNzAxMjE0NjU1WjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAKkdDbx3EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX77XxoSyxfxcPlYcJ2tz5m
# K1vwFVMnBDEfQRsalR3OCROOfGEwWbEwRA/xYIiEVEMM1024OAizQt2TrNZzMFcm
# gqNFDdDq9UeBzb8kYDJYYEbyWEeGMoQedGFnkV+BVLHPk0ySwcSmXdFhE24oxhr5
# hoC732H8RsEnHSRnEnIaIYqvS2SJUGKxXf13Hz3wV3WsvYpCTUBR0Q+cBj5nf/Vm
# wAOWRH7v0Ev9buWayrGo8noqCjHw2k4GkbaICDXoeByw6ZnNPOcvRLqn9NxkvaQB
# wSAJk3jN/LzAyURdXhacAQVPIk0CAwEAAaOCAeYwggHiMBAGCSsGAQQBgjcVAQQD
# AgEAMB0GA1UdDgQWBBTVYzpcijGQ80N7fEYbxTNoWoVtVTAZBgkrBgEEAYI3FAIE
# DB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNV
# HSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVo
# dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAC
# hj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1
# dF8yMDEwLTA2LTIzLmNydDCBoAYDVR0gAQH/BIGVMIGSMIGPBgkrBgEEAYI3LgMw
# gYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9QS0kvZG9j
# cy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8A
# UABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQEL
# BQADggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z66bM9TG+zwXiqf76V20ZMLPCxWbJ
# at/15/B4vceoniXj+bzta1RXCCtRgkQS+7lTjMz0YBKKdsxAQEGb3FwX/1z5Xhc1
# mCRWS3TvQhDIr79/xn/yN31aPxzymXlKkVIArzgPF/UveYFl2am1a+THzvbKegBv
# SzBEJCI8z+0DpZaPWSm8tv0E4XCfMkon/VWvL/625Y4zu2JfmttXQOnxzplmkIz/
# amJ/3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/fZZqkHimbdLhnPkd/DjYlPTGpQqW
# hqS9nhquBEKDuLWAmyI4ILUl5WTs9/S/fmNZJQ96LjlXdqJxqgaKD4kWumGnEcua
# 2A5HmoDF0M2n0O99g/DhO3EJ3110mCIIYdqwUB5vvfHhAN/nMQekkzr3ZUd46Pio
# SKv33nJ+YWtvd6mBy6cJrDm77MbL2IK0cs0d9LiFAR6A+xuJKlQ5slvayA1VmXqH
# czsI5pgt6o3gMy4SKfXAL1QnIffIrE7aKLixqduWsqdCosnPGUFN4Ib5KpqjEWYw
# 07t0MkvfY3v1mYovG8chr1m1rtxEPJdQcdeh0sVV42neV8HR3jDA/czmTfsNv11P
# 6Z0eGTgvvM9YBS7vDaBQNdrvCScc1bN+NR4Iuto229Nfj950iEkSMIIE2TCCA8Gg
# AwIBAgITMwAAAKb9UuCLFic/AAAAAAAApjANBgkqhkiG9w0BAQsFADB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0xNjA5MDcxNzU2NTFaFw0xODA5MDcx
# NzU2NTFaMIGyMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMQww
# CgYDVQQLEwNBT0MxJzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjowREU4LTJEQzUt
# M0NBOTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMG4zZ4JJ7Rwi4X/HVpI0cDm52Fw
# 9T2qVFvA3dWywBDrrkSaXKGJqa9hxVP0Amz9v2zL0fOSmhKgEW2FNz5x3dGg75oh
# 3dhbJoOQDyZ/jR4e4+MkGy0y0bTvt8DNCkfY4E81x7sEOEUma2+o4oUms43097O8
# WfAiGJj/VzQYG07RtO/Y7iqIbf3+HxVdKYFrdjkwxf99I6JEdBizCDTJucjXzYzv
# UU3g8w/vOrQt0rMl+b9kkxdUL+/IUWOVJbEso0hxyGeqcYfY16/K5xudoDkyxaZv
# ahvVGHWUqap5Wazf247Sykmcd0Gq2DA5ZuSReNTtJ+mXw35ZRPotuWpxA90CAwEA
# AaOCARswggEXMB0GA1UdDgQWBBQO4cVDySYb3MuHu9xMZtcGvNHAJjAfBgNVHSME
# GDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVodHRw
# Oi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1TdGFQ
# Q0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4IBAQCEICehBui41vySOspI1p3L0JaOswTayK6EX6s6
# ovTatWJWLwrBso8+tx8sYFp1Is5Hkd9BetmekDQro1gDDcOGxpbVuoXR42O0GVG9
# Z482ZezWGSaXB4z6Vpf+zFwZbXcGWOnRC68aqwsU908JUMMZa5jMIeMlhtZBN+tl
# LdlsbI9H/xdPvaVQNqOrwtx1cOFhWu9BGyoD0QZ5XsqmQxirV0STgcDrQqgTBdQY
# OJxbJjbcleszpbRwmvy9nW+kB6TfHkKnDzu5QbG2S7+EEkXZbs9YfLbjawuuAAbW
# pJa7ZxEvO1Dpkmz1mlnIh+SvZL5VLDNwNh+L9OrmnAE9pDsvoYIDdDCCAlwCAQEw
# geKhgbikgbUwgbIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# DDAKBgNVBAsTA0FPQzEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNOOjBERTgtMkRD
# NS0zQ0E5MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiUK
# AQEwCQYFKw4DAhoFAAMVAH+gMGx8o+rq8oEE0zWi59zi1IU9oIHBMIG+pIG7MIG4
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMQwwCgYDVQQLEwNB
# T0MxJzAlBgNVBAsTHm5DaXBoZXIgTlRTIEVTTjoyNjY1LTRDM0YtQzVERTErMCkG
# A1UEAxMiTWljcm9zb2Z0IFRpbWUgU291cmNlIE1hc3RlciBDbG9jazANBgkqhkiG
# 9w0BAQUFAAIFAN6tvC8wIhgPMjAxODA1MjEyMTQ0MTVaGA8yMDE4MDUyMjIxNDQx
# NVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA3q28LwIBADAHAgEAAgIBnjAHAgEA
# AgIrrTAKAgUA3q8NrwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMB
# oAowCAIBAAIDFuNgoQowCAIBAAIDB6EgMA0GCSqGSIb3DQEBBQUAA4IBAQAAK3JR
# bM3zuj8E+o7gY4PxTPH7bRx+D6J0zjSFEr8YREt8kipYSid6+Ffxql5zjms/s9e3
# pbw4U99mENogmxDWecH0XaZZpzlIn+Qnw1v9VmGPWEOn7Ewd9bz1cbLLoy5HSLoc
# n2ekE3jnWVjtV2atgAoB3besAxChBR4Ikf4+DNvgiGJ7VcJonxUj49h43PcP5xOh
# OkyPbOQWkG8B1vcde8dMbbHIcU8QOpJCJqObT1uXZFAKv7oavzsixIQ3/1cUsZAu
# EGJc3Mtx/VtKSvlN1BMCdabsXqwkr63/U8Me2FpwBcd0ZUkRJH7S92O0ip6xk1cY
# //LcevHa1VBjB31sMYIC9TCCAvECAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTACEzMAAACm/VLgixYnPwAAAAAAAKYwDQYJYIZIAWUDBAIBBQCgggEy
# MBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgOnqS
# 0Jwqx+6uY/2ecjs4KS0wBSs0r+w4Movq7t3Yh7AwgeIGCyqGSIb3DQEJEAIMMYHS
# MIHPMIHMMIGxBBR/oDBsfKPq6vKBBNM1oufc4tSFPTCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAApv1S4IsWJz8AAAAAAACmMBYEFEdv
# 273oxIkpfDKX72S8mcUw9TO8MA0GCSqGSIb3DQEBCwUABIIBAIH2oxdO025YpcPZ
# KL7ZjImR6xov2vHylIfKPOAVYgEYcRPOT8sadaAIKVyvF+xBcdmeEMIvFGHfPfNV
# 8EaKaSHCkfxR9ySUieQysfKTbztayHj/hcxAeI2HotHLFCeRkK4AGEQAA7mRUEM8
# zRYhHWQVd/YT2/H8kSUGI5Ie+JMwfQIo/ppy65C1rg6XK1IQLdVUWxPWnkaIhCZN
# fi1TtT2WUv9IMYNWwSk+3UWfBx4oNFFeehqWL+LLhOZ9OGtPDJdtOuQ0yb0XF+oK
# F9y/fKf6dAI4cWv9YOpeqhXH7TAHc1MBQQRTelJIlK+ecF02du8yeh93/3uoKTYq
# QvHdl5k=
# SIG # End signature block