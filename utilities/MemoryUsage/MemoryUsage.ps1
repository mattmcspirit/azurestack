<#

.SYNOPSIS
For a particular user, gather total memory usage associated with deployed VMs.

.DESCRIPTION
If you'd like to understand the total VM memory consumption associated with your user account, you can use this script to query
your Azure Stack system. It can only be used to target the Administration OR tenant space, and not both simultaneously. It will query and return
the total memory consumed across both native virtual machines, and virtual machines deployed as part of a VM Scale Set (VMSS)

.NOTES
File Name : MemoryUsage.ps1
Author    : Matt McSpirit
Version   : 1.0
Date      : 28-June-2019
Update    : 28-June-2019
Requires  : PowerShell Version 5.0 or above
Module    : Tested with AzureRM 2.5.0 and Azure Stack 1.7.2 already installed

.EXAMPLE
.\MemoryUsage.ps1 -authType AzureAd -tenant "contoso.onmicrosoft.com" -armEndpoint "https://adminmanagement.local.azurestack.external"
.\MemoryUsage.ps1 -authType AzureAd -tenant "contoso.onmicrosoft.com" -armEndpoint "https://management.local.azurestack.external"

These examples will use Azure AD as the authentication model, and the same tenant. The difference here is, that the first example is
targeting the administration space, and the second is targeting the tenant space.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("AzureAd", "ADFS")]
    [String] $authType,

    [Parameter(Mandatory = $true)]
    [String] $tenant,

    [Parameter(Mandatory = $true)]
    [String] $armEndpoint
)

$Global:VerbosePreference = "SilentlyContinue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

Write-Host "Beginning login process into your Azure Stack system"
Write-Host "Selected Active Directory authentication type is $authType"
Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$armEndpoint" | Out-Null
Write-Host "Using the following Azure Stack ARM Endpoint: $armEndpoint"
Write-Host "Obtaining tenant name"
$AuthEndpoint = (Get-AzureRmEnvironment -Name "AzureStackAdmin").ActiveDirectoryAuthority.TrimEnd('/')

if ($authType.ToString() -like "AzureAd") {
    $tenantId = (Invoke-Restmethod -Verbose:$false "$($AuthEndpoint)/$($tenant)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
}
elseif ($authType.ToString() -like "ADFS") {
    $tenantId = (Invoke-Restmethod -Verbose:$false "$($AuthEndpoint)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
}

# After signing in to your environment, Azure Stack cmdlets
# can be easily targeted at your Azure Stack instance.
Write-Host "Logging into Azure Stack. Triggering credential pop-up."
Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantId | Out-Null

Clear-Host

$sub = Get-AzsSubscription
$subMemory = 0
$totalSubMemory = 0

foreach ($s in $sub) {
    $subMemory = 0
    $totalVMMemoryUse = 0
    $totalVmssMemoryUse = 0
    Select-AzureRmSubscription -Subscription $s.SubscriptionId | Out-Null

    # Get Native Virtual Machine memory first
    $VM = Get-AzureRmVM
    $location = (Get-AzureRmLocation).Location

    foreach ($v in $vm) {
        $memory = ((Get-AzureRmVMSize -Location $location | Where-Object { $_.Name -eq $v.HardwareProfile.VmSize }).MemoryInMB) / 1024
        Write-Host "SUBSCRIPTION NAME: $($s.DisplayName)  |  VM NAME: $($v.Name)  |  VM SIZE: $($v.HardwareProfile.VmSize)  |  VM MEMORY USAGE: $($memory)GB"
        $vmMemory += $memory
        $totalVMMemoryUse += $memory
    }

    # Then get VMSS memory usage
    $vmSSlist = Get-AzureRmVmss -ErrorAction SilentlyContinue
    foreach ($vmSS in $vmSSlist) {
        $vmlist = Get-AzureRmVmssVM -VMScaleSetName $($vmSS.Name) -ResourceGroupName $($vmSS.ResourceGroupName) -ErrorAction SilentlyContinue
        foreach ($v in $vmlist) {
            $memory = ((Get-AzureRmVMSize -Location east | Where-Object { $_.Name -eq ($v.Sku).Name }).MemoryInMB) / 1024
            Write-Host "SUBSCRIPTION NAME: $($s.DisplayName)  |  VM NAME: $($v.Name)  |  VM SIZE: $(($v.Sku).Name)  |  VM MEMORY USAGE: $($memory)GB"
            $vmssMemory += $memory
            $totalVmssMemoryUse += $memory
        }
    }
    $subMemory = $totalVMMemoryUse += $totalVmssMemoryUse
    $totalSubMemory += $subMemory
    Write-Host "Subscription $($s.DisplayName) virtual machine memory usage: $($subMemory)GB`n" -ForegroundColor GREEN
}
Write-Host "Final VM Memory Consumption: $($totalSubMemory)GB across your subscriptions" -ForegroundColor GREEN