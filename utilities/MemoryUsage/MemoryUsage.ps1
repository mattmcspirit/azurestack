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
.\MemoryUsage.ps1 -authType AzureAd -tenant "contoso.onmicrosoft.com" -domainSuffix "local.azurestack.external"

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
    [String] $domainSuffix
)

$Global:VerbosePreference = "SilentlyContinue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

Write-Host "Beginning login process into your Azure Stack system"
Write-Host "Selected Active Directory authentication type is $authType"

Write-Host "Creating text file to record memory consumption"
$txtPath = ".\MemoryUsage.txt"
Remove-Item -Path $txtPath -Confirm:$false -Force -ErrorAction SilentlyContinue | Out-Null
New-Item "$txtPath" -ItemType file -Force | Out-Null
$date = $(Get-Date).ToString("MMdd-HHmmss")
Write-Output "VM Memory Usage - $date" >> $txtPath
Write-Output "-------------------------------------------------------------`n" >> $txtPath

Write-Host "Prompting for credentials"
$creds = Get-Credential -Message "Please enter your Azure Stack credentials"

Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "https://adminmanagement.$domainSuffix" | Out-Null
Add-AzureRMEnvironment -Name "AzureStackUser" -ArmEndpoint "https://management.$domainSuffix" | Out-Null

Write-Host "Obtaining tenant name"
$AuthEndpoint = (Get-AzureRmEnvironment -Name "AzureStackAdmin").ActiveDirectoryAuthority.TrimEnd('/')

if ($authType.ToString() -like "AzureAd") {
    $tenantId = (Invoke-Restmethod -Verbose:$false "$($AuthEndpoint)/$($tenant)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
}
elseif ($authType.ToString() -like "ADFS") {
    $tenantId = (Invoke-Restmethod -Verbose:$false "$($AuthEndpoint)/.well-known/openid-configuration").issuer.TrimEnd('/').Split('/')[-1]
}

Clear-Host

$environments = Get-AzureRmEnvironment | Where-Object { $_.Name -like "*AzureStack*" } | Sort-Object -Property Name
foreach ($e in $environments) {
    Write-Host "`nLogging into Azure Stack, into the $($e.Name) environment.`n" -ForegroundColor Cyan 
    Add-AzureRmAccount -EnvironmentName $e.Name -Credential $creds -TenantId $tenantId | Out-Null
    
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
            Write-Output "SUBSCRIPTION NAME: $($s.DisplayName)  |  VM NAME: $($v.Name)  |  VM SIZE: $($v.HardwareProfile.VmSize)  |  VM MEMORY USAGE: $($memory)GB" >> $txtPath
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
                Write-Output "SUBSCRIPTION NAME: $($s.DisplayName)  |  VM NAME: $($v.Name)  |  VM SIZE: $(($v.Sku).Name)  |  VM MEMORY USAGE: $($memory)GB" >> $txtPath
                $vmssMemory += $memory
                $totalVmssMemoryUse += $memory
            }
        }
        $subMemory = $totalVMMemoryUse += $totalVmssMemoryUse
        $totalSubMemory += $subMemory
        if ($subMemory -gt 0) {
            Write-Host "Subscription $($s.DisplayName) virtual machine memory usage: $($subMemory)GB`n" -ForegroundColor DarkYellow
            Write-Output "Subscription $($s.DisplayName) virtual machine memory usage: $($subMemory)GB`n" >> $txtPath
        }
    }
    Write-Host "Final VM Memory Consumption: $($totalSubMemory)GB across your subscriptions in the $($e.Name) environment" -ForegroundColor GREEN
    Write-Output "Final VM Memory Consumption: $($totalSubMemory)GB across your subscriptions in the $($e.Name) environment`n" >> $txtPath
}
$filePath = (Get-ChildItem -Path $txtPath).FullName
Write-Host "`nPlease see a record of the final results in the file located at $filePath" -ForegroundColor Green