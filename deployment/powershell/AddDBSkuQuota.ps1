[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("MySQL", "SQLServer")]
    [String] $dbsku,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,

    [Parameter(Mandatory = $true)]
    [String] $azsLocation,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

    [parameter(Mandatory = $false)]
    [String] $skipMySQL,

    [parameter(Mandatory = $false)]
    [String] $skipMSSQL,

    [Parameter(Mandatory = $true)]
    [String] $sqlServerInstance,

    [Parameter(Mandatory = $true)]
    [String] $databaseName,

    [Parameter(Mandatory = $true)]
    [String] $tableName
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

$logFolder = "$($dbsku)SKUQuota"
$logName = $logFolder
$progressName = $logFolder
$skipRP = $false

if ($dbsku -eq "MySQL") {
    if ($skipMySQL -eq $true) {
        $skipRP = $true
    }
}
elseif ($dbsku -eq "SQLServer") {
    if ($skipMSSQL -eq $true) {
        $skipRP = $true
    }
}

### SET LOG LOCATION ###
$logDate = Get-Date -Format FileDate
New-Item -ItemType Directory -Path "$ScriptLocation\Logs\$logDate\$logFolder" -Force | Out-Null
$logPath = "$ScriptLocation\Logs\$logDate\$logFolder"

### START LOGGING ###
$runTime = $(Get-Date).ToString("MMdd-HHmmss")
$fullLogPath = "$logPath\$($logName)$runTime.txt"
Start-Transcript -Path "$fullLogPath" -Append -IncludeInvocationHeader

$progressStage = $progressName
$progressCheck = CheckProgress -progressStage $progressStage

if ($progressCheck -eq "Complete") {
    Write-Output "ASDK Configurator Stage: $progressStage previously completed successfully"
}
elseif (($skipRP -eq $false) -and ($progressCheck -ne "Complete")) {
    # We first need to check if in a previous run, this section was skipped, but now, the user wants to add this, so we need to reset the progress.
    if ($progressCheck -eq "Skipped") {
        Write-Output "Operator previously skipped this step, but now wants to perform this step. Updating ConfigASDK database to Incomplete."
        # Update the ConfigASDK database with skip status
        StageReset -progressStage $progressStage
        $progressCheck = CheckProgress -progressStage $progressStage
    }
    if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
        try {
            if ($progressCheck -eq "Failed") {
                # Update the ConfigASDK database back to incomplete status if previously failed
                StageReset -progressStage $progressStage
                $progressCheck = CheckProgress -progressStage $progressStage
            }
            # Logout to clean up
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force

            # Need to ensure this stage doesn't start before the DBRP stage has finished
            $dbJobCheck = CheckProgress -progressStage "$($dbsku)RP"
            while ($dbJobCheck -ne "Complete") {
                Write-Output "The $($dbsku)RP stage of the process has not yet completed. Checking again in 20 seconds"
                Start-Sleep -Seconds 20
                $dbJobCheck = CheckProgress -progressStage "$($dbsku)RP"
                if ($dbJobCheck -eq "Failed") {
                    throw "The $($dbsku)RP stage of the process has failed. This should fully complete before the SKU and Quota are created. Check the $($dbsku)RP log, ensure that step is completed first, and rerun."
                }
            }

            ### Login to Azure Stack ###
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            $sub = Get-AzureRmSubscription | Where-Object {$_.Name -eq "Default Provider Subscription"}
            $azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
            $subID = $azureContext.Subscription.Id
            $azureEnvironment = Get-AzureRmEnvironment -Name AzureStackAdmin

            # Set the variables and gather token for creating the SKU & Quota
            if ($dbsku -eq "MySQL") {
                $skuFamily = "MySQL"
                $skuName = "MySQL57"
                $skuTier = "Standalone"
                $dbArmEndpoint = $ArmEndpoint.TrimEnd("/", "\");
                $databaseAdapterNamespace = "Microsoft.MySQLAdapter.Admin"
                $apiVersion = "2017-08-28" 
                $quotaName = "mysqldefault"
                $quotaResourceCount = "10"
                $quotaResourceSizeMB = "1024"
            }
            elseif ($dbsku -eq "SQLServer") {
                $skuFamily = "SQLServer"
                $skuEdition = "Evaluation"
                $skuName = "MSSQL2017"
                $skuTier = "Standalone"
                $dbArmEndpoint = $ArmEndpoint.TrimEnd("/", "\");
                $databaseAdapterNamespace = "Microsoft.SQLAdapter.Admin"
                $apiVersion = "2017-08-28"
                $quotaName = "sqldefault"
                $quotaResourceCount = "10"
                $quotaResourceSizeMB = "1024"
            }

            # Fetch the tokens
            $dbToken = $null
            $dbTokens = $null
            $dbTokens = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems()
            $dbToken = $dbTokens | Where-Object Resource -EQ $azureEnvironment.ActiveDirectoryServiceEndpointResourceId | Where-Object DisplayableId -EQ $AzureContext.Account.Id | Sort-Object ExpiresOn | Select-Object -Last 1 -ErrorAction Stop

            # Build the header for authorization
            $dbHeaders = @{ 'authorization' = "Bearer $($dbToken.AccessToken)"}

            # Build the URIs
            $skuUri = ('{0}/subscriptions/{1}/providers/{2}/locations/{3}/skus/{4}?api-version={5}' -f $dbArmEndpoint, $subID, $databaseAdapterNamespace, $azsLocation, $skuName, $apiVersion)
            $quotaUri = ('{0}/subscriptions/{1}/providers/{2}/locations/{3}/quotas/{4}?api-version={5}' -f $dbArmEndpoint, $subID, $databaseAdapterNamespace, $azsLocation, $quotaName, $apiVersion)

            # Create the request body for SKU
            $skuTenantNamespace = $databaseAdapterNamespace.TrimEnd(".Admin");
            $skuResourceType = '{0}/databases' -f $skuTenantNamespace
            $skuIdForRequestBody = '/subscriptions/{0}/providers/{1}/locations/{2}/skus/{3}' -f $subID, $databaseAdapterNamespace, $azsLocation, $skuName
            if ($dbsku -eq "MySQL") {
                $skuRequestBody = @{
                    properties = @{
                        resourceType = $skuResourceType
                        sku          = @{
                            family = $skuFamily
                            name   = $skuName
                            tier   = $skuTier
                        }
                    }
                    id         = $skuIdForRequestBody
                    name       = $skuName
                }
            }
            elseif ($dbsku -eq "SQLServer") {
                $skuRequestBody = @{
                    properties = @{
                        resourceType = $skuResourceType
                        sku          = @{
                            family = $skuFamily
                            kind   = $skuEdition
                            name   = $skuName
                            tier   = $skuTier
                        }
                    }
                    id         = $skuIdForRequestBody
                    name       = $skuName
                }
            }
            $skuRequestBodyJson = $skuRequestBody | ConvertTo-Json

            # Create the request body for Quota
            $quotaIdForRequestBody = '/subscriptions/{0}/providers/{1}/locations/{2}/quotas/{3}' -f $subID, $databaseAdapterNamespace, $azsLocation, $quotaName
            $quotaRequestBody = @{
                properties = @{
                    resourceCount       = $quotaResourceCount
                    totalResourceSizeMB = $quotaResourceSizeMB
                }
                id         = $quotaIdForRequestBody
                name       = $quotaName
            }
            $quotaRequestBodyJson = $quotaRequestBody | ConvertTo-Json

            # Create the SKU
            Write-Output "Creating new $($dbsku) Resource Provider SKU with name: $($skuName), adapter namespace: $($databaseAdapterNamespace)" -Verbose
            try {
                # Make the REST call
                $skuResponse = Invoke-WebRequest -Uri $skuUri -Method Put -Headers $dbHeaders -Body $skuRequestBodyJson -ContentType "application/json" -UseBasicParsing
                $skuResponse
            }
            catch {
                $message = $_.Exception.Message
                Write-Error -Message ("[New-AzureStackRmDatabaseAdapterSKU]::Failed to create $($dbsku) Resource Provider SKU with name {0}, failed with error: {1}" -f $skuName, $message) 
            }
            # Create the Quota
            Write-Output "Creating new $($dbsku) Resource Provider Quota with name: $($quotaName), adapter namespace: $($databaseAdapterNamespace)" -Verbose
            try {
                # Make the REST call
                $quotaResponse = Invoke-WebRequest -Uri $quotaUri -Method Put -Headers $dbHeaders -Body $quotaRequestBodyJson -ContentType "application/json" -UseBasicParsing
                $quotaResponse
            }
            catch {
                $message = $_.Exception.Message
                Write-Error -Message ("Failed to create $($dbsku) Resource Provider Quota with name {0}, failed with error: {1}" -f $quotaName, $message) 
            }
            # Update the ConfigASDK database with successful completion
            $progressStage = $progressName
            StageComplete -progressStage $progressStage
        }
        catch {
            StageFailed -progressStage $progressStage
            Set-Location $ScriptLocation
            throw $_.Exception.Message
            return
        }
    }
}
elseif (($skipRP) -and ($progressCheck -ne "Complete")) {
    # Update the ConfigASDK database with skip status
    $progressStage = $progressName
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue