[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("MySQL", "SQLServer")]
    [String] $dbsku,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [pscredential] $azsCreds,

    [Parameter(Mandatory = $true)]
    [String] $customDomainSuffix,
    
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
Start-Transcript -Path "$fullLogPath" -Append
Write-Host "Creating log folder"
Write-Host "Log folder has been created at $logPath"
Write-Host "Log file stored at $fullLogPath"
Write-Host "Starting logging"
Write-Host "Log started at $runTime"

$progressStage = $progressName
$progressCheck = CheckProgress -progressStage $progressStage

if ($progressCheck -eq "Complete") {
    Write-Host "Azure Stack POC Configurator Stage: $progressStage previously completed successfully"
}
elseif (($skipRP -eq $false) -and ($progressCheck -ne "Complete")) {
    # We first need to check if in a previous run, this section was skipped, but now, the user wants to add this, so we need to reset the progress.
    if ($progressCheck -eq "Skipped") {
        Write-Host "Operator previously skipped this step, but now wants to perform this step. Updating AzSPoC database to Incomplete."
        # Update the AzSPoC database with skip status
        StageReset -progressStage $progressStage
        $progressCheck = CheckProgress -progressStage $progressStage
    }
    if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
        try {
            if ($progressCheck -eq "Failed") {
                # Update the AzSPoC database back to incomplete status if previously failed
                StageReset -progressStage $progressStage
                $progressCheck = CheckProgress -progressStage $progressStage
            }
            Write-Host "Clearing previous Azure/Azure Stack logins"
            Get-AzContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzContext -Force | Out-Null
            Clear-AzContext -Scope CurrentUser -Force
            Disable-AzContextAutosave -Scope CurrentUser

            # Need to ensure this stage doesn't start before the DBRP stage has finished
            $dbJobCheck = CheckProgress -progressStage "$($dbsku)RP"
            while ($dbJobCheck -ne "Complete") {
                Write-Host "The $($dbsku)RP stage of the process has not yet completed. Checking again in 20 seconds"
                Start-Sleep -Seconds 20
                $dbJobCheck = CheckProgress -progressStage "$($dbsku)RP"
                if ($dbJobCheck -eq "Failed") {
                    Write-Host "The $($dbsku)RP stage of the process looks like it's failed. Checking again in 60 seconds to confirm"
                    Start-Sleep -Seconds 60
                    $dbJobCheck = CheckProgress -progressStage "$($dbsku)RP"
                    if ($dbJobCheck -eq "Failed") {
                        throw "The $($dbsku)RP stage of the process has failed. This should fully complete before the SKU and Quota are created. Check the $($dbsku)RP log, ensure that step is completed first, and rerun."
                    }
                }
            }

            ### Login to Azure Stack ###
            Write-Host "Logging into Azure Stack"
            $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
            Add-AzEnvironment -Name "AzureStackAdmin" -ARMEndpoint "$ArmEndpoint" -ErrorAction Stop
            Connect-AzAccount -Environment "AzureStackAdmin" -Tenant $tenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
            $sub = Get-AzSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
            Get-AzSubscription -SubscriptionID $sub.SubscriptionId | Set-AzContext
            # Get Azure Stack location
            $azsLocation = (Get-AzLocation).DisplayName
            $subID = $sub.SubscriptionId

            Write-Host "Setting variables for creating the SKU and Quota"
            # Set the variables and gather token for creating the SKU & Quota
            if ($dbsku -eq "MySQL") {
                $skuFamily = "MySQL"
                $skuName = "MySQL80"
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

            Write-Host "Fetching tokens for login"
            # Retrieve the access token
            $dbToken = $null
            $AzContext = Get-AzContext
            <# $dbToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
                $AzContext.'Account',
                $AzContext.'Environment',
                $AzContext.'Tenant'.'Id',
                $null,
                [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never,
                $null,
                'https://management.azure.com/'
            )
            #>

            $getProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile;
            $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($getProfile)
            $dbToken = $profileClient.AcquireAccessToken($AzContext.Subscription.TenantId).AccessToken

            # Build the header for authorization
            Write-Host "Building the headers"
            $dbHeaders = @{ 'authorization' = "Bearer $dbToken" }

            # Build the URIs
            Write-Host "Building the URIs"
            $skuUri = ('{0}/subscriptions/{1}/providers/{2}/locations/{3}/skus/{4}?api-version={5}' -f $dbArmEndpoint, $subID, $databaseAdapterNamespace, $azsLocation, $skuName, $apiVersion)
            $quotaUri = ('{0}/subscriptions/{1}/providers/{2}/locations/{3}/quotas/{4}?api-version={5}' -f $dbArmEndpoint, $subID, $databaseAdapterNamespace, $azsLocation, $quotaName, $apiVersion)

            # Create the request body for SKU
            Write-Host "Creating the request body for the SKU: $skuName"
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
            Write-Host "Creating the request body for the quota: $quotaName"
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
            Write-Host "Creating new $($dbsku) Resource Provider SKU with name: $($skuName), adapter namespace: $($databaseAdapterNamespace)" -Verbose
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
            Write-Host "Creating new $($dbsku) Resource Provider Quota with name: $($quotaName), adapter namespace: $($databaseAdapterNamespace)" -Verbose
            try {
                # Make the REST call
                $quotaResponse = Invoke-WebRequest -Uri $quotaUri -Method Put -Headers $dbHeaders -Body $quotaRequestBodyJson -ContentType "application/json" -UseBasicParsing
                $quotaResponse
            }
            catch {
                $message = $_.Exception.Message
                Write-Error -Message ("Failed to create $($dbsku) Resource Provider Quota with name {0}, failed with error: {1}" -f $quotaName, $message) 
            }
            # Update the AzSPoC database with successful completion
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
    # Update the AzSPoC database with skip status
    $progressStage = $progressName
    StageSkipped -progressStage $progressStage
}
Set-Location $ScriptLocation
$endTime = $(Get-Date).ToString("MMdd-HHmmss")
Write-Host "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue