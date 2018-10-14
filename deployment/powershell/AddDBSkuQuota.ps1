[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ConfigASDKProgressLogPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet("MySQL", "SQLServer")]
    [String] $dbsku,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

    [parameter(Mandatory = $false)]
    [String] $skipMySQL,

    [parameter(Mandatory = $false)]
    [String] $skipMSSQL
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

### DOWNLOADER FUNCTION #####################################################################################################################################
#############################################################################################################################################################
function DownloadWithRetry([string] $downloadURI, [string] $downloadLocation, [int] $retries) {
    while ($true) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
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

$logFolder = "$($dbsku)Sku"
$logName = $logFolder
$progressName = $logFolder
if ($dbsku -eq "MySQL") {
    if ($skipMySQL -eq $true) {
        $skipRP = $true
    }
    else {
        $skipRP = $false
    }
}
elseif ($dbsku -eq "SQLServer") {
    if ($skipMSSQL -eq $true) {
        $skipRP = $true
    }
    else {
        $skipRP = $false
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

$progress = Import-Csv -Path $ConfigASDKProgressLogPath
$RowIndex = [array]::IndexOf($progress.Stage, "$progressName")

if ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose -Message "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}
elseif (($skipRP -eq $false) -and ($progress[$RowIndex].Status -ne "Complete")) {
    # We first need to check if in a previous run, this section was skipped, but now, the user wants to add this, so we need to reset the progress.
    if ($progress[$RowIndex].Status -eq "Skipped") {
        Write-Verbose -Message "Operator previously skipped this step, but now wants to perform this step. Updating ConfigASDKProgressLog.csv file to Incomplete."
        # Update the ConfigASDKProgressLog.csv file with successful completion
        $progress = Import-Csv -Path $ConfigASDKProgressLogPath
        $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
        $progress[$RowIndex].Status = "Incomplete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
    }
    if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
        try {
            # Logout to clean up
            Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
            Clear-AzureRmContext -Scope CurrentUser -Force

            # Need to ensure this stage doesn't start before the Windows Server images have been put into the PIR
            $progress = Import-Csv -Path $ConfigASDKProgressLogPath
            $dbJobCheck = [array]::IndexOf($progress.Stage, "$($dbsku)RP")
            while (($progress[$mySQLJobCheck].Status -ne "Complete")) {
                Write-Verbose -Message "The $($dbsku)RP stage of the process has not yet completed. Checking again in 10 seconds"
                Start-Sleep -Seconds 10
                if ($progress[$dbJobCheck].Status -eq "Failed") {
                    throw "The $($dbsku)RP stage of the process has failed. This should fully complete before the SKU and Quota are created. Check the $($dbsku)RP log, ensure that step is completed first, and rerun."
                }
                $progress = Import-Csv -Path $ConfigASDKProgressLogPath
                $dbJobCheck = [array]::IndexOf($progress.Stage, "$($dbsku)RP")
            }
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

            ### Login to Azure Stack ###
            $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
            Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
            Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $tenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
            $sub = Get-AzureRmSubscription | Where-Object {$_.Name -eq "Default Provider Subscription"}
            $azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
            $subID = $azureContext.Subscription.Id
            $azureEnvironment = Get-AzureRmEnvironment -Name AzureStackAdmin

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
            Write-CustomVerbose -Message "Creating new $($dbsku) Resource Provider SKU with name: $($skuName), adapter namespace: $($databaseAdapterNamespace)" -Verbose
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
            Write-CustomVerbose -Message "Creating new $($dbsku) Resource Provider Quota with name: $($quotaName), adapter namespace: $($databaseAdapterNamespace)" -Verbose
            try {
                # Make the REST call
                $quotaResponse = Invoke-WebRequest -Uri $quotaUri -Method Put -Headers $dbHeaders -Body $quotaRequestBodyJson -ContentType "application/json" -UseBasicParsing
                $quotaResponse
            }
            catch {
                $message = $_.Exception.Message
                Write-Error -Message ("Failed to create $($dbsku) Resource Provider Quota with name {0}, failed with error: {1}" -f $quotaName, $message) 
            }
            # Update the ConfigASDKProgressLog.csv file with successful completion
            Write-Verbose "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
            $progress = Import-Csv -Path $ConfigASDKProgressLogPath
            $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
            $progress[$RowIndex].Status = "Complete"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
        }
        catch {
            Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
            $progress = Import-Csv -Path $ConfigASDKProgressLogPath
            $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
            $progress[$RowIndex].Status = "Failed"
            $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
            Write-Output $progress | Out-Host
            Set-Location $ScriptLocation
            throw $_.Exception.Message
            return
        }
    }
}
elseif (($skipRP) -and ($progress[$RowIndex].Status -ne "Complete")) {
    Write-Verbose -Message "Operator chose to skip Resource Provider Deployment`r`n"
    # Update the ConfigASDKProgressLog.csv file with successful completion
    $progress = Import-Csv -Path $ConfigASDKProgressLogPath
    $RowIndex = [array]::IndexOf($progress.Stage, "$progressName")
    $progress[$RowIndex].Status = "Skipped"
    $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
    Write-Output $progress | Out-Host
}
Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue