<#

.SYNOPSIS
Allows you to reset the status of AzSPOC Stages in the AzSPOC Database.

.DESCRIPTION
The script will allow you to select a stage from the database, and it will be reset back to "Incomplete" - this is useful for troubleshooting

.NOTES
File Name : ResetStatus.ps1
Author    : Matt McSpirit
Version   : 1.0
Date      : 7-March-2021
Update    : 7-March-2021
Requires  : PowerShell Version 5.0 or above
Module    : Tested with latest SQL Server Module

.EXAMPLE
.\ResetStatus.ps1

#>

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

$sqlServerInstance = '(localdb)\MSSQLLocalDB'
$databaseName = "AzSPoC"
$tableName = "Progress"

$selectSteps = @('GetScripts', 'CheckPowerShell', 'InstallPowerShell', 'DownloadTools', 'CheckCerts', 'HostConfiguration', 'Registration', `
        'AdminPlanOffer', 'UbuntuServerImage', 'WindowsUpdates', 'ServerCore2016Image', 'ServerFull2016Image', 'ServerCore2019Image', `
        'ServerFull2019Image', 'MySQL57GalleryItem', 'MySQL80GalleryItem', 'SQLServerGalleryItem', 'AddVMExtensions', 'AddDBRPImage', `
        'MySQLRP', 'SQLServerRP', 'MySQLSKUQuota', 'SQLServerSKUQuota', 'UploadScripts', 'MySQLDBVM', 'SQLServerDBVM', 'MySQLAddHosting', `
        'SQLServerAddHosting', 'AppServiceFileServer', 'AppServiceSQLServer', 'DownloadAppService', 'AddAppServicePreReqs', 'DeployAppService', `
        'RegisterNewRPs', 'UserPlanOffer', 'InstallHostApps', 'CreateOutput') `
| Out-GridView -Title "Select the steps you wish to reset to Incomplete - Hold CTRL to make multiple selections" -PassThru

if ($null -ne $selectSteps) {
    foreach ($step in $selectSteps) {
        Write-Host "Setting $step back to Incomplete"
        Invoke-Sqlcmd -Server $sqlServerInstance -Query "USE $databaseName UPDATE Progress SET $step = 'Incomplete';" -Verbose:$false -ErrorAction Stop
    }
    Write-Host "Updated status is:"
    Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" -TableName "$tableName" -ErrorAction SilentlyContinue -Verbose:$false
}
else {
    Write-Host "No steps were selected - Current status is:"
    Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" -TableName "$tableName" -ErrorAction SilentlyContinue -Verbose:$false
}