$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

############## RUNNING JOBS #####################################

# Get all the running jobs
$jobsStillExecuting = $true
While ($jobsStillExecuting -eq $true) {
    Clear-Host
    $runningJobs = (Get-Job | Where-Object { $_.state -eq "running" })
    if ($runningJobs.count -eq 0) {
        $jobsStillExecuting = $false
    }
    Write-Host "`r`n****** CURRENT JOB STATUS - This screen will refresh every 30 seconds ******`r"
    Write-Host "****** DO NOT CLOSE THIS SESSION - If you do, please run .\GetJobStatus.ps1 from within $scriptLocation\Scripts to resume job monitoring ******`r" -ForegroundColor Red
    Write-Host "****** Please wait until all jobs have completed/failed before re-running the main script ******`r`n"
    Write-Host "Current number of running jobs: $($runningJobs.count). Some jobs may take a while - Please be patient!"
    $jobRunningDisplay = $null
    $jobRunningDisplay = @()
    foreach ($runningJob in $runningJobs) {
        $jobDuration = (Get-Date) - ($runningJob.PSBeginTime)
        if ($jobDuration.Hours -gt 0) {
            $jobRuntime = "$($jobDuration.Hours)h:$($jobDuration.Minutes)m:$($jobDuration.Seconds)s"
        }
        else {
            $jobRuntime = "$($jobDuration.Minutes)m:$($jobDuration.Seconds)s"
        }
        $jobRunningDisplay += New-Object psobject -Property @{Name = $($runningJob.Name); StartTime = $($runningJob.PSBeginTime); Duration = $jobRuntime}
    }
    $jobRunningDisplay | Sort-Object StartTime | Format-Table Name, StartTime, Duration

    ############## COMPLETED JOBS #####################################

    $completedJobs = (Get-Job | Where-Object { $_.state -eq "Completed" })
    Write-Host "Current number of completed jobs: $($completedJobs.count)" -ForegroundColor Green
    $jobCompleteDisplay = $null
    $jobCompleteDisplay = @()
    foreach ($completeJob in $completedJobs) {
        $jobDuration = ($completeJob.PSEndTime) - ($completeJob.PSBeginTime)
        if ($jobDuration.Hours -gt 0) {
            $jobRuntime = "$($jobDuration.Hours)h:$($jobDuration.Minutes)m:$($jobDuration.Seconds)s"
        }
        else {
            $jobRuntime = "$($jobDuration.Minutes)m:$($jobDuration.Seconds)s"
        }
        $jobCompleteDisplay += New-Object psobject -Property @{Name = $($completeJob.Name); StartTime = $($completeJob.PSBeginTime); EndTime = $($completeJob.PSEndTime); Duration = $jobRuntime}
    }
    $jobCompleteDisplayTable = $jobCompleteDisplay | Sort-Object StartTime | Format-Table Name, StartTime, EndTime, Duration | Out-String
    Write-Host $jobCompleteDisplayTable -ForegroundColor Green -NoNewline

    ############## FAILED JOBS #####################################
    
    $failedJobs = (Get-Job | Where-Object { $_.state -eq "Failed" })
    if ($failedJobs.count -gt 0) {
        Write-Host "Current number of failed jobs: $($failedJobs.count)" -ForegroundColor Red
    }
    $jobFailedDisplay = $null
    $jobFailedDisplay = @()
    foreach ($failedJob in $failedJobs) {
        $jobDuration = ($failedJob.PSEndTime) - ($failedJob.PSBeginTime)
        if ($jobDuration.Hours -gt 0) {
            $jobRuntime = "$($jobDuration.Hours)h:$($jobDuration.Minutes)m:$($jobDuration.Seconds)s"
        }
        else {
            $jobRuntime = "$($jobDuration.Minutes)m:$($jobDuration.Seconds)s"
        }
        $jobFailedDisplay += New-Object psobject -Property @{Name = $($failedJob.Name); StartTime = $($failedJob.PSBeginTime); EndTime = $($failedJob.PSEndTime); Duration = $jobRuntime}
    }
    $jobFailedDisplayTable = $jobFailedDisplay | Sort-Object StartTime | Format-Table Name, StartTime, EndTime, Duration | Out-String
    Write-Host $jobFailedDisplayTable -ForegroundColor Red -NoNewline
    Write-Host "`r`n****** CURRENT JOB STATUS - This screen will refresh every 30 seconds ******"
    Write-Host "****** DO NOT CLOSE THIS SESSION - If you do, please run .\GetJobStatus.ps1 from within $scriptLocation\Scripts to resume job monitoring ******" -ForegroundColor Red
    Write-Host "****** Please wait until all jobs have completed/failed before re-running the main script ******"
    Start-Sleep -Seconds 20
    Clear-Host
    $sqlServerInstance = '(localdb)\MSSQLLocalDB'
    $databaseName = $databaseName = "ConfigASDK"
    $tableName = "Progress"
    Write-Host "`r`n****** CURRENT JOB STATUS - This screen will refresh every 30 seconds ******"
    Write-Host "****** DO NOT CLOSE THIS SESSION - If you do, please run .\GetJobStatus.ps1 from within $scriptLocation\Scripts to resume job monitoring ******" -ForegroundColor Red
    Write-Host "****** Please wait until all jobs have completed/failed before re-running the main script ******"
    Write-Host "`r`nCurrent Progress:" -NoNewline
    $tableData = Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" -TableName "$tableName" -ErrorAction Stop -Verbose:$false | Out-String
    Write-Host "$tableData" -NoNewline
    Write-Host "****** DO NOT CLOSE THIS SESSION - If you do, please run .\GetJobStatus.ps1 from within $scriptLocation\Scripts to resume job monitoring ******" -ForegroundColor Red
    Write-Host "****** Please wait until all jobs have completed/failed before re-running the main script ******"
    Start-Sleep -Seconds 10
}
if ((Get-Job | Where-Object { $_.state -eq "Failed" })) {
    Write-Host "At least one of the jobs failed."
    $failedJobs = (Get-Job | Where-Object { $_.state -eq "Failed" })
    foreach ($fail in $failedJobs) {
        Write-Host "FAILED JOB: Job Name: $($fail.Name) | Error Message: $($fail.ChildJobs.JobStateInfo.Reason.Message)"
    }
    throw "Please review the logs for further troubleshooting"
}
elseif ((Get-Job | Where-Object { $_.state -eq "Completed" })) {
    Write-Host "All jobs completed successfully. Cleaning up jobs."
    Get-Job | Remove-Job
}