# Get all the running jobs
$jobsStillExecuting = $true
While ($jobsStillExecuting -eq $true) {
    Clear-Host
    $runningJobs = (Get-Job | Where-Object { $_.state -eq "running" })
    if ($runningJobs.count -eq 0) {
        $jobsStillExecuting = $false
    }
    Write-Host "****** CURRENT JOB STATUS - This screen will refresh every 30 seconds ******`r"
    Write-Host "****** DO NOT CLOSE THIS SESSION - If you do, please run .\GetJobStatus.ps1 from within $scriptLocation\Scripts to resume job monitoring ******`r"
    Write-Host "****** Please wait until all jobs have completed/failed before re-running the main script ******`r`n"
    Write-Host "Current number of running jobs: $($runningJobs.count). Some jobs may take a while - Please be patient!" -ForegroundColor Yellow
    Get-Job | Where-Object { $_.state -eq "running" } | Format-Table Name, State, @{L = 'StartTime'; E = {$_.PSBeginTime}}, @{L = 'EndTime'; E = {$_.PSEndTime}}
    foreach ($runningJob in $runningJobs) {
        $jobDuration = (Get-Date) - ($runningJob.PSBeginTime)
        if ($jobDuration.Hours -gt 0) {
            Write-Host "$($runningJob.Name) has been running for $($jobDuration.Hours)h:$($jobDuration.Minutes)m:$($jobDuration.Seconds)s" -ForegroundColor Yellow
        }
        else {
            Write-Host "$($runningJob.Name) has been running for $($jobDuration.Minutes)m:$($jobDuration.Seconds)s" -ForegroundColor Yellow
        }
    }
    $completedJobs = (Get-Job | Where-Object { $_.state -eq "Completed" })
    Write-Host "`r`nCurrent number of completed jobs: $($completedJobs.count)`r`n" -ForegroundColor Green
    foreach ($completeJob in $completedJobs) {
        $jobDuration = ($completeJob.PSEndTime) - ($completeJob.PSBeginTime)
        if ($jobDuration.Hours -gt 0) {
            Write-Host "$($completeJob.Name) finished in $($jobDuration.Hours)h:$($jobDuration.Minutes)m:$($jobDuration.Seconds)s"-ForegroundColor Green
        }
        else {
            Write-Host "$($completeJob.Name) finished in $($jobDuration.Minutes)m:$($jobDuration.Seconds)s" -ForegroundColor Green
        }
    }
    $failedJobs = (Get-Job | Where-Object { $_.state -eq "Failed" })
    Write-Host "`r`nCurrent number of failed jobs: $($failedJobs.count)`r`n" -ForegroundColor Red
    foreach ($failedJob in $failedJobs) {
        $jobDuration = ($failedJob.PSEndTime) - ($failedJob.PSBeginTime)
        if ($jobDuration.Hours -gt 0) {
            Write-Host "$($failedJob.Name) failed after $($jobDuration.Hours)h:$($jobDuration.Minutes)m:$($jobDuration.Seconds)s" -ForegroundColor Red
        }
        else {
            Write-Host "$($failedJob.Name) failed after $($jobDuration.Minutes)m:$($jobDuration.Seconds)s" -ForegroundColor Red
        }
    }
    Write-Host "`r`n****** CURRENT JOB STATUS - This screen will refresh every 30 seconds ******"
    Write-Host "****** DO NOT CLOSE THIS SESSION - If you do, please run .\GetJobStatus.ps1 from within $scriptLocation\Scripts to resume job monitoring ******"
    Write-Host "****** Please wait until all jobs have completed/failed before re-running the main script ******"
    Start-Sleep -Seconds 20
    Clear-Host
    $sqlServerInstance = '(localdb)\MSSQLLocalDB'
    $databaseName = $databaseName = "ConfigASDK"
    $tableName = "Progress"
    Write-Host "`r`n****** CURRENT JOB STATUS - This screen will refresh every 30 seconds ******"
    Write-Host "****** DO NOT CLOSE THIS SESSION - If you do, please run .\GetJobStatus.ps1 from within $scriptLocation\Scripts to resume job monitoring ******"
    Write-Host "****** Please wait until all jobs have completed/failed before re-running the main script ******"
    Write-Host "`r`nCurrent Progress:`r`n"
    $tableData = Read-SqlTableData -ServerInstance $sqlServerInstance -DatabaseName "$databaseName" -SchemaName "dbo" -TableName "$tableName" -ErrorAction Stop | Out-String
    Write-Host "****** DO NOT CLOSE THIS SESSION - If you do, please run .\GetJobStatus.ps1 from within $scriptLocation\Scripts to resume job monitoring ******"
    Write-Host "****** Please wait until all jobs have completed/failed before re-running the main script ******"
    Write-Output "$tableData"
    Start-Sleep -Seconds 10
}
if ((Get-Job | Where-Object { $_.state -eq "Failed" })) {
    Write-Verbose "At least one of the jobs failed."
    $failedJobs = (Get-Job | Where-Object { $_.state -eq "Failed" })
    foreach ($fail in $failedJobs) {
        Write-Verbose "FAILED JOB: Job Name: $($fail.Name) | Error Message: $($fail.ChildJobs.JobStateInfo.Reason.Message)"
    }
    throw "Please review the logs for further troubleshooting"
}
elseif ((Get-Job | Where-Object { $_.state -eq "Completed" })) {
    Write-Host "All jobs completed successfully. Cleaning up jobs."
    Get-Job | Remove-Job
}