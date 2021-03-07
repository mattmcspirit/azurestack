[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $azsPath,

    [Parameter(Mandatory = $true)]
    [String] $ISOPath,

    [Parameter(Mandatory = $false)]
    [String] $ISOPath2019,

    [Parameter(Mandatory = $true)]
    [String] $customDomainSuffix,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [pscredential] $azsCreds,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

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

### SET LOG LOCATION ###
$logDate = Get-Date -Format FileDate
New-Item -ItemType Directory -Path "$ScriptLocation\Logs\$logDate\WindowsUpdates" -Force | Out-Null
$logPath = "$ScriptLocation\Logs\$logDate\WindowsUpdates"

### START LOGGING ###
$runTime = $(Get-Date).ToString("MMdd-HHmmss")
$fullLogPath = "$logPath\WindowsUpdates$runTime.txt"
Start-Transcript -Path "$fullLogPath" -Append
Write-Host "Creating log folder"
Write-Host "Log folder has been created at $logPath"
Write-Host "Log file stored at $fullLogPath"
Write-Host "Starting logging"
Write-Host "Log started at $runTime"

$progressStage = "WindowsUpdates"
$progressCheck = CheckProgress -progressStage $progressStage

if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
    try {
        if ($progressCheck -eq "Failed") {
            StageReset -progressStage $progressStage
        }

        Write-Host "Clearing previous Azure/Azure Stack logins"
        Get-AzContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzContext -Force | Out-Null
        Clear-AzContext -Scope CurrentUser -Force
        Disable-AzContextAutosave -Scope CurrentUser
        
        # Log into Azure Stack to check for existing images and push new ones if required ###
        Write-Host "Logging into Azure Stack to check if images are required, and therefore if updates need downloading"
        $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
        Add-AzEnvironment -Name "AzureStackAdmin" -ARMEndpoint "$ArmEndpoint" -ErrorAction Stop
        Connect-AzAccount -Environment "AzureStackAdmin" -Tenant $tenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
        $sub = Get-AzSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
        Get-AzSubscription -SubscriptionID $sub.SubscriptionId | Set-AzContext
        $azsLocation = (Get-AzLocation).DisplayName
        Write-Host "Determine if a Windows Server 2019 ISO has been provided"
        if ($ISOPath2019) {
            $versionArray = @("2016", "2019")
        }
        else {
            $versionArray = @("2016")
        }

        foreach ($v in $versionArray) {
            # Pre-validate that the Windows Server Server Core VM Image is not already available
            Write-Host "Checking to see if a Windows Server $v image is present in your Azure Stack Platform Image Repository"
            Remove-Variable -Name platformImageCore -Force -ErrorAction SilentlyContinue
            $sku = "$v-Datacenter-Server-Core"
            $platformImageCore = Get-AzsPlatformImage | Where-Object {$_.Id -like "*$azsLocation*MicrosoftWindowsServer*windowsserver*$sku*" } -ErrorAction SilentlyContinue
            $serverCoreVMImageAlreadyAvailable = $false
            if ($platformImageCore -and $platformImageCore.ProvisioningState -eq 'Succeeded') {
                Write-Host "There appears to be at least 1 suitable Windows Server $v Datacenter Server Core image within your Platform Image Repository which we will use for the Azure Stack POC Configurator." 
                $serverCoreVMImageAlreadyAvailable = $true
            }
            # Pre-validate that the Windows Server Full Image is not already available
            Remove-Variable -Name platformImageFull -Force -ErrorAction SilentlyContinue
            $sku = "$v-Datacenter"
            $platformImageFull = Get-AzsPlatformImage | Where-Object {$_.Id -like "*$azsLocation*MicrosoftWindowsServer*windowsserver*$sku*" } -ErrorAction SilentlyContinue
            $serverFullVMImageAlreadyAvailable = $false

            if ($platformImageFull -and $platformImageFull.ProvisioningState -eq 'Succeeded') {
                Write-Host "There appears to be at least 1 suitable Windows Server $v Datacenter Server Full image within your Platform Image Repository which we will use for the Azure Stack POC Configurator." 
                $serverFullVMImageAlreadyAvailable = $true
            }
            if ($serverCoreVMImageAlreadyAvailable -eq $false) {
                $downloadCURequired = $true
                Write-Host "You're missing the Windows Server $v Datacenter Server Core image in your Platform Image Repository."
            }
            if ($serverFullVMImageAlreadyAvailable -eq $false) {
                $downloadCURequired = $true
                Write-Host "You're missing the Windows Server $v Datacenter Full image in your Platform Image Repository."
            }
            if (($serverCoreVMImageAlreadyAvailable -eq $true) -and ($serverFullVMImageAlreadyAvailable -eq $true)) {
                $downloadCURequired = $false
                Write-Host "Windows Server $v Datacenter Full and Core Images already exist in your Platform Image Repository"
            }

            ### Download the latest Cumulative Update for Windows Server - Existing Azure Stack Tools module doesn't work ###
            if ($downloadCURequired -eq $true) {
                if ($deploymentMode -eq "Online") {
                    Write-Host "Updates are required. Checking the ISO for correct build version"
                    # Mount the ISO, check the image for the version, then dismount
                    Remove-Variable -Name buildVersion -ErrorAction SilentlyContinue
                    if ($v -eq "2019") {
                        $ISOPath = $ISOPath2019
                    }
                    $isoMountForVersion = Mount-DiskImage -ImagePath $ISOPath -StorageType ISO -PassThru
                    $isoDriveLetterForVersion = ($isoMountForVersion | Get-Volume).DriveLetter
                    $wimPath = "$IsoDriveLetterForVersion`:\sources\install.wim"
                    $buildVersion = (dism.exe /Get-WimInfo /WimFile:$wimPath /index:1 | Select-String "Version ").ToString().Split(".")[2].Trim()
                    Dismount-DiskImage -ImagePath $ISOPath
                    Write-Host "You're missing at least one of the Windows Server $v Datacenter images, so we'll first download the latest Cumulative Update."
                    
                    # Define parameters
                    Write-Host "Defining StartKB"
                    if ($v -eq "2019") {
                        $StartKB = 'https://support.microsoft.com/en-us/help/4464619'
                        $netKB = 'https://support.microsoft.com/en-us/help/4466961'
                    }
                    else {
                        $StartKB = 'https://support.microsoft.com/en-us/help/4000825'
                    }
                    $SearchString = 'Cumulative.*Server.*x64'
                    Write-Host "StartKB is: $StartKB and Search String is: $SearchString"
                    # Define the arrays that will be used later
                    $KBs = @()

                    ### Firstly, check for build 14393, and if so, download the Servicing Stack Update or other MSUs will fail to apply.
                    Write-Host "Checking build number to determine Servicing Stack Updates"
                    if ($buildVersion -eq "14393") {
                        $rss = "https://support.microsoft.com/app/content/api/content/feeds/sap/en-us/6ae59d69-36fc-8e4d-23dd-631d98bf74a9/rss"
                        $rssFeed = [xml](New-Object System.Net.WebClient).DownloadString($rss)
                        $feed = $rssFeed.rss.channel.item | Where-Object { $_.title -like "*Servicing Stack Update*Windows 10*" }
                        $feed = ($feed | Where-Object { $_.title -like "*1607*" } | Select-Object -Property Link | Sort-Object link) | Select-Object -Last 1
                        $ssuKB = "KB" + ($feed.link).Split('/')[4]
                        $microCodeFeed = $rssFeed.rss.channel.item | Where-Object { $_.description -like "*microcode updates from Intel*version 1607*" }
                        $microCodeFeed = ($microCodeFeed | Select-Object -Property Link | Sort-Object link) | Select-Object -Last 1
                        $microCodeKB = "KB" + ($microCodeFeed.link).Split('/')[4]
                    }
                    elseif ($buildVersion -eq "17763") {
                        $rss = "https://support.microsoft.com/app/content/api/content/feeds/sap/en-us/6ae59d69-36fc-8e4d-23dd-631d98bf74a9/rss"
                        $rssFeed = [xml](New-Object System.Net.WebClient).DownloadString($rss)
                        $feed = $rssFeed.rss.channel.item | Where-Object { $_.title -like "*Servicing Stack Update*Windows 10*" }
                        $feed = ($feed | Where-Object { $_.title -like "*1809*" } | Select-Object -Property Link | Sort-Object link) | Select-Object -Last 1
                        $ssuKB = "KB" + ($feed.link).Split('/')[4]
                        $microCodeFeed = $rssFeed.rss.channel.item | Where-Object { $_.description -like "*microcode updates from Intel*version 1809*" }
                        $microCodeFeed = ($microCodeFeed | Select-Object -Property Link | Sort-Object link) | Select-Object -Last 1
                        $microCodeKB = "KB" + ($microCodeFeed.link).Split('/')[4]
                    }

                    $KBs += "$ssuKB"
                    $KBs += "$microCodeKB"

                    Write-Host "Getting info for removal of Adobe Flash Player"
                    $rssFeed = [xml](New-Object System.Net.WebClient).DownloadString($rss)
                    $feed = $rssFeed.rss.channel.item | Where-Object { $_.title -like "*Adobe Flash Player*" }
                    $feed = ($feed | Select-Object -Property Link | Sort-Object link -Descending) | Select-Object -First 1
                    $flashKB = "KB" + ($feed.link).Split('/')[4]
                    $KBs += $flashKB

                    # Find the KB Article Number for the latest Windows Server Cumulative Update
                    Write-Host "Accessing $StartKB to retrieve the list of updates."

                    if ($buildVersion -eq "17763") {
                    $cumulativekbID = (Invoke-WebRequest -Uri $StartKB -UseBasicParsing).RawContent -split "`n"
                    $cumulativekbID = ($cumulativekbID | Where-Object { ($_ -like "*a class=*$buildVersion*") -and ($_ -notlike "*a class=*preview*") } | Select-Object -First 1)
                    $cumulativekbID = "KB" + ((($cumulativekbID -split "KB", 2)[1]) -split "\s", 2)[0]
                    }
                    else {
                        $cumulativekbID = "KB4598243"
                    }

                    if (!$cumulativekbID) {
                        Write-Host "No Windows Update KB found - this is an error. Your Windows Server images will be out of date"
                    }
                    else {
                        $KBs += "$cumulativekbID"
                    }

                    if ($v -eq "2019") {

                        # Find the KB Article Number for the latest Cumulative Update for .NET Framework
                        Write-Host "Accessing $netKB to retrieve the list of updates."
                        $NETkbID = (Invoke-WebRequest -Uri $netKB -UseBasicParsing).RawContent -split "`n"
                        $NETkbID = ($NETkbID | Where-Object { ($_ -like "*a class=*Cumulative Update for .NET Framework*") -and ($_ -notlike "*a class=*preview*") } | Select-Object -First 1)
                        $NETkbID = "KB" + ((($NETkbID -split "KB", 2)[1]) -split "\s", 2)[0]

                        if (!$NETkbID) {
                            Write-Host "No Windows Update KB found - this is an error. Your Windows Server images will not have the latest .NET update"
                        }
                        else {
                            $KBs += "$NETkbID"
                        }
                    }

                    Write-Host "List of KBs to download is as follows:"
                    $kbDisplay = $KBs -join "`r`n"
                    Write-Host "$kbDisplay"
                    $Urls = @()
                    foreach ($KB in $KBs) {
                        $link = $null
                        $link = (Get-KbUpdate -Architecture x64 -OperatingSystem "Windows Server $v" -Latest -Pattern $KB -ErrorAction SilentlyContinue -Verbose:$false).Link | Select-Object -First 1
                        while (!$link) {
                            Write-Host "Failed to get the URL for $KB - retrying in 30 seconds"
                            Start-Sleep -Seconds 30
                            $link = (Get-KbUpdate -Architecture x64 -OperatingSystem "Windows Server $v" -Latest -Pattern $KB -ErrorAction SilentlyContinue -Verbose:$false).Link | Select-Object -First 1
                        }
                        $Urls += $link
                    }
                    Write-Host "List of URLs that will be used for downloading files:"
                    $urlDisplay = $Urls -join "`r`n"
                    Write-Host "$urlDisplay"

                    # Download the corresponding Windows Server Cumulative Update (and possibly, Servicing Stack Updates)
                    foreach ( $Url in $Urls ) {
                        $filename = (($Url.Substring($Url.LastIndexOf("/") + 1)).Split("-", 2)[1])
                        $filename = $filename -replace "_.*\.", "."
                        $target = "$((Get-Item $azsPath).FullName)\images\$v\$filename"
                        if (!(Test-Path -Path $target)) {
                            if ((Test-Path -Path "$((Get-Item $azsPath).FullName)\images\$v\$($buildVersion)_ssu_$($ssuKB).msu")) {
                                Remove-Item -Path "$((Get-Item $azsPath).FullName)\images\$v\$($buildVersion)_ssu_$($ssuKB).msu" -Force -Verbose -ErrorAction Stop
                            }
                            Write-Host "Update will be stored at $target"
                            Write-Host "These can be larger than 1GB, so may take a few minutes."
                            DownloadWithRetry -downloadURI "$Url" -downloadLocation "$target" -retries 10
                        }
                        else {
                            Write-Host "File exists: $target. Skipping download."
                        }
                    }
                    # If this is for Build 14393, rename the .msu for the servicing stack update, to ensure it gets applied in the correct order when patching the WIM file.
                    
                    if ((Test-Path -Path "$((Get-Item $azsPath).FullName)\images\$v\$($buildVersion)_ssu_$($ssuKB).msu")) {
                        Write-Host "The $buildVersion Servicing Stack Update already exists within the target folder"
                    }
                    else {
                        Write-Host "Renaming the Servicing Stack Update to ensure it is applied in the correct order"
                        Get-ChildItem -Path "$azsPath\images\$v\" -Filter *.msu | Where-Object { $_.FullName -like "*$($ssuKB)*" } | Rename-Item -NewName "$($buildVersion)_ssu_$($ssuKB).msu" -Force -ErrorAction Stop -Verbose
                    }
                    # All updates should now be downloaded - time to distribute them into correct folders.
                    New-Item -ItemType Directory -Path "$azsPath\images\$v\SSU" -Force | Out-Null
                    New-Item -ItemType Directory -Path "$azsPath\images\$v\CU" -Force | Out-Null
                    Get-ChildItem -Path "$azsPath\images\$v\" -Filter *.msu -ErrorAction SilentlyContinue | Where-Object { $_.FullName -like "*ssu*" } | Move-Item -Destination "$azsPath\images\$v\SSU" -Force -ErrorAction Stop -Verbose
                    Get-ChildItem -Path "$azsPath\images\$v\" -Filter *.msu -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike "*ssu*" } | Move-Item -Destination "$azsPath\images\$v\CU" -Force -ErrorAction Stop -Verbose
                }
            }
        }
        # Update the AzSPoC database with successful completion
        $progressStage = "WindowsUpdates"
        StageComplete -progressStage $progressStage
    }
    catch {
        StageFailed -progressStage $progressStage
        Set-Location $ScriptLocation
        throw $_.Exception.Message
        return
    }
}
elseif ($progressCheck -eq "Complete") {
    Write-Host "Azure Stack POC Configurator Stage: $progressStage previously completed successfully"
}
Set-Location $ScriptLocation
$endTime = $(Get-Date).ToString("MMdd-HHmmss")
Write-Host "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue