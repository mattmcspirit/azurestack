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
        Get-AzureRmContext -ListAvailable | Where-Object { $_.Environment -like "Azure*" } | Remove-AzureRmAccount | Out-Null
        Clear-AzureRmContext -Scope CurrentUser -Force
        Disable-AzureRMContextAutosave -Scope CurrentUser

        <#Write-Host "Importing Azure.Storage and AzureRM.Storage modules"
        Import-Module -Name Azure.Storage -RequiredVersion 4.5.0
        Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4
        #>
        
        # Log into Azure Stack to check for existing images and push new ones if required ###
        Write-Host "Logging into Azure Stack to check if images are required, and therefore if updates need downloading"
        $ArmEndpoint = "https://adminmanagement.$customDomainSuffix"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $azsCreds -ErrorAction Stop | Out-Null
        $sub = Get-AzureRmSubscription | Where-Object { $_.Name -eq "Default Provider Subscription" }
        $azureContext = Get-AzureRmSubscription -SubscriptionID $sub.SubscriptionId | Select-AzureRmSubscription
        $azsLocation = (Get-AzureRmLocation).DisplayName
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
            $platformImageCore = Get-AzsPlatformImage -Location $azsLocation -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -ErrorAction SilentlyContinue
            $serverCoreVMImageAlreadyAvailable = $false
            if ($platformImageCore -and $platformImageCore.ProvisioningState -eq 'Succeeded') {
                Write-Host "There appears to be at least 1 suitable Windows Server $v Datacenter Server Core image within your Platform Image Repository which we will use for the Azure Stack POC Configurator." 
                $serverCoreVMImageAlreadyAvailable = $true
            }

            # Pre-validate that the Windows Server Full Image is not already available
            Remove-Variable -Name platformImageFull -Force -ErrorAction SilentlyContinue
            $sku = "$v-Datacenter"
            $platformImageFull = Get-AzsPlatformImage -Location $azsLocation -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -ErrorAction SilentlyContinue
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
                        $rss = "https://support.microsoft.com/app/content/api/content/feeds/sap/en-us/c3a1be8a-50db-47b7-d5eb-259debc3abcc/rss"
                        $rssFeed = [xml](New-Object System.Net.WebClient).DownloadString($rss)
                        $feed = $rssFeed.rss.channel.item | Where-Object { $_.title -like "*Servicing Stack Update*Windows 10*" }
                        $feed = ($feed | Where-Object { $_.title -like "*1607*" } | Select-Object -Property Link | Sort-Object link) | Select-Object -Last 1
                        $ssuKB = "KB" + ($feed.link).Split('/')[4]
                        $microCodeKB = "KB4091664"
                    }
                    elseif ($buildVersion -eq "17763") {
                        $rss = "https://support.microsoft.com/app/content/api/content/feeds/sap/en-us/6ae59d69-36fc-8e4d-23dd-631d98bf74a9/rss"
                        $rssFeed = [xml](New-Object System.Net.WebClient).DownloadString($rss)
                        $feed = $rssFeed.rss.channel.item | Where-Object { $_.title -like "*Servicing Stack Update*Windows 10*" }
                        $feed = ($feed | Where-Object { $_.title -like "*1809*" } | Select-Object -Property Link | Sort-Object link) | Select-Object -Last 1
                        $ssuKB = "KB" + ($feed.link).Split('/')[4]
                        $microCodeKB = "KB4465065"
                    }

                    $KBs += "$ssuKB"
                    $KBs += "$microCodeKB"

                    Write-Host "Getting info for latest Adobe Flash Security Update"
                    $rssFeed = [xml](New-Object System.Net.WebClient).DownloadString($rss)
                    $feed = $rssFeed.rss.channel.item | Where-Object { $_.title -like "*Security Update for Adobe Flash Player*" }
                    $feed = ($feed | Select-Object -Property Link | Sort-Object link -Descending) | Select-Object -First 1
                    $flashKB = "KB" + ($feed.link).Split('/')[4]
                    $KBs += $flashKB

                    # Find the KB Article Number for the latest Windows Server Cumulative Update
                    Write-Host "Accessing $StartKB to retrieve the list of updates."
                    $cumulativekbID = (Invoke-WebRequest -Uri $StartKB -UseBasicParsing).RawContent -split "`n"
                    $cumulativekbID = ($cumulativekbID | Where-Object { $_ -like "*heading*$buildVersion*" } | Select-Object -First 1)
                    $cumulativekbID = "KB" + ((($cumulativekbID -split "KB", 2)[1]) -split "\s", 2)[0]

                    if (!$cumulativekbID) {
                        Write-Host "No Windows Update KB found - this is an error. Your Windows Server images will be out of date"
                    }
                    else {
                        $KBs += "$cumulativekbID"
                    }

                    if ($v -eq "2019") {
                        # Bypass Internet Explorer Setup Popup
                        $keyPath = 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main'
                        if (!(Test-Path $keyPath)) { New-Item $keyPath -Force }
                        Set-ItemProperty -Path $keyPath -Name "DisableFirstRunCustomize" -Value 1

                        ## .NET CU Download ####
                        # Find the KB Article Number for the latest .NET on Windows Server 2019 (Build 17763) Cumulative Update
                        Write-Host "This is a Windows Server 2019 image, so we will download the latest .NET update for the image"
                        Write-Host "Creating COM Object"
                        $ie = New-Object -ComObject "InternetExplorer.Application" -Verbose -ErrorAction Stop
                        Write-Host "Setting IE to silent"
                        $ie.silent = $true
                        Write-Host "Navigating to https://support.microsoft.com/en-us/help/4466961"
                        $ie.Navigate("https://support.microsoft.com/en-us/help/4466961")
                        Write-Host "Waiting for IE to be ready..."
                        while ($ie.ReadyState -ne 4) { start-sleep -m 100 }
                        Write-Host "Getting KB ID"
                        $NETkbID = ($ie.Document.getElementsByTagName('A') | Where-Object { $_.textContent -like "*KB*" }).innerHTML | Select-Object -First 1
                        Write-Host "Splitting KB ID"
                        $NETkbID = ((($NETkbID -split "KB", 2)[1]) -split "\s", 2)[0]
                        Write-Host "KB ID for the latest .NET update for the image is KB$NETkbID"
                        while (!$null -eq $ie) {
                            Write-Host "Releasing ComObject"
                            [System.Runtime.Interopservices.Marshal]::FinalReleaseComObject($ie)
                            Write-Host "Removing IE Variable"
                            Remove-Variable ie -ErrorAction Stop
                        }
                        # Get ID for the corresponding Cumulative Update
                        Write-Host "Found latest .NET Framework update: KB$NETkbID"
                        $kbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$NETkbID" -UseBasicParsing
                        $Available_kbIDs = $kbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
                        #$Available_kbIDs | Out-String | Write-Host
                        $NETkbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }

                        if (!$NETkbIDs) {
                            Write-Host "No Windows Update KB found - this is an error. Your Windows Server images will not have the latest .NET update"
                        }
                        else {
                            $KBs += "$NETkbIDs"
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