[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $ISOPath,

    [Parameter(Mandatory = $false)]
    [String] $ISOPath2019,

    [Parameter(Mandatory = $true)]
    [String] $azsLocation,

    [Parameter(Mandatory = $true)]
    [String] $deploymentMode,

    [parameter(Mandatory = $true)]
    [String] $tenantID,

    [parameter(Mandatory = $true)]
    [pscredential] $asdkCreds,
    
    [parameter(Mandatory = $true)]
    [String] $ScriptLocation,

    [Parameter(Mandatory = $true)]
    [String] $sqlServerInstance,

    [Parameter(Mandatory = $true)]
    [String] $databaseName,

    [Parameter(Mandatory = $true)]
    [String] $tableName
)

#$Global:VerbosePreference = "Continue"
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
        Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
        Clear-AzureRmContext -Scope CurrentUser -Force
        Disable-AzureRMContextAutosave -Scope CurrentUser

        Write-Host "Importing Azure.Storage and AzureRM.Storage modules"
        Import-Module -Name Azure.Storage -RequiredVersion 4.5.0
        Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4
        
        # Log into Azure Stack to check for existing images and push new ones if required ###
        Write-Host "Logging into Azure Stack to check if images are required, and therefore if updates need downloading"
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
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
            $platformImageCore = Get-AzsPlatformImage -Location "$azsLocation" -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -ErrorAction SilentlyContinue
            $serverCoreVMImageAlreadyAvailable = $false
            if ($platformImageCore -and $platformImageCore.ProvisioningState -eq 'Succeeded') {
                Write-Host "There appears to be at least 1 suitable Windows Server $v Datacenter Server Core image within your Platform Image Repository which we will use for the ASDK Configurator." 
                $serverCoreVMImageAlreadyAvailable = $true
            }

            # Pre-validate that the Windows Server Full Image is not already available
            Remove-Variable -Name platformImageFull -Force -ErrorAction SilentlyContinue
            $sku = "$v-Datacenter"
            $platformImageFull = Get-AzsPlatformImage -Location "$azsLocation" -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -ErrorAction SilentlyContinue
            $serverFullVMImageAlreadyAvailable = $false

            if ($platformImageFull -and $platformImageFull.ProvisioningState -eq 'Succeeded') {
                Write-Host "There appears to be at least 1 suitable Windows Server $v Datacenter Server Full image within your Platform Image Repository which we will use for the ASDK Configurator." 
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
                    $kbDownloads = @()
                    $Urls = @()

                    ### Firstly, check for build 14393, and if so, download the Servicing Stack Update or other MSUs will fail to apply.
                    Write-Host "Checking build number to determine Servicing Stack Upadtes"
                    if ($buildVersion -eq "14393") {
                        $ssuArray = @("4132216", "4465659", "4485447")
                        #Fix for broken Feb 2019 update
                        #$ssuArray = @("4132216", "4465659")
                        $updateArray = @("4091664")
                        $ssuSearchString = 'Windows Server 2016'
                    }
                    elseif ($buildVersion -eq "17763") {
                        $ssuArray = @("4470788")
                        $updateArray = @("4465065")
                        $ssuSearchString = 'Windows Server 2019'
                    }
                    foreach ($ssu in $ssuArray) {
                        Write-Host "Build is $buildVersion - Need to download: KB$($ssu) to update Servicing Stack before adding future Cumulative Updates"
                        $ssuKbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$ssu" -UseBasicParsing
                        $ssuAvailable_kbIDs = $ssuKbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
                        #$ssuAvailable_kbIDs | Out-String | Write-Host
                        $ssuKbIDs = $ssuKbObj.Links | Where-Object ID -match '_link' | Where-Object innerText -match $ssuSearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $ssuAvailable_kbIDs }

                        # If innerHTML is empty or does not exist, use outerHTML instead
                        if (!$ssuKbIDs) {
                            $ssuKbIDs = $ssuKbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $ssuSearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $ssuAvailable_kbIDs }
                        }
                        $kbDownloads += "$ssuKbIDs"
                    }
                    
                    foreach ($update in $updateArray) {
                        Write-Host "Build is $buildVersion - Need to download: KB$($update) to ensure image is fully updated at first run"
                        $updateKbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$update%20x64%20$v" -UseBasicParsing
                        $updateAvailable_kbIDs = $updateKbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID | Select-Object -First 1
                        #$updateAvailable_kbIDs | Out-String | Write-Host
                        $kbDownloads += "$updateAvailable_kbIDs"
                    }
                    
                    # Find the KB Article Number for the latest Windows Server Cumulative Update
                    Write-Host "Accessing $StartKB to retrieve the list of updates."
                    $kbID = (Invoke-WebRequest -Uri $StartKB -UseBasicParsing).RawContent -split "`n"
                    $kbID = ($kbID | Where-Object { $_ -like "*heading*$buildVersion*" } | Select-Object -First 1)
                    $kbID = ((($kbID -split "KB", 2)[1]) -split "\s", 2)[0]

                    if (!$kbID) {
                        Write-Host "No Windows Update KB found - this is an error. Your Windows Server images will be out of date"
                    }

                    #Hard code to January 2019 update:
                    #$kbID = "4480977"

                    # Get Download Link for the corresponding Cumulative Update
                    Write-Host "Found latest Cumulative Update: KB$kbID"
                    $kbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$kbID" -UseBasicParsing
                    $Available_kbIDs = $kbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
                    #$Available_kbIDs | Out-String | Write-Host
                    $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object innerText -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }

                    # If innerHTML is empty or does not exist, use outerHTML instead
                    if (!$kbIDs) {
                        $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }
                    }
                    # Defined a KB array to hold the kbIDs and if the build is 14393, add the corresponding KBID to it
                    $kbDownloads += "$kbIDs"

                    if ($v -eq "2019") {
                        ## .NET CU Download ####
                        # Find the KB Article Number for the latest .NET on Windows Server 2019 (Build 17763) Cumulative Update
                        Write-Host "This is a Windows Server 2019 image, so we will download the latest .NET update for the image"
                        $ie = New-Object -ComObject "InternetExplorer.Application"
                        $ie.silent = $true
                        $ie.Navigate("https://support.microsoft.com/en-us/help/4466961")
                        while ($ie.ReadyState -ne 4) {start-sleep -m 100}
                        $NETkbID = ($ie.Document.getElementsByTagName('A') | Where-Object {$_.textContent -like "*KB*"}).innerHTML | Select-Object -First 1
                        $NETkbID = ((($NETkbID -split "KB", 2)[1]) -split "\s", 2)[0]
                        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($ie)
                        Remove-Variable ie -ErrorAction SilentlyContinue

                        if (!$NETkbID) {
                            Write-Host "No Windows Update KB found - this is an error. Your Windows Server images will not have the latest .NET update"
                        }

                        # Get Download Link for the corresponding Cumulative Update
                        Write-Host "Found latest .NET Framework update: KB$NETkbID"
                        $kbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$NETkbID" -UseBasicParsing
                        $Available_kbIDs = $kbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
                        #$Available_kbIDs | Out-String | Write-Host
                        $NETkbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }
                        # Defined a KB array to hold the NETkbIDs
                        $kbDownloads += "$NETkbIDs"
                    }
                    
                    foreach ( $kbID in $kbDownloads ) {
                        Write-Host "Need to download the following update file with KB ID: $kbID"
                        $Post = @{ size = 0; updateID = $kbID; uidInfo = $kbID } | ConvertTo-Json -Compress
                        $PostBody = @{ updateIDs = "[$Post]" } 
                        $Urls += Invoke-WebRequest -Uri 'http://www.catalog.update.microsoft.com/DownloadDialog.aspx' -UseBasicParsing -Method Post -Body $postBody | Select-Object -ExpandProperty Content | Select-String -AllMatches -Pattern "(http[s]?\://download\.windowsupdate\.com\/[^\'\""]*)" | ForEach-Object { $_.matches.value }
                    }

                    # Download the corresponding Windows Server Cumulative Update (and possibly, Servicing Stack Updates)
                    foreach ( $Url in $Urls ) {
                        $filename = (($Url.Substring($Url.LastIndexOf("/") + 1)).Split("-", 2)[1])
                        $filename = $filename -replace "_.*\.", "."
                        $target = "$((Get-Item $ASDKpath).FullName)\images\$v\$filename"
                        if (!(Test-Path -Path $target)) {
                            foreach ($ssu in $ssuArray) {
                                if ((Test-Path -Path "$((Get-Item $ASDKpath).FullName)\images\$v\$($buildVersion)_ssu_kb$($ssu).msu")) {
                                    Remove-Item -Path "$((Get-Item $ASDKpath).FullName)\images\$v\$($buildVersion)_ssu_kb$($ssu).msu" -Force -Verbose -ErrorAction Stop
                                }
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
                    foreach ($ssu in $ssuArray) {
                        if ((Test-Path -Path "$((Get-Item $ASDKpath).FullName)\images\$v\$($buildVersion)_ssu_kb$($ssu).msu")) {
                            Write-Host "The $buildVersion Servicing Stack Update already exists within the target folder"
                        }
                        else {
                            Write-Host "Renaming the Servicing Stack Update to ensure it is applied in the correct order"
                            Get-ChildItem -Path "$ASDKpath\images\$v\" -Filter *.msu | Where-Object {$_.FullName -like "*$($ssu)*"} | Rename-Item -NewName "$($buildVersion)_ssu_kb$($ssu).msu" -Force -ErrorAction Stop -Verbose
                        }
                    }
                    $target = "$ASDKpath\images\$v"
                }
                elseif ($deploymentMode -ne "Online") {
                    $target = "$ASDKpath\images\$v"
                }
            }
        }
        # Update the ConfigASDK database with successful completion
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
    Write-Host "ASDK Configurator Stage: $progressStage previously completed successfully"
}
Set-Location $ScriptLocation
Write-Host "Logging stopped at $endTime"
Stop-Transcript -ErrorAction SilentlyContinue