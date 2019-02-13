[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ASDKpath,

    [Parameter(Mandatory = $true)]
    [String] $ISOPath,

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
Start-Transcript -Path "$fullLogPath" -Append -IncludeInvocationHeader

$progressStage = "WindowsUpdates"
$progressCheck = CheckProgress -progressStage $progressStage

if (($progressCheck -eq "Incomplete") -or ($progressCheck -eq "Failed")) {
    try {
        if ($progressCheck -eq "Failed") {
            StageReset -progressStage $progressStage
        }

        Get-AzureRmContext -ListAvailable | Where-Object {$_.Environment -like "Azure*"} | Remove-AzureRmAccount | Out-Null
        Clear-AzureRmContext -Scope CurrentUser -Force
        Disable-AzureRMContextAutosave -Scope CurrentUser

        Import-Module -Name Azure.Storage -RequiredVersion 4.5.0 -Verbose
        Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4 -Verbose
        
        # Log into Azure Stack to check for existing images and push new ones if required ###
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Add-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null
        Write-Host "Checking to see if a Windows Server 2016 image is present in your Azure Stack Platform Image Repository"
        # Pre-validate that the Windows Server 2016 Server Core VM Image is not already available
        Remove-Variable -Name platformImageCore -Force -ErrorAction SilentlyContinue
        $sku = "2016-Datacenter-Server-Core"
        $platformImageCore = Get-AzsPlatformImage -Location "$azsLocation" -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -Version "1.0.0" -ErrorAction SilentlyContinue
        $serverCoreVMImageAlreadyAvailable = $false

        if ($platformImageCore -and $platformImageCore.ProvisioningState -eq 'Succeeded') {
            Write-Host "There appears to be at least 1 suitable Windows Server $sku image within your Platform Image Repository which we will use for the ASDK Configurator." 
            $serverCoreVMImageAlreadyAvailable = $true
        }

        # Pre-validate that the Windows Server 2016 Full Image is not already available
        Remove-Variable -Name platformImageFull -Force -ErrorAction SilentlyContinue
        $sku = "2016-Datacenter"
        $platformImageFull = Get-AzsPlatformImage -Location "$azsLocation" -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -Version "1.0.0" -ErrorAction SilentlyContinue
        $serverFullVMImageAlreadyAvailable = $false

        if ($platformImageFull -and $platformImageFull.ProvisioningState -eq 'Succeeded') {
            Write-Host "There appears to be at least 1 suitable Windows Server $sku image within your Platform Image Repository which we will use for the ASDK Configurator." 
            $serverFullVMImageAlreadyAvailable = $true
        }

        if ($serverCoreVMImageAlreadyAvailable -eq $false) {
            $downloadCURequired = $true
            Write-Host "You're missing the Windows Server 2016 Datacenter Server Core image in your Platform Image Repository."
        }

        if ($serverFullVMImageAlreadyAvailable -eq $false) {
            $downloadCURequired = $true
            Write-Host "You're missing the Windows Server 2016 Datacenter Full image in your Platform Image Repository."
        }

        if (($serverCoreVMImageAlreadyAvailable -eq $true) -and ($serverFullVMImageAlreadyAvailable -eq $true)) {
            $downloadCURequired = $false
            Write-Host "Windows Server 2016 Datacenter Full and Core Images already exist in your Platform Image Repository"
        }

        ### Download the latest Cumulative Update for Windows Server 2016 - Existing Azure Stack Tools module doesn't work ###

        if ($downloadCURequired -eq $true) {
            if ($deploymentMode -eq "Online") {

                # Mount the ISO, check the image for the version, then dismount
                Remove-Variable -Name buildVersion -ErrorAction SilentlyContinue
                $isoMountForVersion = Mount-DiskImage -ImagePath $ISOPath -StorageType ISO -PassThru
                $isoDriveLetterForVersion = ($isoMountForVersion | Get-Volume).DriveLetter
                $wimPath = "$IsoDriveLetterForVersion`:\sources\install.wim"
                $buildVersion = (dism.exe /Get-WimInfo /WimFile:$wimPath /index:1 | Select-String "Version ").ToString().Split(".")[2].Trim()
                Dismount-DiskImage -ImagePath $ISOPath

                Write-Host "You're missing at least one of the Windows Server 2016 Datacenter images, so we'll first download the latest Cumulative Update."
                # Define parameters
                $StartKB = 'https://support.microsoft.com/en-us/help/4000825'
                #$StartKB = 'https://support.microsoft.com/app/content/api/content/asset/en-us/4000816'
                $SearchString = 'Cumulative.*Server.*x64'
                
                # Define the arrays that will be used later
                $kbDownloads = @()
                $Urls = @()

                ### Firstly, check for build 14393, and if so, download the Servicing Stack Update or other MSUs will fail to apply.    
                if ($buildVersion -eq "14393") {
                    $ssuArray = @("4132216", "4465659")
                    $ssuSearchString = 'Windows Server 2016'

                    #$servicingStackKB = (Invoke-WebRequest -Uri 'https://portal.msrc.microsoft.com/api/security-guidance/en-US/CVE/ADV990001' -UseBasicParsing).Content
                    #$servicingStackKB = ((($servicingStackKB -split 'Windows 10 Version 1607/Server 2016</td>\\n<td>', 2)[1]).Split('<', 2)[0])
                    #$servicingStackKB = "4465659"
                    
                    foreach ($ssu in $ssuArray) {
                        Write-Host "Build is $buildVersion - Need to download: KB$($ssu) to update Servicing Stack before adding future Cumulative Updates"
                        $ssuKbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$ssu" -UseBasicParsing
                        $ssuAvailable_kbIDs = $ssuKbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
                        $ssuAvailable_kbIDs | Out-String | Write-Host
                        $ssuKbIDs = $ssuKbObj.Links | Where-Object ID -match '_link' | Where-Object innerText -match $ssuSearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $ssuAvailable_kbIDs }

                        # If innerHTML is empty or does not exist, use outerHTML instead
                        if (!$ssuKbIDs) {
                            $ssuKbIDs = $ssuKbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $ssuSearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $ssuAvailable_kbIDs }
                        }
                        $kbDownloads += "$ssuKbIDs"
                    }

                    # Get latest Malicious Software Update and other relevant updates
                    #$maliciousKb = (((Invoke-WebRequest -Uri "https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx" -UseBasicParsing).links | Select-Object href | Where-Object {($_.href -like "http:*KB*")} | Sort-Object | Select-Object -First 1).href.ToString()).Split("/")[4].Trim()
                    #$updateArray = @("$maliciousKb", "4091664")
                    $updateArray = @("4091664")
                    foreach ($update in $updateArray) {
                        Write-Host "Build is $buildVersion - Need to download: KB$($update) to ensure image is fully updated at first run"
                        $updateKbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$update%20x64%202016" -UseBasicParsing
                        $updateAvailable_kbIDs = $updateKbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID | Select-Object -First 1
                        $updateAvailable_kbIDs | Out-String | Write-Host
                        $kbDownloads += "$updateAvailable_kbIDs"
                    }
                }

                <# Find the KB Article Number for the latest Windows Server 2016 (Build 14393) Cumulative Update
                Write-Host "Accessing $StartKB to retrieve the list of updates."
                #$kbID = (Invoke-WebRequest -Uri $StartKB -UseBasicParsing).Content | ConvertFrom-Json | Select-Object -ExpandProperty Links | Where-Object level -eq 2 | Where-Object text -match $buildVersion | Select-Object -First 1
                $kbID = (Invoke-WebRequest -Uri 'https://support.microsoft.com/en-us/help/4000825' -UseBasicParsing).RawContent -split "`n"
                $kbID = ($kbID | Where-Object { $_ -like "*heading*$buildVersion*" } | Select-Object -First 1)
                $kbID = ((($kbID -split "KB", 2)[1]) -split "\s", 2)[0]

                if (!$kbID) {
                    Write-Host "No Windows Update KB found - this is an error. Your Windows Server images will be out of date"
                }
                #>

                $kbID = "4480977"

                # Get Download Link for the corresponding Cumulative Update
                #Write-Host "Found ID: KB$($kbID.articleID)"
                Write-Host "Found ID: KB$kbID)"
                $kbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$kbID" -UseBasicParsing
                $Available_kbIDs = $kbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
                $Available_kbIDs | Out-String | Write-Host
                $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object innerText -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }

                # If innerHTML is empty or does not exist, use outerHTML instead
                if (!$kbIDs) {
                    $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }
                }
            
                # Defined a KB array to hold the kbIDs and if the build is 14393, add the corresponding KBID to it
                $kbDownloads += "$kbIDs"

                foreach ( $kbID in $kbDownloads ) {
                    Write-Host "KB ID: $kbID"
                    $Post = @{ size = 0; updateID = $kbID; uidInfo = $kbID } | ConvertTo-Json -Compress
                    $PostBody = @{ updateIDs = "[$Post]" } 
                    $Urls += Invoke-WebRequest -Uri 'http://www.catalog.update.microsoft.com/DownloadDialog.aspx' -UseBasicParsing -Method Post -Body $postBody | Select-Object -ExpandProperty Content | Select-String -AllMatches -Pattern "(http[s]?\://download\.windowsupdate\.com\/[^\'\""]*)" | ForEach-Object { $_.matches.value }
                }

                # Download the corresponding Windows Server 2016 Cumulative Update (and possibly, Servicing Stack Updates)
                foreach ( $Url in $Urls ) {
                    $filename = (($Url.Substring($Url.LastIndexOf("/") + 1)).Split("-", 2)[1])
                    $filename = $filename -replace "_.*\.","."
                    $target = "$((Get-Item $ASDKpath).FullName)\images\$filename"
                    if (!(Test-Path -Path $target)) {
                        foreach ($ssu in $ssuArray) {
                            if ((Test-Path -Path "$((Get-Item $ASDKpath).FullName)\images\14393_ssu_kb$($ssu).msu")) {
                                Remove-Item -Path "$((Get-Item $ASDKpath).FullName)\images\14393_ssu_kb$($ssu).msu" -Force -Verbose -ErrorAction Stop
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
                if ($buildVersion -eq "14393") {
                    foreach ($ssu in $ssuArray) {
                        if ((Test-Path -Path "$((Get-Item $ASDKpath).FullName)\images\14393_ssu_kb$($ssu).msu")) {
                            Write-Host "The 14393 Servicing Stack Update already exists within the target folder"
                        }
                        else {
                            Write-Host "Renaming the Servicing Stack Update to ensure it is applied in the correct order"
                            #Get-ChildItem -Path "$ASDKpath\images" -Filter *.msu | Sort-Object Length | Select-Object -First 1 | Rename-Item -NewName "14393UpdateServicingStack.msu" -Force -ErrorAction Stop -Verbose
                            Get-ChildItem -Path "$ASDKpath\images" -Filter *.msu | Where-Object {$_.FullName -like "*$($ssu)*"} | Rename-Item -NewName "14393_ssu_kb$($ssu).msu" -Force -ErrorAction Stop -Verbose
                        }
                    }
                    $target = "$ASDKpath\images"
                }
            }
            elseif ($deploymentMode -ne "Online") {
                $target = "$ASDKpath\images"
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
Stop-Transcript -ErrorAction SilentlyContinue