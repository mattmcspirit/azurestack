[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $ConfigASDKProgressLogPath,

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
    [String] $ScriptLocation
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

### DOWNLOADER FUNCTION #####################################################################################################################################
#############################################################################################################################################################
function DownloadWithRetry([string] $downloadURI, [string] $downloadLocation, [int] $retries) {
    while ($true) {
        try {
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

### SET LOG LOCATION ###
$logDate = Get-Date -Format FileDate
New-Item -ItemType Directory -Path "$ScriptLocation\Logs\$logDate\WindowsUpdates" -Force | Out-Null
$logPath = "$ScriptLocation\Logs\$logDate\WindowsUpdates"

### START LOGGING ###
$runTime = $(Get-Date).ToString("MMdd-HHmmss")
$fullLogPath = "$logPath\WindowsUpdates$runTime.txt"
Start-Transcript -Path "$fullLogPath" -Append -IncludeInvocationHeader

$progress = Import-Csv -Path $ConfigASDKProgressLogPath
$RowIndex = [array]::IndexOf($progress.Stage, "WindowsUpdates")

if (($progress[$RowIndex].Status -eq "Incomplete") -or ($progress[$RowIndex].Status -eq "Failed")) {
    try {
        $ErrorActionPreference = "Stop";
        # Log into Azure Stack to check for existing images and push new ones if required ###
        $ArmEndpoint = "https://adminmanagement.local.azurestack.external"
        Add-AzureRMEnvironment -Name "AzureStackAdmin" -ArmEndpoint "$ArmEndpoint" -ErrorAction Stop
        Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID -Credential $asdkCreds -ErrorAction Stop | Out-Null

        Write-Verbose "Checking to see if a Windows Server 2016 image is present in your Azure Stack Platform Image Repository"
        # Pre-validate that the Windows Server 2016 Server Core VM Image is not already available

        Remove-Variable -Name platformImageCore -Force -ErrorAction SilentlyContinue
        $sku = "2016-Datacenter-Server-Core"
        $platformImageCore = Get-AzsPlatformImage -Location "$azsLocation" -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -Version "1.0.0" -ErrorAction SilentlyContinue
        $serverCoreVMImageAlreadyAvailable = $false

        if ($null -ne $platformImageCore -and $platformImageCore.ProvisioningState -eq 'Succeeded') {
            Write-Verbose "There appears to be at least 1 suitable Windows Server $sku image within your Platform Image Repository which we will use for the ASDK Configurator." 
            $serverCoreVMImageAlreadyAvailable = $true
        }

        # Pre-validate that the Windows Server 2016 Full Image is not already available
        Remove-Variable -Name platformImageFull -Force -ErrorAction SilentlyContinue
        $sku = "2016-Datacenter"
        $platformImageFull = Get-AzsPlatformImage -Location "$azsLocation" -Publisher MicrosoftWindowsServer -Offer WindowsServer -Sku "$sku" -Version "1.0.0" -ErrorAction SilentlyContinue
        $serverFullVMImageAlreadyAvailable = $false

        if ($null -ne $platformImageFull -and $platformImageFull.ProvisioningState -eq 'Succeeded') {
            Write-Verbose "There appears to be at least 1 suitable Windows Server $sku image within your Platform Image Repository which we will use for the ASDK Configurator." 
            $serverFullVMImageAlreadyAvailable = $true
        }

        if ($serverCoreVMImageAlreadyAvailable -eq $false) {
            $downloadCURequired = $true
            Write-Verbose "You're missing the Windows Server 2016 Datacenter Server Core image in your Platform Image Repository."
        }

        if ($serverFullVMImageAlreadyAvailable -eq $false) {
            $downloadCURequired = $true
            Write-Verbose "You're missing the Windows Server 2016 Datacenter Full image in your Platform Image Repository."
        }

        if (($serverCoreVMImageAlreadyAvailable -eq $true) -and ($serverFullVMImageAlreadyAvailable -eq $true)) {
            $downloadCURequired = $false
            Write-Verbose "Windows Server 2016 Datacenter Full and Core Images already exist in your Platform Image Repository"
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

                Write-Verbose "You're missing at least one of the Windows Server 2016 Datacenter images, so we'll first download the latest Cumulative Update."
                # Define parameters
                $StartKB = 'https://support.microsoft.com/app/content/api/content/asset/en-us/4000816'
                $SearchString = 'Cumulative.*Server.*x64'

                ### Firstly, check for build 14393, and if so, download the Servicing Stack Update or other MSUs will fail to apply.    
                if ($buildVersion -eq "14393") {
                    $servicingStackKB = "4132216"
                    $ServicingSearchString = 'Windows Server 2016'
                    Write-Verbose "Build is $buildVersion - Need to download: KB$($servicingStackKB) to update Servicing Stack before adding future Cumulative Updates"
                    $servicingKbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$servicingStackKB" -UseBasicParsing
                    $servicingAvailable_kbIDs = $servicingKbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
                    $servicingAvailable_kbIDs | Out-String | Write-Verbose
                    $servicingKbIDs = $servicingKbObj.Links | Where-Object ID -match '_link' | Where-Object innerText -match $ServicingSearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $servicingAvailable_kbIDs }

                    # If innerHTML is empty or does not exist, use outerHTML instead
                    if ($null -eq $servicingKbIDs) {
                        $servicingKbIDs = $servicingKbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $ServicingSearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $servicingAvailable_kbIDs }
                    }
                }

                # Find the KB Article Number for the latest Windows Server 2016 (Build 14393) Cumulative Update
                Write-Verbose "Downloading $StartKB to retrieve the list of updates."
                $kbID = (Invoke-WebRequest -Uri $StartKB -UseBasicParsing).Content | ConvertFrom-Json | Select-Object -ExpandProperty Links | Where-Object level -eq 2 | Where-Object text -match $buildVersion | Select-Object -First 1

                # Get Download Link for the corresponding Cumulative Update
                Write-Verbose "Found ID: KB$($kbID.articleID)"
                $kbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$($kbID.articleID)" -UseBasicParsing
                $Available_kbIDs = $kbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
                $Available_kbIDs | Out-String | Write-Verbose
                $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object innerText -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }

                # If innerHTML is empty or does not exist, use outerHTML instead
                if ($null -eq $kbIDs) {
                    $kbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }
                }
            
                # Defined a KB array to hold the kbIDs and if the build is 14393, add the corresponding KBID to it
                $kbDownloads = @()
                if ($buildVersion -eq "14393") {
                    $kbDownloads += "$servicingKbIDs"
                }
                $kbDownloads += "$kbIDs"
                $Urls = @()

                foreach ( $kbID in $kbDownloads ) {
                    Write-Verbose "KB ID: $kbID"
                    $Post = @{ size = 0; updateID = $kbID; uidInfo = $kbID } | ConvertTo-Json -Compress
                    $PostBody = @{ updateIDs = "[$Post]" } 
                    $Urls += Invoke-WebRequest -Uri 'http://www.catalog.update.microsoft.com/DownloadDialog.aspx' -UseBasicParsing -Method Post -Body $postBody | Select-Object -ExpandProperty Content | Select-String -AllMatches -Pattern "(http[s]?\://download\.windowsupdate\.com\/[^\'\""]*)" | ForEach-Object { $_.matches.value }
                }

                # Download the corresponding Windows Server 2016 Cumulative Update (and possibly, Servicing Stack Update)
                foreach ( $Url in $Urls ) {
                    $filename = $Url.Substring($Url.LastIndexOf("/") + 1)
                    $target = "$((Get-Item $ASDKpath).FullName)\images\$filename"
                    Write-Verbose "Update will be stored at $target"
                    Write-Verbose "These can be larger than 1GB, so may take a few minutes."
                    if (!(Test-Path -Path $target)) {
                        if ((Test-Path -Path "$((Get-Item $ASDKpath).FullName)\images\14393UpdateServicingStack.msu")) {
                            Remove-Item -Path "$((Get-Item $ASDKpath).FullName)\images\14393UpdateServicingStack.msu" -Force -Verbose -ErrorAction Stop
                        }
                        DownloadWithRetry -downloadURI "$Url" -downloadLocation "$target" -retries 10
                    }
                    else {
                        Write-Verbose "File exists: $target. Skipping download."
                    }
                }

                # If this is for Build 14393, rename the .msu for the servicing stack update, to ensure it gets applied first when patching the WIM file.
                if ($buildVersion -eq "14393") {
                    if ((Test-Path -Path "$((Get-Item $ASDKpath).FullName)\images\14393UpdateServicingStack.msu")) {
                        Write-Verbose "The 14393 Servicing Stack Update already exists within the target folder"
                    }
                    else {
                        Write-Verbose "Renaming the Servicing Stack Update to ensure it is applied first"
                        Get-ChildItem -Path "$ASDKpath\images" -Filter *.msu | Sort-Object Length | Select-Object -First 1 | Rename-Item -NewName "14393UpdateServicingStack.msu" -Force -ErrorAction Stop -Verbose
                    }
                    $target = "$ASDKpath\images"
                }
            }
            elseif ($deploymentMode -ne "Online") {
                $target = "$ASDKpath\images"
            }
        }
        # Update the ConfigASDKProgressLog.csv file with successful completion
        Write-Verbose "Updating ConfigASDKProgressLog.csv file with successful completion`r`n"
        $progress = Import-Csv -Path $ConfigASDKProgressLogPath
        $progress[$RowIndex].Status = "Complete"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
    }
    catch {
        Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) Failed`r`n"
        $progress = Import-Csv -Path $ConfigASDKProgressLogPath
        $progress[$RowIndex].Status = "Failed"
        $progress | Export-Csv $ConfigASDKProgressLogPath -NoTypeInformation -Force
        Write-Output $progress | Out-Host
        throw "$_.Exception.Message"
        Set-Location $ScriptLocation
        return
    }
}
elseif ($progress[$RowIndex].Status -eq "Complete") {
    Write-Verbose "ASDK Configuration Stage: $($progress[$RowIndex].Stage) previously completed successfully"
}
Set-Location $ScriptLocation
Stop-Transcript -ErrorAction SilentlyContinue