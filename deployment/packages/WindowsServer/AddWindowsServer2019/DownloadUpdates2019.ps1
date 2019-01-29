[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String] $UpdatePath,

    [Parameter(Mandatory = $true)]
    [String] $ISOPath
)

$Global:VerbosePreference = "Continue"
$Global:ErrorActionPreference = 'Stop'
$Global:ProgressPreference = 'SilentlyContinue'

### DOWNLOADER FUNCTION #####################################################################################################################################
#############################################################################################################################################################
function DownloadWithRetry([string] $downloadURI, [string] $downloadLocation, [int] $retries) {
    while ($true) {
        try {
            Write-Host "Downloading: $downloadURI"
            (New-Object System.Net.WebClient).DownloadFile($downloadURI, $downloadLocation)
            break
        }
        catch {
            $exceptionMessage = $_.Exception.Message
            Write-Host "Failed to download '$downloadURI': $exceptionMessage"
            if ($retries -gt 0) {
                $retries--
                Write-Host "Waiting 10 seconds before retrying. Retries left: $retries"
                Start-Sleep -Seconds 10
            }
            else {
                $exception = $_.Exception
                throw $exception
            }
        }
    }
}

### MOUNT ISO AND DETERMINE VERSION #########################################################################################################################
#############################################################################################################################################################

# Mount the ISO, check the image for the version, then dismount
Remove-Variable -Name buildVersion -ErrorAction SilentlyContinue
$isoMountForVersion = Mount-DiskImage -ImagePath $ISOPath -StorageType ISO -PassThru
$isoDriveLetterForVersion = ($isoMountForVersion | Get-Volume).DriveLetter
$wimPath = "$IsoDriveLetterForVersion`:\sources\install.wim"
$buildVersion = (dism.exe /Get-WimInfo /WimFile:$wimPath /index:1 | Select-String "Version ").ToString().Split(".")[2].Trim()
Dismount-DiskImage -ImagePath $ISOPath

### CREATE ARRAYS ###########################################################################################################################################
#############################################################################################################################################################

$kbDownloads = @()
$Urls = @()

### GET SSU AND OTHER UPDATES ###############################################################################################################################
#############################################################################################################################################################

### Firstly, check for build 17763, and if so, download the Servicing Stack Update or other MSUs will fail to apply.
if ($buildVersion -eq "17763") {
    $ssuArray = @("4470788")
    $ssuSearchString = 'Windows Server 2019'
                    
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
        # Add to the array
        $kbDownloads += "$ssuKbIDs"
    }
    # Get latest Malicious Software Update (cannot currently automate install due to .exe) and other relevant updates
    #$maliciousKb = (((Invoke-WebRequest -Uri "https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx" -UseBasicParsing).links | Select-Object href | Where-Object {($_.href -like "http:*KB*")} | Sort-Object | Select-Object -First 1).href.ToString()).Split("/")[4].Trim()
    $updateArray = @("4465065")
    foreach ($update in $updateArray) {
        Write-Host "Build is $buildVersion - Need to download: KB$($update) to ensure image is fully updated at first run"
        $updateKbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$update%20x64%202019" -UseBasicParsing
        $updateAvailable_kbIDs = $updateKbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID | Select-Object -First 1
        $updateAvailable_kbIDs | Out-String | Write-Host
        # Add to the array
        $kbDownloads += "$updateAvailable_kbIDs"
    }
}
else {
    Throw "Build is $buildVersion. This script has not been tested with builds different to 17763 (WS2019 RTM). Please use this build for uploading to Azure Stack."
}

### GET CUMULATIVE UPDATES ##################################################################################################################################
#############################################################################################################################################################

$StartKB = 'https://support.microsoft.com/en-us/help/4464619'
$SearchString = 'Cumulative.*Server.*x64'

# Find the KB Article Number for the latest Windows Server 2019 (Build 17763) Cumulative Update
Write-Host "Accessing $StartKB to retrieve the list of updates."
#$kbID = (Invoke-WebRequest -Uri $StartKB -UseBasicParsing).Content | ConvertFrom-Json | Select-Object -ExpandProperty Links | Where-Object level -eq 2 | Where-Object text -match $buildVersion | Select-Object -First 1
$kbID = (Invoke-WebRequest -Uri 'https://support.microsoft.com/en-us/help/4464619' -UseBasicParsing).RawContent -split "`n"
$kbID = ($kbID | Where-Object { $_ -like "*heading*17763*" } | Select-Object -First 1)
$kbID = ((($kbID -split "KB", 2)[1]) -split "\s", 2)[0]

if (!$kbID) {
    Write-Host "No Windows Update KB found - this is an error. Your Windows Server images will be out of date"
}

# Get Download Link for the corresponding Cumulative Update
Write-Host "Found ID: KB$kbID)"
$kbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$kbID" -UseBasicParsing
$Available_kbIDs = $kbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
$Available_kbIDs | Out-String | Write-Host
$CUkbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }

# Add to the array
$kbDownloads += "$CUkbIDs"

### GET .NET UPDATE #########################################################################################################################################
#############################################################################################################################################################

# Find the KB Article Number for the latest .NET on Windows Server 2019 (Build 17763) Cumulative Update
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
Write-Host "Found ID: KB$NETkbID)"
$kbObj = Invoke-WebRequest -Uri "http://www.catalog.update.microsoft.com/Search.aspx?q=KB$NETkbID" -UseBasicParsing
$Available_kbIDs = $kbObj.InputFields | Where-Object { $_.Type -eq 'Button' -and $_.Value -eq 'Download' } | Select-Object -ExpandProperty ID
$Available_kbIDs | Out-String | Write-Host
$NETkbIDs = $kbObj.Links | Where-Object ID -match '_link' | Where-Object outerHTML -match $SearchString | ForEach-Object { $_.Id.Replace('_link', '') } | Where-Object { $_ -in $Available_kbIDs }
            
# Add to the array
$kbDownloads += "$NETkbIDs"

foreach ( $kbID in $kbDownloads ) {
    Write-Host "KB ID: $kbID"
    $Post = @{ size = 0; updateID = $kbID; uidInfo = $kbID } | ConvertTo-Json -Compress
    $PostBody = @{ updateIDs = "[$Post]" } 
    $Urls += Invoke-WebRequest -Uri 'http://www.catalog.update.microsoft.com/DownloadDialog.aspx' -UseBasicParsing -Method Post -Body $postBody | Select-Object -ExpandProperty Content | Select-String -AllMatches -Pattern "(http[s]?\://download\.windowsupdate\.com\/[^\'\""]*)" | ForEach-Object { $_.matches.value }
}

### DOWNLOAD ALL UPDATES ####################################################################################################################################
#############################################################################################################################################################

# Download the corresponding Windows Server 2019 Cumulative Update (and possibly, Servicing Stack Updates)
foreach ( $Url in $Urls ) {
    $filename = (($Url.Substring($Url.LastIndexOf("/") + 1)).Split("-", 2)[1])
    $filename = $filename -replace "_.*\.", "."
    $target = "$((Get-Item $UpdatePath).FullName)\$filename"
    if (!(Test-Path -Path $target)) {
        foreach ($ssu in $ssuArray) {
            if ((Test-Path -Path "$((Get-Item $UpdatePath).FullName)\17763_SSU_KB$($ssu).msu")) {
                Remove-Item -Path "$((Get-Item $UpdatePath).FullName)\17763_SSU_KB$($ssu).msu" -Force -Verbose -ErrorAction Stop
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

# If this is for Build 17763, rename the .msu for the servicing stack update, to ensure it gets applied in the correct order when patching the WIM file.
if ($buildVersion -eq "17763") {
    foreach ($ssu in $ssuArray) {
        if ((Test-Path -Path "$((Get-Item $UpdatePath).FullName)\17763_SSU_KB$($ssu).msu")) {
            Write-Host "The 17763 Servicing Stack Update already exists within the target folder"
        }
        else {
            Write-Host "Renaming the Servicing Stack Update to ensure it is applied in the correct order"
            #Get-ChildItem -Path "$UpdatePath" -Filter *.msu | Sort-Object Length | Select-Object -First 1 | Rename-Item -NewName "17763UpdateServicingStack.msu" -Force -ErrorAction Stop -Verbose
            Get-ChildItem -Path "$UpdatePath" -Filter *.msu | Where-Object {$_.FullName -like "*$($ssu)*"} | Rename-Item -NewName "17763_SSU_KB$($ssu).msu" -Force -ErrorAction Stop -Verbose
        }
    }
    $target = "$UpdatePath"
}