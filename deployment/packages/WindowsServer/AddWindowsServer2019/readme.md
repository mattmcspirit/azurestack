Adding Windows Server 2019 Evaluation Images to Azure Stack
==============
There is not currently a Windows Server 2019 image available for depoloyment within an Azure Stack environment. For those of you who wish to add a Windows Server 2019 Evaluation image, for either Server Core, Server with Desktop Experience, or both, the following guide will help you do add the images and corresponding gallery items to your Azure Stack system.

Requirements
-----------
Before you run the scripts, you will need the following:

* A **Windows Server 2019 Evaluation ISO** - this can be downloaded from https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019.
* A machine with access to your Azure Stack environment. If this is an ASDK, you can run these scripts on the ASDK host. If this is an integrated system, you will want to use a machine that can access the integrated system over a fast network, as the upload process from your machine to the integrated system involves a **large transfer of data**.
* The machine you use for running the scripts, and uploading the images, needs to have **the latest Azure Stack PowerShell modules** installed. If you configured your ASDK with my ASDK Configurator, you will already have the appropriate PowerShell modules installed. If you did not use my ASDK Configurator, follow guidance here: https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-powershell-install.
* The machine you use for running the script **must have enough storage space**, locally, to create a VHD from the ISO. This means, if you choose to create a 50GB Windows Server 2019 VHD, you will need around ~55-60GB (which includes the space for the ISO file, and any overhead).

Step by Step guidance
-----------
Open a PowerShell ISE window (as administrator) and run the following commands:

```powershell
# Create directory on a chosen drive.
New-Item -ItemType Directory -Force -Path "D:\WS2019IMAGES"
Set-Location "D:\WS2019IMAGES"

# Download the scripts.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-Webrequest http://bit.ly/configasdk -UseBasicParsing -OutFile DeployImages2019.ps1
```