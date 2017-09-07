# Running the DevOps Toolkit Script

In order to download the script, you'll want to run the following from your administrative PowerShell console:

```powershell
    # Variables
    $Uri = 'https://raw.githubusercontent.com/mattmcspirit/azurestack/master/powershell/DevOpsToolkit.ps1'
    $LocalPath = 'c:\DevOpsToolkit'

    # Create folder
    New-Item $LocalPath -Type directory

    # Download file
    Invoke-WebRequest $uri -OutFile ($LocalPath + '\' + 'DevOpsToolkit.ps1')
    Set-Location $LocalPath
```

Once downloaded, in order to execute the script, you will simply run the following, substituting your values where appropriate:

```powershell
    .\DevOpsToolkit.ps1 -azureDirectoryTenantName <yourdirectoryname> -authenticationType <yourauthenticationtype>
```

- For -azureDirectoryTenantName, you would use either **yourDirectoryTenantName.onmicrosoft.com**, or, if you're using a custom domain name, you'd use that, such as **contoso.com**. You **don't** need to specify a user@domain at this time.
- For -authenticationType, specify **either AzureAD or ADFS**

So, for instance, a completed example may look like:

```powershell
    .\DevOpsToolkit.ps1 -azureDirectoryTenantName contosoazurestack.com -authenticationType AzureAD
```

## Troubleshooting & Improvements
This script, and the packages have been developed, and tested, to the best of my abaility.  I'm not a PowerShell guru, nor a specialist in Linux scripting, thus, if you do encounter issues, [let me know through GitHub](<../../issues>) and I'll do my best to resolve them.

Likewise, if you are awesome at PowerShell, or Linux scripting, or would like to have additional tools included within the packages, let me know, and we can collaborate to improve the overall project!

## Changelog
To view version history, and see changes made for new versions, check out the [changelog](changelog.md)
