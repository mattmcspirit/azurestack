# ConfigASDK.ps1 Version History
Here you'll find information on key changes, bug fixes and improvements made by version.

## ConfigASDK.ps1

    1807    Updated to provide support for offline deployments, using zip file containing pre-downloaded binaries, tools and scripts along with PS 1.4.0 support
    1805.3  Added support for offline deployment in conjunction with the ASDK Offline Dependency Downloader
    1805.2  Update to Windows Image creation to handle adding of KB4132216 to update Servicing Stack (for build 14393) for future updates
            (<https://support.microsoft.com/en-us/help/4132216>)
    1805.1  Updates to handling Azure subscriptions with multiple Azure AD tenants, and error handling for random Add-AzureRmVhd pipeline error,
            added automated App Service quota to base plan, created user subscription and activated RPs for that subscription.
    1805    Updated with improvements to Azure account verification, ability to skip RP deployment, run counters and bug fixes
    1804    Updated with support for ASDK 1804 and PowerShell 1.3.0, bug fixes, reduced number of modules imported from GitHub tools repo
    3.1     Update added App Service automation, bug fixes, MySQL Root account fix.
    3.0     Major update for ASDK release 20180329.1
    2.0     Update for release 1.0.280917.3 
    1.0:    Small bug fixes and adding quotas/plan/offer creation
    0.5:    Add SQL 2014 VM deployment
    0.4:    Add Windows update disable
    0.3:    Bug fix (SQL Provider prompting for tenantdirectoryID)
    0.2:    Bug Fix (AZStools download)