# DevOps Toolkit Packages

In this folder, you'll find all of the .azpkg files, that ultimately get uploaded into your Azure Stack. In addition, these .azpkg files are essentially zip files, that contain the necessary files and folders required for an Azure Stack marketplace item.  You'll find the 
respective 'raw' files and folders are also accessible to you, to modify, customize, and make your own.

If you do wish to modify the raw files, you'll need to recreate the package, for which you can [find guidance here](https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-create-and-publish-marketplace-item).

In each folder, you'll also find a maintemplate.parameters.json file, which, if you're choosing to automate some of the deployments of the tools once the DevOps Toolkit has been installed, you should find those files useful.
