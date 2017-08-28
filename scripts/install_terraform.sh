%#!/bin/bash

# Validate input parameters
if [[ !("$#" -eq 1) ]]; 
    then echo "Parameters missing for Terraform configuration." >&2
    exit 1
fi

# Get parameters and assign variables
terraform_admin=$1

# Get latest updates
sudo apt-get update

# Download the 0.10.2 version of x64 Terraform
wget https://releases.hashicorp.com/terraform/0.10.2/terraform_0.10.2_linux_amd64.zip

# Make new directory for Terraform files
mkdir -p ~/opt/terraform

# Unzio files
unzip terraform_0.1.1_darwin_amd64.zip -d ~/opt/terraform

# Update Root Path to reflect Terraform
# sed -i -e '/secure_path/ s|"|:~/opt/terraform/bin"|2' /etc/sudoers

