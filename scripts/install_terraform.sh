%#!/bin/bash

# Validate input parameters
if [[ !("$#" -eq 1) ]]; 
    then echo "Parameters missing for Terraform configuration." >&2
    exit 1
fi

# Get parameters and assign variables
adminUsername=$1

# Get latest updates
sudo apt-get update

# Install jq and unzip
sudo apt-get install jq unzip -y

# Create directories to house Terraform files
cd
mkdir -p /opt/terraform && cd $_

# Download the latest version of x64 Terraform and unzip
terraform_url=$(curl https://releases.hashicorp.com/index.json | jq '{terraform}' | egrep "linux.amd64" | sort --version-sort -r | head -1 | awk -F[\"] '{print $4}')
curl -o terraform.zip $terraform_url
unzip terraform.zip

# Update profiles to reflect Terraform PATH and source it
echo 'export PATH=$PATH:/opt/terraform/' >> ~/.bashrc
source ~/.bashrc
echo 'export PATH=$PATH:/opt/terraform/' >> /home/${adminUsername}/.profile
echo 'export PATH=$PATH:/opt/terraform/' >> ~/.profile
sed -i -e '/secure_path/ s|"|:/opt/terraform"|2' /etc/sudoers