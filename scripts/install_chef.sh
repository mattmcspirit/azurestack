#!/bin/bash

# Validate input parameters
if [[ !("$#" -eq 7) ]]; 
    then echo "Parameters missing for Chef Server 12 configuration." >&2
    exit 1
fi

# Get parameters
chef_fqdn=$1
chef_admin=$2
chef_firstname=$3
chef_lastname=$4
chef_email=$5
chef_password=$6
chef_org=$7

sudo hostname ${chef_fqdn}

# Download & Install Chef Server 12
cd ~
wget https://packages.chef.io/files/stable/chef-server/12.15.7/ubuntu/16.04/chef-server-core_12.15.7-1_amd64.deb
sudo dpkg -i chef-server-core_*.deb

# Start Configuration
sudo chef-server-ctl reconfigure

# Configure user and organization
sleep 5

# Create user
sudo chef-server-ctl user-create ${chef_admin} ${chef_firstname} ${chef_lastname} ${chef_email} ${chef_password} --filename /home/${chef_admin}/${chef_admin}.pem

# Remove any whitespace from Company name
chef_orgConcat="$(echo -e "${chef_org}" | tr -d '[:space:]')"

# Create Organization
sudo chef-server-ctl org-create ${chef_org} "${chef_org}" --association_user ${chef_admin} --filename /home/${chef_admin}/${chef_orgConcat}-validator.pem

# Add the management GUI
sudo chef-server-ctl install chef-manage
sudo chef-server-ctl reconfigure
sudo chef-manage-ctl reconfigure --accept-license

#Add reporting
sudo chef-server-ctl install opscode-reporting
sudo chef-server-ctl reconfigure
sudo opscode-reporting-ctl reconfigure --accept-license
