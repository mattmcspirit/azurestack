#!/bin/bash

# Validate input parameters
if [[ !("$#" -eq 8) ]]; 
    then echo "Parameters missing for Chef Server 12 configuration." >&2
    exit 1
fi

# Get parameters
chef_fqdn=$1
chef_vmadmin=$2
chef_admin=$3
chef_firstname=$4
chef_lastname=$5
chef_email=$6
chef_password=$7
chef_org=$8

echo "${chef_fqdn}"
echo "${chef_vmadmin}"
echo "${chef_admin}"
echo "${chef_firstname}"
echo "${chef_lastname}"
echo "${chef_email}"
echo "${chef_password}"
echo "${chef_org}"

sleep 30

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
sudo chef-server-ctl user-create ${chef_admin} ${chef_firstname} ${chef_lastname} ${chef_email} ${chef_password} --filename "${chef_admin}".pem

# Remove any whitespace from Company name and create lower case version
chef_orgConcat="$(echo -e "${chef_org}" | tr -d '[:space:]')"
chef_orgLower="$(echo -e "${chef_orgConcat}" | tr '[:upper:]' '[:lower:]')"

# Create Organization
sudo chef-server-ctl org-create "${chef_orgLower}" "${chef_org}" --association_user ${chef_admin} --filename "${chef_orgLower}"-validator.pem

# Add the management GUI
sudo chef-server-ctl install chef-manage
sudo chef-server-ctl reconfigure
sudo chef-manage-ctl reconfigure --accept-license

#Add reporting
sudo chef-server-ctl install opscode-reporting
sudo chef-server-ctl reconfigure
sudo opscode-reporting-ctl reconfigure --accept-license
