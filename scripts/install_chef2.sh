#!/bin/bash

# Get parameters
chef_fqdn="$1"
chef_vmadmin="$2"
chef_admin="$3"
chef_firstname="$4"
chef_lastname="$5"
chef_email="$6"
chef_password="$7"
chef_org="$8"

sudo hostname ${chef_fqdn}

echo "${chef_fqdn}"
echo "${chef_vmadmin}"
echo "${chef_admin}"
echo "${chef_firstname}"
echo "${chef_lastname}"
echo "${chef_email}"
echo "${chef_password}"
echo "${chef_org}"

# Remove any whitespace from Company name
chef_orgConcat="$(echo -e "${chef_org}" | tr -d '[:space:]')"

echo "${chef_orgConcat}"
