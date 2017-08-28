%#!/bin/bash

# Add the Ansible PPA Repo
sudo apt-add-repository ppa:ansible/ansible

# Get latest updates
sudo apt-get update

# Install Ansible
sudo apt-get install ansible

# Update profiles to reflect Terraform PATH and source it
echo 'export PATH=$PATH:~/terraform/' >> ~/.bashrc
echo 'export PATH=$PATH:~/terraform/' >> /home/${adminUsername}/.profile
