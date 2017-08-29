%#!/bin/bash

# Add the Ansible PPA Repo
sudo apt-get update
sudo apt-get install software-properties-common -y
sudo apt-add-repository ppa:ansible/ansible -y

# Get latest updates
sudo apt-get update

# Install Ansible
sudo apt-get install ansible -y
