#!/bin/bash

# Validate input parameters

if [[ !("$#" -eq 1) ]]; 
    then echo "Parameters missing for Jenkins configuration." >&2
    exit 1
fi

# Get parameter
Jenkins_fqdn=$1

# Set Hostname
sudo hostname ${Jenkins_fqdn}

# Install Jenkins Dependencies
sudo add-apt-repository ppa:openjdk-r/ppa --yes
sudo apt-get update --yes
sudo apt-get install openjdk-8-jre openjdk-8-jre-headless openjdk-8-jdk --yes
sudo apt-get install wget --yes

# Install and Start Jenkins
wget -q -O - https://pkg.jenkins.io/debian/jenkins-ci.org.key | sudo apt-key add -
sh -c 'echo deb http://pkg.jenkins.io/debian-stable binary/ > /etc/apt/sources.list.d/jenkins.list'
sudo apt-get update
sudo apt-get install jenkins --yes
sudo service jenkins restart
