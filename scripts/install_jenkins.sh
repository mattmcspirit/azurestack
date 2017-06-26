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
add-apt-repository ppa:openjdk-r/ppa
apt-get update
apt-get install openjdk-7-jdk -y
apt-get install openjdk-7-jre -y
apt-get install wget -y

# Set Java environment variables
export JAVA_HOME=/usr/lib/jvm/java-7-openjdk-amd64
export PATH=$PATH:/usr/lib/jvm/java-7-openjdk-amd64/bin

# Install and Start Jenkins
wget -q -O - https://pkg.jenkins.io/debian/jenkins-ci.org.key | sudo apt-key add -
sh -c 'echo deb http://pkg.jenkins.io/debian-stable binary/ > /etc/apt/sources.list.d/jenkins.list'
apt-get update
apt-get install jenkins -y
systemctl start jenkins
