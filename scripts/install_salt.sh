#!/bin/bash

# Validate input parameters
if [[ !("$#" -eq 1) ]]; 
    then echo "Parameters missing for Salt Master configuration." >&2
    exit 1
fi

# Get parameters and assign variables
salt_fqdn=$1

# Change the hostname to reflect external Azure Stack server name
sudo hostname "${salt_fqdn}"

# Get latest updates and install wget
apt-get update
apt-get install wget -y

# Import the SaltStack Repo Key
wget -O - https://repo.saltstack.com/apt/ubuntu/16.04/amd64/latest/SALTSTACK-GPG-KEY.pub | sudo apt-key add -

# Save the file
echo "deb http://repo.saltstack.com/apt/ubuntu/16.04/amd64/latest xenial main" > /etc/apt/sources.list.d/saltstack.list

# Get latest updates & install the Salt Master and Minion
apt-get update
apt-get install salt-master salt-minion -y

# Create Configuration Management Directory Structure
sudo mkdir -p /srv/{salt,formulas,pillar}

# Edit Salt Master Configuration File 
cat << EOF > /etc/salt/master
file_ignore_regex:
  - '/\.svn($|/)'
  - '/\.git($|/)'

hash_type: sha512

file_roots:
  base:
    - /srv/salt
    - /srv/formulas
    
pillar_roots:
  base:
    - /srv/pillar
EOF

# Edit Salt Minion Configuration File
cat << EOF > /etc/salt/minion
master: $(hostname)
master_finger: $(salt-key -F | grep master.pub | awk '{print $2}')
EOF

# Restart Salt Services
sudo service salt-master restart
sudo service salt-minion restart

# Sleep for 10 seconds
sleep 10

# Accept Salt Minion Key on Master
salt-key -a $(cat /etc/salt/minion_id) -y

# Test Salt Communication
salt '*' test.ping
