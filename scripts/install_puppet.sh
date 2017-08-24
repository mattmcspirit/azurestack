%#!/bin/bash

# Add the Puppet Repo with latest bits
wget https://apt.puppetlabs.com/puppet-release-xenial.deb
sudo dpkg -i puppet-release-xenial.deb 

# Get latest updates
sudo apt-get update

# View cache & install Puppet Server
sudo apt-cache show puppetserver
DEBIAN_FRONTEND=noninteractive && apt-get install puppetserver -y

# Check Puppet Server Status
sudo systemctl status puppetserver --no-pager

# Update puppet.conf file to reflect hostname
/opt/puppetlabs/bin/puppet config set --section master dns_alt_names $(hostname -f),$(hostname)
/opt/puppetlabs/bin/puppet config set --section main certname $(hostname -f)
/opt/puppetlabs/bin/puppet config set --section main server $(hostname -f)
/opt/puppetlabs/bin/puppet config set --section main environment production
/opt/puppetlabs/bin/puppet config set --section main runinterval 1h

# Start puppetmaster service
sudo systemctl start puppetserver
sudo systemctl enable puppetserver

# Update Firewall iptables rules
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 8140 -j ACCEPT

# Enable the Puppet Agent on the Puppet Master
sudo /opt/puppetlabs/bin/puppet resource service puppet ensure=running enable=true

# Wait for the service to start and initial config to sync
sleep 30

# Sync Puppet Agent and Master
sudo /opt/puppetlabs/bin/puppet agent --test
