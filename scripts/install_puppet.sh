%#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

# Add the Puppet Repo with latest bits
wget https://apt.puppetlabs.com/puppet-release-xenial.deb
ls -ltrh puppet-release-xenial.deb 
sudo dpkg -i puppet-release-xenial.deb 

# Get latest updates
sudo apt-get update

# View cache & install Puppet Server
sudo apt-cache show puppetserver
sudo apt-get install puppetserver -y

# Check Puppet Server Status
systemctl status puppetserver --no-pager

# Start Puppet Server Service
systemctl start puppetserver

# Re-Check Puppet Server Status
systemctl status puppetserver --no-pager

# Update the executable location path for Puppet for future reboots
echo 'export PATH=/opt/puppetlabs/bin:$PATH' >> ~/.profile
export PATH=/opt/puppetlabs/bin:$PATH

# Update Firewall iptables rules
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 8140 -j ACCEPT

# Enable the Puppet Agent on the Puppet Master
sudo /opt/puppetlabs/bin/puppet resource service puppet ensure=running enable=true

#Wait for the service to start and initial config to sync
Sleep 30

# Sync Puppet Agent and Master
# sudo /opt/puppetlabs/bin/puppet agent --test
