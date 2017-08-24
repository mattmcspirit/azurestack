%#!/bin/bash

# Add the Puppet Repo with latest bits
wget https://apt.puppetlabs.com/puppet-release-xenial.deb
# ls -ltrh puppet-release-xenial.deb 
sudo dpkg -i puppet-release-xenial.deb 

# Get latest updates
sudo apt-get update

# View cache & install Puppet Server
sudo apt-cache show puppetserver
DEBIAN_FRONTEND=noninteractive && apt-get install puppetserver -y

# Check Puppet Server Status
systemctl status puppetserver --no-pager

# Start Puppet Server Service
systemctl start puppetserver

# Re-Check Puppet Server Status
systemctl status puppetserver --no-pager

# Update Firewall iptables rules
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 8140 -j ACCEPT

# Enable the Puppet Agent on the Puppet Master
sudo /opt/puppetlabs/bin/puppet resource service puppet ensure=running enable=true

# Update the executable location path for Puppet for future reboots
echo 'export PATH=/opt/puppetlabs/bin:$PATH' >> ~/.profile
echo 'export PATH=/opt/puppetlabs/bin:$PATH' >> ~/.bashrc
export PATH=/opt/puppetlabs/bin:$PATH

# Update the hostname for the agent
sudo /opt/puppetlabs/bin/puppet config set --section agent server $(hostname)

# Update certificates for agents
rm /etc/puppetlabs/puppet/ssl/private_keys/$(hostname -f).pem
rm /etc/puppetlabs/puppet/ssl/ca/signed/$(hostname -f).pem
rm /etc/puppetlabs/puppet/ssl/certs/$(hostname -f).pem
puppet cert generate $(hostname -f) --dns_alt_names=$(hostname -f),$(hostname)

# Restart Puppet Master
service puppetserver restart

#Wait for the service to start and initial config to sync
sleep 30

# Sync Puppet Agent and Master
# sudo /opt/puppetlabs/bin/puppet agent --test
