
#!/bin/bash

# Get latest updates
apt-get update
apt-get dist-upgrade

# Install Salt with Bootstrap
curl -L https://bootstrap.saltstack.com -o install_salt.sh
sudo sh install_salt.sh -P -M

# Open Firewall
sudo ufw allow 4505:4506/tcp

# Edit Salt Minion Configuration File
sudo sed -i "s/#master: salt/master: $(hostname)/g" /etc/salt/minion
sudo sed -i "s/#master_finger: ''/master_finger: $(salt-key -F | grep master.pub | awk '{print $2}')/g" /etc/salt/minion

# Restart Salt Minion Services
sudo service salt-minion restart

# Sleep for 10 seconds
sleep 10

# Accept Salt Minion Key on Master
salt-key -a $(cat /etc/salt/minion_id) -y

# Test Salt Communication
salt '*' test.ping
