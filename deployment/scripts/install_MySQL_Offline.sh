#!/bin/bash
# This script is used when installing MySQL 5.7 from locally downloaded MySQL binaries
# These binaries should be stored in a local Azure Stack storage account, and configured by the ASDK Configurator

# Validate input parameters
if [[ ! ("$#" -eq 2) ]];
then
    echo "Parameters missing for MySQL configuration." >&2
    exit 1
fi

# Get parameters and assign variables
MySQLPassword=$1
AllowRemoteConnections=$(echo "$2" | tr '[:upper:]' '[:lower:]')

# Set hostname in etc/hosts
sudo echo "127.0.0.1  $HOSTNAME" | sudo tee -a /etc/hosts

# Enable Ubuntu Firewall and allow SSH & MySQL Ports
ufw --force enable
ufw allow 22
ufw allow 3306

# Start Install of MySQL 5.7
echo "mysql-server-5.7 mysql-server/root_password password root" | sudo debconf-set-selections
echo "mysql-server-5.7 mysql-server/root_password_again password root" | sudo debconf-set-selections

export DEBIAN_FRONTEND=noninteractive

# Download the dependencies and binaries from a local Azure Stack Storage Account (use HTTP, not HTTPS)
wget http://offlinestor.blob.local.azurestack.external/offlinecontainer/mysql-{libaio,libevent-core,libmecab,common,client-core,client,server-core,server}.deb

# Install the files
dpkg -i mysql-libaio.deb
sleep 3
dpkg -i mysql-libevent-core.deb
sleep 3
dpkg -i mysql-libmecab.deb
sleep 3
dpkg -i mysql-common.deb
sleep 3
dpkg -i mysql-client-core.deb
sleep 3
dpkg -i mysql-client.deb
sleep 3
dpkg -i mysql-server-core.deb
sleep 3
dpkg -i mysql-server.deb
sleep 3

# Reset MySQL Password to match supplied parameter
mysql -u root -proot -e "use mysql; UPDATE user SET authentication_string=PASSWORD('$MySQLPassword') WHERE User='root'; flush privileges;"

if [ "$AllowRemoteConnections" = "yes" ]
then
    echo "Setting up remote connections for root user"
    # Allow remote connectivity for the root user
    mysql -u root -p"$MySQLPassword" -e "use mysql; CREATE USER 'root'@'%' IDENTIFIED BY '$MySQLPassword'; GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' with GRANT OPTION; flush privileges;"
    # Edit the MySQL Configuration File to allow Remote Connectivity
    sed -i "s/.*bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/mysql.conf.d/mysqld.cnf
fi

# Restart MySQL
sudo service mysql restart
