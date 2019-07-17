#!/bin/bash
# This script is used when installing MySQL 8.0 from locally downloaded MySQL binaries
# These binaries should be stored in a local Azure Stack storage account, and configured by the ASDK Configurator

# Validate input parameters
if [[ ! ("$#" -eq 3) ]];
then
    echo "Parameters missing for MySQL configuration." >&2
    exit 1
fi

# Get parameters and assign variables
MySQLPassword=$1
AllowRemoteConnections=$(echo "$2" | tr '[:upper:]' '[:lower:]')
STORAGE_URI=$3

# Set hostname in etc/hosts
sudo echo "127.0.0.1  $HOSTNAME" | sudo tee -a /etc/hosts

# Enable Ubuntu Firewall and allow SSH & MySQL Ports
ufw --force enable
ufw allow 22
ufw allow 3306

# Install MySQL 8.0
echo "mysql-community-server mysql-community-server/root-pass password root" | sudo debconf-set-selections
echo "mysql-community-server mysql-community-server/re-root-pass password root" | sudo debconf-set-selections
echo "mysql-community-server mysql-server/default-auth-override select Use Legacy Authentication Method (Retain MySQL 5.x Compatibility)" | sudo debconf-set-selections

export DEBIAN_FRONTEND=noninteractive

# Download the dependencies and binaries from a local Azure Stack Storage Account (use HTTP, not HTTPS)
wget ${STORAGE_URI}mysql-{libaio,libevent-core,libmecab,mecab-utils,mecab-ipadic,mecab-ipadic-utf,server-core,server}.deb
wget ${STORAGE_URI}mysql8-{common,community-client-core,community-client,client,community-server-core,community-server,server}.deb

# Install the files
dpkg -i mysql-libaio.deb
sleep 3
dpkg -i mysql-libevent-core.deb
sleep 3
dpkg -i mysql-libmecab.deb
sleep 3
dpkg -i mysql-mecab-utils.deb
sleep 3
dpkg -i mysql-mecab-ipadic.deb
sleep 3
dpkg -i mysql-mecab-ipadic-utf.deb
sleep 3
dpkg -i mysql8-common.deb
sleep 3
dpkg -i mysql8-community-client-core.deb
sleep 3
dpkg -i mysql8-community-client.deb
sleep 3
dpkg -i mysql8-client.deb
sleep 3
dpkg -i mysql8-community-server-core.deb
sleep 3
dpkg -i mysql8-community-server.deb
sleep 3
dpkg -i mysql8-server.deb
sleep 3

# Reset MySQL Password to match supplied parameter
mysql -u root -proot -e "use mysql; ALTER USER 'root'@'localhost' IDENTIFIED BY '$MySQLPassword'; flush privileges;"

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