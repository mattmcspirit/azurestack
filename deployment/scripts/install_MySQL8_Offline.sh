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

# Download the dependencies and binaries from a local Azure Stack Storage Account (use HTTP, not HTTPS)
wget ${STORAGE_URI}mysql-{apt-config_8,common_8,community-client-core_8,community-client_8,client_8,community-server-core_8,community-server_8,server_8}_.deb
wget ${STORAGE_URI}{libaio1,libmecab2_8,mecab-utils_8,mecab-ipadic_8,mecab-ipadic-utf8_8}_.deb

# Install MySQL 8.0
export DEBIAN_FRONTEND=noninteractive
echo "mysql-community-server mysql-community-server/root-pass password root" | sudo debconf-set-selections
echo "mysql-community-server mysql-community-server/re-root-pass password root" | sudo debconf-set-selections
echo "mysql-community-server mysql-server/default-auth-override select Use Legacy Authentication Method (Retain MySQL 5.x Compatibility)" | sudo debconf-set-selections
echo "mysql-apt-config mysql-apt-config/enable-repo select mysql-8.0" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive dpkg -i mysql-apt-config*
sudo rm mysql-apt-config*

# Install the files
dpkg -i libaio1.deb
sleep 3
dpkg -i libmecab2_8_.deb
sleep 3
dpkg -i mecab-utils_8_.deb
sleep 3
dpkg -i mecab-ipadic_8_.deb
sleep 3
dpkg -i mecab-ipadic-utf8_8_.deb
sleep 3
dpkg -i mysql-common_8_.deb
sleep 3
dpkg -i mysql-community-client-core_8_.deb
sleep 3
dpkg -i mysql-community-client_8_.deb
sleep 3
dpkg -i mysql-client_8_.deb
sleep 3
dpkg -i mysql-community-server-core.deb
sleep 3
dpkg -i mysql-community-server_8_.deb
sleep 3
dpkg -i mysql-server_8_.deb
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