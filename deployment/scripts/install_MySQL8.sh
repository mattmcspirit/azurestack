#!/bin/bash

# Validate input parameters
if [[ ! ("$#" -eq 3) ]]; 
then
    echo "Parameters missing for MySQL configuration." >&2
    exit 1
fi

# Get parameters and assign variables
MySQLPassword=$1
AllowRemoteConnections=$(echo "$2" | tr '[:upper:]' '[:lower:]')

# Download and Install the Latest Updates for the OS
sudo apt-get update -y

# Set hostname in etc/hosts
sudo echo "127.0.0.1  $HOSTNAME" >> /etc/hosts

# Enable Ubuntu Firewall and allow SSH & MySQL Ports
ufw --force enable
ufw allow 22
ufw allow 3306

# Install dirmngr (certs)
sudo apt install -y dirmngr
sudo apt-key adv --keyserver pool.sks-keyservers.net --recv-keys 5072E1F5

    # Retrieve the latest APT repo for MySQL and save it
    echo "deb http://repo.mysql.com/apt/ubuntu $(lsb_release -sc) mysql-8.0" | sudo tee /etc/apt/sources.list.d/mysql80.list

# Update
sudo apt update -y
apt-get upgrade -y

# Install MySQL 8.0
echo "mysql-community-server mysql-community-server/root-pass password root" | sudo debconf-set-selections
echo "mysql-community-server mysql-community-server/re-root-pass password root" | sudo debconf-set-selections
echo "mysql-community-server mysql-server/default-auth-override select Use Legacy Authentication Method (Retain MySQL 5.x Compatibility)" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt install mysql-server mysql-client -y

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