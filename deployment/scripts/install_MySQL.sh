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

# Install MySQL 5.7
echo "mysql-server-5.7 mysql-server/root_password password root" | sudo debconf-set-selections
echo "mysql-server-5.7 mysql-server/root_password_again password root" | sudo debconf-set-selections
apt-get -y install mysql-server-5.7 mysql-client

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
