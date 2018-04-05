#!/bin/bash

# Validate input parameters
if [[ !("$#" -eq 2) ]]; 
    then echo "Parameters missing for MySQL configuration." >&2
    exit 1
fi

# Get parameters and assign variables
MySQLPassword=$1
AllowRemoteConnections=$2

# Download and Install the Latest Updates for the OS
sudo apt-get update -y

# Enable Ubuntu Firewall and allow SSH & MySQL Ports
ufw --force enable
ufw allow 22
ufw allow 3306

# Install MySQL 5.7
echo "mysql-server-5.7 mysql-server/root_password password root" | sudo debconf-set-selections
echo "mysql-server-5.7 mysql-server/root_password_again password root" | sudo debconf-set-selections
apt-get -y install mysql-server-5.7 mysql-client

# Reset MySQL Password to match supplied parameter
mysql -u root -proot -e "use mysql; UPDATE user SET authentication_string=PASSWORD('$1') WHERE User='root'; flush privileges;"

if [$2 -eq "Yes"] then
    echo "Setting up remote connections for root user"
    # Allow remote connectivity for the root user
    mysql -u root -p$1 -e "use mysql; CREATE USER 'root'@'%' IDENTIFIED BY '$1'; GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '$1'; flush privileges;"
    # Edit the MySQL Configuration File to allow Remote Connectivity
    sed -i "s/.*bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/mysql.conf.d/mysqld.cnf
fi

# Restart MySQL
sudo service mysql restart