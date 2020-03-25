#!/bin/bash
# This script is used when installing MySQL 5.7 from locally downloaded MySQL binaries
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

# Start Install of MySQL 5.7
echo "mysql-server-5.7 mysql-server/root_password password root" | sudo debconf-set-selections
echo "mysql-server-5.7 mysql-server/root_password_again password root" | sudo debconf-set-selections

export DEBIAN_FRONTEND=noninteractive

# Download the dependencies and binaries from a local Azure Stack Storage Account (use HTTP, not HTTPS)
wget ${STORAGE_URI}{libaio1,libhtml-tagset-perl,liburi-perl,libhtml-parser-perl,liblwp-mediatypes-perl,libcgi-pm-perl,libfcgi-perl,\
libcgi-fast-perl,libtimedate-perl,libio-html-perl,libhtml-template-perl,libencode-locale-perl,libhttp-date-perl,libhttp-message-perl,\
libevent-core-2.0-5,mysql-common,mysql-client-core-5.7,mysql-client-5.7,mysql-server-core-5.7,mysql-server-5.7}.deb


# Install the files
dpkg -i libaio1.deb
sleep 3
dpkg -i libhtml-tagset-perl.deb
sleep 3
dpkg -i liburi-perl.deb
sleep 3
dpkg -i libhtml-parser-perl.deb
sleep 3
dpkg -i liblwp-mediatypes-perl.deb
sleep 3
dpkg -i libcgi-pm-perl.deb
sleep 3
dpkg -i libfcgi-perl.deb
sleep 3
dpkg -i libcgi-fast-perl.deb
sleep 3
dpkg -i libtimedate-perl.deb
sleep 3
dpkg -i libio-html-perl.deb
sleep 3
dpkg -i libhtml-template-perl.deb
sleep 3
dpkg -i libencode-locale-perl.deb
sleep 3
dpkg -i libhttp-date-perl.deb
sleep 3
dpkg -i libhttp-message-perl.deb
sleep 3
dpkg -i libevent-core-2.0-5.deb
sleep 3
dpkg -i mysql-common.deb
sleep 3
dpkg -i mysql-client-core-5.7.deb
sleep 3
dpkg -i mysql-client-5.7.deb
sleep 3
dpkg -i mysql-server-core-5.7.deb
sleep 3
dpkg -i mysql-server-5.7.deb
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
