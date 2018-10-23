#!/bin/bash -e

# Use the following variables to control your install:

# Validate input parameters
if [[ !("$#" -eq 1) ]]; 
    then echo "Parameters missing for SQL Server 2017 configuration." >&2
    exit 1
fi

# Password for the SA user (required)
MSSQL_SA_PASSWORD=$1

# Set hostname in etc/hosts
sudo echo "127.0.0.1  $HOSTNAME" | sudo tee -a /etc/hosts

# Product ID of the version of SQL server you're installing
# Must be evaluation, developer, express, web, standard, enterprise, or your 25 digit product key
# Defaults to developer
MSSQL_PID='evaluation'

if [ -z $MSSQL_SA_PASSWORD ]
then
  echo Environment variable MSSQL_SA_PASSWORD must be set for unattended install
  exit 1
fi

# Configure firewall to allow TCP port 1433:
echo Configuring UFW to allow traffic on port 1433...
sudo ufw allow out 53
sudo ufw allow 1433/tcp
sudo ufw allow ssh
sudo ufw reload
yes | sudo ufw enable

echo Downloading SQL Server dependencies...
export DEBIAN_FRONTEND=noninteractive

# Download the dependencies and binaries from a local Azure Stack Storage Account (use HTTP, not HTTPS)
wget http://offlinestor.blob.local.azurestack.external/offlinecontainer/mssql-{libjemalloc,libc,libcabi,gdb,libsss,libbabeltrace1,libbabeltrace-ctf1,libcurl3,libsasl2,server}.deb

echo Installing SQL Server dependencies...
dpkg -i mssql-libjemalloc.deb
sleep 3
dpkg -i mssql-libsss.deb
sleep 3
dpkg -i mssql-libcabi.deb
sleep 3
dpkg -i mssql-libc.deb
sleep 3
dpkg -i mssql-libbabeltrace1.deb
sleep 3
dpkg -i mssql-libbabeltrace-ctf1.deb
sleep 3
dpkg -i mssql-gdb.deb
sleep 3
dpkg -i mssql-libcurl3.deb
sleep 3
dpkg -i mssql-libsasl2.deb
sleep 3
dpkg -i mssql-server.deb

echo Running mssql-conf setup...
sudo MSSQL_SA_PASSWORD=$MSSQL_SA_PASSWORD \
     MSSQL_PID=$MSSQL_PID \
     /opt/mssql/bin/mssql-conf -n setup accept-eula

# Restart SQL Server after installing:
echo Restarting SQL Server...
sudo systemctl restart mssql-server

# Connect to server and get the version:
counter=1
errstatus=1
while [ $counter -le 5 ] && [ $errstatus = 1 ]
do
  echo Waiting for SQL Server to start...
  sleep 3s
  /opt/mssql-tools/bin/sqlcmd \
    -S localhost \
    -U SA \
    -P $MSSQL_SA_PASSWORD \
    -Q "SELECT @@VERSION" 2>/dev/null
  errstatus=$?
  ((counter++))
done

# Display error if connection failed:
if [ $errstatus = 1 ]
then
  echo Cannot connect to SQL Server, installation aborted
  exit $errstatus
fi

echo Done!
