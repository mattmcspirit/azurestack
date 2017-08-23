wget https://apt.puppetlabs.com/puppet-release-xenial.deb
ls -ltrh puppet-release-xenial.deb 
sudo dpkg -i puppet-release-xenial.deb 
sudo apt-get update
sudo apt-cache show puppetserver
sudo apt-get install puppetserver -y
systemctl status puppetserver
systemctl start puppetserver
systemctl status puppetserver
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 8140 -j ACCEPT
puppet agent -t
