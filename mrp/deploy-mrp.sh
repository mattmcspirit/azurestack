# Add the records to ordering database on MongoDB
sudo mongo ordering /var/lib/partsunlimited/MongoRecords.js

# Change Tomcat listening port from 8080 to 9080
sudo sed -i s/8080/9080/g /etc/tomcat7/server.xml

# Remove existing MRP directory and copy WAR file to Tomcat directory for auto-deployment
sudo rm -rf /var/lib/tomcat7/webapps/mrp
sudo cp /var/lib/partsunlimited/mrp.war /var/lib/tomcat7/webapps

# Restart Tomcat
sudo /etc/init.d/tomcat7 restart

# Run Ordering Service app
sudo java -jar /var/lib/partsunlimited/ordering-service-0.1.0.jar &>/dev/null &

echo "MRP application successfully deployed. Go to http://<YourDNSname>:9080/mrp"