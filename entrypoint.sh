#!/bin/sh
# Script to initialize Moloch, add a user, and run the services

# Configure Moloch
/data/moloch/bin/Configure << EOF
$INTERFACE
no
$ES_HOST
$CLUSTER_PW
EOF

# Insert interface environment variable into config
sed -i 's/${INTERFACE}/'$INTERFACE' /g' /data/moloch/etc/config.ini

# Check to see if Elasticsearch is reachable
echo "Trying to reach Elasticsearch..."
until $(curl --output /dev/null --fail --silent -X GET "$ES_HOST/_cat/health?v"); do
  echo "Couldn't get Elasticsearch at $ES_HOST, are you sure it's reachable?"
  sleep 5
done

# Check to see if Moloch has been installed before to prevent data loss
STATUS5=$(curl -s -X GET "$ES_HOST/sequence_v1" | jq --raw-output '.status')
STATUS6=$(curl -s -X GET "$ES_HOST/sequence_v2" | jq --raw-output '.status')

# Initialize Moloch if this is the first install
if [ "$STATUS5" = "404" ] && [ "$STATUS6" = "404" ]
then
  echo "Initializing Moloch indices..."
  echo INIT | /data/moloch/db/db.pl $ES_HOST init
  /data/moloch/bin/moloch_add_user.sh admin "Admin User" $ADMIN_PW --admin
  /data/moloch/bin/moloch_update_geo.sh
fi

chmod a+rwx /data/moloch/raw /data/moloch/logs

# Deploy Moloch as a sensor node
if [ "$SENSOR" = "true" ]
then
  echo "Starting Moloch capture and viewer..."
  /bin/sh
  /data/moloch/bin/moloch_config_interfaces.sh
  cd /data/moloch
  nohup /data/moloch/bin/moloch-capture -c /data/moloch/etc/config.ini >> /data/moloch/logs/capture.log 2>&1 &
  cd /data/moloch/viewer
  /data/moloch/bin/node viewer.js -c /data/moloch/etc/config.ini >> /data/moloch/logs/viewer.log 2>&1
# Viewer only node
else
  echo "Starting Moloch viewer..."
  cd /data/moloch/viewer
  /data/moloch/bin/node viewer.js -c /data/moloch/etc/config.ini >> /data/moloch/logs/viewer.log 2>&1
fi