#!/bin/bash

cd "$(dirname -- $0)/.."

TMP_DIR=$(mktemp -d /tmp/$(basename -- $0).XXXXXXXXXX)

# generate fake version change
original_client_version=$(grep 'CLIENT_VERSION =' ddc_client.py | cut -d '=' -f 2)
original_client_version=${original_client_version#*' '}
original_page_processor_version=$(grep 'VERSION =' ddc_process.py | cut -d '=' -f 2)
original_page_processor_version=${original_page_processor_version#*' '}
new_client_version=$(( $original_client_version + 1 ))
new_page_processor_version=$(( $original_page_processor_version + 1 ))
sed -i "s/^\(.*LAST_CLIENT_VERSION = SERVER_PROTOCOL_VERSION = \).*$/\1$new_client_version/" ddc_server.py
sed -i "s/^\(.*LAST_PC_VERSION = \).*$/\1$new_page_processor_version/" ddc_server.py

# create upgrade archives
cp ddc_client.py ddc_process.py $TMP_DIR/
sed -i "s/^\(.*CLIENT_VERSION = \).*$/\1$new_client_version/" "$TMP_DIR/ddc_client.py"
sed -i "s/^\(.*VERSION = \).*$/\1$new_page_processor_version/" "$TMP_DIR/ddc_process.py"
zip -qj "client-v${new_client_version}.zip" "$TMP_DIR/ddc_client.py"
zip -qj "page-processor-v${new_page_processor_version}.zip" "$TMP_DIR/ddc_process.py"

# start server
./ddc_server.py -p 10001 &
server_job_id=$!

# wait a bit to be sure the server is ready
sleep 1s

# start client
./ddc_client.py -s 127.0.0.1 -p 10001
./ddc_client.py -s 127.0.0.1 -p 10001 &
client_job_id=$!

# kill both after X s
sleep 5s
kill $client_job_id
kill $server_job_id

# restore original versions
sed -i "s/^\(.*LAST_CLIENT_VERSION = SERVER_PROTOCOL_VERSION = \).*$/\1$original_client_version/" ddc_server.py
sed -i "s/^\(.*LAST_PC_VERSION = \).*$/\1$original_page_processor_version/" ddc_server.py
sed -i "s/^\(.*CLIENT_VERSION = \).*$/\1$original_client_version/" ddc_client.py
sed -i "s/^\(.*VERSION = \).*$/\1$original_page_processor_version/" ddc_process.py

# cleanup
rm -R "$TMP_DIR"
rm "client-v$new_client_version.zip" "page-processor-v$new_page_processor_version.zip"
