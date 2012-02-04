#!/bin/bash

KILL_AFTER=${1:-'10s'}

cd "$(dirname -- $0)/.."

# start server
./ddc_server.py -p 10001 &
server_job_id=$!

# wait a bit to be sure the server is ready
sleep 1s

# start client
./ddc_client.py -s 127.0.0.1 -p 10001 &
client_job_id=$!

# kill both after X s
sleep $KILL_AFTER
kill $client_job_id
kill $server_job_id
