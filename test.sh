#!/bin/bash

cd "$(dirname -- $0)"

# start server
./ddc_server.py -p 10001 &
server_pid=$?

# wait a bit to be sure the server is ready
sleep 1s

# start client
./ddc_client.py -s 127.0.0.1 -p 10001 &
client_pid=$?

# kill server after X s
sleep 10s
kill $server_pid