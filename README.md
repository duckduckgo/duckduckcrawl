# DuckDuckGo distributed crawler (DDC) prototype 

The purpose of this project is to prototype a distributed crawler for the DuckDuckGo search engine.

## Protocol

### Basic workflow
 * A client requests a list of domains to check for spam, the server answers with a list of domains
 * The server might also add in the response additional data to ask the client to upgrade itself or the page analysis component
 * The client does the analysis on the domains, and then sends the results back to the server
 * The client request another bunch of domains to check and so on

### Implementation
 * It's a classic REST API
 * To get a domain list the client sends a GET request, and to post the results it sends a POST request

### URL parameters: 
 * version : the protocol version which defines the XML response structure, it must be incremented when a change breaks client compatibility. The server must always handle all old protocol versions, to at least to tell the clients they must upgrade
 * pc_version : the version of the page processing binary component 

### XML response format
It contains one of these nodes immediately above the root:

 * 'upgrades' : can contain nodes to tell the client to upgrade its components (with URL to download the new version) 
 * 'domainlist' : the list of domains to check ('domain' nodes)

## Files

 * ddc_client.py : Code for a crawling worker
 * ddc_process.py : This file contains the code that simulates the binary component, currently it returns dumb results just to simulate
 * ddc_server.py : Code for the server that distributes the crawling work to the clients and gets the result from them
 * tests/single_client.sh : Bash script to do a small simulation by launching the server and connecting a client to it
 * tests/client_upgrade.sh : Bash script to simulate a client upgrade initiated by the server

## Dependencies

 * [Python 3.2](http://www.python.org/download/)

 * [httplib2 0.7+](https://code.google.com/p/httplib2/downloads/list)

### Ubuntu users

On recent Ubuntu versions, you can install all dependencies by running the following command line:
```bash
sudo apt-get -V install python3 python3-httplib2
```

The code has only been tested on Linux but is fully OS neutral.
