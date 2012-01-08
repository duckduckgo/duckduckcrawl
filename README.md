### The protocol:
 * It's a classic REST API
 * Everything is STATELESS, it's more simple to design that way, and it saves server ressources

### URL parameters: 
 * version : the protocol version which defines the XML response structure, it must be incremented when a change breaks client compatibility
The server must always handle all old protocol versions, at least to tell the clients they must upgrade
 * pc_version : the version of the page processing binary component 
 * action : there are only two, 'getdomains' and 'senddomainsdata' (self explanatory)

### XML response (for the 'getdomains' action)
It contains 2 kind of nodes immediately above the root:
 * 'upgrade' : can contain 'client_upgrade' or 'pc_upgrade' nodes to tell the client to upgrade the given parts (with URL to download the new version) 
 * 'domainlist' : the list of domains to check ('domain nodes')

### Sending back the results to the server
When a client has done it's job, it sends the server the same 'domainlist' node it has been given with an additional 'spam' attribute set, via a POST request.