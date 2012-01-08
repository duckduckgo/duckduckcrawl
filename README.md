Little protocole explanation:
- it's a classic REST API
- everything is STATELESS, it's simplier to design that way, and it saves server ressources

Now about the URL parameters: 
- version : the protocol version which defines the XML response structure, it must be increased when a change breaks client compatibility
The server must always handle all old protocol versions, at least to tell the clients they must upgrade
- pc_version : the version of the page processing binary component 
- action : there are only two, 'getdomains' and 'senddomainsdata' (self explanatory)

Now about the XML response (for the 'getdomains' action), which contains 2 kind of nodes immediately above the root:
- 'upgrade' : can contain 'client_upgrade' or 'pc_upgrade' nodes to tell the clients to upgrade the given parts (with url to download the new version) 
- 'domainlist' : the list of domains to check ('domain nodes')

When a client has done it's job, it sends the server the same 'domainlist' node it has been given with an additional 'spam' attribute set, via a POST request.
The server returns a 204 code, and it goes on and on...