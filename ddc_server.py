#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, gzip, hashlib, http.server, logging, os.path, random, string, time, urllib.parse, xml.etree.ElementTree, zlib


class InvalidRequestException(Exception):

  def __init__(self, url, client, msg, http_code=400):
    self.url = url
    self.client = client
    self.msg = msg
    self.http_code = http_code

  def __str__(self):
    return "Invalid request from %s for url '%s': %s" % (self.client, self.url, self.msg)


class PotentiallyMaliciousRequestException(InvalidRequestException):

  def __str__(self):
    return "Potentially malicious request from %s for url '%s': %s" % (self.client, self.url, self.msg) 


class XmlMessage:

  MAX_DOMAIN_LIST_SIZE = 20

  def __init__(self,client_version,page_processor_version):
    self.xml = xml.etree.ElementTree.Element("ddc")

    # generate upgrade nodes
    xml_upgrade = xml.etree.ElementTree.SubElement(self.xml,"upgrades")
    need_upgrade = False
    if client_version < DistributedCrawlerServer.LAST_CLIENT_VERSION:
      # need to upgrade the client
      xml.etree.ElementTree.SubElement(xml_upgrade,"upgrade",attrib={"type"     : "client",
                                                                      "url"     : "/upgrade?file=client-v%d.zip" % (DistributedCrawlerServer.LAST_CLIENT_VERSION) ,
                                                                      "version" : str(DistributedCrawlerServer.LAST_CLIENT_VERSION) } )
      need_upgrade = True
    if page_processor_version < DistributedCrawlerServer.LAST_PC_VERSION:
      # need to upgrade the page processing component
      xml.etree.ElementTree.SubElement(xml_upgrade,"upgrade",attrib={"type"  : "page analysis",
                                                                      "url"   : "/upgrade?file=page-processor-v%d.zip" % (DistributedCrawlerServer.LAST_PC_VERSION),
                                                                      "version" : str(DistributedCrawlerServer.LAST_CLIENT_VERSION) } )
      need_upgrade = True

    if not need_upgrade:
      # generate domain list nodes
      xml_domain_list = xml.etree.ElementTree.SubElement(self.xml,"domainlist")
      domains_to_send_count = min(len(DistributedCrawlerServer.domains_to_check),__class__.MAX_DOMAIN_LIST_SIZE)
      for i in range(domains_to_send_count):
        domain = random.choice(DistributedCrawlerServer.domains_to_check) # pick a random domain in the list
        xml.etree.ElementTree.SubElement(xml_domain_list,"domain",attrib={"name":domain})
        logging.getLogger().debug("Picked domain %s to be checked" % (domain) ) 

      # add a signature, so we can detect a malicious client trying to send fake results for different domains
      sig = __class__.getXmlDomainListSig(xml_domain_list,as_bytes=False)[1]
      xml_domain_list.set("sig",sig)

      if not domains_to_send_count:
        logging.getLogger().warning("No more domains to be checked")

  def __str__(self):
    return xml.etree.ElementTree.tostring(self.xml,"unicode")

  @staticmethod
  def getXmlDomainListSig(xml_domain_list,as_bytes=True,as_string=True):
    # WARNING  : to be sure a malicious client can not send fake results for specific domains,
    # the following hash function needs to be changed and hidden (not in a public repository)
    # it must be complex and unconventionel (no md5, sha, etc.), so it can not be guessed
    hasher = hashlib.sha256()
    for domain in xml_domain_list.iterfind("domain"):
      hasher.update(domain.get("name").encode("utf-8"))
    if as_bytes:
      bin_sig = hasher.digest()
    else:
      bin_sig = None
    if as_string:
      str_sig = hasher.hexdigest()
    else:
      str_sig = None
    return (bin_sig, str_sig)


class DistributedCrawlerServer(http.server.HTTPServer):

  LAST_CLIENT_VERSION = SERVER_PROTOCOL_VERSION = 1
  LAST_PC_VERSION = 1
  MIN_ANALYSIS_PER_DOMAIN = 3

  SIGNATURE_BLACKLIST_TIMEOUT_S = 60*60*24*30*3 # 3 month

  domains_to_check = [ "domain%04d.com" % (i) for i in range(50) ] # we generate random domains for simulation
  checked_domains = {} # this holds the results as ie: checked_domains["a-domain.com"] = (is_spam, number_of_clients_who_checked_this_domain)

  excluded_sigs = [] # list of temporarily exluded domainlist signatures to prevent client spamming
  excluded_sigs_time = [] # timestamps of the time when each signature has been excluded

  def __init__(self,port):
    super().__init__(("127.0.0.1",port),RequestHandler)

  def start(self):
    logging.getLogger().info("DuckDuckGo distributed crawler server v%d started" % (__class__.SERVER_PROTOCOL_VERSION))
    self.serve_forever()


class RequestHandler(http.server.BaseHTTPRequestHandler):

  # override some useful http.server.BaseHTTPRequestHandler attributes
  server_version = "DDC_Server/%d" % (DistributedCrawlerServer.SERVER_PROTOCOL_VERSION)
  protocol_version = "HTTP/1.1"

  def do_GET(self):
    try:
      # parse request url & url parameters
      parsed_url = urllib.parse.urlsplit(self.path)
      params = urllib.parse.parse_qs(parsed_url.query,keep_blank_values=False,strict_parsing=True)

      if parsed_url.path == "/upgrade":
        # check query is well formed
        if "file" not in params or \
            not self.isSafeFilename(params["file"][0]): # we check for evil injection here
          raise InvalidRequestException(self.path,self.client_address[0],"Invalid query parameters")

        # serve file (might short-circuit that part with an Apache/Nginx URL rediretion directly to the static content)
        upgrade_file = params["file"][0]
        try:
          with open(upgrade_file,"rb") as file_handle:
            # send http headers
            self.send_response(200)
            self.send_header("Content-Type",        "application/zip")
            self.send_header("Content-Length",      os.path.getsize(upgrade_file))
            self.send_header("Content-Disposition", "attachement; filename=%s" % (upgrade_file) )
            self.end_headers()
            # send file
            self.wfile.write(file_handle.read())
        except (IOError, OSError):
          raise InvalidRequestException(self.path,self.client_address[0],"Upgrade file '%s' does not exist or is not readable" % (upgrade_file))

      elif parsed_url.path == "/rest":
        # check query is well formed
        # TODO: more robust checking
        if "action" not in params or \
            params["action"][0] != "getdomains" or \
            "version" not in params or \
            "pc_version" not in params:
          raise InvalidRequestException(self.path,self.client_address[0],"Invalid query parameters")

        # generate xml
        xml_response = str(XmlMessage(int(params["version"][0]),int(params["pc_version"][0])))
        
        # prepare response
        raw_response = xml_response.encode("utf-8")
        if "accept-encoding" in self.headers:
          supported_compressions = list(map(lambda x: x.strip(),self.headers["accept-encoding"].split(",")))
        else:
          supported_compressions = []
        if "gzip" in supported_compressions:
          compression = "gzip"
          buffer = memoryview(raw_response)
          raw_response = gzip.compress(buffer)
        elif "deflate" in supported_compressions:
          compression = "deflate"
          buffer = memoryview(raw_response)
          raw_response = zlib.compress(buffer)
        else:
          compression = "identity"

        # send http headers
        self.send_response(200)
        # these headers are necessary even if we know what compression the client supports, and which encoding it expects,
        # because the HTTP request might go through proxies, routers, etc
        self.send_header("Content-Type",      "text/xml; charset=utf-8")
        self.send_header("Content-Encoding",  compression)
        self.send_header("Content-Length",    str(len(raw_response)))
        self.send_header("Cache-Control",     "no-cache, no-store")
        self.end_headers()

        # send response
        self.wfile.write(raw_response)

      else:
        # buggy client, crawler, or someone else we don't care about...
        raise InvalidRequestException(self.path,self.client_address[0],"URL not found",404)

    except InvalidRequestException as e:
      logging.getLogger().warning(e)
      self.send_error(e.http_code)

    except:
      # boom!
      self.send_error(500)
      raise

  def do_POST(self):
    try:
      # parse request url
      parsed_url = urllib.parse.urlsplit(self.path)

      if parsed_url.path == "/rest":
        # parse url parameters
        params = urllib.parse.parse_qs(parsed_url.query,keep_blank_values=False,strict_parsing=True)

        # check query is well formed
        # TODO: more robust checking
        if "action" not in params or \
            params["action"][0] != "senddomainsdata" or \
            "version" not in params or \
            "pc_version" not in params:
          raise InvalidRequestException(self.path,self.client_address[0],"Invalid query parameters")

        # TODO do version check of the client to decide to ignore it or not

        # read post data
        post_data = self.rfile.read(int(self.headers["content-length"]))
        xml_post_data = xml.etree.ElementTree.fromstring(post_data.decode("utf-8"))

        # check domainlist signature
        xml_domainlist = xml_post_data.find("domainlist")
        domainlist_sig = XmlMessage.getXmlDomainListSig(xml_domainlist)
        if xml_domainlist.get("sig") != domainlist_sig[1]:
          # we do NOT return a different HTTP error code here, so that the evil malicious clients can keep wasting their time
          raise PotentiallyMaliciousRequestException(self.path,self.client_address[0],"Invalid signature for domainlist",204)

        # remove outdated exluded signatures
        current_time = int(time.time())
        while DistributedCrawlerServer.excluded_sigs_time and (current_time - DistributedCrawlerServer.excluded_sigs_time[0] > DistributedCrawlerServer.SIGNATURE_BLACKLIST_TIMEOUT_S):
          del DistributedCrawlerServer.excluded_sigs[0]
          del DistributedCrawlerServer.excluded_sigs_time[0]

        # check the signature is not exluded (= the client is spamming its probably fake analysis)
        try:
          index = DistributedCrawlerServer.excluded_sigs.index(domainlist_sig[0])
        except ValueError:
          # sig not in blacklist, all good
          pass
        else:
          if len(domains_to_check) >= XmlMessage.MAX_DOMAIN_LIST_SIZE: # without this the server will exclude all analysis when there is only a few domains left
            # blacklist the signature for another SIGNATURE_BLACKLIST_TIMEOUT_S
            del DistributedCrawlerServer.excluded_sigs[index]
            del DistributedCrawlerServer.excluded_sigs_time[index]
            DistributedCrawlerServer.excluded_sigs.append(domainlist_sig[0])
            DistributedCrawlerServer.excluded_sigs_time.append(current_time)
            raise PotentiallyMaliciousRequestException(self.path,self.client_address[0],"Client is spamming an already sent domainlist",204)

        # update exluded signature list
        DistributedCrawlerServer.excluded_sigs.append(domainlist_sig[0]) # we store the signature in its binary form for space efficiency (the list will grow huge)
        DistributedCrawlerServer.excluded_sigs_time.append(current_time)

        # read domain analysis results
        for xml_domain in xml_post_data.iterfind("domainlist/domain"):
          domain = xml_domain.get("name")
          logging.getLogger().debug("Got client analysis for domain '%s'" % (domain) ) 
          is_spam = (xml_domain.get("spam") == "1")
          if domain in DistributedCrawlerServer.checked_domains:
            # this domain has already been checked by at least another client
            previous_is_spam = DistributedCrawlerServer.checked_domains[domain][0]
            analysis_count = DistributedCrawlerServer.checked_domains[domain][1] +1
            if (previous_is_spam != is_spam) and (analysis_count > 1):
              # differents clients gave different analysis, reset analysis count
              logging.getLogger().warning("Conflicting client analysis for domain '%s'" % (domain) ) 
              analysis_count = 0
            else:
              if analysis_count >= DistributedCrawlerServer.MIN_ANALYSIS_PER_DOMAIN:
                # enough checks for this domain
                try:
                  DistributedCrawlerServer.domains_to_check.remove(domain)
                except ValueError:
                  # ValueError is thrown if the domain is not in the list which can happen if another client has already sent the MIN_ANALYSIS_PER_DOMAIN'th analysis
                  # => we dont't care
                  pass
              logging.getLogger().debug("Domain '%s' has has been checked %d times, is_spam=%d" % (domain, analysis_count, is_spam) ) 
          else:
            analysis_count = 1
            logging.getLogger().debug("Domain '%s' is checked for the first time, is_spam=%d" % (domain, is_spam) ) 
          DistributedCrawlerServer.checked_domains[domain] = (is_spam, analysis_count)

        # thanks buddy client!
        self.send_response(204) # 204 is like 200 OK, but the client should expect no content
        self.end_headers()

      else:
        # buggy client, crawler, or someone else we don't care about...
        raise InvalidRequestException(self.path,self.client_address[0],"URL not found",404)

    except (PotentiallyMaliciousRequestException, InvalidRequestException) as e:
      logging.getLogger().warning(e)
      self.send_error(e.http_code)

    except:
      # boom!
      self.send_error(500)
      raise

  def isSafeFilename(self,filename):
    # ensure a filename has the form XXX.XX, with no slashes, double dots, etc. to protect from injection
    safe_chars = frozenset(string.ascii_letters + string.digits + "-")
    components = filename.split(".")
    if len(components) != 2:
      return False
    for component in components:
      for char in component:
        if char not in safe_chars:
          return False
    return True


if __name__ == "__main__":

  # setup logger
  logger = logging.getLogger()
  logger.setLevel(logging.DEBUG)

  # parse args
  cli_parser = argparse.ArgumentParser()
  cli_parser.add_argument("-p", 
                          "--port",
                          action="store",
                          required=True,
                          type=int,
                          dest="port",
                          help="Network port to use to communicate with clients")
  options = cli_parser.parse_args()

  # start server
  server = DistributedCrawlerServer(options.port)
  server.start()
