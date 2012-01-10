#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, gzip, http.server, logging, random, string, urllib.parse, xml.etree.ElementTree, zlib


class XmlMessage:

  MAX_DOMAIN_LIST_SIZE = 5

  def __init__(self,protocol_version,page_processor_version):
    self.xml = xml.etree.ElementTree.Element("ddc")

    # TODO generate upgrade nodes

    # generate domain list nodes
    xml_domain_list = xml.etree.ElementTree.SubElement(self.xml,"domainlist")
    domains_to_send_count = min(len(DistributedCrawlerServer.unchecked_domains),self.MAX_DOMAIN_LIST_SIZE)
    for i in range(domains_to_send_count):
      domain_index = random.randint(0,len(DistributedCrawlerServer.unchecked_domains)-1) # pick a random domain in the list
      domain = DistributedCrawlerServer.unchecked_domains[domain_index]
      xml.etree.ElementTree.SubElement(xml_domain_list,"domain",attrib={"name":domain})
      del DistributedCrawlerServer.unchecked_domains[domain_index]
      DistributedCrawlerServer.pending_domains.append(domain)
      logging.getLogger().debug("Picked unchecked domain %s to be checked" % (domain) ) 

    # TODO enforce redundancy of spam checks: a domain must be checked by at least X clients

    if (domains_to_send_count < self.MAX_DOMAIN_LIST_SIZE) and DistributedCrawlerServer.pending_domains:
      # if no more domains to check, (re)check pending domains (a client might not have responded)
      additional_domains_to_send_count = min(len(DistributedCrawlerServer.pending_domains),self.MAX_DOMAIN_LIST_SIZE-domains_to_send_count)
      for i in range(additional_domains_to_send_count):
        domain = DistributedCrawlerServer.pending_domains[0] # this time we pick the first one because it's a queue
        xml.etree.ElementTree.SubElement(xml_domain_list,"domain",attrib={"name":domain})
        logging.getLogger().debug("Picked pending domain %s to be checked" % (domain) ) 
    else:
      additional_domains_to_send_count = 0

    total_domains_to_send_count = domains_to_send_count + additional_domains_to_send_count
    if total_domains_to_send_count:
      logging.getLogger().debug("Picked %d domains to be checked" % (total_domains_to_send_count) )
    else:
      logging.getLogger().warning("No more domains to be checked")

    # TODO add a key (custom cryptographic hash of the domain list), and check that key when the clients responds
    # to be sure the client will not check different domains that the ones it has been sent.
    # NOTE: the hash function needs to be hidden (closed source), and must change frequently so that it can not be guessed with a large number of hashed domain lists

  def __str__(self):
    return xml.etree.ElementTree.tostring(self.xml,"unicode")


class DistributedCrawlerServer(http.server.HTTPServer):

  LAST_PROTOCOL_VERSION = 1

  unchecked_domains = [ "domain%04d.com" % (i) for i in range(50) ] # we generate random domains for simulation
  pending_domains = []
  checked_domains = {} # this holds the results as ie: checked_domains["spam-domain.com"] = True

  def __init__(self,port):
    super().__init__(("127.0.0.1",port),RequestHandler)

  def start(self):
    logging.getLogger().info("Server started")
    self.serve_forever()


class RequestHandler(http.server.BaseHTTPRequestHandler):

  # override some useful http.server.BaseHTTPRequestHandler attributes
  server_version = "DDC_Server/%d" % (DistributedCrawlerServer.LAST_PROTOCOL_VERSION)
  protocol_version = "HTTP/1.1"

  def do_GET(self):
    try:
      # parse request url
      parsed_url = urllib.parse.urlsplit(self.path)

      if parsed_url.path == "/upgrade":
        # serve file (might short-circuit that part with an Apache/Nginx URL rediretion directly to the static content)
        # TODO
        pass

      elif parsed_url.path == "/rest":
        # parse url parameters
        params = urllib.parse.parse_qs(parsed_url.query,keep_blank_values=False,strict_parsing=True)

        # check query is well formed
        if "action" not in params or \
            params["action"][0] != "getdomains" or \
            "version" not in params or \
            "pc_version" not in params:
          logging.getLogger().warning("Invalid query parameters for URL '%s'" % (self.path) ) 
          self.send_error(400)
        else:
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

          # TODO add encryption?

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
        self.send_error(404)

    except:
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
        if "action" not in params or \
            params["action"][0] != "senddomainsdata" or \
            "version" not in params or \
            "pc_version" not in params:
          logging.getLogger().warning("Invalid query parameters for URL '%s'" % (self.path) ) 
          self.send_error(400)
        else:
          # TODO do version check of the client to decide to ignore it or not

          # read post data
          post_data = self.rfile.read(int(self.headers["content-length"]))
          xml_post_data = xml.etree.ElementTree.fromstring(post_data.decode("utf-8"))

          # read domain analysis results
          for xml_domain in xml_post_data.iterfind("domainlist/domain"):
            domain = xml_domain.get("name")
            logging.getLogger().debug("Got client analysis for domain '%s'" % (domain) ) 
            if domain not in DistributedCrawlerServer.pending_domains:
              # this domain has already been checked by another client
              logging.getLogger().debug("Domain '%s' has already been checked, ignoring new analysis" % (domain) ) 
              continue
            is_spam = (xml_domain.get("spam") == "1")
            DistributedCrawlerServer.checked_domains[domain] = is_spam
            DistributedCrawlerServer.pending_domains.remove(domain)

          # thanks buddy client!
          self.send_response(204) # 204 is like 200 OK, but the client should expect no content
          self.end_headers()

      else:
        # buggy client, crawler, or someone else we don't care about...
        self.send_error(404)

    except:
      # boom!
      self.send_error(500)
      raise


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
