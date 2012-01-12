#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, gzip, http.server, logging, os.path, random, string, urllib.parse, xml.etree.ElementTree, zlib
import ddc_process # just to get the version


class XmlMessage:

  MAX_DOMAIN_LIST_SIZE = 20

  def __init__(self,client_version,page_processor_version):
    self.xml = xml.etree.ElementTree.Element("ddc")

    # generate upgrade nodes
    xml_upgrade = xml.etree.ElementTree.SubElement(self.xml,"upgrades")
    if client_version < DistributedCrawlerServer.LAST_CLIENT_VERSION:
      # need to upgrade the client
      xml.etree.ElementTree.SubElement(xml_upgrade,"upgrade",attrib={"type"  : "client",
                                                                      "url"   : "/upgrade?file=client-v%d.zip" % (DistributedCrawlerServer.LAST_CLIENT_VERSION) })
    if page_processor_version < ddc_process.VERSION:
      # need to upgrade the page processing component
      xml.etree.ElementTree.SubElement(xml_upgrade,"upgrade",attrib={"type"  : "client",
                                                                      "url"   : "/upgrade?file=page-processor-v%d.zip" % (ddc_process.VERSION) })

    # generate domain list nodes
    xml_domain_list = xml.etree.ElementTree.SubElement(self.xml,"domainlist")
    domains_to_send_count = min(len(DistributedCrawlerServer.domains_to_check),self.MAX_DOMAIN_LIST_SIZE)
    for i in range(domains_to_send_count):
      domain = random.choice(DistributedCrawlerServer.domains_to_check) # pick a random domain in the list
      xml.etree.ElementTree.SubElement(xml_domain_list,"domain",attrib={"name":domain})
      logging.getLogger().debug("Picked domain %s to be checked" % (domain) ) 

    if not domains_to_send_count:
      logging.getLogger().warning("No more domains to be checked")

    # TODO add a key (custom cryptographic hash of the domain list), and check that key when the clients responds
    # to be sure the client will not check different domains that the ones it has been sent.
    # NOTE: the hash function needs to be hidden (closed source), and must change frequently so that it can not be guessed with a large number of hashed domain lists

  def __str__(self):
    return xml.etree.ElementTree.tostring(self.xml,"unicode")


class DistributedCrawlerServer(http.server.HTTPServer):

  LAST_CLIENT_VERSION = SERVER_PROTOCOL_VERSION = 1
  MIN_ANALYSIS_PER_DOMAIN = 3

  domains_to_check = [ "domain%04d.com" % (i) for i in range(50) ] # we generate random domains for simulation
  checked_domains = {} # this holds the results as ie: checked_domains["spam-domain.com"] = (is_spam, number_of_clients_who_checked_this_domain)

  def __init__(self,port):
    super().__init__(("127.0.0.1",port),RequestHandler)

  def start(self):
    logging.getLogger().info("Server started")
    self.serve_forever()


class RequestHandler(http.server.BaseHTTPRequestHandler):

  # TODO replace all the redundant log/send_error blocks with exceptions

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
            not self.is_safe_filename(params["files"][0]): # we check for evil injection here
          logging.getLogger().warning("Invalid query parameters for URL '%s'" % (self.path) ) 
          self.send_error(400)

        # serve file (might short-circuit that part with an Apache/Nginx URL rediretion directly to the static content)
        upgrade_file = params["files"][0]
        try:
          with open(upgrade_file,"rb") as file_handle:
            # send http headers
            self.send_response(200)
            self.send_header("Content-Type",      "application/zip")
            self.send_header("Content-Length",    file_size)
            self.end_headers()
            # send file
            self.wfile.write(file_handle.read())
        except IOError:
          logging.getLogger().warning("Upgrade file '%s' does not exist or is not readable" % (upgrade_file) ) 
          self.send_error(400)

      elif parsed_url.path == "/rest":
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
            is_spam = (xml_domain.get("spam") == "1")
            if domain in DistributedCrawlerServer.checked_domains:
              # this domain has already been checked by at least another client
              previous_is_spam = DistributedCrawlerServer.checked_domains[domain][0]
              analysis_count = DistributedCrawlerServer.checked_domains[domain][1] +1
              if (previous_is_spam != is_spam) and (analysis_count > 1):
                # differents clients gave different analysis, reset analysis count
                # TODO it is still possible to game the system if the client send the same analysis X times in a row
                logging.getLogger().warning("Conflicting client analysis for domain '%s'" % (domain) ) 
                analysis_count = 0
              elif analysis_count >= DistributedCrawlerServer.MIN_ANALYSIS_PER_DOMAIN:
                # enough checks for this domain
                logging.getLogger().debug("Domain '%s' has has been checked %d times, is_spam=%d" % (domain, analysis_count, is_spam) ) 
                try:
                  DistributedCrawlerServer.domains_to_check.remove(domain)
                except ValueError:
                  # ValueError is thrown if the domain is not in the list which can happen if another client has already sent the MIN_ANALYSIS_PER_DOMAIN'th analysis
                  # => we dont't care
                  pass
            else:
              # this domain is checked for the first time
              analysis_count = 1
            DistributedCrawlerServer.checked_domains[domain] = (is_spam, analysis_count)

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

  def is_safe_filename(self,filename):
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
