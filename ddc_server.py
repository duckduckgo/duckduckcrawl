#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, gzip, http.server, logging, urllib.parse, xml.etree.ElementTree, zlib


class XmlMessage:

  def __init__(self,protocol_version,page_processor_version):
    self.xml = xml.etree.ElementTree.Element("ddc")
    # TODO generate upgrade nodes
    # TODO generate domain list nodes

  def __str__(self):
    return xml.etree.ElementTree.tostring(self.xml,"unicode")


class DistributedCrawlerServer(http.server.HTTPServer):

  LAST_PROTOCOL_VERSION = 1

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
        pass

      elif parsed_url.path == "/rest":
        # parse url parameters
        params = urllib.parse.parse_qs(parsed_url.query,keep_blank_values=False,strict_parsing=True)

        # check query is well formed
        if "action" not in params or \
            params["action"][0] != "getdomains" or \
            "version" not in params or \
            "pc_version" not in params:
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

          # TODO add encryption

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
