#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, http.server, logging, urllib.parse


class DistributedCrawlerServer(http.server.HTTPServer):

  PROTOCOL_VERSION = 1

  def __init__(self,port):
    super().__init__(("127.0.0.1",port),RequestHandler)

  def start(self):
    self.serve_forever()


class RequestHandler(http.server.BaseHTTPRequestHandler):

  server_version = "DDC Server" # overrides http.server.BaseHTTPRequestHandler.server_version

  def do_GET(self):
    # parse request url
    parsed_url = urllib.parse.urlsplit(self.path)

    if parsed_url.path == "/upgrade":
      # serve file (might short-circuit that part with an Apache/Nginx URL rediretion directly to the static content)
      pass
    elif parsed_url.path == "/rest":
      # handle parameters
      params = urllib.parse.parse_qs(parsed_url.query)
      if "action" in params and params["action"] and params["action"][0] == "getdomains":
        # TODO
        pass
      self.send_response(200,"I'm the server")
    else:
      # buggy client, crawler, or someone else we don't care about...
      self.send_error(404)


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
