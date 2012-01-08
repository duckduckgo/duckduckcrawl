#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, logging, urllib.parse
import httplib2
import ddc_process


class DistributedCrawlerClient():

  PROTOCOL_VERSION = 1
  PROCESSOR_COMPONENT_VERSION = 1
  http_client = httplib2.Http(timeout=10,disable_ssl_certificate_validation=True)

  def __init__(self,server,port):
    self.base_url = "http://%s:%d/rest" % (server,port)
  
  def start(self,):
    # see README.md for params description
    response = self.request({ 'action'          : 'getdomains',
                              'version'         : str(self.PROTOCOL_VERSION),
                              'pc_version'      : str(self.PROCESSOR_COMPONENT_VERSION) }).decode("utf-8")
    print(response)

  def request(self,params):
    # construct url
    url = "%s?%s" % (self.base_url,urllib.parse.urlencode(params))
    # send request
    logging.getLogger().debug("Fetching '%s' ..." % (url) )
    response, content = self.http_client.request(url)
    return content


if __name__ == '__main__':

  # setup logger
  logger = logging.getLogger()
  logger.setLevel(logging.DEBUG)

  # parse args
  cli_parser = argparse.ArgumentParser()
  cli_parser.add_argument("-s", 
                          "--server",
                          action="store",
                          required=True,
                          dest="server",
                          help="Server IP or domain to connect to")
  cli_parser.add_argument("-p", 
                          "--port",
                          action="store",
                          required=True,
                          type=int,
                          dest="port",
                          help="Network port to use to communicate with server")
  options = cli_parser.parse_args()
  
  # start client
  client = DistributedCrawlerClient(options.server,options.port)
  client.start()