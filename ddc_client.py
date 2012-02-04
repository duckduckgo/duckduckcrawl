#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, logging, time, urllib.parse, xml.etree.ElementTree, zipfile
import httplib2
import ddc_process


class NeedRestartException(Exception):
  pass


class DistributedCrawlerClient():

  CLIENT_VERSION = 1
  http_client = httplib2.Http(timeout=10)

  def __init__(self,server,port):
    self.base_url = "http://%s:%d" % (server,port)
    self.api_base_url = "%s/domains" % (self.base_url)
  
  def start(self,):
    logging.getLogger().info("DuckDuckGo distributed crawler client v%d started" % (__class__.CLIENT_VERSION))
    logging.getLogger().info("Page analysis component v%d loaded" % (ddc_process.VERSION))

    try:
      while True:
        # see README.md for params description
        response = self.api_request({ "version"         : str(__class__.CLIENT_VERSION),
                                      "pc_version"      : str(ddc_process.VERSION) }).decode("utf-8")

        # read response
        xml_response = xml.etree.ElementTree.fromstring(response)
        xml_domains = xml_response.findall("domainlist/domain")
        domain_count = len(xml_domains)

        # upgrade components if necessary
        need_restart = False
        for xml_upgrade in xml_response.findall("upgrades/upgrade"):
          type = xml_upgrade.get("type")
          version = xml_upgrade.get("version")
          logging.getLogger().info("Upgrading '%s' component to version %s" % (type,version) )
          url = self.base_url + xml_upgrade.get("url")
          response, content = __class__.http_client.request(url)
          zip_filename = response["content-disposition"].split(";")[1].split("=")[1]
          with open(zip_filename,"r+b") as file_handle:
            file_handle.write(content)
            archive = zipfile.ZipFile(file_handle,"r")
            archive.extractall()
            archive.close()
          need_restart = True
        if need_restart:
          raise NeedRestartException()

        # if the server has no work for us, take a nap
        if not domain_count:
          logging.getLogger().info("Got no domains to check from server, sleeping for 30s...")
          time.sleep(30)
          continue

        # check domains
        logging.getLogger().info("Got %d domains to check from server" % (domain_count) )
        domains_state = [ False for i in range(domain_count) ]
        for (i, xml_domain) in enumerate(xml_domains):
          domain = xml_domain.get("name")
          logging.getLogger().debug("Checking domain '%s'" % (domain) )
          domains_state[i] = ddc_process.is_spam(domain)
          # TODO should add a special XML attribute for when a domain check fails (network, etc.)

        # prepare POST request content
        xml_root = xml.etree.ElementTree.Element("ddc")
        xml_domain_list = xml_response.find("domainlist") # reuse the previous XML domain list
        for (xml_domain, is_spam) in zip(xml_domain_list.iterfind("domain"),domains_state):
          xml_domain.set("spam",str(int(is_spam)))
        xml_root.append(xml_domain_list)

        # send POST request
        post_data = xml.etree.ElementTree.tostring(xml_root)
        self.api_request( { "version"    : str(__class__.CLIENT_VERSION),
                            "pc_version" : str(ddc_process.VERSION) },
                            True,
                            post_data) # we don't care for what the server actually returns here

    except NeedRestartException:
      logging.getLogger().info("Restarting client")
      exit(7)


  def api_request(self,url_params,post_request=False,post_data=None):
    # construct url
    url = "%s?%s" % (self.api_base_url,urllib.parse.urlencode(url_params))
    # send request
    if post_request:
      logging.getLogger().info("Posting data to '%s'" % (url) )
      response, content = __class__.http_client.request(url,"POST",post_data)
    else:
      logging.getLogger().info("Fetching '%s'" % (url) )
      response, content = __class__.http_client.request(url)
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