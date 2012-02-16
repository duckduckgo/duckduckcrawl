#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib


VERSION = 1


class FailedAnalysis(Exception):
  pass


def is_spam(domain):
  # returns dummy result, but consistent for a domain
  hasher = hashlib.md5()
  hasher.update(domain.encode("utf-8"))
  return hasher.digest()[0] > 127
