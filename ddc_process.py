#!/usr/bin/env python3
# -*- coding: utf-8 -*-


def is_spam(domain):
  return len(domain.strip())%2 > 0
