#!/usr/bin/env python

"""Fetch a remote host's certificate."""

import argparse
import logging
import ssl

from OpenSSL import crypto

from py509 import client


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('host')
  args = parser.parse_args()

  x509cert = client.get_host_certificate(args.host)
  print crypto.dump_certificate(crypto.FILETYPE_PEM, x509cert)


if __name__ == '__main__':
  main()
