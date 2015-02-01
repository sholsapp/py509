#!/usr/bin/env python

"""List contents of a certificate."""

import argparse
import logging
import ssl
import sys

from OpenSSL import crypto
import dateutil.parser
import tabulate

from py509 import client


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def stringify_version(v):
  try:
    return {
      ssl.PROTOCOL_SSLv2: 'SSLv2',
      ssl.PROTOCOL_SSLv23: 'SSLv23',
      ssl.PROTOCOL_SSLv3: 'SSLv3',
      ssl.PROTOCOL_TLSv1: 'TLSv1',
    }[v]
  except KeyError:
    return '???'


def stringify_subject(s):
  return 'CN=%(CN)s' % dict(s)


def main():

  #parser = argparse.ArgumentParser(description=__doc__)
  #parser.add_argument('host')
  #args = parser.parse_args()

  x509cert = crypto.load_certificate(crypto.FILETYPE_PEM, sys.stdin.read())

  table = [
    ['subject', stringify_subject(x509cert.get_subject().get_components())],
    ['issuer', stringify_subject(x509cert.get_issuer().get_components())],
    ['notBefore', dateutil.parser.parse(x509cert.get_notBefore())],
    ['notAfter', dateutil.parser.parse(x509cert.get_notAfter())],
    ['serial', x509cert.get_serial_number()],
    ['version', stringify_version(x509cert.get_version())],
    #['extensions', x509cert.get_extension_count()],
  ]

  for idx in range(0, x509cert.get_extension_count()):
    ext = x509cert.get_extension(idx)
    if ext.get_short_name() not in ['crlDistributionPoints', 'certificatePolicies', 'authorityInfoAccess']:
      table.append([ext.get_short_name(), str(ext)[:80]])

  print tabulate.tabulate(table, headers=['field', 'value'])

if __name__ == '__main__':
  main()
