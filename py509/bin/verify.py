#!/usr/bin/env python

"""Verify a certificate."""

import argparse
import logging
import sys

import certifi
from OpenSSL import crypto

from py509.x509 import load_x509_certificates


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

def main():

  trust_store = []
  with open(certifi.where()) as fh:
  #with open('/Users/sholsapp/workspace/py509/test.pem') as fh:
    trust_store = list(load_x509_certificates(fh.read()))

  x509store = crypto.X509Store()
  for ca in trust_store:
    print ca.get_subject()
    x509store.add_cert(ca)

  x509cert = crypto.load_certificate(crypto.FILETYPE_PEM, sys.stdin.read())

  try:
    crypto.X509StoreContext(x509store, x509cert).verify_certificate()
    print 'Success'
  except crypto.X509StoreContextError as e:
    print 'Failed on {0}'.format(e.certificate.get_subject())
    print 'Issuer {0}'.format(e.certificate.get_issuer())
    print 'Message: {0}'.format(e)
