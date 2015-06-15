#!/usr/bin/env python

"""Verify a certificate."""

import argparse
import logging
import sys

from OpenSSL import crypto
import certifi
import urllib3

from py509.x509 import load_x509_certificates, decode_authority_information_access


logging.getLogger('urllib3').setLevel(logging.WARNING)


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def get_certificate(url, strict_compliance=False):
  http = urllib3.PoolManager()
  rsp = http.request('GET', url, headers={'Content-Type': 'application/pkix-cert'})
  if rsp.status == 200:
    if strict_compliance and 'application/x-x509-ca-cert' not in rsp.headers:
      # This web server's response isn't following the RFC, but might contain
      # data representing a DER encoded certificate.
      return
  else:
    raise RuntimeError('Failed to fetch intermediate certificate at {0}!'.format(url))
  return crypto.load_certificate(crypto.FILETYPE_ASN1, rsp.data)


def main():

  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--ca', required=False, default=certifi.where())
  parser.add_argument('--no-resolve-intermediate', action='store_true', default=False)
  parser.add_argument('--strict-compliance', action='store_true', default=False)
  args = parser.parse_args()

  trust_store = []
  with open(args.ca) as fh:
    trust_store = list(load_x509_certificates(fh.read()))

  x509store = crypto.X509Store()
  for ca in trust_store:
    x509store.add_cert(ca)

  x509cert = crypto.load_certificate(crypto.FILETYPE_PEM, sys.stdin.read())

  if not args.no_resolve_intermediate:
    for idx in range(0, x509cert.get_extension_count()):
      ext = x509cert.get_extension(idx)
      if ext.get_short_name() in ['authorityInfoAccess']:
        access = decode_authority_information_access(ext.get_data())
        intermediate = get_certificate(access, strict_compliance=args.strict_compliance)
        if intermediate:
          x509store.add_cert(intermediate)

  try:
    crypto.X509StoreContext(x509store, x509cert).verify_certificate()
    print 'Good'
  except crypto.X509StoreContextError as e:
    print 'Failed on {0}'.format(e.certificate.get_subject())
    print 'Issuer {0}'.format(e.certificate.get_issuer())
    print 'Message: {0}'.format(e)
