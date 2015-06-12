#!/usr/bin/env python

"""Verify a certificate."""

import argparse
import logging
import sys

import certifi
from OpenSSL import crypto

from pyasn1.codec.der.decoder import decode
from py509.x509 import load_x509_certificates
from py509.asn1.authority_info_access import AuthorityInfoAccess



logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# https://tools.ietf.org/html/rfc5280
def decode_authority_information_access(asn1_data):
  OCSP = '1.3.6.1.5.5.7.48.1'
  CA_ISSUER = '1.3.6.1.5.5.7.48.2'
  for authority in decode(asn1_data, asn1Spec=AuthorityInfoAccess()):
    if isinstance(authority, AuthorityInfoAccess):
      for entry in range(len(authority)):
        component = authority.getComponentByPosition(entry)
        if component.getComponentByName('accessMethod').prettyPrint() == CA_ISSUER:
          return component.getComponentByName('accessLocation').getComponent().asOctets()

def main():

  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--ca', required=False, default=certifi.where())
  args = parser.parse_args()

  trust_store = []
  with open(args.ca) as fh:
    trust_store = list(load_x509_certificates(fh.read()))

  x509store = crypto.X509Store()
  for ca in trust_store:
    print ca.get_subject()
    x509store.add_cert(ca)

  x509cert = crypto.load_certificate(crypto.FILETYPE_PEM, sys.stdin.read())

  for idx in range(0, x509cert.get_extension_count()):
    ext = x509cert.get_extension(idx)
    if ext.get_short_name() in ['authorityInfoAccess']:
      print ext.get_short_name()
      print str(ext)
      print decode_authority_information_access(ext.get_data())

  try:
    crypto.X509StoreContext(x509store, x509cert).verify_certificate()
    print 'Success'
  except crypto.X509StoreContextError as e:
    print 'Failed on {0}'.format(e.certificate.get_subject())
    print 'Issuer {0}'.format(e.certificate.get_issuer())
    print 'Message: {0}'.format(e)
