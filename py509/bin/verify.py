#!/usr/bin/env python

"""Verify a certificate."""

import argparse
import click
import logging
import sys

from OpenSSL import crypto
import certifi
import urllib3

from py509.extensions import AuthorityInformationAccess
from py509.utils import tree, assemble_chain
from py509.x509 import load_x509_certificates


logging.getLogger('urllib3').setLevel(logging.WARNING)


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def get_certificate(url):
  http = urllib3.PoolManager()
  rsp = http.request('GET', url, headers={'Content-Type': 'application/pkix-cert'})
  if rsp.status == 200:
    # if strict_compliance and 'application/x-x509-ca-cert' not in rsp.headers:
    #   # This web server's response isn't following the RFC, but might contain
    #   # data representing a DER encoded certificate.
    #   return
    return crypto.load_certificate(crypto.FILETYPE_ASN1, rsp.data)
  else:
    raise RuntimeError('Failed to fetch intermediate certificate at {0}!'.format(url))


CERTIFI = certifi.where()


@click.command()
@click.option('--ca', default=CERTIFI,
              help='A custom trust store to use if different than certifi\'s.')
@click.option('--resolve/--no-resolve', default=True,
              help='Should intermediate certificates be resolved and added to the trust store?')
def main(ca, resolve):

  trust_store = []
  with open(ca) as fh:
    trust_store = list(load_x509_certificates(fh.read()))

  x509store = crypto.X509Store()
  for ca in trust_store:
    x509store.add_cert(ca)

  x509cert = crypto.load_certificate(crypto.FILETYPE_PEM, sys.stdin.read())

  if resolve:
    for idx in range(0, x509cert.get_extension_count()):
      ext = x509cert.get_extension(idx)
      if ext.get_short_name() in ['authorityInfoAccess']:
        access = AuthorityInformationAccess(ext.get_data())
        intermediate = get_certificate(access.ca_issuer)
        if intermediate:
          x509store.add_cert(intermediate)

  try:
    crypto.X509StoreContext(x509store, x509cert).verify_certificate()

    chain = assemble_chain(x509cert, trust_store + [intermediate])
    d = {chain[0].get_subject().CN: {}}
    tmp = d
    for c in chain:
      tmp[c.get_subject().CN] = {}
      tmp = tmp[c.get_subject().CN]

    click.secho('[good] ', nl=False, fg='green')
    click.secho(' * the chain is valid', fg='green')
    for line in tree(d):
      click.secho('[good] ', nl=False, fg='green')
      click.secho(line)

  except crypto.X509StoreContextError as e:
    print 'Failed on {0}'.format(e.certificate.get_subject())
    print 'Issuer {0}'.format(e.certificate.get_issuer())
    print 'Message: {0}'.format(e)
