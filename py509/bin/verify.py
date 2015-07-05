#!/usr/bin/env python

"""Verify a certificate."""

from functools import partial
import click
import logging
import sys

from OpenSSL import crypto
import certifi

from py509.extensions import AuthorityInformationAccess
from py509.utils import tree, transmogrify, assemble_chain
from py509.x509 import resolve_pkix_certificate, load_x509_certificates, load_certificate


logging.getLogger('urllib3').setLevel(logging.WARNING)


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


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

  x509cert = load_certificate(crypto.FILETYPE_PEM, sys.stdin.read())

  intermediate = None
  if resolve:
    if 'authorityInfoAccess' in  x509cert.extensions:
      intermediate = resolve_pkix_certificate(x509cert.extensions['authorityInfoAccess'].ca_issuer)
      if intermediate:
        x509store.add_cert(intermediate)
        trust_store.append(intermediate)

  def cert_string(cert):
    return '{0}'.format(cert.get_subject().CN)

  def style_cert(valid, key):
    color = 'green' if valid else 'red'
    string = []
    string.append(click.style('[+] ', fg=color))
    uid = 'unknown'
    if 'subjectKeyIdentifier' in key.extensions:
      uid = key.extensions['subjectKeyIdentifier']
      uid = uid.replace(':', '')
      uid = uid.lower()
      uid = uid[:8]
    if uid == 'unknown':
      string.append(click.style('({0})'.format(uid), fg='yellow'))
    else:
      string.append('({0})'.format(uid))
    return ''.join(string)

  def style_intermediate(key):
    if intermediate and intermediate.get_subject().CN == key.get_subject().CN:
      return click.style('(resolved)', fg='yellow')
    return ''

  try:
    crypto.X509StoreContext(x509store, x509cert).verify_certificate()

    chain = assemble_chain(x509cert, trust_store)
    # Success
    g = partial(style_cert, True)
    click.secho('[{0}] '.format(len(chain)), nl=False, fg='green')
    click.secho('certificates verified')
    for line in tree(transmogrify(chain), formatter=cert_string, prefix=g, postfix=style_intermediate):
      click.secho(line)

  except crypto.X509StoreContextError as e:
    chain = assemble_chain(x509cert, trust_store)
    # Failure
    g = partial(style_cert, False)
    click.secho('[{0}] '.format(len(chain)), nl=False, fg='red')
    click.secho(e.message[2])
    for line in tree(transmogrify(chain), formatter=cert_string, prefix=g, postfix=style_intermediate):
      click.secho(line)
