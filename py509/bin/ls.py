#!/usr/bin/env python

"""List contents of a certificate."""

import datetime
import logging
import ssl
import sys

from OpenSSL import crypto
import dateutil.parser
import tabulate

from py509.utils import tree
from py509.x509 import load_certificate


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def stringify_version(v):
  try:
    return {
      # ssl.PROTOCOL_SSLv2: 'SSLv2',
      ssl.PROTOCOL_SSLv23: 'SSLv23',
      ssl.PROTOCOL_SSLv3: 'SSLv3',
      ssl.PROTOCOL_TLSv1: 'TLSv1',
    }[v]
  except KeyError:
    return '???'


def stringify_subject(s):
  return 'CN=%(CN)s (%(O)s - %(C)s)' % dict(s)


def main():

  x509cert = load_certificate(crypto.FILETYPE_PEM, sys.stdin.read())

  subject_id = 'unknown'
  if 'subjectKeyIdentifier' in x509cert.extensions:
    subject_id = x509cert.extensions['subjectKeyIdentifier'].id

  issuer_id = 'unknown'
  if 'authorityKeyIdentifier' in x509cert.extensions:
    issuer_id = x509cert.extensions['authorityKeyIdentifier'].id

  print 'Listing:'
  print '\n'.join(tree({
    'validity': {
      'lifetime': {
        '{0} to {1}'.format(
          dateutil.parser.parse(x509cert.get_notBefore()).date(),
          dateutil.parser.parse(x509cert.get_notAfter()).date()): {
            str(dateutil.parser.parse(x509cert.get_notAfter()) -
                dateutil.parser.parse(x509cert.get_notBefore())): {},
            str(dateutil.parser.parse(x509cert.get_notAfter(), ignoretz=True) -
                datetime.datetime.utcnow()): {}
        },
      },
    },
    'issuer': {
      'name': {
        str(x509cert.get_issuer()): {},
      },
      'identifiers': {
        'key identifier': {
          issuer_id: {},
        },
      },
    },
    'subject': {
      'name': {
        str(x509cert.get_subject()): {},
      },
      'identifiers': {
        'key identifier': {
          subject_id: {},
        },
      },
    }
  }))

  table = [
    ['subject', stringify_subject(x509cert.get_subject().get_components())],
    ['issuer', stringify_subject(x509cert.get_issuer().get_components())],
    ['serial', x509cert.get_serial_number()],
    ['version', stringify_version(x509cert.get_version())],
  ]

  for ext, data in x509cert.extensions.iteritems():
    table.append([ext, data])

  print tabulate.tabulate(table, headers=['field', 'value'])

if __name__ == '__main__':
  main()
