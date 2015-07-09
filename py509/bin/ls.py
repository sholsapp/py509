#!/usr/bin/env python

"""List contents of a certificate."""

import datetime
import logging
import ssl
import sys

from OpenSSL import crypto
import dateutil.parser

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

  print 'Certificate:'
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
        'CN={0}'.format(x509cert.get_issuer().CN): {},
        '{0}, {1}, {2}'.format(
          x509cert.get_issuer().L,
          x509cert.get_issuer().ST,
          x509cert.get_issuer().C): {},
        'O={0}'.format(x509cert.get_issuer().O): {},
      },
      'identifiers': {
        'key identifier': {
          issuer_id: {},
        },
      },
    },
    'subject': {
      'name': {
        'CN={0}'.format(x509cert.get_subject().CN): {},
        '{0}, {1}, {2}'.format(
          x509cert.get_subject().L,
          x509cert.get_subject().ST,
          x509cert.get_subject().C): {},
        'O={0}'.format(x509cert.get_subject().O): {},
      },
      'identifiers': {
        'key identifier': {
          subject_id: {},
        },
      },
    }
  }))


if __name__ == '__main__':
  main()
