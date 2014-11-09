import re
import socket
import uuid

from pyasn1.codec.der.decoder import decode
from OpenSSL import crypto

from py509.asn1.san import SubjectAltName


def make_serial():
  """Make a random serial number."""
  return uuid.uuid4().int


def make_pkey(key_type=crypto.TYPE_RSA, key_bits=4096):
  """Make a public/private key pair."""
  key = crypto.PKey()
  key.generate_key(key_type, key_bits)
  return key


def make_certificate_signing_request(pkey, digest='sha512', **name):
  """Make a certificate signing request."""
  csr = crypto.X509Req()
  subj = csr.get_subject()
  subj.C = name.get('C', 'US')
  subj.ST = name.get('ST', 'CA')
  subj.L = name.get('L', 'Home')
  subj.O = name.get('O', 'Home')
  #subj.OU = name.get('OU', socket.gethostbyname(socket.getfqdn()))
  #subj.CN = name.get('CN', socket.getfqdn())
  subj.OU = name.get('OU', 'Unit')
  subj.CN = name.get('CN', 'Common')
  csr.set_pubkey(pkey)
  csr.set_version(3)
  csr.sign(pkey, digest)
  return csr


def make_certificate(csr, ca_key, ca_cert, serial, not_before, not_after, digest='sha512', version=2, exts=()):
  """Make a certificate.

  The following extensions are added to all certificates in the following order
  *before* additional extensions specified by `exts` kwarg:

    - subjectKeyIdentifier
    - authorityKeyIdentifier

  """
  crt = crypto.X509()
  crt.set_serial_number(serial)
  crt.gmtime_adj_notBefore(not_before)
  crt.gmtime_adj_notAfter(not_after)
  crt.set_issuer(ca_cert.get_subject())
  crt.set_subject(csr.get_subject())
  crt.set_pubkey(csr.get_pubkey())
  crt.set_version(version)

  crt.add_extensions([
    crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=crt)])
  if ca_cert.get_subject() == crt.get_subject():
    crt.add_extensions([
      crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always', issuer=crt)])
  else:
    crt.add_extensions([
      crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always', issuer=ca_cert)])

  crt.add_extensions(exts)

  crt.sign(ca_key, digest)
  return crt


def make_certificate_authority(**name):
  """Make a certificate authority.

  A certificate authority can sign certificates. For clients to be able to
  validate certificates signed by your certificate authorithy, they must trust
  the certificate returned by this function.

  """
  key = make_pkey()
  csr = make_certificate_signing_request(key, **name)
  crt = make_certificate(csr, key, csr, make_serial(), 0, 10 * 365 * 24 * 60 * 60, exts=[crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE')])
  return key, crt


def load_x509_certificates(buf):
  """Load one or multiple X.509 certificates from a buffer.

  :param buf: A buffer is an instance of `basestring` and can contain multiple
    certificates.

  """
  if not isinstance(buf, basestring):
    raise ValueError('`buf` should be an instance of `basestring` not `%s`' % type(buf))

  for pem in re.findall('(-----BEGIN CERTIFICATE-----\s(\S+\n*)+\s-----END CERTIFICATE-----\s)', buf):
    yield crypto.load_certificate(crypto.FILETYPE_PEM, pem[0])


def decode_subject_alt_name(asn1_data):
  """Decode a subject alternative name's data.

  Note, not all of the possible types are handled by this method. For a
  complete listing, see https://tools.ietf.org/html/rfc3280#section-4.2.1.7.
  Currently, only DNS names, IP addresses, and URI are supported.

  """
  for name in decode(asn1_data, asn1Spec=SubjectAltName()):
    if isinstance(name, SubjectAltName):
      for entry in range(len(name)):
        component = name.getComponentByPosition(entry)
        component_name = component.getName()
        component_data = component.getComponent().asOctets()
        if component_name == 'dNSName':
          yield bytes.decode(component_data)
        elif component_name == 'iPAddress':
          yield socket.inet_ntoa(component_data)
        elif component_name == 'uniformResourceIdentifier':
          yield bytes.decode(component_data)
        else:
          # FIXME: other types are currently not handled.
          pass
