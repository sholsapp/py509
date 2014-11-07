import socket
import uuid

from OpenSSL import crypto


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
  subj.OU = name.get('OU', socket.gethostbyname(socket.getfqdn()))
  subj.CN = name.get('CN', socket.getfqdn())
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
