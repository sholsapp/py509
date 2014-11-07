from OpenSSL import crypto

from py509.x509 import make_pkey, make_certificate_signing_request, make_certificate_authority, make_certificate


def test_make_pkey():
  key = make_pkey(key_type=crypto.TYPE_RSA, key_bits=4096)
  assert key.bits() == 4096
  assert key.type() == crypto.TYPE_RSA
  assert key.check()


def test_make_certificate_signing_request():
  pkey = make_pkey()
  csr = make_certificate_signing_request(pkey, CN='Test Name')
  assert csr.verify(pkey)
  assert csr.get_subject().CN == 'Test Name'
  assert csr.get_version() == 3


def test_make_certificate_authority():
  key, crt = make_certificate_authority(CN='Test CA')
  assert crt.get_subject().CN == 'Test CA'
  assert crt.get_extension(0).get_short_name() == b'subjectKeyIdentifier'
  assert crt.get_extension(1).get_short_name() == b'authorityKeyIdentifier'
  assert crt.get_extension(2).get_short_name() == b'basicConstraints'
  # TODO: Add an ASN.1 parser so that we can decode the data that is tucked
  # away in this extension.
  #assert crt.get_extension(0).get_data() == 'CA:TRUE'
