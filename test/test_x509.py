from OpenSSL import crypto

from py509.x509 import make_pkey, make_certificate_signing_request, make_certificate_authority, make_certificate, make_serial


# These are known to be weak, but this is fast, and this is just for testing.
TEST_KEY_SIZE = 512
TEST_DIGEST = 'md5'


def test_make_pkey():
  key = make_pkey(key_type=crypto.TYPE_RSA, key_bits=TEST_KEY_SIZE)
  assert key.bits() == TEST_KEY_SIZE
  assert key.type() == crypto.TYPE_RSA
  assert key.check()


def test_make_certificate_signing_request():
  pkey = make_pkey(key_bits=TEST_KEY_SIZE)
  csr = make_certificate_signing_request(pkey, CN='Test Name', digest=TEST_DIGEST)
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
  # print crt.get_extension(0).get_data()
  # print crt.get_extension(1).get_data()
  # print crt.get_extension(2).get_data()


def test_make_certificate():
  ca_key, ca_crt = make_certificate_authority(CN='Test CA')
  pkey = make_pkey(key_bits=TEST_KEY_SIZE)
  csr = make_certificate_signing_request(pkey, CN='Test Cert', digest=TEST_DIGEST)
  crt = make_certificate(
    csr, ca_key, ca_crt,
    make_serial(), 0, 10 * 365 * 24 * 60 * 60,
    exts=[crypto.X509Extension(b'subjectAltName', True, b'IP:0.0.0.0')],
    digest=TEST_DIGEST)
  assert crt.get_subject().CN == 'Test Cert'
