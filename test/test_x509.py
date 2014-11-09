from OpenSSL import crypto

from py509.x509 import make_pkey, make_certificate_signing_request, make_certificate_authority, make_certificate, make_serial, decode_subject_alt_name


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
  #print crt.get_extension(0).get_data()
  #print crt.get_extension(1).get_data()
  #print crt.get_extension(2).get_data()


def test_make_certificate():
  ca_key, ca_crt = make_certificate_authority(CN='Test CA')
  pkey = make_pkey()
  csr = make_certificate_signing_request(pkey, CN='Test Cert')
  crt = make_certificate(
    csr, ca_key, ca_crt,
    make_serial(), 0, 10 * 365 * 24 * 60 * 60,
    exts=[crypto.X509Extension(b'subjectAltName', True, b'IP:0.0.0.0')])
  assert crt.get_subject().CN == 'Test Cert'


def test_make_san_extensions():
  e1 = crypto.X509Extension(b'subjectAltName', True, b'IP:0.0.0.0')
  assert e1
  assert list(decode_subject_alt_name(e1.get_data())) == ['0.0.0.0']
  e2 = crypto.X509Extension(b'subjectAltName', True, b'DNS:foo.com')
  assert e2
  assert list(decode_subject_alt_name(e2.get_data())) == ['foo.com']
  e3 = crypto.X509Extension(b'subjectAltName', True, b'URI:this:is:a:uri(hello-world)')
  assert e3
  assert list(decode_subject_alt_name(e3.get_data())) == ['this:is:a:uri(hello-world)']
