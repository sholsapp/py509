from OpenSSL import crypto

from py509.extensions import SubjectAltName


def test_make_san_extensions():
  e1 = crypto.X509Extension(b'subjectAltName', True, b'IP:0.0.0.0')
  assert e1
  assert SubjectAltName(e1.get_data()).ips == ['0.0.0.0']
  e2 = crypto.X509Extension(b'subjectAltName', True, b'DNS:foo.com')
  assert e2
  assert SubjectAltName(e2.get_data()).dns == ['foo.com']
  e3 = crypto.X509Extension(b'subjectAltName', True, b'URI:this:is:a:uri(hello-world)')
  assert e3
  assert SubjectAltName(e3.get_data()).uris == ['this:is:a:uri(hello-world)']
