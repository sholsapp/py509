import re
import socket
import uuid

from pyasn1.codec.der.decoder import decode
from OpenSSL import crypto

from py509.asn1.san import SubjectAltName
from py509.asn1.authority_info_access import AuthorityInfoAccess


def make_serial():
  """Make a random serial number.

  :return: A serial number as an integer.
  :rtype: int

  """
  return uuid.uuid4().int


def make_pkey(key_type=crypto.TYPE_RSA, key_bits=4096):
  """Make a public/private key pair.

  :param int key_type: The key type. For example,
    :class:`OpenSSL.crypto.TYPE_RSA`.
  :param int key_bits: The size of the key in bits.
  :return: A private key.
  :rtype: :class:`OpenSSL.crypto.PKey`

  """
  key = crypto.PKey()
  key.generate_key(key_type, key_bits)
  return key


def make_certificate_signing_request(pkey, digest='sha512', **name):
  """Make a certificate signing request.

  :param OpenSSL.crypto.PKey pkey: A private key.
  :param str digest: A valid digest to use. For example, `sha512`.
  :param name: Key word arguments containing subject name parts: C, ST, L, O,
    OU, CN.
  :return: A certificate signing request.
  :rtype: :class:`OpenSSL.crypto.X509Request`

  """
  csr = crypto.X509Req()
  subj = csr.get_subject()
  subj.C = name.get('C', 'US')
  subj.ST = name.get('ST', 'CA')
  subj.L = name.get('L', 'Home')
  subj.O = name.get('O', 'Home')
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

  :param OpenSSL.crypto.X509Request csr: A certificate signing request.
  :param OpenSSL.crypto.PKey ca_key: The signing authority's key.
  :param OpenSSL.crypto.X509 ca_cert: The signing authority's certificate.
  :param int serial: A serial number.
  :param int not_before: A number of seconds from now to wait before the certificate is valid.
  :param int not_after: A number of seconds from now to wait before expiring the certificate.
  :param str digest: A valid digest.
  :param int version: The version of SSL to use with this certificate.
  :param list[OpenSSL.crypto.X509Extension] exts: A list of extensions to add to this certificate.
  :return: A X.509 certificate.
  :rtype: :class:`OpenSSL.crypto.X509`

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

  :param name: Key word arguments containing subject name parts: C, ST, L, O,
    OU, CN.
  :return: A root self-signed certificate to act as an authority.
  :rtype: :class:`OpenSSL.crypto.X509`

  """
  key = make_pkey()
  csr = make_certificate_signing_request(key, **name)
  crt = make_certificate(csr, key, csr, make_serial(), 0, 10 * 365 * 24 * 60 * 60, exts=[crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE')])
  return key, crt


def load_x509_certificates(buf):
  """Load one or multiple X.509 certificates from a buffer.

  :param str buf: A buffer is an instance of `basestring` and can contain multiple
    certificates.
  :return: An iterator that iterates over certificates in a buffer.
  :rtype: list[:class:`OpenSSL.crypto.X509`]

  """
  if not isinstance(buf, basestring):
    raise ValueError('`buf` should be an instance of `basestring` not `%s`' % type(buf))

  for pem in re.findall('(-----BEGIN CERTIFICATE-----\s(\S+\n*)+\s-----END CERTIFICATE-----\s)', buf):
    yield crypto.load_certificate(crypto.FILETYPE_PEM, pem[0])


def decode_subject_alt_name(asn1_data):
  """Decode a subject alternative name extensions's data.

  Note, not all of the possible types are handled by this method. Currently,
  only DNS names, IP addresses and URI are handled.

  See https://tools.ietf.org/html/rfc3280 for more information.

  :param bytes asn1_data: The ASN.1 data to decode.
  :return: A list of alternative names.
  :rtype: list[str]

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


def decode_authority_information_access(asn1_data):
  """Decode an authority information access extension's data.

  See https://tools.ietf.org/html/rfc5280.

  :param bytes asn1_data: The ASN.1 data to decode.
  :return: A URI to access the authority's information.
  :rtype: str

  """
  # OCSP_OID = '1.3.6.1.5.5.7.48.1'
  CA_ISSUER_OID = '1.3.6.1.5.5.7.48.2'
  for authority in decode(asn1_data, asn1Spec=AuthorityInfoAccess()):
    if isinstance(authority, AuthorityInfoAccess):
      for entry in range(len(authority)):
        component = authority.getComponentByPosition(entry)
        if component.getComponentByName('accessMethod').prettyPrint() == CA_ISSUER_OID:
          return component.getComponentByName('accessLocation').getComponent().asOctets()
