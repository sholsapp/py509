import binascii
import socket

from pyasn1.codec.der.decoder import decode
from pyasn1_modules.rfc2459 import (
    AuthorityInfoAccessSyntax as _AuthorityInfoAccessSyntax,
    AuthorityKeyIdentifier as _AuthorityKeyIdentifier,
    SubjectAltName as _SubjectAltName,
    SubjectKeyIdentifier as _SubjectKeyIdentifier,
)


class SubjectAltName(object):
  """Decode a subject alternative name extensions's data.

  .. warning::

    Not all of the possible types are handled by this method. Currently, only
    DNS names, IP addresses and URI are handled. If these types of names are
    present in the ``asn1_data`` they will simply be ignored.

  See https://tools.ietf.org/html/rfc5280.

  :param bytes asn1_data: The ASN.1 data to decode.
  :return: A list of alternative names.
  :rtype: list[str]

  """

  #: A list of DNS names.
  dns = []

  #: A list of IP addresses.
  ips = []

  #: A list of uniform resource identifiers.
  uris = []

  def __init__(self, asn1_data):
    for name in decode(asn1_data, asn1Spec=_SubjectAltName()):
      if isinstance(name, _SubjectAltName):
        for entry in range(len(name)):
          component = name.getComponentByPosition(entry)
          component_name = component.getName()
          component_data = component.getComponent().asOctets()
          if component_name == 'dNSName':
            self.dns.append(bytes.decode(component_data))
          elif component_name == 'iPAddress':
            self.ips.append(socket.inet_ntoa(component_data))
          elif component_name == 'uniformResourceIdentifier':
            self.uris.append(bytes.decode(component_data))
          else:
            # FIXME: other types are currently not handled.
            pass

  def __repr__(self):
    return 'SubjectAltName(dns={0}, ip={1}, uri={2})'.format(len(self.dns), len(self.ips), len(self.uris))


class AuthorityInformationAccess(object):
  """Decode an authority information access extension's data.

  See https://tools.ietf.org/html/rfc5280.

  :param bytes asn1_data: The ASN.1 data to decode.
  :return: A URI to access the authority's information.
  :rtype: str

  """

  ocsp = None

  ca_issuer = None

  def __init__(self, asn1_data):
    OCSP_OID = '1.3.6.1.5.5.7.48.1'
    CA_ISSUER_OID = '1.3.6.1.5.5.7.48.2'
    for authority in decode(asn1_data, asn1Spec=_AuthorityInfoAccessSyntax()):
      if isinstance(authority, _AuthorityInfoAccessSyntax):
        for entry in range(len(authority)):
          component = authority.getComponentByPosition(entry)
          if str(component.getComponentByName('accessMethod').prettyPrint()) == CA_ISSUER_OID:
            self.ca_issuer = component.getComponentByName('accessLocation').getComponent().asOctets()
          elif str(component.getComponentByName('accessMethod').prettyPrint()) == OCSP_OID:
            self.ocsp = component.getComponentByName('accessLocation').getComponent().asOctets()

  def __repr__(self):
    return 'AuthorityInformationAccess(oscp="{0}", ca_issuer="{1}")'.format(self.ocsp, self.ca_issuer)


class SubjectKeyIdentifier(object):

  id = None

  def __init__(self, asn1_data):
    for authority in decode(asn1_data, asn1Spec=_SubjectKeyIdentifier()):
      if isinstance(authority, _SubjectKeyIdentifier):
        self.id = binascii.hexlify(authority.asOctets())


class AuthorityKeyIdentifier(object):

  id = None

  issuer = None

  serial = None

  def __init__(self, asn1_data):
    for authority in decode(asn1_data, asn1Spec=_AuthorityKeyIdentifier()):
      if isinstance(authority, _AuthorityKeyIdentifier):
        self.id = binascii.hexlify(authority.getComponentByName('keyIdentifier').asOctets())
        self.issuer = authority.getComponentByName('authorityCertIssuer')
        self.serial = authority.getComponentByName('authorityCertSerialNumber')
