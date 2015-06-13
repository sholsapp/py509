"""ASN.1 implementation for subjectAltNames support.

Adopted and slightly modified from the NDG HTTPS client at
https://github.com/cedadev/ndg_httpsclient, which was adopted from some legacy
pyOpenSSL extensions. Unfortunately, a first-class OpenSSL + ASN.1 library
doesn't exist, so it seems common practice to include this ASN.1 boilerplate
in your own projects.

"""

from pyasn1.type import univ, constraint, char, namedtype, tag


# The maximum allowed string length allowed.
MAX = 256


class DirectoryString(univ.Choice):
  """ASN.1 Directory string class."""
  componentType = namedtype.NamedTypes(
    namedtype.NamedType(
      'teletexString', char.TeletexString().subtype(
        subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
    namedtype.NamedType(
      'printableString', char.PrintableString().subtype(
        subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
    namedtype.NamedType(
      'universalString', char.UniversalString().subtype(
        subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
    namedtype.NamedType(
      'utf8String', char.UTF8String().subtype(
        subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
    namedtype.NamedType(
      'bmpString', char.BMPString().subtype(
        subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
    namedtype.NamedType(
      'ia5String', char.IA5String().subtype(
        subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
  )


class AttributeValue(DirectoryString):
  """ASN.1 Attribute value."""


class AttributeType(univ.ObjectIdentifier):
  """ASN.1 Attribute type."""


class AttributeTypeAndValue(univ.Sequence):
  """ASN.1 Attribute type and value class."""
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('type', AttributeType()),
    namedtype.NamedType('value', AttributeValue()),
  )


class RelativeDistinguishedName(univ.SetOf):
  """ASN.1 Realtive distinguished name."""
  componentType = AttributeTypeAndValue()


class RDNSequence(univ.SequenceOf):
  """ASN.1 RDN sequence class."""
  componentType = RelativeDistinguishedName()


class Name(univ.Choice):
  """ASN.1 name class."""
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('', RDNSequence()),
  )


class Extension(univ.Sequence):
  """ASN.1 extension class."""
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('extnID', univ.ObjectIdentifier()),
    namedtype.DefaultedNamedType('critical', univ.Boolean('False')),
    namedtype.NamedType('extnValue', univ.OctetString()),
  )


class Extensions(univ.SequenceOf):
  """ASN.1 extensions class."""
  componentType = Extension()
  sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)


class AnotherName(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('type-id', univ.ObjectIdentifier()),
    namedtype.NamedType('value', univ.Any().subtype(
      explicitTag=tag.Tag(
        tag.tagClassContext,
        tag.tagFormatSimple, 0))))


class GeneralName(univ.Choice):
  """ASN.1 component type for a general name fields.

  A general name is one of:

    - otherName
    - rfc822Name
    - dNSName
    - directoryName
    - uniformResourceIdentifier
    - iPAddress
    - registeredID

  """
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('otherName', AnotherName().subtype(
      implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    namedtype.NamedType('rfc822Name', char.IA5String().subtype(
      implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.NamedType('dNSName', char.IA5String().subtype(
      implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    # namedtype.NamedType('x400Address', ORAddress().subtype(
    #  implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.NamedType('directoryName', Name().subtype(
      implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
    # namedtype.NamedType('ediPartyName', EDIPartyName().subtype(
    #   implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
    namedtype.NamedType('uniformResourceIdentifier', char.IA5String().subtype(
      implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
    namedtype.NamedType('iPAddress', univ.OctetString().subtype(
      implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
    namedtype.NamedType('registeredID', univ.ObjectIdentifier().subtype(
      implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8))),
  )


class GeneralNames(univ.SequenceOf):
  """Sequence of general names."""
  componentType = GeneralName()
  sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)
