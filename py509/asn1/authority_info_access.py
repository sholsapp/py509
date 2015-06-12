from pyasn1.type import univ, constraint, namedtype

from py509.asn1.base import GeneralName, MAX


class AccessDescription(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
    namedtype.NamedType('accessLocation', GeneralName()),
  )


class AuthorityInfoAccess(univ.SequenceOf):
  """ASN.1 implementation for subjectAltNames support."""
  componentType = AccessDescription()
  sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)
