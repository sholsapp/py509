"""Utilties and helpers that don't have a home."""

from OpenSSL import crypto

from py509.x509 import patch_certificate


def transmogrify(l):
  """Fit a flat list into a treeable object."""
  d = {l[0]: {}}
  tmp = d
  for c in l:
    tmp[c] = {}
    tmp = tmp[c]
  return d


def tree(node, formatter=None, prefix=None, postfix=None, _depth=1):
  """Print a tree.

  Sometimes it's useful to print datastructures as a tree. This function prints
  out a pretty tree with root `node`. A tree is represented as a :class:`dict`,
  whose keys are node names and values are :class:`dict` objects for sub-trees
  and :class:`None` for terminals.

  :param dict node: The root of the tree to print.
  :param callable formatter: A callable that takes a single argument, the key,
    that formats the key in the tree.
  :param callable prefix: A callable that takes a single argument, the key,
    that adds any additional text before the formatted key.
  :param callable postfix: A callable that takes a single argument, the key,
    that adds any additional text after the formatted key.

  """
  current = 0
  length = len(node.keys())
  tee_joint = '\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80'
  elbow_joint = '\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80'
  for key, value in node.iteritems():
    current += 1
    k = formatter(key) if formatter else key
    pre = prefix(key) if prefix else ''
    post = postfix(key) if postfix else ''
    space = elbow_joint if current == length else tee_joint
    yield ' {space} {prefix}{key}{postfix}'.format(space=elbow_joint, key=k, prefix=pre, postfix=post)
    if value:
      for e in tree(value, formatter=formatter, prefix=prefix, postfix=postfix, _depth=_depth + 1):
        yield (' |  ' if current != length else '    ') + e


# XXX: Currently, pyOpenSSL doesn't expose any nice OpenSSL.crypto.X509Store
# functions for us to use to take a *real* store as an input.
def assemble_chain(leaf, store):
  """Assemble the trust chain.

  This assembly method uses the certificates subject and issuer common name and
  should be used for informational purposes only. It does *not*
  cryptographically verify the chain!

  :param OpenSSL.crypto.X509 leaf: The leaf certificate from which to build the
    chain.
  :param list[OpenSSL.crypto.X509] store: A list of certificates to use to
    resolve the chain.
  :return: The trust chain.
  :rtype: list[OpenSSL.crypto.X509]

  """
  store_dict = {}
  for cert in store:
    store_dict[cert.get_subject().CN] = cert

  chain = [leaf]

  current = leaf
  try:
    while current.get_issuer().CN != current.get_subject().CN:
      chain.append(store_dict[current.get_issuer().CN])
      current = store_dict[current.get_issuer().CN]
  except KeyError:
    invalid = crypto.X509()
    patch_certificate(invalid)
    invalid.set_subject(current.get_issuer())
    chain.append(invalid)

  chain.reverse()
  return chain
