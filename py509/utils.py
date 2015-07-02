def tree(node, _depth=1):
  """Print a tree.

  Sometimes it's useful to print datastructures as a tree. This function prints
  out a pretty tree with root `node`. A tree is represented as a :class:`dict`,
  whose keys are node names and values are :class:`dict` objects for sub-trees
  and :class:`None` for terminals.

  :param dict node: The root of the tree to print.

  """
  current = 0
  length = len(node.keys())
  tee_joint = '\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80'
  elbow_joint = '\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80'
  for key, value in node.iteritems():
    current += 1
    if current == length:
       yield ' {space} {key}'.format(space=elbow_joint, key=key)
    else:
       yield ' {space} {key}'.format(space=tee_joint, key=key)
    if value:
      for e in tree(value, _depth=_depth + 1):
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
  chain = [leaf]
  current = leaf
  while current.get_issuer().CN != current.get_subject().CN:
    for cert in store:
      if cert.get_subject().CN == current.get_issuer().CN:
        chain.append(cert)
        current = cert
  chain.reverse()
  return chain
