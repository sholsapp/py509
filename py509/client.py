import socket
import logging

from OpenSSL import SSL
import certifi


log = logging.getLogger(__name__)


def get_host_certificate(host, port=443):
  """Get a host's certificate.

  :param str host: The hostname from which to fetch the certificate.
  :param int port: The port from which to fetch the certificate, if different
    than ``443``.
  :return: The host's X.509 certificate.
  :rtype: :class:`OpenSSL.crypto.X509`

  """
  ip_addr = socket.gethostbyname(host)
  sock = socket.socket()
  context = SSL.Context(SSL.TLSv1_METHOD)
  context.set_options(SSL.OP_NO_SSLv2)
  context.load_verify_locations(certifi.where(), None)
  ssl_sock = SSL.Connection(context, sock)
  ssl_sock.connect((ip_addr, port))
  ssl_sock.do_handshake()
  return ssl_sock.get_peer_certificate()
