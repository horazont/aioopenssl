OpenSSL Transport for asyncio
#############################

.. image:: https://github.com/horazont/aioopenssl/workflows/CI/badge.svg
  :target: https://github.com/horazont/aioopenssl/actions?query=workflow%3ACI+branch%3Adevel

.. image:: https://coveralls.io/repos/github/horazont/aioopenssl/badge.svg?branch=devel
  :target: https://coveralls.io/github/horazont/aioopenssl?branch=devel

``aioopenssl`` provides a `asyncio
<https://docs.python.org/3/library/asyncio.html>`_ Transport which uses
`PyOpenSSL <https://pyopenssl.readthedocs.org/>`_ instead of the built-in ssl
module.

The transport has two main advantages compared to the original:

* The TLS handshake can be deferred by passing ``use_starttls=True`` and later
  calling the ``starttls()`` coroutine method.

  This is useful for protocols with a `STARTTLS
  <https://en.wikipedia.org/wiki/STARTTLS>`_ feature.

* A coroutine can be called during the TLS handshake; this can be used to defer
  the certificate check to a later point, allowing e.g. to get user feedback
  before the ``starttls()`` method returns.

  This allows to ask users for certificate trust without the application layer
  protocol interfering or starting to communicate with the unverified peer.

.. note::

   Use this module at your own risk. It has lower test coverage than I’d like
   it to have; it has been exported from aioxmpp on request, where it undergoes
   implicit testing. If you find bugs, please report them. If possible, add
   regression tests while you’re at it.

   If you find security-critical bugs, please follow the procedure announced in
   the `aioxmpp readme <https://github.com/horazont/aioxmpp>`_.`

Documentation
-------------

Official documentation can be built with sphinx and is available online
`on our servers <https://docs.zombofant.net/aioopenssl/0.6/>`_.
