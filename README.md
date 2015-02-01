# py509

[![Latest Version](https://pypip.in/version/py509/badge.svg?style=flat)](https://pypi.python.org/pypi/py509/)
[![Travis](https://secure.travis-ci.org/sholsapp/py509.png?branch=master)](https://travis-ci.org/sholsapp/py509)

Framework and scripts written with pyOpenSSL and cryptography for running
public key infrastructure.

## packaging

Consider using [pex](https://pex.readthedocs.org/en/latest/index.html) to
package the scripts provided by this library to make them relocatable and
installable on machines.

```bash
mkdir ~/wheel-cache
pip wheel -w ~/wheel-cache .
pex -r py509 --no-pypi --repo=~/wheel-cache -o pyssl-get -e py509.bin.get:main
```
