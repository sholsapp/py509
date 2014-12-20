#!/usr/bin/env python

import os

from setuptools import setup

setup(
  name='py509',
  version='0.0.3',
  description="Framework and utility code for running public key infrastructure.",
  author='Stephen Holsapple',
  author_email='sholsapp@gmail.com',
  url='https://github.com/sholsapp/py509',
  packages=['py509', 'py509.asn1'],
  install_requires=[
    'certifi',
    'cryptography',
    'pyOpenSSL',
    'pyasn1',
    'pytest',
    'python-dateutil',
    'tabulate',
  ],
)
