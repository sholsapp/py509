#!/usr/bin/env python

import os

from setuptools import setup

setup(
  name='py509',
  version='0.0.2',
  description="Framework and utility code for running public key infrastructure at home.",
  author='Stephen Holsapple',
  author_email='sholsapp@gmail.com',
  url='http://www.google.com',
  package_dir={'py509': ''},
  packages=['py509'],
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
