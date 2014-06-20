#!/usr/bin/env python

import os

from setuptools import setup

README = None
with open(os.path.abspath('README.md')) as fh:
  README = fh.read()

setup(
  name='bishop',
  version='1.0',
  description=README,
  author='Stephen Holsapple',
  author_email='sholsapp@gmail.com',
  url='http://www.google.com',
  packages=['bishop'],
  install_requires=[
    'pyOpenSSL',
    'cryptography',
    'pytest',
  ],
)
