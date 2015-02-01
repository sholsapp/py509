#!/usr/bin/env python

import os

from setuptools import setup, find_packages

setup(
  name='py509',
  version='0.0.3',
  description="Framework and utility code for running public key infrastructure.",
  author='Stephen Holsapple',
  author_email='sholsapp@gmail.com',
  url='https://github.com/sholsapp/py509',
  packages=find_packages(),
  install_requires=[
    'certifi',
    'cryptography',
    'pyOpenSSL',
    'pyasn1',
    'pytest',
    'python-dateutil',
    'tabulate',
  ],
  tests_require = [
    'pytest',
  ],
  entry_points = {
    'console_scripts': [
      'pyssl-diff = py509.bin.diff:main',
      'pyssl-get = py509.bin.get:main',
      'pyssl-ls = py509.bin.ls:main',
      'pyssl-verify = py509.bin.verify:main',
    ],
  },
)
