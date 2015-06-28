#!/usr/bin/env python

import os
import subprocess

from setuptools import setup, find_packages, Command


entry_points = {
  'console_scripts': [
    'ssl-diff = py509.bin.diff:main',
    'ssl-get = py509.bin.get:main',
    'ssl-ls = py509.bin.ls:main',
    'ssl-verify = py509.bin.verify:main',
  ],
}


class Pex(Command):

  user_options = []

  def initialize_options(self):
    """Abstract method that is required to be overwritten"""

  def finalize_options(self):
    """Abstract method that is required to be overwritten"""

  def run(self):
    if not os.path.exists('dist/wheel-cache'):
      print('You need to create dist/wheel-cache first! You\'ll need to run the following.')
      print('  mkdir dist/wheel-cache')
      print('  pip wheel -w dist/wheel-cache')
      return
    for entry in entry_points['console_scripts']:
      name, call = tuple([_.strip() for _ in entry.split('=')])
      print('Creating {0} as {1}'.format(name, call))
      subprocess.check_call([
        'pex',
        '-r', 'py509',
        '--no-pypi',
        '--repo=dist/wheel-cache',
        '-o', name,
        '-e', call])


setup(
  name='py509',
  version='0.0.6',
  description="Framework and utility code for running public key infrastructure.",
  author='Stephen Holsapple',
  author_email='sholsapp@gmail.com',
  url='https://github.com/sholsapp/py509',
  packages=find_packages(),
  install_requires=[
    # For compatibility with py2.6
    'argparse',
    'certifi>=2015.4.28',
    'cryptography>=0.9.1',
    'pyOpenSSL>=0.15.1',
    'pyasn1>=0.1.8',
    'pyasn1_modules>=0.0.6',
    'python-dateutil>=2.4.2',
    'tabulate>=0.7.5',
    'urllib3>=1.10.4',
  ],
  tests_require=[
    'pytest',
    'flake8',
  ],
  entry_points=entry_points,
  cmdclass={'pexify': Pex},
)
