#!/usr/bin/env python

from distutils.core import setup

setup(name='dnslib',
      version = '0.1',
      description = 'Encode/decode DNS packets',
      long_description = """
            Simple library to encode/decode DNS wire-format packets
      """,
      author = 'Paul Chakravarti',
      author_email = 'paul.chakravarti@gmail.com',
      url = 'http://bitbucket.org/paulc/dnslib/',
      packages = ['dnslib'],
      package_dir = {'dnslib':'src'},
      license = 'BSD'
     )
