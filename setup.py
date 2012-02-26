#!/usr/bin/env python

try:
    from setuptools import setup, Command
except ImportError:
    from distutils.core import Command,setup

import dnslib.dns
long_description = dnslib.dns.DNSRecord.__doc__.rstrip() + "\n"
version = dnslib.dns.DNSRecord.version

class GenerateReadme(Command):
    description = "Generates README file from long_description"
    user_options = []
    def initialize_options(self): pass
    def finalize_options(self): pass
    def run(self):
        open("README","w").write(long_description)

setup(name='dnslib',
      version = version,
      description = 'Simple library to encode/decode DNS wire-format packets',
      long_description = long_description,
      author = 'Paul Chakravarti',
      author_email = 'paul.chakravarti@gmail.com',
      url = 'http://bitbucket.org/paulc/dnslib/',
      cmdclass = { 'readme' : GenerateReadme },
      packages = ['dnslib'],
      license = 'BSD',
      classifiers = [ "Topic :: Internet :: Name Service (DNS)" ],
     )
