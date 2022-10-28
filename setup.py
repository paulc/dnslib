#!/usr/bin/env python

# To update PyPi version:
#
# (Make sure you have updated version and changelog in __init__.py)
#
# ./run_tests.sh
# python3 setup.py readme
# git commit -am ...
# git push 
# git tag -a <version> -m <message>
# git push --tags
# (Create release from tag on Github)
#
# rm -rf dist
# python3 setup.py sdist
# python3 setup.py bdist_wheel 
# python2 setup.py bdist_wheel 
# twine upload

try:
    from setuptools import Command, setup
except ImportError:
    from distutils.core import Command, setup

import dnslib
long_description = dnslib.__doc__.rstrip() + "\n"
version = dnslib.version

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
      long_description_content_type="text/markdown",
      author = 'PaulC',
      url = 'https://github.com/paulc/dnslib',
      cmdclass = {'readme' : GenerateReadme},
      packages = ['dnslib'],
      package_dir = {'dnslib' : 'dnslib'},
      license = 'BSD',
      classifiers = [ "Topic :: Internet :: Name Service (DNS)",
                      "Programming Language :: Python :: 2",
                      "Programming Language :: Python :: 3",
                      ],
     )
