# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
from setuptools import setup, find_packages

version = '0.1'
PACKAGE_NAME = 'jwt'

if sys.version < '2.5' or sys.version >= '3.0':
    print >>sys.stderr, '%s requires Python >= 2.5 and < 3.0' % PACKAGE_NAME
    sys.exit(1)

deps = []

try:
    import json
except ImportError:
    deps.append('simplejson')

setup(name='jwt',
      version=version,
      description="JSON Web Tokens",
      long_description="""\
""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='Mark Cote',
      author_email='mcote@mozilla.com',
      url='http://',
      license='MPL 2.0',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=deps,
      test_suite='tests' 
      )
