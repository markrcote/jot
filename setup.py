# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
from setuptools import setup, find_packages

version = '0.1'
PACKAGE_NAME = 'jot'

if sys.version < '2.6' or sys.version >= '3.0':
    print >>sys.stderr, '%s requires Python >= 2.6 and < 3.0' % PACKAGE_NAME
    sys.exit(1)

setup(name='jot',
      version=version,
      description="JSON Web Tokens",
      long_description="""
""",
      classifiers=[],
      keywords='',
      author='Mark Côté',
      author_email='mcote@mozilla.com',
      url='https://github.com/markrcote/jot',
      license='MPL 2.0',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[],
      test_suite='tests'
)
