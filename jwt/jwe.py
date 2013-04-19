# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import rsa

try:
    import json
except ImportError:
    import simplejson as json


class JweBase(object):

    def __init__(self, algid, key=None):
        self.algid = algid
        self._key = key

    @property
    def headers(self):
        h = {'alg': self.algid}
        h.update(self.get_headers())
        return h

    @property
    def key(self):
        if self._key is None:
            return self.get_key()
        return self._key

    def get_headers(self):
        return {}

    def get_key(self):
        return None

    def validate(self, headers, signing_input, signature):
        return signature == self.sign(signing_input)
 
    def sign(self, signing_input):
        raise NotImplementedError


class Rsa15(JweBase):

    def __init__(self, private_key=None, public_key=None):
        self.private_key = private_key
        self.public_key = public_key

    
