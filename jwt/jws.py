# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

__all__ = ['JwsBase', 'HmacSha', 'KeyRequiredException',
           'KeyNotFoundException']

import base64
import hashlib
import hmac

try:
    import json
except ImportError:
    import simplejson as json


class KeyRequiredException(Exception):
    def __init__(self):
        Exception.__init__(self, 'a key is required but was not provided')


class InvalidAlgorithmException(Exception):
    def __init__(self, algid):
        Exception.__init__(self, 'invalid algorithm %s' % algid)


ALGS = { 'HS': 'HmacSha' }

class JwsAlgorithm(object):
    pass


class Jws(object):

    def __init__(self, alg, key=None):
        if isinstance(alg, basestring):
            m = re.match('(\D+)(\d*)', alg)
            if not m:
                raise InvalidAlgorithmException(alg)
            cls = ALGS.get(m.group(1))
            if isinstance(cls, JwsAlgorithm):
                bits = None
                if m.group(2):
                    try:
                        bits = int(m.group(2))
                    except ValueError:
                        raise InvalidAlgorithmException(alg)
                self.alg = cls(bits=bits)
        else:
            self.alg = alg
        self._key = key

    @property
    def headers(self):
        h = {'alg': self.alg.id}
        h.update(self.alg.headers())
        return h

    @property
    def key(self):
        if self._key is None:
            return self.get_key()
        return self._key

    def get_key(self):
        return None

    def validate(self, headers, signing_input, signature):
        return signature == self.sign(signing_input)
 
    def sign(self, signing_input):
        return self.alg.sign(signing_input)


class HmacSha(JwsBase):

    """Jws with HMAC SHA authentication.
    You can include a dict (or dict-like object supporting get()) of keys.
    In this case, you can provide a key id to encode(), mapping to a key in
    keydict, instead of directly passing the key.
    Similarly, if no key is passed to decode(), the function will check for
    a 'kid' header and use that to fetch the appropriate key from keydict.
    Exceptions are raised if no key is found.
    """

    def __init__(self, bits=256, key=None, keydict={}, key_id=''):
        JwsBase.__init__(self, 'HS%d' % bits, key)
        self.keydict = keydict
        self.key_id = key_id
        self.digestmod = getattr(hashlib, 'sha%d' % bits)

    def get_headers(self):
        headers = {}
        if self.key_id:
            headers['kid'] = self.key_id
        return headers

    def get_key(self):
        if not self.key_id or not self.keydict:
            return None
        return self.keydict.get(self.key_id, None)

    def sign(self, signing_input, key=None):
        if not key:
            key = self.key
        if not key:
            raise KeyRequiredException()
        return hmac.new(key, signing_input, self.digestmod).digest()

    def validate(self, headers, signing_input, signature):
        """Order for determining which key to use:
        - self.key
        - self.keydict[self.key_id]
        - self.keydict[headers['kid']]
        """
        key = None
        if self.key:
            key = self.key
        elif 'kid' in headers and self.keydict:
            try:
                key = self.keydict[headers['kid']]
            except KeyError:
                return False
        try:
            return signature == self.sign(signing_input, key)
        except KeyRequiredException:
            return False
