# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

__all__ = ['JwsBase', 'HmacSha', 'KeyRequiredException']

import hashlib
import hmac


class KeyRequiredException(Exception):

    def __init__(self):
        Exception.__init__(self, 'a key is required but was not provided')


class JwsBase(object):

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
        """If self.key is present and verifies the signature, return True.
        If a 'kid' header is given, has an associated key in self.keydict,
            and that key verifies the signature, return True.
        If a 'kid' header is not given and self.keydict[self.key_id] exists
            and verifies the signature, return True.
        Otherwise, return False.
        """
        def check(key):
            return signature == self.sign(signing_input, key)

        if self.key and check(self.key):
            return True

        if 'kid' in headers:
            try:
                return check(self.keydict[headers['kid']])
            except KeyError:
                return False

        if self.key and self.key_id and check(self.keydict[self.key_id]):
            return True

        return False
