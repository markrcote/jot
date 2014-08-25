# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import jwt
import unittest

class TestJwt(unittest.TestCase):

    payload = { 'iss': 'joe', 'exp': 1300819380,
                'http://example.com/is_root': True }
    jws_repr = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

    key = ''.join([chr(i) for i in
                   [3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119,
                    123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169,
                    15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210,
                    6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46,
                    33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128,
                    163]])
    key_id = u'secret'

    def test_hmac_sha256(self):
        self.assertEqual(jwt.decode(self.jws_repr,
                                    signers=[jwt.jws.HmacSha(key=self.key)]),
                         { 'headers': {u'alg': u'HS256', u'typ': u'JWT'},
                           'payload': self.payload,
                           'valid': True })

        # test encoding and decoding using key id
        keydict = {'secret': self.key, 'secret2': 'abcd'}
        self.assertEqual(jwt.decode(
                jwt.encode(self.payload,
                           signer=jwt.jws.HmacSha(keydict=keydict,
                                                  key_id='secret')),
                signers=[jwt.jws.HmacSha(keydict=keydict)]),
                         { 'headers': {u'alg': u'HS256', u'typ': u'JWT',
                                       u'kid': u'secret'},
                           'payload': self.payload,
                           'valid': True })

        # Test some errors in encoding.
        self.assertRaises(jwt.jws.KeyRequiredException, jwt.encode,
                          self.payload, signer=jwt.jws.HmacSha())

        self.assertRaises(jwt.jws.KeyRequiredException, jwt.encode,
                          self.payload,
                          signer=jwt.jws.HmacSha(keydict=keydict,
                                                 key_id='notfound'))

        # Test encoding with no kid.

        msg = jwt.encode(self.payload, jwt.jws.HmacSha(key=self.key))
        # Just default key given to decoder.
        self.assertTrue(jwt.decode(msg, signers=[jwt.jws.HmacSha(key=self.key)])['valid'])
        # Default key and random entry in keydict.
        self.assertTrue(jwt.decode(msg, signers=[jwt.jws.HmacSha(key=self.key, keydict={'foo': 'bar'})])['valid'])
        # Default key, nonmatching default key id, random entry in keydict.
        self.assertTrue(jwt.decode(msg, signers=[jwt.jws.HmacSha(key=self.key, key_id='foo', keydict={'foo': 'bar'})])['valid'])
        # No default key, nonmatching default key id, random entry in keydict.
        self.assertFalse(jwt.decode(msg, signers=[jwt.jws.HmacSha(key_id='foo', keydict={'foo': 'bar'})])['valid'])
        # No default key, matching default key id, random entry in keydict.
        self.assertTrue(jwt.decode(msg, signers=[jwt.jws.HmacSha(key_id='foo', keydict={'foo': self.key})])['valid'])
        # No key given to decoder.
        self.assertFalse(jwt.decode(msg, signers=[jwt.jws.HmacSha()])['valid'])
        self.assertFalse(jwt.decode(msg, signers=[jwt.jws.HmacSha(keydict={'foo': 'bar'})])['valid'])

        # With kid.
        msg = jwt.encode(self.payload, jwt.jws.HmacSha(key=self.key, key_id=self.key_id))
        # Default matching key.
        self.assertTrue(jwt.decode(msg, signers=[jwt.jws.HmacSha(key=self.key)])['valid'])
        # Nonmatching default key, matching entry in keydict.
        self.assertTrue(jwt.decode(msg, signers=[jwt.jws.HmacSha(key='nope', keydict={self.key_id: self.key})])['valid'])
        # Default key and random entry in keydict.
        self.assertTrue(jwt.decode(msg, signers=[jwt.jws.HmacSha(key=self.key, keydict={'foo': 'bar'})])['valid'])
        # No default key, nonmatching default key id, random entry in keydict.
        self.assertFalse(jwt.decode(msg, signers=[jwt.jws.HmacSha(key_id='foo', keydict={'foo': 'bar'})])['valid'])
        # No default key, matching default key id, random entry in keydict.
        self.assertTrue(jwt.decode(msg, signers=[jwt.jws.HmacSha(key_id='foo', keydict={'foo': self.key})])['valid'])

        msg = jwt.encode(self.payload, signer=jwt.jws.HmacSha(
                key=self.key, key_id='secret'))
        self.assertFalse(jwt.decode(msg, signers=[jwt.jws.HmacSha(
                    keydict={'wrongkid': self.key})])['valid'])


if __name__ == '__main__':
    unittest.main()
