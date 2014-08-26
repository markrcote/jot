# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

__all__ = ['SignAndEncryptError', 'encode', 'decode']

import base64
import json


class SignAndEncryptError(Exception):

    def __init__(self):
        self.message = 'can\'t both sign and encrypt a token'


def encode(payload, signer=None, encrypter=None):
    if signer and encrypter:
        raise SignAndEncryptError()

    headers = {'typ': 'JWT', 'alg': 'none'}
    if signer:
        headers.update(signer.headers)
    if encrypter:
        headers.update(encrypter.headers)

    headers_json = json.dumps(headers, separators=(',', ':'))
    payload_json = json.dumps(payload, separators=(',', ':'))
    header_b64 = b64encode(headers_json)
    payload_b64 = b64encode(payload_json)

    first_part = header_b64
    second_part = payload_b64
    third_part = ''

    if signer:
        third_part = b64encode(signer.sign(first_part + '.' +
                                                second_part))
    if encrypter:
        pass  # TODO

    return first_part + '.' + second_part + '.' + third_part


def decode(jws_repr, signers=[], encrypters=[]):
    first_part_b64, dot, rest = jws_repr.partition('.')
    second_part_b64, dot, third_part_b64 = rest.partition('.')

    headers = json.loads(b64decode(first_part_b64))
    second_part = b64decode(second_part_b64)
    third_part = b64decode(third_part_b64)

    valid = False
    payload = None

    if headers['alg'] == 'none':
        payload = json.loads(second_part)
        valid = True
    elif 'enc' in headers:
        for encrypter in encrypters:
            if headers['alg'] == encrypter.algid:
                payload, valid = encrypter.decrypt(headers, second_part,
                                                   third_part)
                break
    else:
        for signer in signers:
            if headers['alg'] == signer.algid:
                payload = json.loads(second_part)
                valid = signer.validate(headers,
                                        first_part_b64 + '.' + second_part_b64,
                                        third_part)
                break

    return {'headers': headers, 'payload': payload, 'valid': valid}


def b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip('=')


def b64decode(data):
    quads = len(data) % 4
    if quads == 2:
        data += '=='
    elif quads == 3:
        data += '='
    return base64.urlsafe_b64decode(data)
