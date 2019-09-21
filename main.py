#! /usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import hashlib
import base64
import hmac
import math
import json
import six
import pickle
import random
from Crypto.Cipher import AES

from fxa.core import Session as FxASession
from fxa.crypto import quick_stretch_password
from syncclient.client import (SyncClient, FxAClient,
                               TOKENSERVER_URL, hexlify, sha256)


class KeyBundle:

    def __init__(self, encryption_key, hmac_key):
        self.encryption_key = encryption_key
        self.hmac_key = hmac_key

    @classmethod
    def fromMasterKey(cls, master_key, info):
        key_material = HKDF(master_key, None, info, 2 * 32)
        return cls(key_material[:32], key_material[32:])


def HKDF_extract(salt, IKM, hashmod=hashlib.sha256):
    """HKDF-Extract; see RFC-5869 for the details."""
    if salt is None:
        salt = b"\x00" * hashmod().digest_size
    return hmac.new(salt, IKM, hashmod).digest()


def HKDF_expand(PRK, info, L, hashmod=hashlib.sha256):
    """HKDF-Expand; see RFC-5869 for the details."""
    digest_size = hashmod().digest_size
    N = int(math.ceil(L * 1.0 / digest_size))
    assert N <= 255
    T = b""
    output = []
    for i in range(1, N + 1):
        data = T + info + bytes(bytearray([i]))
        T = hmac.new(PRK, data, hashmod).digest()
        output.append(T)
    return b"".join(output)[:L]


def HKDF(secret, salt, info, size, hashmod=hashlib.sha256):
    """HKDF-extract-and-expand as a single function."""
    PRK = HKDF_extract(salt, secret, hashmod)
    return HKDF_expand(PRK, info, size, hashmod)


def decrypt_payload(payload, key_bundle):
    j = json.loads(payload)
    # Always check the hmac before decrypting anything.
    expected_hmac = hmac.new(key_bundle.hmac_key,
                             j['ciphertext'].encode(),
                             hashlib.sha256).hexdigest()
    if j['hmac'] != expected_hmac:
        raise ValueError("HMAC mismatch: %s != %s" %
                         (j['hmac'], expected_hmac))
    ciphertext = base64.b64decode(j['ciphertext'])
    iv = base64.b64decode(j['IV'])
    aes = AES.new(key_bundle.encryption_key, AES.MODE_CBC, iv)
    plaintext = aes.decrypt(ciphertext)
    plaintext = plaintext[:-plaintext[-1]]
    # Remove any CBC block padding, assuming it's a well-formed JSON payload.
    # plaintext = plaintext[:plaintext.rfind(b"}") + 1]
    return json.loads(plaintext)


def encrypt_payload(payload, key_bundle):
    payload = json.dumps(payload).encode()
    # pkcs#7 padding
    padding_size = (16 - (len(payload) % 16))
    payload += bytes(bytearray(padding_size for _ in range(padding_size)))

    iv = bytes(bytearray(random.randint(0, 255) for _ in range(16)))

    aes = AES.new(key_bundle.encryption_key, AES.MODE_CBC, iv)
    encrypted = aes.encrypt(payload)
    encrypted_b64 = base64.b64encode(encrypted)

    encrypted_hmac = hmac.new(
        key_bundle.hmac_key, encrypted_b64, hashlib.sha256).hexdigest()
    return {
        'hmac': encrypted_hmac,
        'IV': base64.b64encode(iv).decode(),
        'ciphertext': encrypted_b64.decode(),
    }


def get_browserid_assertion(fxaSession, tokenserver_url=TOKENSERVER_URL):
    bid_assertion = fxaSession.get_identity_assertion(tokenserver_url)
    _, keyB = fxaSession.keys
    if isinstance(keyB, six.text_type):  # pragma: no cover
        keyB = keyB.encode('utf-8')
    return bid_assertion, hexlify(sha256(keyB).digest()[0:16])


def random_id():
    ALPHABET = '0123456789'
    ALPHABET += 'abcdefghijklmnopqrstuvwxyz'
    ALPHABET += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.choice(ALPHABET) for _ in range(12))


def get_client_and_key(username, password):
    fxa_client = FxAClient()

    pickle_filename = username + '.pickle'
    prev_session = None
    try:
        prev_session = pickle.load(open(pickle_filename, 'rb'))
    except Exception:
        pass

    if prev_session:
        session = FxASession(fxa_client, username,
                             quick_stretch_password(username, password),
                             prev_session.uid,
                             prev_session.token)
        session.keys = prev_session.keys
        session.check_session_status()
    else:
        session = fxa_client.login(username, password, keys=True)
        session.fetch_keys()

    pickle.dump(session, open(pickle_filename, 'wb'))

    bid_assertion_args = get_browserid_assertion(session)
    client = SyncClient(*bid_assertion_args)

    sync_keys = KeyBundle.fromMasterKey(
        session.keys[1],
        b"identity.mozilla.com/picl/v1/oldsync")

    # Fetch the sync bundle keys out of storage.
    # They're encrypted with the account-level key.
    keys = decrypt_payload(client.get_record('crypto', 'keys')['payload'],
                           sync_keys)

    # There's some provision for using separate key bundles
    # for separate collections
    # but I haven't bothered digging through to see what that's about because
    # it doesn't seem to be in use, at least on my account.
    if keys["collections"]:
        raise RuntimeError("no support for per-collection key bundles")

    bulk_keys = KeyBundle(base64.b64decode(keys["default"][0]),
                          base64.b64decode(keys["default"][1]))
    return (client, bulk_keys)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(dest='userpass_src',
                        help='Source username:password')
    parser.add_argument(dest='userpass_dst',
                        help='Destination username:password')

    args = parser.parse_args()

    src_client, src_keys = get_client_and_key(*args.userpass_src.split(':', 1))
    dst_client, dst_keys = get_client_and_key(*args.userpass_dst.split(':', 1))

    for collection in ('history', 'tabs'):
        print('Processing', collection)
        last_timestamp_pickle_file = collection + '-last_timestamp.pickle'
        try:
            last_timestamp = pickle.load(
                open(last_timestamp_pickle_file, 'rb'))
            assert type(last_timestamp) is float
        except Exception:
            last_timestamp = None
        print('Last timestamp=', last_timestamp)

        content = src_client.get_records(collection, newer=last_timestamp)
        last_timestamp = float(
            src_client.raw_resp.headers['X-Weave-Timestamp'])
        print('Got', len(content), 'records')
        print('New last timestamp=', last_timestamp)
        for record in content:
            record['payload'] = json.dumps(
                encrypt_payload(
                    decrypt_payload(record['payload'], src_keys),
                    dst_keys
                )
            )
        print('Decryption/Encryption done')
        for i in range(0, len(content), 100):
            part = content[i:i+100]
            res = dst_client._request(
                'POST', '/storage/' + collection,
                data=json.dumps(part),
                headers={
                    'Content-Type': 'application/json',
                })
            print('Submitted', i, i+100,
                  'success:', len(res['success']),
                  'fail:', len(res['failed']))
        pickle.dump(last_timestamp, open(last_timestamp_pickle_file, 'wb'))
        print('Complete')


if __name__ == '__main__':
    main()
