#!/usr/bin/env python3
# From: https://github.com/Tw1sm/aesKrbKeyGen/blob/master/aesKrbKeyGen.py
# Parameters modified

from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from binascii import unhexlify
import argparse


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
    return aes_256_raw.hex().upper()


def do_aes_128(aes_128_pbkdf2):
    cipher = AES.new(aes_128_pbkdf2, AES.MODE_CBC, bytes(IV))
    aes_128_raw = cipher.encrypt(bytes(AES128_CONSTANT))
    return aes_128_raw.hex().upper()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate AES128/256 Kerberos keys for an AD account using a plaintext password', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('identity', metavar='FQDN/USER:PASSWORD', help='USER==sAMAccountName - this is case sensitive for AD user accounts (add the $ at the end for hosts). If user is a host, the password must be in hex format')
    args = parser.parse_args()

    identity = args.identity.split(':')
    tmp = identity[0].split('/')
    fqdn = tmp[0].upper()
    user = tmp[1]
    password = identity[1]

    if '$' in user:
        host = user.replace('$', '')
        salt = f'{fqdn}host{host.lower()}.{fqdn.lower()}'
        password_bytes = unhexlify(password).decode('utf-16-le', 'replace').encode('utf-8', 'replace')
    else:
        salt = f'{fqdn}{user}'
        password_bytes = password.encode('utf-8')

    salt_bytes = salt.encode('utf-8')

    aes_256_pbkdf2 = KDF.PBKDF2(password_bytes, salt_bytes, 32, ITERATION)
    aes_128_pbkdf2 = aes_256_pbkdf2[:16]
    
    aes_256_key = do_aes_256(aes_256_pbkdf2)
    aes_128_key = do_aes_128(aes_128_pbkdf2)
    
    print(f'aes-256:{aes_256_key}')
    print(f'aes-128:{aes_128_key}')
