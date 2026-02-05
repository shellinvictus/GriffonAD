import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from binascii import unhexlify, hexlify

def password_to_nthash(password:str) -> str:
    return hexlify(hashlib.new("md4", password.encode("utf-16le")).digest()).decode()

# Prevent class name injection
def sanityze_symbol(sym:str) -> str:
    return 'x_' + sym.replace('(', '').\
        replace(')', '').\
        replace('.', '').\
        replace('::', '').\
        replace('+', '_plus_')

# Constants
AES256_CONSTANT = [0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4]
AES128_CONSTANT = AES256_CONSTANT[:16]
IV = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
ITERATION = 4096 # Active Directory default

# salt for computers ONLY
def get_aes_256_from_hex(fqdn:str, user:str, hexpassword:str) -> str:
    password_bytes = unhexlify(hexpassword).decode('utf-16-le', 'replace').encode('utf-8', 'replace')
    host = user.replace('$', '')
    salt = f'{fqdn}host{host.lower()}.{fqdn.lower()}'

    salt_bytes = salt.encode('utf-8')

    aes_256_pbkdf2 = KDF.PBKDF2(password_bytes, salt_bytes, 32, ITERATION)

    cipher = AES.new(aes_256_pbkdf2, AES.MODE_CBC, bytes(IV))
    key_1 = cipher.encrypt(bytes(AES256_CONSTANT))
    
    cipher = AES.new(aes_256_pbkdf2, AES.MODE_CBC, bytes(IV))
    key_2 = cipher.encrypt(bytearray(key_1))
    
    aes_256_raw = key_1[:16] + key_2[:16]
    return aes_256_raw.hex().upper()
