#!/usr/bin/env python3

import argparse
from ldap_auth import ldap_auth, add_common_parameters
from ldap3 import SUBTREE, MODIFY_REPLACE


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    add_common_parameters(parser)
    parser.add_argument('-t', type=str, required=True, metavar='TARGET')
    parser.add_argument('-w', action='store_true', help='Write - toggle the flag')
    args = parser.parse_args()

    args.t = args.t.replace('$', '')

    serv, conn = ldap_auth(args)

    conn.search(
        search_base=serv.info.other['defaultNamingContext'][0],
        search_filter=f'(&(objectClass=user)(name={args.t}))',
        search_scope=SUBTREE,
        attributes = ['userAccountControl'])

    uac = int(conn.response[0]['raw_attributes']['userAccountControl'][0].decode())
    dn = conn.response[0]['raw_dn'].decode()
    print('[+] Target:', dn)
    if uac & 0b10 == 0b10:
        print('[+] uac is', hex(uac), '(account disabled)')
    else:
        print('[+] uac is', hex(uac), '(account enabled)')

    if args.w:
        uac ^= 0b10
        if conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, uac)]}):
            if uac & 0b10 == 0b10:
                print('[+] modified to', hex(uac), '(account disabled)')
            else:
                print('[+] modified to', hex(uac), '(account enabled)')
        else:
            print('[-] error: the flag was not modified')

