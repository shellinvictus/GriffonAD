#!/usr/bin/env python3

import argparse
from ldap_auth import ldap_auth, add_common_parameters
from ldap3 import SUBTREE, MODIFY_REPLACE, MODIFY_DELETE, MODIFY_ADD


def funcattr(args, key):
    args.t = args.t.replace('$', '')

    serv, conn = ldap_auth(args)
    conn.search(
        search_base=serv.info.other['defaultNamingContext'][0],
        search_filter=f'(&(name={args.t}))',
        search_scope=SUBTREE,
        attributes = [key])

    if 'raw_dn' not in conn.response[0]:
        print(f'[-] error: can\'t find the target {args.t}')
        return

    dn = conn.response[0]['raw_dn'].decode()
    print(dn)

    attr = conn.response[0]['raw_attributes']
    if key in attr and attr[key]:
        try:
            val = [s.decode() for s in attr[key]]
            print(f'[+] current value is:')
            for v in val:
                print(v)
        except:
            for v in attr[key]:
                print(v)
            if args.add or args.rm:
                print('[-] error: unsupported binary values')
                return
    else:
        print('[+] current value is null')
        print()
        val = []


    if args.w:
        if args.w in val:
            print(f'[-] the entry already exists')
        elif conn.modify(dn, {key: [(MODIFY_REPLACE, [args.w])]}):
            print(f'[+] the entry was written')
            print(f'[+] current value is:')
            print(args.w)
        else:
            print(f'[-] error: the entry wasn\'t written')
    elif args.add:
        if args.add in val:
            print(f'[-] the entry already exists')
        elif conn.modify(dn, {key: [(MODIFY_ADD, [args.add])]}):
            print(f'[+] the entry was added')
            print(f'[+] current value is:')
            val.append(args.add)
            for v in val:
                print(v)
        else:
            print(f'[-] error: the entry wasn\'t added, you may try to remove the old value or the format is not correct')
    elif args.flush:
        if conn.modify(dn, {key: [(MODIFY_REPLACE, [])]}):
            print(f'[+] the key {key} was flushed')
        else:
            print(f'[-] error: the key {key} wasn\'t flushed')
    elif args.rm:
        if conn.modify(dn, {key: [(MODIFY_DELETE, [args.rm])]}):
            print(f'[+] the entry was deleted')
            print(f'[+] current value is:')
            val.remove(args.rm)
            for v in val:
                print(v)
        else:
            print(f'[-] error: the entry wasn\'t deleted')


def attr_common_parameters(parser):
    parser.add_argument('-t', type=str, default=None, metavar='TARGET')
    parser.add_argument('-add', type=str, default=None, metavar='STRING', help='Append an entry (not supported on all attributes)')
    parser.add_argument('-rm', type=str, default=None, metavar='STRING', help='Remove an entry')
    parser.add_argument('-w', type=str, default=None, metavar='STRING', help='Write, replace the content')
    parser.add_argument('-flush', action='store_true', default=False, help='Remove all')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    add_common_parameters(parser)
    parser.add_argument('-key', type=str, default=None, metavar='STRING', required=True)
    attr_common_parameters(parser)
    args = parser.parse_args()
    funcattr(args, args.key)
