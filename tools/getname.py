#!/usr/bin/env python3

import argparse
from ldap_auth import ldap_auth, add_common_parameters
from ldap3 import SUBTREE, MODIFY_REPLACE, MODIFY_DELETE


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    add_common_parameters(parser)
    parser.add_argument('-t', type=str, required=True, metavar='TARGET')
    args = parser.parse_args()

    args.t = args.t.replace('$', '')

    serv, conn = ldap_auth(args)

    conn.search(
        search_base=serv.info.other['defaultNamingContext'][0],
        search_filter=f'(&(name={args.t}))',
        search_scope=SUBTREE,
        attributes = ['*'])

    print(conn.response_to_json())
