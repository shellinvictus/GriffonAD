#!/usr/bin/env python3

import argparse
from ldap_auth import add_common_parameters
from attr import funcattr, attr_common_parameters

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    add_common_parameters(parser)
    attr_common_parameters(parser)
    args = parser.parse_args()
    funcattr(args, 'servicePrincipalName')
