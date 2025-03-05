#!/usr/bin/env python3

import os
import argparse

gpt = """[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Group Membership]
{sid_group}__Memberof =
{sid_group}__Members = {sid_members}
""".replace('\n', '\r\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('group', type=str, metavar='GROUPSID')
    parser.add_argument('-m', '--members', type=str, metavar='SID1,SID2,...')
    args = parser.parse_args()
    sid_group = f'*{args.group}'
    sid_members = ','.join([f'*{s}' for s in args.members.split(',')])
    os.write(1, b'\xff\xfe' + gpt.format(sid_group=sid_group, sid_members=sid_members).encode('utf-16le'))
