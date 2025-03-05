#!/usr/bin/env python3

import os
import argparse

ini = """
[{tag}]
0CmdLine={cmd}
0Parameters=
""".replace('\n', '\r\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('cmd')
    parser.add_argument('--tag', type=str, help='Examples: Startup, Logon')
    args = parser.parse_args()
    os.write(1, b'\xff\xfe' + ini.format(cmd=args.cmd, tag=args.tag).encode('utf-16le'))
