#!/usr/bin/env python3

import base64
import argparse
import json
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import preg

TYPE_TO_INT = {
    'REG_NONE': 0,
    'REG_SZ': 1,
    'REG_EXPAND_SZ': 2,
    'REG_BINARY': 3,
    'REG_DWORD': 4,
    'REG_DWORD_BIG_ENDIAN': 5,
    'REG_LINK': 6,
    'REG_MULTI_SZ': 7,
    'REG_RESOURCE_LIST': 8,
    'REG_QWORD': 11,
}

TYPE_TO_STR = {v: k for k, v in TYPE_TO_INT.items()}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('filename', help='read as registry file if the extension is .pol, else as json')
    parser.add_argument('--save', type=str, help='save to json or pol')
    args = parser.parse_args()

    if args.filename.endswith('.pol'):
        try:
            raw = open(args.filename, 'rb').read()
        except:
            print(f'error: can\'t open {args.filename}')
            exit(0)

        pol = []
        for e in ndr_unpack(preg.file, raw).entries:
            if e.type in [3, 7]:
                data = base64.b64encode(e.data).decode()
            else:
                data = e.data
            pol.append({
                'keyname': e.keyname,
                'valuename': e.valuename,
                'data': data,
                'type': TYPE_TO_STR[e.type],
            })

        if args.save:
            open(args.save, 'w+').write(json.dumps(pol, indent=4))
        else:
            print(json.dumps(pol, indent=4))

    else:
        try:
            pol = json.loads(open(args.filename, 'r').read())
        except:
            print(f'error: can\'t open {args.filename}')
            exit(0)

        entries = []
        for jsonentry in pol:
            e = preg.entry()
            e.keyname = jsonentry['keyname'].encode()
            e.valuename = jsonentry['valuename'].encode()
            e.type = TYPE_TO_INT[jsonentry['type']]
            if jsonentry['type'] in ['REG_BINARY', 'REG_MULTI_SZ']:
                e.data = base64.b64decode(jsonentry['data'])
            elif isinstance(jsonentry['data'], int):
                e.data = jsonentry['data']
            elif jsonentry['type'] != 'REG_NONE':
                e.data = jsonentry['data'].encode()
            entries.append(e)

        out = preg.file()
        out.entries = entries
        out.num_entries = len(entries)

        if args.save:
            open(args.save, 'wb+').write(ndr_pack(out))
        else:
            print('--save is missing')
