#!/usr/bin/env python3
# Used to modify values of gPCMachineExtensionNames and gPCUserExtensionNames

import sys

# string = "[{a}{b}{c}][[{d}{e}][{f}{g}]"
# result is -> [a: {b, c}, d: {e}, f: {g}]
def convert_to_dict(string):
    res = {}
    for sub in string[1:-1].split(']['):
        if not (sub[0] == '{' and sub[-1] == '}'):
            print(f'error: {{ or }} is missing for {sub}')
            exit(0)
        lst = sub[1:-1].split('}{')
        k = '{' + lst[0] + '}'
        res[k] = set()
        for x in lst[1:]:
            res[k].add('{' + x + '}')
    return res

if __name__ == '__main__':
    s1 = sys.argv[1]
    s2 = sys.argv[2]

    if not s1:
        print(s2)
        exit(0)
    if not s2:
        print(s1)
        exit(0)

    dict1 = convert_to_dict(s1)
    dict2 = convert_to_dict(s2)

    for k, subset in dict2.items():
        if k not in dict1:
            dict1[k] = subset
        else:
            dict1[k].update(subset)

    s = ''
    for k in sorted(list(dict1.keys())):
        subset = dict1[k]
        s += '[' + k + ''.join(sorted(list(subset))) + ']'

    print(s, end='')
