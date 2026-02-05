#!/usr/bin/env python3

import time
import re
import tracemalloc
import linecache
import json
from colorama import init as colorama_init
from colorama import Style
Style.UNDERLINE = '\033[4m'

import os
import argparse

import griffonad
import griffonad as lib
import griffonad.lib.consts as c
import griffonad.lib.ml
import griffonad.config
from griffonad.lib.print import (print_path, print_paths, print_script, print_groups, print_hvt,
        print_ous, print_desc, print_comment)
from griffonad.lib.database import Database, Owned
from griffonad.lib.ml import MiniLanguage
from griffonad.lib.graph import Graph
from griffonad.lib.sysvol import Sysvol


def trace_start(args):
    if args.debug:
        tracemalloc.start()

def trace_stop(args):
    if args.debug:
        first_size, first_peak = tracemalloc.get_traced_memory()

        print("[ Memory ]")
        print(f'peak: {first_peak//1024//1024} MiB')
        print(f'memory: {first_size//1024//1024} MiB')
        print()

        limit = 10
        key_type = 'lineno'

        snapshot = tracemalloc.take_snapshot()

        snapshot = snapshot.filter_traces((
            tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
            tracemalloc.Filter(False, "<unknown>"),
        ))
        top_stats = snapshot.statistics(key_type)

        print("[ Top 10 ]")
        for index, stat in enumerate(top_stats[:limit], 1):
            frame = stat.traceback[0]
            print("#%s: %s:%s: %.1f KiB"
                  % (index, frame.filename, frame.lineno, stat.size / 1024))
            line = linecache.getline(frame.filename, frame.lineno).strip()
            if line:
                print('    %s' % line)

        other = top_stats[limit:]
        if other:
            size = sum(stat.size for stat in other)
            print("%s other: %.1f KiB" % (len(other), size / 1024))

        print()

        tracemalloc.stop()


def main():
    colorama_init()

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('filename', nargs='*')

    parser.add_argument('--groups', action='store_true', help='List groups and members (recursively)')
    parser.add_argument('--ous', action='store_true', help='List OUs (recursively)')
    parser.add_argument('--members', action='store_true', help='Display all [sub]members of groups/ous (with --groups / --ous)')
    parser.add_argument('--desc', action='store_true', help='Print all objects with a description')
    parser.add_argument('--graph', action='store_true', help='Generate a js graph')
    parser.add_argument('--sep', type=str, default=':', help='Separator string in the owned file')
    parser.add_argument('--save-compiled', type=str, metavar='FILE')
    parser.add_argument('--select', type=str, metavar='STARTSWITH', help='Filter targets/ous/groups')
    parser.add_argument('--sysvol', metavar='PATH', type=str, help='Analyze GPOs')
    parser.add_argument('--debug', action='store_true')

    arg_paths = parser.add_argument_group('Paths')
    arg_paths.add_argument('--fromo', action='store_true', help='Paths from owned')
    arg_paths.add_argument('--fromv', action='store_true', help='Paths from vulnerable users (NP users (only unprotected users), password not required,  and kerberoastable users)')
    arg_paths.add_argument('--rights', action='store_true', help='With --fromo or --fromv, display rights instead of actions')
    arg_paths.add_argument('--onlyadmin', action='store_true')
    arg_paths.add_argument('--from', type=str, metavar='USER', help='Get paths from this user')
    arg_paths.add_argument('--opt', type=str, default='', metavar='OPT1,OPT2,...', help='Custom flags')
    parser.add_argument('-f', '--no-follow', action='store_true',
            help='Don\'t try to continue on owned targets but display all available scenarios for one target')

    arg_script = parser.add_argument_group('Script generation')
    arg_script.add_argument('-s', '--script', metavar='N', type=str, help='Generate commands for a given path. N is the line number')
    arg_script.add_argument('--dc-ip', type=str, default='DC_IP', metavar='DC_IP')

    args = parser.parse_args()

    trace_start(args)

    if griffonad.config.OPTS:
        args.opt = config.OPTS
    else:
        o = set()
        for opt in args.opt.split(','):
            o.add(f'opt.{opt}')
        args.opt = o

    config_path = os.path.join(griffonad.__path__[0], 'config.ml')
   
    ml = MiniLanguage(args)
    ml.compile(config_path)

    if args.save_compiled:
        open(args.save_compiled, 'w+').write(ml.code)
        print(f'compiled code saved to {args.save_compiled}')
        exit(0)

    if not args.filename and args.sysvol:
        if args.sysvol:
            sysv = Sysvol(args.sysvol)
            sysv.search_all_gpt()
            print_comment('Local members', end=False)
            print(json.dumps(sysv.gpo_groups, indent=4))
            print()
            print_comment('Privileges', end=False)
            print(json.dumps(sysv.gpo_privileges, indent=4))
        exit(0)
    elif not args.filename:
        print('error: positional argument is missing')
        exit(0)
    else:
        t = time.time()

        db = Database()
        db.load_objects(args)
        db.populate_ous()
        db.populate_groups()

        if args.sysvol:
            sysv = Sysvol(args.sysvol)
            sysv.search_all_gpt()
            sysv.updatedb(db)

        db.propagate_admin_groups()
        db.propagate_aces()
        db.merge_rights()
        db.set_delegations()
        db.reverse_relations()
        db.propagate_can_admin(ml)
        # db.reduce_aces()
        db.set_has_sessions()
        db.prune_users()
        db.load_owned(args)

        diff = time.time() - t
        if diff > .4:
            print(f'[+] database analyzed in {diff} seconds')

    if args.graph:
        Graph(db).run()
        exit(0)

    if args.ous:
        print_ous(args, db)
        trace_stop(args)
        exit(0)

    if args.groups:
        print_groups(args, db)
        trace_stop(args)
        exit(0)

    if args.desc:
        print_desc(db)
        trace_stop(args)
        exit(0)

    if not args.fromv and not args.fromo and not args.__getattribute__('from'):
        print_hvt(args, db)
        trace_stop(args)
        exit(0)

    final_paths = []

    if args.fromo:
        final_paths = ml.execute_owned(db)
    elif args.fromv:
        final_paths = ml.execute_np(db)
        final_paths += ml.execute_user_spn(db)
        final_paths += ml.execute_password_not_required(db)
    elif args.__getattribute__('from'):
        obj = db.search_by_name(args.__getattribute__('from'))
        if obj is None:
            print(f"[-] error: can't find the object '{args.__getattribute__('from')}'")
            exit(1)
        o = Owned(obj, secret='PASSWORD', secret_type=c.T_SECRET_PASSWORD)
        final_paths = ml.execute_user_rights(db, o)
        db.owned_db[obj.name] = o

    if not args.script:
        print_paths(args, db, final_paths)
        trace_stop(args)
        exit(0)

    # Script generation
    line = int(args.script, 16)
    if line >= len(final_paths):
        print(f'[-] error: no path for the line {line}')
        exit(1)
    path = final_paths[line]
    print()
    print_path(args, path)
    print()
    print_script(args, db, path)
    trace_stop(args)

if __name__ == '__main__':
    main()
