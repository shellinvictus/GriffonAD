import os
import binascii
import time
from colorama import Back, Fore, Style

import lib.consts as c
import lib.actions
import config
from lib.actionutils import *
from lib.database import Owned, Database
from lib.ml import MiniLanguage
from lib.utils import sanityze_symbol


def color1_object(o:LDAPObject, underline=False) -> str:
    if o is None:
        return 'many'
    if underline:
        u = Style.UNDERLINE
    else:
        u = ''
    sid = o.sid.replace(o.from_domain + '-', '')
    if sid in c.BUILTIN_SID:
        name = 'BUILTIN\\' + o.name.upper()
    else:
        name = o.name.upper()
    if o.is_admin:
        return f'{u}{Fore.RED}♦{name}{Style.RESET_ALL}'
    if o.can_admin:
        return f'{u}{Fore.YELLOW}★{name}{Style.RESET_ALL}'
    return f'{u}{name}{Style.RESET_ALL}'


def color2_object(o:LDAPObject, underline=False) -> str:
    if o is None:
        return 'many'
    if underline:
        u = Style.UNDERLINE
    else:
        u = ''
    if o.sid in c.BUILTIN_SID:
        name = 'BUILTIN\\' + name.upper()
    else:
        name = o.name.upper()
    if o.is_admin:
        return f'{u}{Fore.RED}♦{name}{Style.RESET_ALL}'
    if o.can_admin:
        return f'{u}{Fore.YELLOW}★{name}{Style.RESET_ALL}'
    return f'{u}{Fore.GREEN}{name}{Style.RESET_ALL}'


# High value targets
def print_hvt(args, db:Database):
    print()
    print(f'{Fore.RED}♦USER{Style.RESET_ALL} the user is an admin')
    print(f'{Fore.YELLOW}★USER{Style.RESET_ALL} there is a path to gain admin privileges')
    print(f'{Style.UNDERLINE}USER{Style.RESET_ALL} the user is owned')
    print(f'{Fore.GREEN}A{Style.RESET_ALL}  admincount is set (this flag doesn\'t tell that the user is an admin, it could be an old admin)')
    print(f'{Fore.GREEN}K{Style.RESET_ALL}  the user may be Kerberoastable (at least one SPN is set)')
    print(f'{Fore.GREEN}N{Style.RESET_ALL}  DONT_REQUIRE_PREAUTH (ASREPRoastable)')
    print(f'{Fore.GREEN}P{Style.RESET_ALL}  the user is in the Protected group')
    print(f'{Fore.GREEN}!R{Style.RESET_ALL} PASSWORD_NOTREQUIRED (it means the password can be empty)')
    print(f'{Fore.GREEN}S{Style.RESET_ALL}  SENSITIVE')
    print(f'{Fore.GREEN}T{Style.RESET_ALL}  TRUSTED_TO_AUTH_FOR_DELEGATION (it means you can impersonate to admin in constrained delegations)')
    print(f'{Fore.GREEN}!X{Style.RESET_ALL} DONT_EXPIRE_PASSWORD')
    print()

    for o in db.iter_users():
        if args.select and not o.name.upper().startswith(args.select.upper()):
            continue

        if o.name.upper() in db.owned_db:
            print(color1_object(o, underline=True), end='')
        else:
            print(color1_object(o), end='')

        if o.admincount:
            print(f'{Fore.GREEN} A{Style.RESET_ALL}', end='')
        if o.spn and o.type != c.T_COMPUTER and o.name.upper() != 'KRBTGT':
            print(f'{Fore.GREEN} K{Style.RESET_ALL}', end='')
        if o.np:
            print(f'{Fore.GREEN} N{Style.RESET_ALL}', end='')
        if o.protected:
            print(f'{Fore.GREEN} P{Style.RESET_ALL}', end='')
        if o.passwordnotreqd:
            print(f'{Fore.GREEN} !R{Style.RESET_ALL}', end='')
        if o.sensitive:
            print(f'{Fore.GREEN} S{Style.RESET_ALL}', end='')
        if o.trustedtoauth:
            print(f'{Fore.GREEN} T{Style.RESET_ALL}', end='')
        if o.pwdneverexpires:
            print(f'{Fore.GREEN} !X{Style.RESET_ALL}', end='')
        print()

        for sid in o.group_sids:
            if sid == 'many':
                name = 'many'
            elif sid not in db.objects_by_sid:
                name = f'UNKNOWN_{sid}'
            else:
                name = color1_object(db.objects_by_sid[sid])
            print(f'    < {name}')

        for sid, rights in o.rights_by_sid.items():
            if sid == 'many':
                name = 'many'
            elif sid not in db.objects_by_sid:
                name = f'UNKNOWN_{sid}'
            else:
                name = color1_object(db.objects_by_sid[sid])
            for i, r in enumerate(rights.keys()):
                if rights[r] is not None:
                    print(f'    ({r}, {rights[r]} -> {name})')
                else:
                    print(f'    ({r}, {name})')
    print()


def print_ous(args, db:Database):
    names = []
    for dn in db.ous_by_dn.keys():
        ou = db.objects_by_sid[db.ous_dn_to_sid[dn]]
        if not args.select or ou.name.upper().startswith(args.select.upper()):
            names.append(ou.name.upper())
    names.sort()

    for name in names:
        ou = db.objects_by_name[name]
        data = db.ous_by_dn[ou.dn]

        if not data['members'] and not data['gpo_links']:
            continue

        print(ou.dn)

        if data['gpo_links']:
            for sid in data['gpo_links']:
                print('  <=>', color1_object(db.objects_by_sid[sid]))

        if data['members']:
            print(f'    {len(data["members"])} members')
            if args.members:
                for sid in data['members']:
                    if sid not in db.objects_by_sid:
                        name = f'UNKNOWN_{sid}'
                    else:
                        name = color1_object(db.objects_by_sid[sid])
                    print('   ', name)

        print()


def print_groups(args, db:Database):
    protected_group = f'{db.domain.sid}-525'
    print()

    names = []
    for sid in db.groups_by_sid.keys():
        g = db.objects_by_sid[sid]
        if not args.select or g.name.upper().startswith(args.select.upper()):
            names.append(g.name.upper())
    names.sort()

    printed = False

    for name in names:
        g = db.objects_by_name[name]
        members = db.groups_by_sid[g.sid]

        # always print the protected group
        if g.sid != protected_group and not g.rights_by_sid:
            continue

        printed = True

        sid = g.sid.replace(g.from_domain + '-', '')

        print(f'{color1_object(g)} ({sid})')

        if members:
            print(f'    {len(members)} members')
            if args.members:
                for m in members:
                    print('   ', color1_object(db.objects_by_sid[m]))

        for sid, rights in g.rights_by_sid.items():
            if sid == 'many':
                name = 'many'
            elif sid not in db.objects_by_sid:
                name = f'UNKNOWN_{sid}'
            else:
                name = color1_object(db.objects_by_sid[sid])
            for i, r in enumerate(rights.keys()):
                if rights[r] is not None:
                    print(f'    ({r}, {rights[r]} -> {name})')
                else:
                    print(f'    ({r}, {name})')

    if args.select and not printed:
        print('This group may not have interesting rights')

    print()


def print_paths(args, db:Database, paths:list):
    if paths:
        print()
        found_path_to_admin = False
        for i, p in enumerate(paths):
            if not args.onlyadmin or p[-1][2].is_admin and args.onlyadmin:
                print('%0.3x ' % i, end='')
            last_is_admin = p[-1][2] is not None and p[-1][2].is_admin
            if last_is_admin:
                print(f'{Fore.WHITE}{Back.RED}+{Style.RESET_ALL}', end=' ')
            elif not args.onlyadmin:
                print('  ', end='')
            if not args.onlyadmin or last_is_admin and args.onlyadmin:
                print_path(args, p)
                print()
    else:
        print('[+] No paths found :(')


def print_path(args, path:list):
    length = len(path)
    end = ' —> '
    i = 0

    # print(path)

    while i < length:
        if i == length - 1:
            end = ''

        parent, symbol, target, required = path[i]

        if parent is not None:
            parent_name = color2_object(parent.obj)
            print(f'{parent_name}', end=end)

        # If the target changes multiple times before an apply or a stop, only the
        # final target will be displayed

        # Print all actions and requires until an apply or a stop
        while True:
            par, sym, tar, req = path[i]

            if sym in c.TERMINALS:
                break

            if args.rights:
                if sym[:2] not in ['__', '::']:
                    print(f'{sym},', end='')
            else:
                if sym.startswith('::') and sym[2] != '_':
                    print(f'{sym}', end='')

                if req is not None:
                    print(f"[{req['class_name']}]", end='')

            i += 1


        target_name = color2_object(target)
        print(f'({target_name}):', end='')

        # don't print apply* and stop keywords
        if sym in c.TERMINALS:
            i += 1

    parent, symbol, target, required = path[i-1]
    target_name = color2_object(target)
    print(f'{target_name}')


def print_script(args, db:Database, path:list):
    glob = {
        'fqdn': db.domain.name,
        'fqdn_lower': db.domain.name.lower(),
        'domain_short_name': db.domain.name.split('.')[0],
        'dc_name': db.main_dc.name.replace('$', ''),
        'dc_ip': args.dc_ip,
        'domain_sid': db.domain.sid,
        'new_pass': config.DEFAULT_PASSWORD,
    }

    print_comment([
        'You may need to add these lines to /etc/hosts:',
        f"{glob['dc_ip']} {glob['dc_name']}.{glob['fqdn']}",
        f"{glob['dc_ip']} {glob['dc_name']}",
    ])

    last_target = None
    last_parent = None

    previous_action = ''

    for parent, symbol, target, require in path:

        if target is not None and last_target is not None and \
                last_target.sid != target.sid and target.sid in db.users:
            diff = time.time() - target.lastlogon
            if target.lastlogon == -1:
                print_warning(f'{target.name} never logged, is it a honey pot?')
            elif diff > 60*60*24*30*6:
                print_warning(f'{target.name} lastlogon > 6 months, is it a honey pot?')

        if target is None:
            last_target = None
        else:
            last_target = target

        if parent is None:
            last_parent = None
        else:
            if last_parent is not None and last_parent.krb_auth and not parent.krb_auth:
                print_cmd('unset KRB5CCNAME\n')
            last_parent = parent

        if parent is not None and not parent.krb_auth:
            if parent.obj.protected:
                print_comment(f'{parent.obj.name} is protected, switch to kerberos')
                lib.actions.TGTRequest(glob, parent)
            elif parent.secret_type == c.T_SECRET_PASSWORD and parent.secret == '':
                print_comment(f'PASSWORD_NOTREQUIRED: the password may be blank, it\'s easier to get a TGT first')
                lib.actions.TGTRequest(glob, parent, nopass=True)

        if require is not None:
            class_name = sanityze_symbol(require['class_name'])
            lib.require.__getattribute__(class_name).print(glob, parent, require)

        if symbol.startswith('::'):
            # Print commands, we will create a new owned object if we have a full control on it
            s = sanityze_symbol(symbol)
            res = lib.actions.__getattribute__(s).print(
                    previous_action,
                    glob,
                    parent,
                    target,
                    require)

        previous_action = symbol


def print_desc(db:Database):
    for o in db.objects_by_sid.values():
        if o.description is not None and o.description.strip():
            if o.type not in [c.T_GPO, c.T_CONTAINER, c.T_OU]:
                rid = int(o.sid.split('-')[-1])
                do_print = rid >= 1000
            else:
                do_print = True

            if do_print:
                if o.type in [c.T_USER, c.T_COMPUTER]:
                    print(color2_object(o))
                else:
                    print(color1_object(o))
                print('   ', o.description)

