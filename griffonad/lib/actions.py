from colorama import Back, Fore, Style

import griffonad.lib.consts as c
from griffonad.lib.database import Owned, LDAPObject
from griffonad.lib.utils import password_to_nthash


def vars(glob:dict, parent:Owned, target:LDAPObject=None, **more_vars):
    v = {}
    if parent is not None:
        v.update({
            'parent': parent,
            'parent_no_dollar': parent.obj.name.replace('$', ''),
            'parent_ip': f'{Fore.RED}{parent.obj.name.replace("$","")}_IP{Style.RESET_ALL}',
        })
    if target is not None:
        v.update({
            'target': target,
            'target_no_dollar': target.name.replace('$', ''),
            'target_ip': f'{Fore.RED}{target.name.replace("$","")}_IP{Style.RESET_ALL}',
        })
    if parent is not None and target is not None:
        if parent.krb_need_fqdn:
            v['target_no_dollar'] += f".{glob['fqdn']}"
    v.update(glob)
    v.update(more_vars)
    return v

def print_line(comment, cmd, vars=None, end=True):
    print_comment(comment, vars, False)
    print_cmd(cmd, vars)
    if end:
        print()

def print_comment(comment, vars={}, end=True):
    if isinstance(comment, str):
        comment = [comment]
    for l in comment:
        print(f'{Fore.BLUE}# {l.format(**vars)}{Style.RESET_ALL}')
    if end:
        print()

def print_cmd(cmd, vars={}):
    if 'parent' in vars:
        orig_passwd = vars['parent'].secret
        vars['parent'].secret = f'{Fore.RED}{vars["parent"].secret}{Style.RESET_ALL}'
    if isinstance(cmd, str):
        cmd = [cmd]
    for l in cmd:
        print(l.format(**vars))
    if 'parent' in vars:
        vars['parent'].secret = orig_passwd

def print_warning(s):
    print(f'{Fore.RED}# WARNING: {s}{Style.RESET_ALL}')


# These classes are only used during the path search.

class Action():
    def commit(target:LDAPObject):
        pass
    def rollback(target:LDAPObject):
        pass

class x_WriteSPN(Action):
    def commit(target:LDAPObject):
        target.old_spn = list(target.spn)
        target.spn.append('random/spn')
    def rollback(target:LDAPObject):
        target.spn = target.old_spn

class x_EnableNP(Action):
    def commit(target:LDAPObject):
        target.old_np = target.np
        target.np = True
    def rollback(target:LDAPObject):
        target.np = target.old_np
