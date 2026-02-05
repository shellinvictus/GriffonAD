from griffonad.lib.database import LDAPObject, FakeLDAPObject, Owned, Database
from griffonad.lib.actionutils import *
import griffonad.lib.consts as c
import griffonad.config


class Require():
    def get(db:Database, parent:Owned, target:LDAPObject) -> object:
        pass

    def print(glob:dict, parent:Owned, require:dict):
        pass


###############################################################################
# require_targets: return a list of LDAPObject (not Owned)
# Convention: all of them are prefixed by ta_

class x_ta_dc(Require):
    def get(db:Database, parent:Owned, target:LDAPObject) -> list:
        return [db.main_dc]


class x_ta_users_without_admincount(Require):
    def get(db:Database, parent:Owned, target:LDAPObject):
        ret = []
        # iter_users contains only interesting users so it's relatively fast
        for o in db.iter_users():
            if not o.admincount and o.rights_by_sid and o.name not in db.owned_db:
                ret.append(o)

        if not ret:
            return None

        return ret


class x_ta_users_and_groups_without_admincount(Require):

    def get(db:Database, parent:Owned, target:LDAPObject):
        ret = x_ta_users_without_admincount.get(db, parent, target)

        for group_sid in db.groups_by_sid.keys():
            if group_sid not in db.objects_by_sid:
                continue
            o = db.objects_by_sid[group_sid]
            if not o.admincount and o.rights_by_sid:
                ret.append(o)

        if not ret:
            return None

        return ret


class x_ta_all_computers_in_ou(Require):
    CACHE = {}

    def get(db:Database, parent:Owned, target:LDAPObject) -> list:
        if target.type != c.T_GPO and target.type != c.T_OU:
            print(f'error: the target of all_computers_in_ou must be a GPO or OU (we have {target.name})')
            exit(0)

        if target.sid in x_ta_all_computers_in_ou.CACHE:
            return x_ta_all_computers_in_ou.CACHE[target.sid]

        ret = []

        if target.type == c.T_GPO:
            # for all links
            for ou_dn in target.gpo_links_to_ou:
                for sid in db.ous_by_dn[ou_dn]['members']:
                    o = db.objects_by_sid[sid]
                    # take all computers even if they don't have rights on other objects
                    if o.type == c.T_COMPUTER:
                        ret.append(o)
        elif target.type == c.T_OU:
            for sid in db.ous_by_dn[target.dn]['members']:
                o = db.objects_by_sid[sid]
                if o.type == c.T_COMPUTER:
                    ret.append(o)

        x_ta_all_computers_in_ou.CACHE[target.sid] = ret
        return ret


class x_ta_all_users_in_ou(Require):
    CACHE = {}

    def get(db:Database, parent:Owned, target:LDAPObject) -> list:
        if target.type != c.T_GPO:
            print(f'error: the target of all_users_in_ou must be a GPO (we have {target.name})')
            exit(0)

        if target.sid in x_ta_all_users_in_ou.CACHE:
            return x_ta_all_users_in_ou.CACHE[target.sid]

        ret = []

        # for all links
        for ou_dn in target.gpo_links_to_ou:
            for sid in db.ous_by_dn[ou_dn]['members']:
                o = db.objects_by_sid[sid]
                # db.users contains only interesting users
                if o.type == c.T_USER and sid in db.users and \
                       o.sid != parent.obj.sid:
                    ret.append(o)

        x_ta_all_users_in_ou.CACHE[target.sid] = ret
        return ret


###############################################################################
# Below require + require_for_auth + require_once
# They must return a single Owned object

class x_unprotected_owned_with_spn(Require):
    def get(db:Database, parent:Owned, target:LDAPObject) -> Owned:
        for o in db.owned_db.values():
            if o.obj.spn and not o.obj.protected:
                return o
        return None

    def print(glob:dict, parent:Owned, require:dict):
        v = vars(glob, parent, target=None, required_object=require['object'])
        comment = 'require: unprotected_owned_with_spn -> {required_object.obj.name}'
        print_comment(comment, v)


class x_unprotected_owned_with_spn_not_eq_parent(Require):
    def get(db:Database, parent:Owned, target:LDAPObject) -> Owned:
        for o in db.owned_db.values():
            if o.obj.spn and not o.obj.protected and o.obj.sid != parent.obj.sid:
                return o
        return None

    def print(glob:dict, parent:Owned, require:dict):
        v = vars(glob, parent, target=None, required_object=require['object'])
        comment = 'require: unprotected_owned_with_spn_not_eq_parent -> {required_object.obj.name}'
        print_comment(comment, v)


class x_owned_user_without_spn(Require):
    def get(db:Database, parent:Owned, target:LDAPObject) -> Owned:
        for o in db.owned_db.values():
            if o.obj.type == c.T_USER and not o.obj.spn:
                return o
        return None

    def print(glob:dict, parent:Owned, require:dict):
        v = vars(glob, parent, target=None, required_object=require['object'])
        comment = 'require: owned_user_without_spn -> {required_object.obj.name}'
        print_comment(comment, v)


class x_any_owned(Require):
    def get(db:Database, parent:Owned, target:LDAPObject) -> Owned:
        if db.owned_db:
            return next(iter(db.owned_db.values()))
        return None

    def print(glob:dict, parent:Owned, require:dict):
        v = vars(glob, parent, target=None, required_object=require['object'])
        comment = 'require: owned_user_without_spn -> {required_object.obj.name}'
        print_comment(comment, v)


class x_add_computer(Require):
    def get(db:Database, parent:Owned, target:LDAPObject) -> Owned:
        obj = FakeLDAPObject()
        obj.type = c.T_COMPUTER
        obj.name = griffonad.config.DEFAULT_COMPUTER_NAME
        obj.spn = ['HOST/' + obj.name.replace('$', '')]
        return Owned(obj, secret=griffonad.config.DEFAULT_PASSWORD, secret_type=c.T_SECRET_PASSWORD)

    def print(glob:dict, parent:Owned, require:dict):
        v = vars(glob, parent, target=None, required_object=require['object'])

        comment = [
            'Check if the machine account quota is > zero, otherwise this scenario will',
            'not work (try with --opt noaddcomputer)',
        ]

        if parent.krb_auth:
            cmd = "./tools/getbyname.py '{fqdn}/{parent.obj.name}@{dc_name}' -dc-ip {dc_ip} -k -t {domain_short_name} | grep MachineAccountQuota -A 2"
        elif parent.secret_type == c.T_SECRET_NTHASH:
            cmd = "./tools/getbyname.py '{fqdn}/{parent.obj.name}@{dc_name}' -dc-ip {dc_ip} -hashes :{parent.secret} -t {domain_short_name} | grep MachineAccountQuota -A 2"
        elif parent.secret_type == c.T_SECRET_AESKEY:
            cmd = "./tools/getbyname.py '{fqdn}/{parent.obj.name}@{dc_name}' -dc-ip {dc_ip} -k -aesKey {parent.secret} -t {domain_short_name} | grep MachineAccountQuota -A 2"
        elif parent.secret_type == c.T_SECRET_PASSWORD:
            cmd = "./tools/getbyname.py '{fqdn}/{parent.obj.name}:{parent.secret}@{dc_name}' -dc-ip {dc_ip} -t {domain_short_name} | grep MachineAccountQuota -A 2"

        print_line(comment, cmd, v)

        comment = 'Add a computer in the domain'

        if parent.krb_auth:
            cmd = "addcomputer.py '{fqdn}/{parent.obj.name}' -dc-ip {dc_ip} -k -no-pass -computer-name '{required_object.obj.name}' -computer-pass '{required_object.secret}' -method SAMR -dc-host {dc_name}"
        elif parent.secret_type == c.T_SECRET_NTHASH:
            cmd = "addcomputer.py '{fqdn}/{parent.obj.name}' -dc-ip {dc_ip} -hashes :{parent.secret} -computer-name '{required_object.secret}' -computer-pass '{required_object.secret}' -method SAMR"
        elif parent.secret_type == c.T_SECRET_AESKEY:
            cmd = "addcomputer.py '{fqdn}/{parent.obj.name}' -dc-ip {dc_ip} -k -no-pass -aesKey {parent.secret} -computer-name '{required_object.obj.name}' -computer-pass '{required_object.secret}' -method SAMR"
        elif parent.secret_type == c.T_SECRET_PASSWORD:
            cmd = "addcomputer.py '{fqdn}/{parent.obj.name}:{parent.secret}' -dc-ip {dc_ip} -computer-name '{required_object.obj.name}' -computer-pass '{required_object.secret}' -method SAMR"

        print_line(comment, cmd, v)
