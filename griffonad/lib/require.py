from griffonad.lib.database import LDAPObject, FakeLDAPObject, Owned, Database
from griffonad.lib.actions import *
from griffonad.lib.print import print_script
import griffonad.lib.consts as c
import griffonad.config

WRITE_SPN = {'GenericAll', 'GenericWrite', 'WriteSPN', 'WriteDacl', 'WriteOwner', 'Owns'}


class Require():
    def get(db:Database, parent:Owned, target:LDAPObject) -> object:
        pass

    def print(db:Database, glob:dict, parent:Owned, require:dict):
        pass


###############################################################################
# require_targets: return a list of LDAPObject (not Owned)
# Convention: all of them are prefixed by ta_


# We need to find 3 users:
# - an owned user which is able to remove the SPN of the original target
# - a new target to pwn
# - another owned user which is able to set the SPN on the new target
class x_ta_spn_jacking_requirements(Require):
    def get(db:Database, parent:Owned, target:LDAPObject) -> list:
        ret = []
        found_writer = False

        for owned in db.owned_db.values():
            for sid, rights in owned.obj.rights_by_sid.items():
                new_target = db.objects_by_sid[sid]
                if new_target.type == c.T_COMPUTER and set(rights.keys()).intersection(WRITE_SPN):
                    if sid == target.sid:
                        target.spn_writer = owned
                        found_writer = True
                    else:
                        new_target.spn_writer = owned
                        ret.append(new_target)

        if not found_writer:
            return []

        return ret

    def print(db:Database, glob:dict, parent:Owned, require:dict):
        tmp_target = require['object']
        writer = tmp_target.spn_writer
        rights = writer.obj.rights_by_sid[tmp_target.sid]

        if 'GenericAll' in rights or 'GenericWrite' in  rights or 'WriteSPN' in rights:
            return

        v = vars(glob, parent=writer, target=tmp_target)
        comment = 'require: we need to set the capability to write a SPN on {target} for {parent}'
        print_comment(comment, v)

        if 'WriteDacl' in rights or 'Owns' in rights:
            path = [
                (writer, '::DaclServicePrincipalName', tmp_target, None),
            ]
        elif 'WriteOwner' in rights:
            path = [
                (writer, '::WriteOwner', tmp_target, None),
                (writer, '::DaclServicePrincipalName', tmp_target, None),
            ]

        print_script(db, glob, path)


class x_ta_dc(Require):
    def get(db:Database, parent:Owned, target:LDAPObject) -> list:
        return [db.main_dc]


class x_ta_users_without_admincount(Require):
    def get(db:Database, parent:Owned, target:LDAPObject):
        ret = []
        # iter_users contains only interesting users so it's relatively fast
        for o in db.iter_users():
            if not o.admincount and o.rights_by_sid and o.name.upper() not in db.owned_db:
                ret.append(o)

        if not ret:
            return None

        return ret


class x_ta_users_and_groups_without_admincount(Require):
    def get(db:Database, parent:Owned, target:LDAPObject):
        ret = x_ta_users_without_admincount.get(db, parent, target)
        if ret is None:
            ret = []

        for group_sid in db.groups_by_sid.keys():
            if group_sid not in db.objects_by_sid:
                continue
            o = db.objects_by_sid[group_sid]
            if not o.admincount and o.rights_by_sid:
                ret.append(o)

        if not ret:
            return None

        return ret


class x_ta_all_computers_in_domain(Require):
    CACHE = {}

    def get(db:Database, parent:Owned, target:LDAPObject):
        if target.sid in x_ta_all_computers_in_domain.CACHE:
            return x_ta_all_computers_in_domain.CACHE[target.sid]

        ret = []

        # iter_users contains only interesting users so it's relatively fast
        for o in db.iter_users():
            if db.objects_by_sid[o.sid].type == c.T_COMPUTER:
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
        if target.type != c.T_GPO and target.type != c.T_OU:
            print(f'error: the target of all_users_in_ou must be a GPO or OU (we have {target.name})')
            exit(0)

        if target.sid in x_ta_all_users_in_ou.CACHE:
            return x_ta_all_users_in_ou.CACHE[target.sid]

        ret = []

        if target.type == c.T_GPO:
            # for all links
            for ou_dn in target.gpo_links_to_ou:
                for sid in db.ous_by_dn[ou_dn]['members']:
                    o = db.objects_by_sid[sid]
                    # db.users contains only interesting users
                    if o.type == c.T_USER and sid in db.users and \
                           o.sid != parent.obj.sid:
                        ret.append(o)
        elif target.type == c.T_OU:
            for sid in db.ous_by_dn[target.dn]['members']:
                o = db.objects_by_sid[sid]
                if o.type == c.T_USER:
                    ret.append(o)

        x_ta_all_users_in_ou.CACHE[target.sid] = ret
        return ret


class x_ta_one_dc_in_ou(Require):
    CACHE = {}

    def get(db:Database, parent:Owned, target:LDAPObject) -> list:
        if target.sid in x_ta_one_dc_in_ou.CACHE:
            return x_ta_one_dc_in_ou.CACHE[target.sid]

        ret = []

        # for all links
        for sid in db.ous_by_dn[target.dn]['members']:
            o = db.objects_by_sid[sid]
            if o.type == c.T_DC and o.sid != parent.obj.sid:
                ret.append(o)
                break

        x_ta_one_dc_in_ou.CACHE[target.sid] = ret
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

    def print(db:Database, glob:dict, parent:Owned, require:dict):
        v = vars(glob, parent, target=None, required_object=require['object'])
        comment = 'require: unprotected_owned_with_spn -> {required_object.obj.name}'
        print_comment(comment, v)


class x_unprotected_owned_with_spn_not_eq_parent(Require):
    def get(db:Database, parent:Owned, target:LDAPObject) -> Owned:
        for o in db.owned_db.values():
            if o.obj.spn and not o.obj.protected and o.obj.sid != parent.obj.sid:
                return o
        return None

    def print(db:Database, glob:dict, parent:Owned, require:dict):
        v = vars(glob, parent, target=None, required_object=require['object'])
        comment = 'require: unprotected_owned_with_spn_not_eq_parent -> {required_object.obj.name}'
        print_comment(comment, v)


class x_owned_user_without_spn(Require):
    def get(db:Database, parent:Owned, target:LDAPObject) -> Owned:
        for o in db.owned_db.values():
            if o.obj.type == c.T_USER and not o.obj.spn:
                return o
        return None

    def print(db:Database, glob:dict, parent:Owned, require:dict):
        v = vars(glob, parent, target=None, required_object=require['object'])
        comment = 'require: owned_user_without_spn -> {required_object.obj.name}'
        print_comment(comment, v)


class x_any_owned(Require):
    def get(db:Database, parent:Owned, target:LDAPObject) -> Owned:
        if db.owned_db:
            return next(iter(db.owned_db.values()))
        return None

    def print(db:Database, glob:dict, parent:Owned, require:dict):
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

    def print(db:Database, glob:dict, parent:Owned, require:dict):
        path = [(
            parent,
            '::AddComputer',
            require['object'].obj, # the target must be a LDAPObject
            {'object': require['object']} # pass the Owned object as the require to get the secret
        )]
        print_script(db, glob, path)
