import time
import json
import binascii
import lib.consts as c
import uuid
from lib.utils import get_aes_256_from_hex
from lib.ml import MiniLanguage


VERBOSE = False


def logger(s):
    if VERBOSE:
        print(s)


class Owned():
    def __init__(self, obj, secret=None, secret_type=None, krb_auth=False, relayed=False, ticket_with_fqdn=False):
        self.obj = obj
        self.relayed = relayed
        self.krb_auth = krb_auth # means we have requested a TGT for this user (the KRB5CCNAME is set)
        self.ticket_with_fqdn = ticket_with_fqdn
        self.secret_type = secret_type
        if relayed:
            self.secret = 'dontcarepassword'
        else:
            self.secret = secret

    def __str__(self):
        return self.obj.name

    def __repr__(self):
        return self.obj.name


class LDAPObject():
    def __init__(self, o:dict, type:int):
        # bloodhound_json should be used only in this file
        self.bloodhound_json = o

        self.is_admin = False
        self.can_admin = False
        self.type = type
        self.sid = o['ObjectIdentifier']
        self.protected = False # in protected users group
        self.groups_rid = set() # list of groups this object belongs
        self.groups_sid = set() # list of groups this object belongs
        self.gpo_links_to_ou = [] # only for GPO, it contains the ou dn 
        self.from_domain = o['Properties']['domain']

        # Arg is most of the time set to None, it's useful for right=AllowedToDelegate,
        # then arg is a list with authorized SPNs.
        self.rights_by_sid = {} # target_sid -> dict({right1: arg, right2: arg, ...})
        self.is_owned_domain = False
        self.is_owned_dc = False

        self.lastlogon = o['Properties']['lastlogon'] if 'lastlogon' in o['Properties'] else 0
        self.dn = o['Properties']['distinguishedname'] if 'distinguishedname' in o['Properties'] else self.sid
        self.spn = o['Properties']['serviceprincipalnames'] if 'serviceprincipalnames' in o['Properties'] else []
        self.np = 'dontreqpreauth' in o['Properties'] and o['Properties']['dontreqpreauth']
        self.trustedtoauth = 'trustedtoauth' in o['Properties'] and o['Properties']['trustedtoauth']
        self.sensitive = 'sensitive' in o['Properties'] and o['Properties']['sensitive']
        self.admincount = 'admincount' in o['Properties'] and o['Properties']['admincount']
        self.unconstraineddelegation = 'unconstraineddelegation' in o['Properties'] and o['Properties']['unconstraineddelegation']
        self.passwordnotreqd = 'passwordnotreqd' in o['Properties'] and o['Properties']['passwordnotreqd']
        self.pwdneverexpires = 'pwdneverexpires' in o['Properties'] and o['Properties']['pwdneverexpires']
        self.description = o['Properties']['description'] if 'description' in o['Properties'] else ''
        self.enabled = 'enabled' in o['Properties'] and o['Properties']['enabled']

        if self.type == c.T_DOMAIN:
            self.name = o['Properties']['name']
            self.rid = 0
        elif self.type == c.T_GPO:
            # gpo_id is not the ObjectIdentifier (sid), this is a guid
            # This id is the name of the directory in SYSVOL
            self.gpo_id = '{' + self.dn.split('{')[1].split('}')[0] + '}'
            self.name = self.gpo_id + '[' + o['Properties']['name'] + ']'
            self.rid = 0
        elif self.type == c.T_CONTAINER or self.type == c.T_OU:
            self.rid = 0
            self.name = o['Properties']['name']
        else:
            self.rid = int(self.sid.split('-')[-1])
            if 'samaccountname' in o['Properties']:
                self.name = o['Properties']['samaccountname']
            else:
                self.name = o['Properties']['name'].split('@')[0]

        self.is_krbtgt = self.name.upper() == 'KRBTGT'

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class FakeLDAPObject(LDAPObject):
    def __init__(self):
        self.sid = str(uuid.uuid1())
        self.is_admin = False
        self.can_admin = False
        self.type = c.T_USER
        self.protected = False
        self.sensitive = False
        self.lastlogon = 0
        self.name = ''
        self.dn = ''
        self.np = False
        self.passwordnotreqd = False
        self.pwdneverexpires = False
        self.spn = []
        self.admincount = False
        self.trustedtoauth = False
        self.unconstraineddelegation = False
        self.groups_sid = set()
        self.groups_rid = set()
        self.is_local_admin = False
        self.rights_by_sid = {}
        self.bloodhound_json = None
        self.is_owned_domain = False
        self.is_owned_dc = False
        self.description = ''
        self.enabled = True
        self.from_domain = ''

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class Database():
    def __init__(self):
        self.objects_by_sid = {} # sid -> LDAPObject, or guid for gpo
        self.groups_by_sid = {} # group_sid -> [member_sid, ...]
        self.ous_by_dn = {} # ou_dn -> {'members': [sid, ...], 'gpo_links': [gpo_guid, ...]}
        self.ous_dn_to_sid = {} # ou_dn -> ou_sid
        self.main_dc = None # LDAPObject
        self.domain = None # LDAPObject
        self.owned_db = {} # name -> Owned
        self.objects_by_name = {} # upper_name -> LDAPObject
        self.sessions = {} # user_sid -> set(computer_sid, ...)

        # All user sids (users + computers)
        # The set is simplified by prune_users to keep only interesting users.
        self.users = set()


    def sid_to_dn(self, sid:str) -> str:
        return self.objects_by_sid[sid].dn


    def search_by_name(self, name:str) -> LDAPObject:
        name = name.upper()
        if name in self.objects_by_name:
            return self.objects_by_name[name]
        return None


    def load_owned(self, args):
        try:
            fd = open('owned', 'r+')
        except:
            return

        for line in fd.readlines():
            line = line.strip().split(args.sep)

            obj = self.search_by_name(line[0])
            if obj is None:
                print(f"[-] error: can't find the object '{line[0]}' in the file owned")
                exit(1)

            if obj.type == c.T_COMPUTER:
                self.owned_db[obj.name.upper()] = Owned(obj,
                    secret=get_aes_256_from_hex(self.domain.name, obj.name, line[2]),
                    secret_type=c.SECRET_AESKEY,
                    krb_auth=False)
            else:
                self.owned_db[obj.name.upper()] = Owned(obj,
                    secret=line[2],
                    secret_type=c.MAP_SECRET_TYPE[line[1]],
                    krb_auth=False)


    def __load_json(self, filename:str):
        data = json.load(open(filename, 'r'))
        objects = data['data']
        type = c.BH_OBJECT_TYPE[data['meta']['type']]
        for o_json in objects:
            sid = o_json['ObjectIdentifier']
            o = LDAPObject(o_json, type)
            self.objects_by_sid[sid] = o
            self.objects_by_name[o.name.upper()] = o
            if type == c.T_COMPUTER and 'OU=DOMAIN CONTROLLERS' in \
                     o_json['Properties']['distinguishedname']:
                o.type = c.T_DC
                self.users.add(sid)
                if self.main_dc is None:
                    self.main_dc = o
                elif o.rid < self.main_dc.rid:
                    self.main_dc = o
            elif type == c.T_DOMAIN:
                # TODO: actually support for only one domain
                self.domain = self.objects_by_sid[sid]
            elif type == c.T_USER or type == c.T_COMPUTER:
                self.users.add(sid)

            if type == c.T_COMPUTER:
                self.save_sessions(o_json)


    def save_sessions(self, o_json):
        # Collector 'Session'
        for sess in o_json['Sessions']['Results']:
            user_sid = sess['UserSID']
            user_sid = sess['ComputerSID']
            if sess['UserSID'] not in self.sessions:
                self.sessions[sess['UserSID']] = set()
            self.sessions[sess['UserSID']].add(sess['ComputerSID'])

        # Collector 'LoggedOn'
        for sess in o_json['RegistrySessions']['Results']:
            user_sid = sess['UserSID']
            user_sid = sess['ComputerSID']
            if sess['UserSID'] not in self.sessions:
                self.sessions[sess['UserSID']] = set()
            self.sessions[sess['UserSID']].add(sess['ComputerSID'])

        # Collector 'PrivilegedSessions'
        for sess in o_json['RegistrySessions']['Results']:
            user_sid = sess['UserSID']
            user_sid = sess['ComputerSID']
            if sess['UserSID'] not in self.sessions:
                self.sessions[sess['UserSID']] = set()
            self.sessions[sess['UserSID']].add(sess['ComputerSID'])


    def load_objects(self, args):
        t = time.time()

        for fn in args.filename:
            self.__load_json(fn)

        diff = time.time() - t
        if diff > .4:
            print(f'[+] json loaded in {diff} seconds')

        if self.domain is None:
            self.domain = FakeLDAPObject()
            self.domain.name = 'UNKNOWN_DOMAIN'
            self.domain.dn = 'UNKNOWN_DOMAIN_DN'
            self.type = c.T_DOMAIN


    def set_has_sessions(self):
        for user_sid, targets_sid in self.sessions.items():
            if user_sid not in self.objects_by_sid:
                o = FakeLDAPObject()
                o.sid = user_sid
                o.name = user_sid
                o.type = c.T_USER
                self.users.add(o.sid)
                self.objects_by_sid[user_sid] = o
                self.objects_by_name[user_sid] = o
            else:
                o = self.objects_by_sid[user_sid]
            for sid in targets_sid:
                o.rights_by_sid[sid] = {'HasSession': None}


    def populate_groups(self):
        def __add(group_sid:str, members:set, o:LDAPObject):
            if o.type in [c.T_USER, c.T_COMPUTER, c.T_DC]:
                o.groups_rid.add(int(group_sid.split('-')[-1]))
                o.groups_sid.add(group_sid)
            elif o.type == c.T_GROUP:
                for member in o.bloodhound_json['Members']:
                    sid = member['ObjectIdentifier']
                    if sid in members:
                        continue
                    if sid not in self.objects_by_sid:
                        continue
                    members.add(sid)
                    __add(group_sid, members, self.objects_by_sid[sid])

        # Populate recursively
        for sid, o in self.objects_by_sid.items():
            if o.type == c.T_GROUP:
                members = set()
                self.groups_by_sid[sid] = members
                __add(sid, members, o)

        # Set the flag protected
        sid = f'{self.domain.sid}-525' # Protected Users
        if sid in self.groups_by_sid:
            self.protected_users = self.groups_by_sid[sid]
            for p_sid in self.protected_users:
                self.objects_by_sid[p_sid].protected = True


    def populate_ous(self):
        # Note: this is not a sid for GPO but Bloodhound set the gpo id in
        # ObjectIdentifier, which is saved into LDAPObject.sid

        # Populate all links on each OU
        for sid, o in self.objects_by_sid.items():
            if o.type == c.T_OU:
                self.ous_dn_to_sid[o.dn] = sid
                self.ous_by_dn[o.dn] = {'members': [], 'gpo_links': []}
                for lk in o.bloodhound_json['Links']:
                    gpo_guid = lk['GUID']
                    self.ous_by_dn[o.dn]['gpo_links'].append(gpo_guid)
                    self.objects_by_sid[gpo_guid].gpo_links_to_ou.append(o.dn)
                    # Not every efficient, bu we expect the list is not too long
                    self.objects_by_sid[gpo_guid].gpo_links_to_ou.sort()

        # Populate OU members
        for sid, o in self.objects_by_sid.items():
            # Not sure if all these types can be in an OU
            if o.type in [c.T_GROUP, c.T_USER, c.T_COMPUTER, c.T_DC]:
                i = o.dn.find(',')
                # Keep only the OU part, example:
                # if we have CN=MYUSER,OU=MYOU,DC=CORP,DC=LOCAL
                # the result is OU=MYOU,DC=CORP,DC=LOCAL
                if i != -1:
                    ou_dn = o.dn[i+1:]
                    if ou_dn.startswith('OU=') and ou_dn in self.ous_by_dn:
                        self.ous_by_dn[ou_dn]['members'].append(o.sid)


    def propagate_aces(self):
        def __set_or_add(rights, sid, right):
            if sid in rights:
                rights[sid][right] = None
            else:
                rights[sid] = {right: None}

        def __add(parent:LDAPObject, target_sid:str, right:str):
            if target_sid in self.objects_by_sid:
                target = self.objects_by_sid[target_sid]

                # Only keep rights to domain
                if target.type == c.T_DOMAIN:
                    if not parent.is_owned_domain and right in ['GenericAll',
                                'WriteDacl', 'WriteOwner', 'Owns', 'AllExtendedRights']:
                        parent.is_owned_domain = True
                        parent.rights_by_sid.clear()
                    __set_or_add(parent.rights_by_sid, target.sid, right)
                    if 'GenericAll' in parent.rights_by_sid[target.sid]:
                        parent.rights_by_sid[target_sid] = {'GenericAll': None}
                    elif 'AllExtendedRights' in parent.rights_by_sid[target.sid]:
                        parent.rights_by_sid[target_sid] = {'AllExtendedRights': None}
                    return

                # Else only keep rights to dc
                if target.type == c.T_DC and not parent.is_owned_domain:
                    if not parent.is_owned_dc and right in ['GenericAll',
                                'WriteDacl', 'WriteOwner', 'Owns']:
                        parent.is_owned_dc = True
                        parent.rights_by_sid.clear()
                    __set_or_add(parent.rights_by_sid, target.sid, right)
                    if 'GenericAll' in parent.rights_by_sid[target.sid]:
                        parent.rights_by_sid[target_sid] = {'GenericAll': None}
                    return

            if not parent.is_owned_domain and not parent.is_owned_dc:
                __set_or_add(parent.rights_by_sid, target_sid, right)
                if target_sid != 'many' and 'GenericAll' in parent.rights_by_sid[target_sid]:
                    parent.rights_by_sid[target_sid] = {'GenericAll': None}

        exclude = [
            f'{self.domain.name}-S-1-5-32-548', # Account operators
            f'{self.domain.sid}-527', # Enterprise key admins
            f'{self.domain.sid}-526', # Key admins
            f'{self.domain.name}-S-1-5-32-562', # Distributed COM Users
            f'{self.domain.name}-S-1-5-32-569', # Cryptographic Operators
            f'{self.domain.name}-S-1-5-32-582', # Storage Replica Administrators
        ]

        # Manage/simplify special groups

        # Account operators
        if exclude[0] in self.objects_by_sid:
            self.objects_by_sid[exclude[0]].\
                rights_by_sid = {'many': {'GenericAll': None}}

        # Enterprise key admins
        if exclude[1] in self.objects_by_sid:
            self.objects_by_sid[exclude[1]].\
                rights_by_sid = {'many': {'AddKeyCredentialLink': None}}

        # Key admins
        if exclude[2] in self.objects_by_sid:
            self.objects_by_sid[exclude[2]].\
                rights_by_sid = {'many': {'AddKeyCredentialLink': None}}

        # Distributed COM Users
        if exclude[3] in self.objects_by_sid:
            self.objects_by_sid[exclude[3]].\
                rights_by_sid = {'many': {'GenericAll': None}}

        # Cryptographic Operators
        if exclude[4] in self.objects_by_sid:
            self.objects_by_sid[exclude[4]].\
                rights_by_sid = {'many': {'GenericAll': None}}

        # Storage Replica Administrators
        if exclude[5] in self.objects_by_sid:
            self.objects_by_sid[exclude[5]].\
                rights_by_sid = {'many': {'GenericAll': None}}

        # Backup operators
        # Just add the SeBackup to simplify
        backup_operators = f'{self.domain.name}-S-1-5-32-551'
        if backup_operators in self.objects_by_sid:
            self.objects_by_sid[backup_operators].\
                rights_by_sid['many'] = {
                    'SeBackup': None,
                    # 'SeRestore': None,
                }
            # Groups are already propagated, so don't need to recurse on members
            for member_sid in self.groups_by_sid[backup_operators]:
                o = self.objects_by_sid[member_sid]
                __add(o, 'many', 'SeBackup')
                # __add(o, 'many', 'SeRestore')

        # ACEs are stored in the reversed direction in AD
        # If A has the right GenericAll on B, so B has an ACE GenericAll from A
        # The relation is reversed in rights_by_sid (A stores his rights to B in his object):
        # -> A.rights_by_sid[sid_of_B] = {'GenericAll': None}
        # None means there is no argument for this right (useful with constrained
        # delegation where the argument is the spn)
        for target in self.objects_by_sid.values():

            if isinstance(target, FakeLDAPObject):
                continue

            for ace in target.bloodhound_json['Aces']:
                parent_sid = ace['PrincipalSID']

                if parent_sid not in self.objects_by_sid:
                    logger(f'warning: unknown sid {parent_sid}')
                    continue

                if parent_sid in exclude:
                    target_sid = 'many'
                else:
                    target_sid = target.sid

                parent = self.objects_by_sid[parent_sid]
                __add(parent, target_sid, ace['RightName'])

                # Groups are already propagated, so don't need to recurse on members
                if parent.type == c.T_GROUP:
                    for member_sid in self.groups_by_sid[parent.sid]:
                        if member_sid == target_sid:
                            # infinite loop otherwise
                            continue
                        __add(self.objects_by_sid[member_sid], target_sid, ace['RightName'])


    def set_delegations(self):
        # Don't use iter_users, the list could be long!
        # iter_users sorts by names before
        for sid in self.users:
            o = self.objects_by_sid[sid]

            if isinstance(o, FakeLDAPObject):
                continue

            # RBCD
            # AllowedToAct is the attribute msDS-AllowedToActOnBehalfOfOtherIdentity
            # !!! The relation is reversed in rights_by_sid
            if 'AllowedToAct' in o.bloodhound_json:
                for delegate_from in o.bloodhound_json['AllowedToAct']:
                    from_sid = delegate_from['ObjectIdentifier']

                    # If 'o' has object sids in the list, it means that these sids
                    # can ask a TGS to 'o' and 'o' can impersonate any users
                    if from_sid not in self.objects_by_sid:
                        print(f'warning: {o} can AllowedToActOnBehalf {from_sid} but {from_sid} is unknown')
                        continue
                    from_obj = self.objects_by_sid[from_sid]
                    if o.sid in from_obj.rights_by_sid:
                        from_obj.rights_by_sid[o.sid]['AllowedToAct'] = None
                    else:
                        from_obj.rights_by_sid = {o.sid: {'AllowedToAct': None}}

            # Unconstrained delegation
            if o.unconstraineddelegation:
                o.rights_by_sid['many'] = {'AllowedToDelegate': None}

            # Constrained delegation
            elif 'allowedtodelegate' in o.bloodhound_json['Properties']:
                for spn in o.bloodhound_json['Properties']['allowedtodelegate']:
                    spn_split = spn.split('/')

                    dom = f'.{self.domain.name}'
                    name = spn_split[1].upper().replace(dom, '')

                    target = self.search_by_name(name)
                    if target is None:
                        target = self.search_by_name(name + '$')
                        if target is None:
                            logger(f'spn not found {spn}')
                            continue

                    if target.sid in o.rights_by_sid:
                        if 'AllowedToDelegate' in o.rights_by_sid[target.sid]:
                            o.rights_by_sid[target.sid]['AllowedToDelegate'].append(spn)
                        else:
                            o.rights_by_sid[target.sid]['AllowedToDelegate'] = [spn]
                    else:
                        o.rights_by_sid[target.sid] = {'AllowedToDelegate': [spn]}


    def merge_getchanges_rights(self):
        for o in self.objects_by_sid.values():
            for rights in o.rights_by_sid.values():
                if 'GetChanges' in rights:
                    found_one = False
                    if 'GetChangesInFilteredSet' in rights:
                        del rights['GetChangesInFilteredSet']
                        rights['GetChanges_GetChangesInFilteredSet'] = None
                        found_one = True
                    if 'GetChangesAll' in rights:
                        del rights['GetChangesAll']
                        rights['GetChanges_GetChangesAll'] = None
                        found_one = True
                    if found_one:
                        del rights['GetChanges']


    def propagate_admin_groups(self):
        # propagate to children
        def __propagate(o:LDAPObject):
            if o.is_admin:
                return
            o.is_admin = True
            if o.sid in self.groups_by_sid:
                # propagate to all members of this group
                for sid in self.groups_by_sid[o.sid]:
                    __propagate(self.objects_by_sid[sid])

        admins = [
            f'{self.domain.sid}',          # domain
            f'{self.domain.sid}-512',      # Domain Admins
            f'{self.domain.sid}-502',      # krbtgt
            f'{self.domain.sid}-519',      # Enterprise Admins
            f'{self.domain.name}-S-1-5-9', # Enterprise Domain Controllers
            f'{self.domain.name}-S-1-5-32-544', # Administrators
        ]

        for sid in admins:
            if sid not in self.objects_by_sid:
                continue
            __propagate(self.objects_by_sid[sid])


    def reverse_relations(self):
        self.reversed_relations = {}
        for parent_sid in self.objects_by_sid:
            for target_sid in self.objects_by_sid[parent_sid].rights_by_sid.keys():
                if target_sid not in self.reversed_relations:
                    self.reversed_relations[target_sid] = {parent_sid}
                else:
                    self.reversed_relations[target_sid].add(parent_sid)


    # Normally it's fastest after the call of prune_users
    # We should not have a lot of interesting users
    # Sort by names before, to always print paths in the same order
    def iter_users(self):
        names = {}
        for sid in self.users:
            o = self.objects_by_sid[sid]
            names[o.name.upper()] = o

        for name in sorted(list(names.keys())):
            yield names[name]


    def propagate_can_admin(self, ml:MiniLanguage):
        def __propagate_to_parent(o):
            if o.can_admin:
                return
            o.can_admin = True
            if o.sid not in self.reversed_relations:
                return
            for parent_sid in self.reversed_relations[o.sid]:
                parent = self.objects_by_sid[parent_sid]
                rights = parent.rights_by_sid[o.sid]
                if not rights.keys().isdisjoint(ml.get_rights_to_apply(o.type)):
                    __propagate_to_parent(parent)

        # Propagate backup operators
        backup_operators = f'{self.domain.name}-S-1-5-32-551'
        if backup_operators in self.objects_by_sid:
            self.objects_by_sid[backup_operators].can_admin = True
            for member_sid in self.groups_by_sid[backup_operators]:
                __propagate_to_parent(self.objects_by_sid[member_sid])

        # Propagate admins + unconstrained delegation
        for o in self.objects_by_sid.values():
            if o.is_admin or o.can_admin or o.unconstraineddelegation:
                __propagate_to_parent(o)


    # If a user has the flags is_admin or can_admin then we keep only rights
    # to admin or can_admin users
    def reduce_aces(self):
        for sid in self.users:
            o = self.objects_by_sid[sid]
            if not (o.is_admin or o.can_admin):
                continue
            for target_sid in list(o.rights_by_sid):
                if target_sid == 'many':
                    continue
                target = self.objects_by_sid[target_sid]
                if not (target.is_admin or target.can_admin):
                    del o.rights_by_sid[target_sid]


    def prune_users(self):
        to_remove = []
        # Don't use iter_users, the list could be long!
        # iter_users sorts by names before
        for sid in self.users:
            o = self.objects_by_sid[sid]
            if not o.enabled:
                to_remove.append(o.sid)
            elif not (o.rights_by_sid or o.np or (o.spn and o.type == c.T_USER) or \
                    o.is_admin or o.trustedtoauth or o.passwordnotreqd):
                to_remove.append(o.sid)
        for sid in to_remove:
            self.users.remove(sid)
