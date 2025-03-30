#!/usr/bin/env python3

import configparser
import os
import re

from lib.database import Database


class Sysvol():
    def __init__(self, sysvol_path:str):
        self.sysvol_path = sysvol_path
        self.gpo_groups = {}
        self.gpo_privileges = {}


    # Parse a GptTmpl.inf file, search for membership 
    def parse_gpt(self, path):
        config = configparser.ConfigParser()
        buf = open(path, "rb").read()

        if not buf.startswith(b'\xff\xfe'):
            return {}, {}
        config.read_string(buf[2:].decode("utf-16le"))

        result = re.search(r'({[-a-fA-F0-9]+})', path)
        gpo_dirname_id = result.group(1).upper()

        groups = {} # sid -> [sid1, sid2, ...]

        # attributes are not case sensitives

        if 'Group Membership' in config:
            for key, val in config['Group Membership'].items():
                if key.endswith('__members'):
                    group_ident = key[:-9].strip().replace('*', '').upper()
                    for member_ident in val.split(','):
                        if member_ident:
                            if group_ident not in groups:
                                groups[group_ident] = []
                            groups[group_ident].append(member_ident.strip().replace('*', '').upper())

                if key.endswith('__memberof'):
                    member_ident = key[:-10].strip().replace('*', '').upper()
                    for group_ident in val.split(','):
                        group_ident = group_ident.strip().replace('*', '').upper()
                        if group_ident:
                            if group_ident not in groups:
                                groups[group_ident] = []
                            groups[group_ident].append(member_ident)

        privileges = {
            'SeImpersonatePrivilege': [],
            'SeAssignPrimaryPrivilege': [],
            'SeTcbPrivilege': [],
            'SeBackupPrivilege': [],
            'SeRestorePrivilege': [],
            'SeCreateTokenPrivilege': [],
            'SeLoadDriverPrivilege': [],
            'SeTakeOwnershipPrivilege': [],
            'SeDebugPrivilege': [],
        }
        lower_case_privs = {p.lower():p for p in privileges}

        if 'Privilege Rights' in config:
            for key, val in config['Privilege Rights'].items():
                if key in lower_case_privs:
                    for ident in val.split(','):
                        privileges[lower_case_privs[key]].append(
                            ident.strip().replace('*', '').upper())

        to_remove = []
        for name, value in privileges.items():
            if not value:
                to_remove.append(name)
        for name in to_remove:
            del privileges[name]

        return {gpo_dirname_id: groups}, {gpo_dirname_id: privileges}


    def search_all_gpt(self):
        for dirname, dirs, files in os.walk(self.sysvol_path):
            for f in files:
                if f == 'GptTmpl.inf':
                    groups, privileges = self.parse_gpt(f'{dirname}/{f}')
                    self.gpo_groups.update(groups)
                    self.gpo_privileges.update(privileges)


    def updatedb(self, db:Database):
        def get_object(sid:str):
            if sid in db.objects_by_sid:
                return db.objects_by_sid[sid]
            if sid in db.prefixed_sids:
                return db.objects_by_sid[db.prefixed_sids[sid]]
            if sid in db.objects_by_name:
                return db.objects_by_name[sid]
            return None

        # Create the right RestrictedGroups to all local members

        for gpo_dirname_id, groups in self.gpo_groups.items():
            gpo = db.objects_by_name[gpo_dirname_id]

            for g_sid, members in groups.items():
                g = get_object(g_sid)

                for o_sid in members:
                    o = get_object(o_sid)

                    for ou_dn in gpo.gpo_links_to_ou:
                        ou_sid = db.ous_dn_to_sid[ou_dn]

                        if ou_sid not in o.rights_by_sid:
                            o.rights_by_sid[ou_sid] = {}

                        if 'RestrictedGroups' not in o.rights_by_sid[ou_sid]:
                            o.rights_by_sid[ou_sid] = {'RestrictedGroups': []}
                        o.rights_by_sid[ou_sid]['RestrictedGroups'].append(g)

                        # Backup operators
                        if g_sid == 'S-1-5-32-551':
                            o.rights_by_sid[ou_sid]['SeBackupPrivilege'] = None

                        # Administrators
                        if g_sid == 'S-1-5-32-544':
                            o.rights_by_sid[ou_sid]['AdminTo'] = None


        # Apply privileges

        for gpo_dirname_id, privileges in self.gpo_privileges.items():
            gpo = db.objects_by_name[gpo_dirname_id]

            for ou_dn in gpo.gpo_links_to_ou:
                ou_sid = db.ous_dn_to_sid[ou_dn]

                for priv_name, sids in privileges.items():
                    for sid in sids:
                        o = get_object(sid)
                        if ou_sid not in o.rights_by_sid:
                            o.rights_by_sid[ou_sid] = {}
                        o.rights_by_sid[ou_sid][priv_name + '_LATFP_or_RDP_required'] = None
