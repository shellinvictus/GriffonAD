#!/usr/bin/env python3

import configparser
import os
import re

from lib.database import Database


class Sysvol():
    def __init__(self, db:Database, sysvol_path:str):
        self.db = db
        self.sysvol_path = sysvol_path


    # Parse a GptTmpl.inf file, search for membership 
    def parse_gpttmpl(self, path):
        config = configparser.ConfigParser()
        buf = open(path, "rb").read()

        if not buf.startswith(b'\xff\xfe'):
            return {}
        config.read_string(buf[2:].decode("utf-16le"))
        if 'Group Membership' not in config:
            return {}

        result = re.search(r'({[-A-F0-9]+})', path)
        gpo_dirname_id = result.group(1)
        groups = {}

        for key, val in config['Group Membership'].items():
            # attributes are not case sensitive
            result = re.search(r'\*(s[-0-9]+)__members', key)
            if result is None:
                continue
            sid = result.group(1).upper()
            if sid not in groups:
                groups[sid] = []

            for member in val.split(','):
                result = re.search(r'\*([sS][-0-9]+)', key)
                if member.startswith('*'):
                    groups[sid].append(member[1:].upper())

        return {gpo_dirname_id: groups}


    # Search all GptTmpl.inf
    def updatedb(self):
        gpo_groups = {}
        for dirname, dirs, files in os.walk(self.sysvol_path):
            for f in files:
                if f == 'GptTmpl.inf':
                    gpo_groups.update(self.parse_gpttmpl(f'{dirname}/{f}'))

        for gpo_dirname_id, groups in gpo_groups.items():
            gpo = self.db.objects_by_name[gpo_dirname_id]

            for g_sid, members in groups.items():
                g = self.db.objects_by_sid[g_sid]
                for o_sid in members:
                    o = self.db.objects_by_sid[o_sid]

                    for ou_dn in gpo.gpo_links_to_ou:
                        ou_sid = self.db.ous_dn_to_sid[ou_dn]

                        if ou_sid not in o.rights_by_sid:
                            o.rights_by_sid[ou_sid] = {}
                        if 'RestrictedGroup' not in o.rights_by_sid[ou_sid]:
                            o.rights_by_sid[ou_sid] = {'RestrictedGroup': []}
                        o.rights_by_sid[ou_sid]['RestrictedGroup'].append(g)
