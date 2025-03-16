import lib.consts as c
from lib.database import Database, FakeLDAPObject, Owned

def generate_fake_db():
    db = Database()

    domain = FakeLDAPObject()
    domain.is_admin = True
    domain.type = c.T_DOMAIN
    domain.sid = f'S-1-5-21-636977047-910435930-493999333'
    domain.rid = 0
    domain.from_domain = 'CORP.LOCAL'
    domain.dn = 'DC=CORP,DC=LOCAL'
    domain.name = 'CORP.LOCAL'

    dc = FakeLDAPObject()
    dc.is_admin = True
    dc.type = c.T_DC
    dc.sid = f'{domain.sid}-1000'
    dc.rid = 1000
    dc.from_domain = domain.from_domain
    dc.dn = 'CN=DC,CN=DOMAIN CONTROLLER,DC=CORP,DC=LOCAL'
    dc.spn = ['HOST/DC']
    dc.name = 'DC$'
    dc.unconstraineddelegation = True

    # one owned without spn
    alice = FakeLDAPObject()
    alice.type = c.T_USER
    alice.sid = f'{domain.sid}-1100'
    alice.rid = 1100
    alice.from_domain = domain.from_domain
    alice.dn = 'CN=ALICE,CN=USERS,DC=CORP,DC=LOCAL'
    alice.name = 'Alice'
    alice.can_admin = True

    # one owned with spn
    bob = FakeLDAPObject()
    bob.type = c.T_USER
    bob.sid = f'{domain.sid}-1101'
    bob.rid = 1101
    bob.from_domain = domain.from_domain
    bob.dn = 'CN=BOB,CN=USERS,DC=CORP,DC=LOCAL'
    bob.spn = ['spn/random1']
    bob.name = 'Bob'

    # belongs to some security groups
    eve = FakeLDAPObject()
    eve.type = c.T_USER
    eve.sid = f'{domain.sid}-1107'
    eve.rid = 1107
    eve.from_domain = domain.from_domain
    eve.dn = 'CN=EVE,CN=USERS,DC=CORP,DC=LOCAL'
    eve.name = 'Eve'

    # one not owned with spn and np
    charlie = FakeLDAPObject()
    charlie.is_admin = True
    charlie.type = c.T_USER
    charlie.sid = f'{domain.sid}-1105'
    charlie.rid = 1105
    charlie.from_domain = domain.from_domain
    charlie.dn = 'CN=CHARLIE,OU=SPECIAL_OU,DC=CORP,DC=LOCAL'
    charlie.spn = ['spn/random2']
    charlie.np = True
    charlie.name = 'Charlie'
    charlie.admincount = True

    # MSA
    msa = FakeLDAPObject()
    msa.type = c.T_USER
    msa.sid = f'{domain.sid}-1110'
    msa.rid = 1110
    msa.from_domain = domain.from_domain
    msa.dn = 'CN=MSA$,CN=USERS,DC=CORP,DC=LOCAL'
    msa.name = 'MSA$'

    d1 = FakeLDAPObject()
    d1.can_admin = True
    d1.type = c.T_COMPUTER
    d1.sid = f'{domain.sid}-1102'
    d1.rid = 1102
    d1.from_domain = domain.from_domain
    d1.dn = 'CN=DESKTOP-1,CN=COMPUTERS,DC=CORP,DC=LOCAL'
    d1.spn = ['HOST/DESKTOP-1']
    d1.unconstraineddelegation = True
    d1.name = 'DESKTOP-1$'

    s1 = FakeLDAPObject()
    s1.type = c.T_COMPUTER
    s1.sid = f'{domain.sid}-1106'
    s1.rid = 1106
    s1.from_domain = domain.from_domain
    s1.dn = 'CN=SERVER-1,OU=SPECIAL_OU,DC=CORP,DC=LOCAL'
    s1.spn = ['HOST/SERVER-1', 'WWW/SERVER-1']
    s1.trustedtoauth = True
    s1.name = 'SERVER-1$'

    s2 = FakeLDAPObject()
    s2.type = c.T_COMPUTER
    s2.sid = f'{domain.sid}-1104'
    s2.rid = 1104
    s2.from_domain = domain.from_domain
    s2.dn = 'CN=SERVER-2,OU=SPECIAL_OU,DC=CORP,DC=LOCAL'
    s2.spn = ['HOST/SERVER-2', 'WWW/SERVER-2']
    s2.trustedtoauth = False
    s2.name = 'SERVER-2$'

    s3 = FakeLDAPObject()
    s3.type = c.T_COMPUTER
    s3.sid = f'{domain.sid}-1103'
    s3.rid = 1103
    s3.from_domain = domain.from_domain
    s3.dn = 'CN=SERVER-3,OU=SPECIAL_OU,DC=CORP,DC=LOCAL'
    s3.spn = ['HOST/SERVER-3', 'WWW/SERVER-3']
    s3.name = 'SERVER-3$'

    gr1 = FakeLDAPObject()
    gr1.type = c.T_GROUP
    gr1.sid = f'{domain.sid}-1108'
    gr1.rid = 1108
    gr1.from_domain = domain.from_domain
    gr1.dn = 'CN=ADMIN_GROUP,CN=USERS,DC=CORP,DC=LOCAL'
    gr1.name = 'ADMIN_GROUP'
    gr1.can_admin = True

    ou1 = FakeLDAPObject()
    ou1.type = c.T_OU
    ou1.sid = f'{domain.sid}-1109'
    ou1.rid = 1109
    ou1.from_domain = domain.from_domain
    ou1.dn = 'OU=SPECIAL_OU,DC=CORP,DC=LOCAL'
    ou1.name = 'SPECIAL_OU'

    gpo1 = FakeLDAPObject()
    gpo1.type = c.T_GPO
    gpo1.sid = f'BED515D0-9B43-4BC3-ACC1-1BFF1E5D6F72'
    gpo1.from_domain = domain.from_domain
    gpo1.dn = 'CN={C4060C9D-C608-4FF7-BF84-4088DDDB58E6},CN=POLICIES,CN=SYSTEM,DC=CORP,DC=LOCAL'
    gpo1.name = '{C4060C9D-C608-4FF7-BF84-4088DDDB58E6}[GPO@CORP.LOCAL]'
    gpo1.original_name = 'GPO@CORP.LOCAL'
    gpo1.gpo_dirname_id = '{C4060C9D-C608-4FF7-BF84-4088DDDB58E6}'

    gpo1.gpo_links_to_ou = [
        ou1.dn,
    ]

    gr2 = FakeLDAPObject()
    gr2.type = c.T_GROUP
    gr2.sid = f'{domain.name}-S-1-5-32-548'
    gr2.from_domain = domain.from_domain
    gr2.dn = 'CN=ACCOUNT OPERATORS,CN=BUILTIN,DC=CORP,DC=LOCAL'
    gr2.name = 'BUILTIN\\Account Operators'

    gr3 = FakeLDAPObject()
    gr3.type = c.T_GROUP
    gr3.sid = f'{domain.name}-S-1-5-32-551'
    gr3.from_domain = domain.from_domain
    gr3.dn = 'CN=BACKUP OPERATORS,CN=BUILTIN,DC=CORP,DC=LOCAL'
    gr3.name = 'BUILTIN\\Backup Operators'

    dc.rights_by_sid = {
        domain.sid: {'GenericAll': None},
        'many': {'AllowedToDelegate': None},
    }

    charlie.rights_by_sid = {
        domain.sid: {'GenericAll': None},
    }

    gr1.rights_by_sid = {
        domain.sid: {'GenericAll': None},
    }

    gr2.rights_by_sid = {
        'many': {'GenericAll': None},
    }

    gr3.rights_by_sid = {
        'many': {'SeBackup': None},
    }

    d1.rights_by_sid = {
        'many': {'AllowedToDelegate': None},
        s1.sid: {'AllowedToAct': None},
    }

    s1.rights_by_sid = {
        s3.sid: {'AllowedToDelegate': ['WWW/SERVER-3']},
    }

    s2.rights_by_sid = {
        s3.sid: {'AllowedToDelegate': ['WWW/SERVER-3']},
    }

    alice.rights_by_sid = {
        d1.sid: {
            'Owns': None,
            'ReadLAPSPassword': None
        },
        gr1.sid: {'GenericWrite': None},
        gpo1.sid: {'GenericAll': None},
        eve.sid: {'GenericAll': None}
    }

    eve.rights_by_sid = {
        'many': {
            'GenericAll': None,
            'SeBackup': None,
        },
    }

    s3.rights_by_sid = {
        msa.sid: {'ReadGMSAPassword': None},
    }

    db.objects_by_sid = {
        alice.sid: alice,
        bob.sid: bob,
        charlie.sid: charlie,
        eve.sid: eve,
        msa.sid: msa,
        domain.sid: domain,
        dc.sid: dc,
        d1.sid: d1,
        s1.sid: s1,
        s2.sid: s2,
        s3.sid: s3,
        gr1.sid: gr1,
        gr2.sid: gr2,
        gr3.sid: gr3,
        ou1.sid: ou1,
        gpo1.sid: gpo1,
    }

    db.groups_by_sid = {
        gr1.sid: [charlie.sid],
        gr2.sid: [eve.sid],
        gr3.sid: [eve.sid],
    }

    charlie.groups_rid = [
        int(gr1.sid.split('-')[-1]),
    ]

    eve.groups_rid = [
        int(gr2.sid.split('-')[-1]),
        int(gr3.sid.split('-')[-1]),
    ]

    charlie.groups_sid = [
        gr1.sid,
    ]

    eve.groups_sid = [
        gr2.sid,
        gr3.sid,
    ]

    db.ous_by_dn = {
        ou1.dn: {
            'members': [
                s1.sid,
                s2.sid,
                s3.sid,
                charlie.sid,
            ],
            'gpo_links': [
                gpo1.sid,
            ],
        },
    }

    db.ous_dn_to_sid = {
        ou1.dn: ou1.sid,
    }

    db.main_dc = dc
    db.domain = domain

    db.objects_by_name = {}
    db.users = set()

    for o in db.objects_by_sid.values():
        db.objects_by_name[o.name.upper()] = o
        if o.type in [c.T_USER, c.T_COMPUTER, c.T_DC]:
            db.users.add(o.sid)

    db.owned_db = {
        alice.name.upper(): Owned(alice, secret='PASSWORD', secret_type=c.SECRET_PASSWORD),
        bob.name.upper(): Owned(bob, secret='PASSWORD', secret_type=c.SECRET_PASSWORD),
    }

    return db
