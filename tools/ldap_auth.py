import ssl
import binascii
import hashlib
import ldap3
from ldap3 import ALL, Connection, Server, Tls, NTLM, SUBTREE, MODIFY_REPLACE
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.core.exceptions import LDAPBindError

def add_common_parameters(parser):
    parser.add_argument('connection', help='FQDN/USER[:PASSWORD]@SERVER')
    parser.add_argument('-hashes', type=str, help='NTLM hashes, format is [LMHASH]:NTHASH')
    parser.add_argument('-k', action='store_true', help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    parser.add_argument('-aesKey', type=str, help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    parser.add_argument('-dc-ip', type=str)
    parser.add_argument('-use-ldaps', action='store_true')

def ldap_auth(args):
    c = args.connection.split('@')
    server = c[1]
    identity = c[0].split(':')
    tmp = identity[0].split('/')
    fqdn = tmp[0]
    user = tmp[1]

    if args.dc_ip is not None:
        connect_to = args.dc_ip
    else:
        connect_to = server

    if len(identity) == 2:
        password = identity[1]
        args.hashes = ':' + binascii.hexlify(hashlib.new('md4', password.encode('utf-16le')).digest()).decode()
    else:
        password = ''

    if args.aesKey:
        args.k = True 
    elif args.hashes:
        args.hashes = args.hashes.split(':')
        if len(args.hashes[1]) != 32:
            print('[-] error: bad nt hash')
            exit(1)
        args.hashes = f'aad3b435b51404eeaad3b435b51404ee:{args.hashes[1]}'

    try:
        if args.use_ldaps:
            tls = Tls(ciphers='ALL', version=ssl.PROTOCOL_SSLv23, validate=ssl.CERT_NONE)
            ldap_serv = ldap3.Server(host=connect_to, port=636, use_ssl=True, tls=tls, get_info=ALL)
        else:
            ldap_serv = ldap3.Server(host=connect_to, port=389, use_ssl=False, get_info=ALL)

        if args.k:
            conn = ldap3.Connection(ldap_serv)
            conn.bind()
            ldap3_kerberos_login(conn, server, user, password, fqdn,
                                 aesKey=args.aesKey,kdcHost=args.dc_ip)
        else:
            conn = ldap3.Connection(ldap_serv, user=f'{fqdn}\\{user}',
                password=args.hashes, authentication=NTLM, version=3,
                auto_bind=True, auto_referrals=False)

    except LDAPBindError as e:
        print('error:', e)
        exit(1)

    return ldap_serv, conn

#
# From impacket dacledit.py
#
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Authors:
#   Charlie BROMBERG (@_nwodtuhs)
#   Guillaume DAUMAS (@BlWasp_)
#   Lucien DOUSTALY (@Wlayzz)
#
def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None,
                         TGT=None, TGS=None, useCache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    '''
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    '''

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
    import datetime
    import ldap3

    if TGT is not None or TGS is not None:
        useCache = False

    target = 'ldap/%s' % target
    if useCache:
        domain, user, TGT, TGS = CCache.parseFile(domain, user, target)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                    aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal(target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True
