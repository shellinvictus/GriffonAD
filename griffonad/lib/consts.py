import os
import binascii

APPLY = [
    'apply_with_ticket', 'apply_with_aes', 'apply_with_cracked_passwd',
    'apply_group', 'apply_with_forced_passwd', 'apply_with_blank_passwd',
    'apply_with_nthash',
]

TERMINALS = APPLY + ['stop']

T_MANY = -1
T_USER = 0
T_COMPUTER = 1
T_DOMAIN = 2
T_GPO = 4
T_GROUP = 5
T_OU = 6
T_DC = 7
T_CONTAINER = 8
T_OU = 9

# types in config.ml
ML_TYPES_FROM_STR = {
    'user': T_USER,
    'computer': T_COMPUTER,
    'domain': T_DOMAIN,
    'group': T_GROUP,
    'gpo': T_GPO,
    'dc': T_DC,
    'ou': T_OU,
    'container': T_CONTAINER,
    'many': T_MANY,
}

ML_TYPES_TO_STR = {
    T_USER: 'user',
    T_COMPUTER: 'computer',
    T_DOMAIN: 'domain',
    T_GROUP: 'group',
    T_GPO: 'gpo',
    T_DC: 'dc',
    T_OU: 'ou',
    T_CONTAINER: 'container',
    T_MANY: 'many',
}

# In bloodhound json
BH_OBJECT_TYPE = {
    'computers': T_COMPUTER,
    'users': T_USER,
    'domains': T_DOMAIN,
    'gpos': T_GPO,
    'groups': T_GROUP,
    'containers': T_CONTAINER,
    'ous': T_OU,
}

T_SECRET_PASSWORD = 0
T_SECRET_NTHASH = 1
T_SECRET_AESKEY = 2

MAP_SECRET_TYPE = {
    'password': T_SECRET_PASSWORD,
    'aes': T_SECRET_AESKEY,
    'nt': T_SECRET_NTHASH,
}

BUILTIN_SID = {
    "S-1-0-0", # Null SID: A group with no members. This is often used when a SID value is not known.
    "S-1-1-0", # World: A group that includes all users. 
    "S-1-2-0", # Local: Users who log on to terminals locally (physically) connected to the system.
    "S-1-3-0", # Creator Owner ID: A security identifier to be replaced by the security identifier of the user who created a new object. This SID is used in inheritable ACEs.
    "S-1-3-1", # Creator Group ID: A security identifier to be replaced by the primary-group SID of the user who created a new object. Use this SID in inheritable ACEs.
    "S-1-5-1", # Dialup: A group that includes all users who are signed in to the system via dial-up connection.
    "S-1-5-113", # Local account: You can use this SID when you're restricting network sign-in to local accounts instead of "administrator" or equivalent. This SID can be effective in blocking network sign-in for local users and groups by account type regardless of what they're named.
    "S-1-5-114", # Local account and member of Administrators group: You can use this SID when you're restricting network sign-in to local accounts instead of "administrator" or equivalent. This SID can be effective in blocking network sign-in for local users and groups by account type regardless of what they're named.
    "S-1-5-2", # Network: A group that includes all users who are signed in via a network connection. Access tokens for interactive users don't contain the Network SID.
    "S-1-5-3", # Batch: A group that includes all users who have signed in via batch queue facility, such as task scheduler jobs.
    "S-1-5-4", # Interactive: A group that includes all users who sign in interactively. A user can start an interactive sign-in session by opening a Remote Desktop Services connection from a remote computer, or by using a remote shell such as Telnet. In each case, the user's access token contains the Interactive SID. If the user signs in by using a Remote Desktop Services connection, the user's access token also contains the Remote Interactive Logon SID.
    "S-1-5-5- X-Y", # Logon Session: The X and Y values for these SIDs uniquely identify a particular sign-in session.
    "S-1-5-6", # Service: A group that includes all security principals that have signed in as a service.
    "S-1-5-7", # Anonymous Logon: A user who has connected to the computer without supplying a user name and password. The Anonymous Logon identity is different from the identity that's used by Internet Information Services (IIS) for anonymous web access. IIS uses an actual account—by default, IUSR_ComputerName, for anonymous access to resources on a website. Strictly speaking, such access isn't anonymous, because the security principal is known even though unidentified people are using the account. IUSR_ComputerName (or whatever you name the account) has a password, and IIS signs in to the account when the service starts. As a result, the IIS "anonymous" user is a member of Authenticated Users but Anonymous Logon isn't.
    "S-1-5-8", # Proxy: Doesn't currently apply: this SID isn't used.
    "S-1-5-9", # Enterprise Domain Controllers: A group that includes all domain controllers in a forest of domains.
    "S-1-5-10", # Self: A placeholder in an ACE for a user, group, or computer object in Active Directory. When you grant permissions to Self, you grant them to the security principal that's represented by the object. During an access check, the operating system replaces the SID for Self with the SID for the security principal that's represented by the object.
    "S-1-5-11", # Authenticated Users: A group that includes all users and computers with identities that have been authenticated. Authenticated Users doesn't include Guest even if the Guest account has a password. This group includes authenticated security principals from any trusted domain, not only the current domain.
    "S-1-5-12", # Restricted Code: An identity that's used by a process that's running in a restricted security context. In Windows and Windows Server operating systems, a software restriction policy can assign one of three security levels to code: Unrestricted Restricted Disallowed. When code runs at the restricted security level, the Restricted SID is added to the user's access token.
    "S-1-5-13", # Terminal Server User: A group that includes all users who sign in to a server with Remote Desktop Services enabled.
    "S-1-5-14", # Remote Interactive Logon: A group that includes all users who sign in to the computer by using a remote desktop connection. This group is a subset of the Interactive group. Access tokens that contain the Remote Interactive Logon SID also contain the Interactive SID.
    "S-1-5-15", # This Organization: A group that includes all users from the same organization. Included only with Active Directory accounts and added only by a domain controller.
    "S-1-5-17", # IUSR: An account that's used by the default Internet Information Services (IIS) user.
    "S-1-5-18", # System (or LocalSystem): An identity that's used locally by the operating system and by services that are configured to sign in as LocalSystem. System is a hidden member of Administrators. That is, any process running as System has the SID for the built-in Administrators group in its access token. When a process that's running locally as System accesses network resources, it does so by using the computer's domain identity. Its access token on the remote computer includes the SID for the local computer's domain account plus SIDs for security groups that the computer is a member of, such as Domain Computers and Authenticated Users.
    "S-1-5-19", # NT Authority (LocalService): An identity that's used by services that are local to the computer, have no need for extensive local access, and don't need authenticated network access. Services that run as LocalService access local resources as ordinary users, and they access network resources as anonymous users. As a result, a service that runs as LocalService has significantly less authority than a service that runs as LocalSystem locally and on the network.
    "S-1-5-20", # Network Service: An identity that's used by services that have no need for extensive local access but do need authenticated network access. Services running as NetworkService access local resources as ordinary users and access network resources by using the computer's identity. As a result, a service that runs as NetworkService has the same network access as a service that runs as LocalSystem, but it has significantly reduced local access.
    "S-1-5-32-544", # Administrators: A built-in group. After the initial installation of the operating system, the only member of the group is the Administrator account. When a computer joins a domain, the Domain Admins group is added to the Administrators group. When a server becomes a domain controller, the Enterprise Admins group also is added to the Administrators group.
    "S-1-5-32-545", # Users: A built-in group. After the initial installation of the operating system, the only member is the Authenticated Users group.
    "S-1-5-32-546", # Guests: A built-in group. By default, the only member is the Guest account. The Guests group allows occasional or one-time users to sign in with limited privileges to a computer's built-in Guest account.
    "S-1-5-32-547", # Power Users: A built-in group. By default, the group has no members. Power users can create local users and groups; modify and delete accounts that they have created; and remove users from the Power Users, Users, and Guests groups. Power users also can install programs; create, manage, and delete local printers; and create and delete file shares.
    "S-1-5-32-548", # Account Operators: A built-in group that exists only on domain controllers. By default, the group has no members. By default, Account Operators have permission to create, modify, and delete accounts for users, groups, and computers in all containers and organizational units of Active Directory except the Builtin container and the Domain Controllers OU. Account Operators don't have permission to modify the Administrators and Domain Admins groups, nor do they have permission to modify the accounts for members of those groups.
    "S-1-5-32-549", # Server Operators: Description: A built-in group that exists only on domain controllers. By default, the group has no members. Server Operators can sign in to a server interactively; create and delete network shares; start and stop services; back up and restore files; format the hard disk of the computer; and shut down the computer.
    "S-1-5-32-550", # Print Operators: A built-in group that exists only on domain controllers. By default, the only member is the Domain Users group. Print Operators can manage printers and document queues.
    "S-1-5-32-551", # Backup Operators: A built-in group. By default, the group has no members. Backup Operators can back up and restore all files on a computer, regardless of the permissions that protect those files. Backup Operators also can sign in to the computer and shut it down.
    "S-1-5-32-552", # Replicators: A built-in group that's used by the File Replication service on domain controllers. By default, the group has no members. Don't add users to this group.
    "S-1-5-domain-553", # RAS and IAS Servers: A local domain group. By default, this group has no members. Computers that are running the Routing and Remote Access service are added to the group automatically. Members of this group have access to certain properties of User objects, such as Read Account Restrictions, Read Logon Information, and Read Remote Access Information.
    "S-1-5-32-554", # Builtin\\Pre-Windows 2000 Compatible Access: An alias added by Windows 2000. A backward compatibility group that allows read access on all users and groups in the domain.
    "S-1-5-32-555", # Builtin\\Remote Desktop Users: An alias. Members of this group are granted the right to sign in remotely.
    "S-1-5-32-556", # Builtin\\Network Configuration Operators: An alias. Members of this group can have some administrative privileges to manage configuration of networking features.
    "S-1-5-32-557", # Builtin\\Incoming Forest Trust Builders: An alias. Members of this group can create incoming, one-way trusts to this forest.
    "S-1-5-32-558", # Builtin\\Performance Monitor Users: An alias. Members of this group have remote access to monitor this computer.
    "S-1-5-32-559", # Builtin\\Performance Log Users: An alias. Members of this group have remote access to schedule logging of performance counters on this computer.
    "S-1-5-32-560", # Builtin\\Windows Authorization Access Group: An alias. Members of this group have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects.
    "S-1-5-32-561", # Builtin\\Terminal Server License Servers: An alias. A group for Terminal Server License Servers. When Windows Server 2003 Service Pack 1 is installed, a new local group is created.
    "S-1-5-32-562", # Builtin\\Distributed COM Users: An alias. A group for COM to provide computer-wide access controls that govern access to all call, activation, or launch requests on the computer.
    "S-1-5-32-568", # Builtin\\IIS_IUSRS: An alias. A built-in group account for IIS users.
    "S-1-5-32-569", # Builtin\\Cryptographic Operators: A built-in local group. Members are authorized to perform cryptographic operations.
    "S-1-5-domain-571", # Allowed RODC Password Replication Group: Members in this group can have their passwords replicated to all read-only domain controllers in the domain.
    "S-1-5-domain-572", # Denied RODC Password Replication Group: Members in this group can't have their passwords replicated to all read-only domain controllers in the domain.
    "S-1-5-32-573", # Builtin\\Event Log Readers: A built-in local group. Members of this group can read event logs from a local computer.
    "S-1-5-32-574", # Builtin\\Certificate Service DCOM Access: A built-in local group. Members of this group are allowed to connect to Certification Authorities in the enterprise.
    "S-1-5-32-575", # Builtin\\RDS Remote Access Servers: A built-in local group. Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. In internet-facing deployments, these servers are typically deployed in an edge network. This group needs to be populated on servers that are running RD Connection Broker. RD Gateway servers and RD Web Access servers used in the deployment need to be in this group.
    "S-1-5-32-576", # Builtin\\RDS Endpoint Servers: A built-in local group. Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run. This group needs to be populated on servers running RD Connection Broker. RD Session Host servers and RD Virtualization Host servers used in the deployment need to be in this group.
    "S-1-5-32-577", # Builtin\\RDS Management Servers: A built-in local group. Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. This group needs to be populated on all servers in a Remote Desktop Services deployment. The servers running the RDS Central Management service must be included in this group.
    "S-1-5-32-578", # Builtin\\Hyper-V Administrators: A built-in local group. Members of this group have complete and unrestricted access to all features of Hyper-V.
    "S-1-5-32-579", # Builtin\\Access Control Assistance Operators: A built-in local group. Members of this group can remotely query authorization attributes and permissions for resources on this computer.
    "S-1-5-32-580", # Builtin\\Remote Management Users: A built-in local group. Members of this group can access Windows Management Instrumentation (WMI) resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
    "S-1-5-64-10", # NTLM Authentication: A SID that's used when the NTLM authentication package authenticates the client.
    "S-1-5-64-14", # SChannel Authentication: A SID that's used when the SChannel authentication package authenticates the client.
    "S-1-5-64-21", # Digest Authentication: A SID that's used when the Digest authentication package authenticates the client.
    "S-1-5-80", # NT Service: A SID that's used as an NT Service account prefix.
    "S-1-5-80-0", # All Services: A group that includes all service processes that are configured on the system. Membership is controlled by the operating system. SID S-1-5-80-0 equals NT SERVICES\\ALL SERVICES. This SID was introduced in Windows Server 2008 R2.
    "S-1-5-83-0", # NT VIRTUAL MACHINE\\Virtual Machines: A built-in group. The group is created when the Hyper-V role is installed. Membership in the group is maintained by the Hyper-V Management Service (VMMS). This group requires the Create Symbolic Links right (SeCreateSymbolicLinkPrivilege) and the Log on as a Service right (SeServiceLogonRight).   
}
