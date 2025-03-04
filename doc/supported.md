Supported rights
================

Global:

- GenericAll, GenericWrite, AllExtendedRights, Owns, WriteOwner
- Manage users in 'Protected Users' -> force Kerberos authentication instead of NTLM
- Users in '[Enterprise] Key Admins'
- Users in 'Account Operators'
- Users in 'Backup Operators'
- WriteDacl:
    - FullControl
    - Allow to write specific attribute
- Users with the sensitive flag

Users:

- ForceChangePassword
- AddKeyCredentialLink
- ASREPRoasting (on users with the do not preauth flag)
- WriteSPN (kerberoastable user)
- Kerberoasting (on users with SPN)
- WriteUserAccountControl (enable the do not preauth flag)
- SetLogonScript
- ReadGMSAPassword

Computers:

- AllowedToActOnBehalfOfOtherIdentity (= AllowedToAct)
- AddAllowedToAct:
    - Add RBCD with AddComputer
    - Add RBCD with owned user with SPN
    - Add RBCD with U2U
- AllowedToDelegate (unconstrained delegation with Rubeus and krbrelayx)
- AllowedToDelegate with protocol transition (constrained delegation)
- AllowedToDelegate without protocol transition (constrained delegation, kerberos only)
    - Add Self RBCD with AddComputer
    - Add Self RBCD with owned user with SPN
- WriteAccountRestrictions (allow to RBCD)
- ReadLAPSPassword

DC:

- DCSync

Groups:

- AddMember
- AddSelf

GPO, use the option `--opt allgpo` to see all of them (gpo applied only for
admin users + computers in the same OU as the gpo link):

- Immediate task
- Startup/logon script
- Add a user in the local Administrators group
- Firewall open port


TODO/Unsupported
================

- FIXME: Account Operators: also apply GenericAll on groups
- More scenarios with GPO: https://wald0.com/?p=179
- GPO enforcement, OU inheritance
- Delegation unsupported on users
- More security groups
- WriteGPLink on OU: actually the right is managed in config.ml but any commands are printed
- Protected ACL
- Multi-domains
- Other alternative for Self RBCD (Windows > 2022)
- Everything else not written here...
