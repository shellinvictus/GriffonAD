#
# Convention:
# ::NAME(target) = this is an action (it generates code in lib/actions.py)
# __NAME(target) = this is a temporary state
# NAME(target) = this is a bloodhound right
#
# The parent is the object we own (we have his password or a ticket) and the one
# which has the right on the target.
# Full documentation here: doc/config.md
#

# Private actions
::_Secretsdump(computer) -> ::_TransformPasswordToAES
::_TransformPasswordToAES(any) -> apply_with_aes

# FullControl, let Griffon choose the best scenario
GenericAll(any) -> AllExtendedRights
GenericAll(any) -> GenericWrite

# Unconstrained delegation
# TRUSTED_FOR_DELEGATION: userAccountControl & 0x80000
# It could be any computer instead of the dc, if we coerce the dc we are admin!
# TODO: delegation parameter on a user (actually only on computer)
AllowedToDelegate(many) -> ::AllowedToDelegateToAny require_targets ta_dc
::AllowedToDelegateToAny(dc) -> apply_with_ticket \
        if not parent.sensitive and not parent.protected \
        elsewarn "PARENT -> AllowedToDelegateToAny(TARGET): PARENT is sensitive or protected"

# Manage special groups

# 'Key Admins' or 'Enterprise Key Admins'
AddKeyCredentialLink(many) -> ::AddKeyCredentialLink   \
        require_targets ta_users_without_admincount \
        if opt.allkeys and (526 in parent.groups or 527 in parent.groups) \
        elsewarn "Set the option --opt allkeys to execute the scenario AddKeyCredentialLink(many)"

# 'Account Operators'
GenericAll(many) -> GenericAll \
        require_targets ta_users_and_groups_without_admincount \
        if 548 in parent.groups

# 'Backup Operators'
# Works only on a DC. To work on other computers a GPO must set this privilege to
# be applied on all computers
SeBackupPrivilege(many) -> ::RegBackup \
        require_targets ta_dc \
        if 551 in parent.groups
::RegBackup(dc) -> ::_TransformPasswordToAES

# PASSWD_NOTREQD: userAccountControl & 0x20
::BlankPassword(user) -> apply_with_blank_passwd
::BlankPassword(computer) -> apply_with_blank_passwd

# User

ForceChangePassword(user) -> ::ForceChangePassword
AddKeyCredentialLink(user) -> ::AddKeyCredentialLink
WriteUserAccountControl(user) -> ::EnableNP
WriteSPN(user) -> ::WriteSPN
SetLogonScript(user) -> ::SetLogonScript
AllExtendedRights(user) -> ForceChangePassword
GenericWrite(user) -> AddKeyCredentialLink 
GenericWrite(user) -> WriteUserAccountControl
GenericWrite(user) -> WriteSPN
GenericWrite(user) -> SetLogonScript
WriteDacl(user) -> ::DaclResetPassword
WriteDacl(user) -> ::DaclKeyCredentialLink
WriteDacl(user) -> ::DaclUserAccountControl
WriteDacl(user) -> ::DaclServicePrincipalName
WriteDacl(user) -> ::DaclInitialProgram
::DaclResetPassword(user) -> ForceChangePassword
::DaclKeyCredentialLink(user) -> AddKeyCredentialLink
::DaclUserAccountControl(user) -> WriteUserAccountControl
::DaclServicePrincipalName(user) -> WriteSPN
::DaclInitialProgram(user) -> SetLogonScript
::ForceChangePassword(user) -> apply_with_forced_passwd if not opt.noforce
::AddKeyCredentialLink(user) -> apply_with_ticket
::Kerberoasting(user) -> apply_with_cracked_passwd \
        require_for_auth any_owned \
        if target.has_spn and not target.protected \
        elsewarn "Kerberoasting: I need an owned user to request the TGS for TARGET"
::SetLogonScript(user) -> stop
::WriteSPN(user) -> ::Kerberoasting

SessionForUser(user) -> ::LSASS_dumper
# computer -> LSASS_dumper(user)
# it means we own the computer and we know that the user has a session on it
::LSASS_dumper(user) -> apply_with_nthash

# DONT_REQ_PREAUTH: userAccountControl & 0x400000
::EnableNP(user) -> ::ASREPRoasting
::ASREPRoasting(user) -> apply_with_cracked_passwd if target.np

ReadGMSAPassword(user) -> ::ReadGMSAPassword
::ReadGMSAPassword(user) -> apply_with_aes

# Computer
AdminTo(computer) -> ::_Secretsdump
ReadLAPSPassword(computer) -> ::ReadLAPSPassword
::ReadLAPSPassword(computer) -> ::_TransformPasswordToAES
SeBackupPrivilege(computer) -> ::RegBackup
::RegBackup(computer) -> ::_TransformPasswordToAES
::CanRDP+SeBackupPrivilege(computer) -> ::_TransformPasswordToAES

# RBCD
# In the computer ldap object:
# - msDS-AllowedToActOnBehalfOfOtherIdentity: contains the allowed accounts
# - msDS-AllowedToDelegateTo: contains the list of allowed SPNs
# Griffon inverts the relation and sets the AllowedToAct right on the account
# (the parent which executes this statement)
AllowedToAct(computer) -> ::AllowedToAct if parent.has_spn
AllowedToAct(computer) -> ::U2U

# Add an account on the computer
AddAllowedToAct(computer) -> ::RBCD
::RBCD(computer) -> ::AllowedToAct    require unprotected_owned_with_spn
::RBCD(computer) -> ::AllowedToAct    require add_computer   if not opt.noaddcomputer
::RBCD(computer) -> ::U2U             require owned_user_without_spn
::U2U(computer) -> ::AllowedToAct if parent.is_user
# return aes instead of password because it's easier (otherwise the password is in hexa)
::AllowedToAct(computer) -> ::_Secretsdump \
        if not parent.sensitive and not parent.protected \
        elsewarn "PARENT -> AllowedToAct(TARGET): PARENT is sensitive or protected"

# Constrained delegations (with/without protocol transition)
# msDS-AllowedToDelegateTo contains a list of SPNs
AllowedToDelegate(computer) -> __AllowedToDelegate_ok \
        if not parent.sensitive and not parent.protected \
        elsewarn "PARENT -> AllowedToDelegate(TARGET): PARENT is sensitive or protected"

# Constrained delegations with protocol transition
# TRUSTED_TO_AUTH_FOR_DELEGATION: userAccountControl & 0x1000000
__AllowedToDelegate_ok(computer) -> ::AllowedToDelegate if parent.trustedtoauth

# Else: Constrained delegations without protocol transition (kerberos only)
# Mimic Kerberos protocol transition using reflective RBCD
# https://medium.com/tenable-techblog/how-to-mimic-kerberos-protocol-transition-using-reflective-rbcd-a4984bb7c4cb
# It also works if trustedtoauth is True but we check trustedtoauth to avoid duplicated paths
# TODO: U2U?
__AllowedToDelegate_ok(computer) -> ::SelfRBCD if not parent.trustedtoauth
::SelfRBCD(computer) -> ::AllowedToDelegate require_once unprotected_owned_with_spn_not_eq_parent
::SelfRBCD(computer) -> ::AllowedToDelegate require_once add_computer

::AllowedToDelegate(computer) -> ::_Secretsdump

WriteAccountRestrictions(computer) -> AddAllowedToAct
AddKeyCredentialLink(computer) -> ::AddKeyCredentialLink

GenericWrite(computer) -> AddAllowedToAct
# correct but it duplicates the path AddAllowedToAct
# GenericWrite(computer) -> WriteAccountRestrictions
GenericWrite(computer) -> AddKeyCredentialLink
WriteDacl(computer) -> ::DaclAccountRestrictions
WriteDacl(computer) -> ::DaclKeyCredentialLink
WriteDacl(computer) -> ::DaclAllowedToAct
# DaclAllowedToAct is an other alternative to DaclAccountRestrictions
# ::DaclAllowedToAct(computer) -> AddAllowedToAct
::DaclAccountRestrictions(computer) -> AddAllowedToAct
::DaclKeyCredentialLink(computer) -> AddKeyCredentialLink
::AddKeyCredentialLink(computer) -> apply_with_ticket

# Group
AddMember(group) -> ::AddMember
AddSelf(group) -> ::AddSelf
GenericWrite(group) -> AddMember
GenericWrite(group) -> AddSelf
WriteDacl(group) -> ::DaclMemberShips
WriteDacl(group) -> ::DaclSelf
::DaclMemberShips(group) -> AddMember
::DaclSelf(group) -> AddSelf
::AddMember(group) -> apply_group
::AddSelf(group) -> apply_group

# Domain
AllExtendedRights(domain) -> GetChanges_GetChangesAll
AllExtendedRights(domain) -> GetChanges_GetChangesInFilteredSet
GetChanges_GetChangesAll(domain) -> ::DCSync
GetChanges_GetChangesInFilteredSet(domain) -> ::DCSync if parent.is_dc
# from GPO on domain
SeBackupPrivilege(domain) -> ::RegBackup require_targets ta_dc
# from GPO (local Administrator)
AdminTo(domain) -> ::DCSync
::DCSync(domain) -> stop

# DC
GenericWrite(dc) -> AddKeyCredentialLink
AddKeyCredentialLink(dc) -> ::AddKeyCredentialLink
::AddKeyCredentialLink(dc) -> apply_with_ticket

# GPO
GenericWrite(gpo) -> ::GPOImmediateTask        if opt.allgpo \
    elsewarn "Set the option --opt allgpo to execute all GPO scenarios"
GenericWrite(gpo) -> ::GPOLogonScript          if opt.allgpo
GenericWrite(gpo) -> ::GPODisableDefender      if opt.allgpo
GenericWrite(gpo) -> ::GPOAddLocalAdmin
WriteDacl(gpo) -> ::DaclFullControl

# Execute a command
::GPOImmediateTask(gpo) => stop               require_targets ta_all_computers_in_ou
::GPOImmediateTask(gpo) => stop               require_targets ta_all_users_in_ou
# Execute a script (Startup / Logon)
::GPOLogonScript(gpo) => stop                 require_targets ta_all_computers_in_ou
::GPOLogonScript(gpo) => stop                 require_targets ta_all_users_in_ou
# Disable windows defender + disable firewall + enable RDP
::GPODisableDefender(gpo) => stop             require_targets ta_all_computers_in_ou
# Stop forking for the last predicate
# Set the parent in the local Administrators group (via the RestrictedGroups)
::GPOAddLocalAdmin(gpo) -> ::_Secretsdump     require_targets ta_all_computers_in_ou

# OU

# Unimplemented
# https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory
# https://markgamache.blogspot.com/2020/07/exploiting-ad-gplink-for-good-or-evil.html
GenericWrite(ou) -> WriteGPLink
WriteGPLink(ou) -> ::WriteGPLink
::WriteGPLink(ou) -> stop

# from GPO on an OU
SeBackupPrivilege(ou) -> ::RegBackup  require_targets ta_all_computers_in_ou
# from GPO on an OU (local Administrator)
AdminTo(ou) -> AdminTo require_targets ta_all_computers_in_ou
CanRDP+SeBackupPrivilege(ou) -> \
    ::CanRDP+SeBackupPrivilege \
    require_targets ta_all_computers_in_ou

# Last chance
__WriteDacl(any) -> ::DaclFullControl if not opt.nofull
__WriteDacl(any) -> WriteDacl         if opt.nofull
::DaclFullControl(any) -> GenericAll
Owns(any) -> __WriteDacl
::WriteOwner(any) -> Owns
WriteOwner(any) -> ::WriteOwner
