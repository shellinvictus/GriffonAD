set AllowChangePassword = true
set DefaultSetFullControl = true
set AllAddKeyCredentialLink = false
set AllowAddComputer = true
set DoGPOAddLocalAdmin = true
set DoGPOLogonScript = false
set DoGPOImmediateTask = false
set DoGPODisableDefender = false

# Group RIDs
set BACKUP_OPERATORS = 551
set ACCOUNT_OPERATORS = 548
set KEY_ADMINS = 526
set ENTERPRISE_KEY_ADMINS = 527
set REMOTE_DESKTOP_USERS = 555

#
# Convention:
# ::NAME(target) = this is an action (generated code is in templates/)
# __NAME(target) = this is a temporary state
# NAME(target) = this is a bloodhound right
#
# The parent is the object we own (we have his password or a ticket) and the one
# which has the right on the target.
# Full documentation here: doc/config.md
#

# Private actions
# The password is in hexa, it's easier to manage the computer with
# its AES key
::_Secretsdump(computer) -> ::_TransformPasswordToAES
::_TransformPasswordToAES(any) -> apply_with_aes

# GMSA first because below AllExtendedRights is checked before GenericWrite
# -> prefer AddGMSAReader instead of ForceChangePassword
GenericAll(user) -> ::AddGMSAReader if target.is_gmsa
GenericWrite(user) -> ::AddGMSAReader if target.is_gmsa
ReadGMSAPassword(user) -> ::ReadGMSAPassword
::AddGMSAReader(user) -> ::ReadGMSAPassword
::ReadGMSAPassword(user) -> apply_with_aes

# FullControl, let Griffon choose the best scenario
# any != many
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

# 'Account Operators'
GenericAll(many) -> GenericAll \
    require_targets ta_users_and_groups_without_admincount \
    if ACCOUNT_OPERATORS in parent.groups

# 'Key Admins' or 'Enterprise Key Admins'
AddKeyCredentialLink(many) -> ::AddKeyCredentialLink   \
    require_targets ta_users_without_admincount \
    if AllAddKeyCredentialLink and \
        (KEY_ADMINS in parent.groups or ENTERPRISE_KEY_ADMINS in parent.groups) \
    elsewarn "Set the flag AllAddKeyCredentialLink in config.ml to execute the scenario AddKeyCredentialLink(many)"

# PASSWD_NOTREQD: userAccountControl & 0x20
::BlankPassword(user) -> apply_with_blank_passwd
::BlankPassword(computer) -> apply_with_blank_passwd

::CanRDP_RegSave(dc) -> apply_with_aes
::CanRDP_RegSave(computer) -> apply_with_aes

# User

WriteUserAccountControl(user) -> ::EnableUser if target.disabled
::EnableUser(user) -> restart

ForceChangePassword(user) -> ::ForceChangePassword if not target.disabled
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
::ForceChangePassword(user) -> apply_with_forced_passwd \
    if AllowChangePassword and not target.disabled
::AddKeyCredentialLink(user) -> apply_with_ticket if not target.disabled
::Kerberoasting(user) -> apply_with_cracked_passwd \
    require_for_auth any_owned \
    if target.has_spn and not target.protected and not target.disabled \
    elsewarn "warning: TARGET seems to be kerberoastable, but I need an owned user to request the TGS"
::SetLogonScript(user) -> stop if not target.disabled
::WriteSPN(user) -> ::Kerberoasting if not target.disabled

SessionForUser(user) -> ::LSASS_dumper
# computer -> LSASS_dumper(user)
# it means we own the computer and we know that the user has a session on it
::LSASS_dumper(user) -> apply_with_nthash

# DONT_REQ_PREAUTH: userAccountControl & 0x400000
::EnableNP(user) -> ::ASREPRoasting
::ASREPRoasting(user) -> apply_with_cracked_passwd if target.np

# Computer
AdminTo(computer) -> ::_Secretsdump
ReadLAPSPassword(computer) -> ::ReadLAPSPassword
::ReadLAPSPassword(computer) -> ::_TransformPasswordToAES
::RegBackup(computer) -> ::_TransformPasswordToAES

# RBCD
# In the computer ldap object:
# - msDS-AllowedToActOnBehalfOfOtherIdentity: contains the allowed accounts
# - msDS-AllowedToDelegateTo: contains the list of allowed SPNs
# Griffon inverts the relation and sets the AllowedToAct right on the account
# (the parent which executes this statement)
AllowedToAct(computer) -> ::AllowedToAct if parent.has_spn
AllowedToAct(computer) -> ::U2U

AddAllowedToAct(computer) -> ::RBCD
::RBCD(computer) -> ::AllowedToAct    require unprotected_owned_with_spn
::RBCD(computer) -> ::AllowedToAct    require add_computer   if AllowAddComputer
::RBCD(computer) -> ::U2U             require owned_user_without_spn
::U2U(computer) -> ::AllowedToAct if parent.is_user
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
__AllowedToDelegate_ok(computer) => ::SPNJacking        if parent.trustedtoauth
__AllowedToDelegate_ok(computer) -> ::AllowedToDelegate if parent.trustedtoauth

# else
# Constrained delegations without protocol transition (kerberos only)
#
# Mimic Kerberos protocol transition using reflective RBCD
# https://medium.com/tenable-techblog/how-to-mimic-kerberos-protocol-transition-using-reflective-rbcd-a4984bb7c4cb
#
# It also works if trustedtoauth is True but we check trustedtoauth to avoid
# duplicated paths
#
# Here we use the 'require_once' and not the 'require' like the normal RBCD
# For the RBCD: the 'require' is used to authenticate after
# Here we just need an object to create the SelfRBCD, then we don't use it anymore
#
# TODO: U2U?
__AllowedToDelegate_ok(computer) -> ::SelfRBCD if not parent.trustedtoauth
::SelfRBCD(computer) -> __NextSelfRBCD require_once unprotected_owned_with_spn_not_eq_parent
::SelfRBCD(computer) -> __NextSelfRBCD require_once add_computer if AllowAddComputer
__NextSelfRBCD(computer) => ::SPNJacking
__NextSelfRBCD(computer) -> ::AllowedToDelegate

::AllowedToDelegate(computer) -> ::_Secretsdump
::SPNJacking(computer) -> ::AllowedToDelegate require_targets ta_spn_jacking_requirements

WriteAccountRestrictions(computer) -> AddAllowedToAct
AddKeyCredentialLink(computer) -> ::AddKeyCredentialLink

GenericWrite(computer) -> AddAllowedToAct
# correct but it duplicates the path AddAllowedToAct
# GenericWrite(computer) -> WriteAccountRestrictions
GenericWrite(computer) -> AddKeyCredentialLink
WriteDacl(computer) -> ::DaclAccountRestrictions
WriteDacl(computer) -> ::DaclKeyCredentialLink
# DaclAllowedToAct is an other alternative to DaclAccountRestrictions
# WriteDacl(computer) -> ::DaclAllowedToAct
# ::DaclAllowedToAct(computer) -> AddAllowedToAct
::DaclAccountRestrictions(computer) -> AddAllowedToAct
::DaclKeyCredentialLink(computer) -> AddKeyCredentialLink
::AddKeyCredentialLink(computer) -> apply_with_ticket

# Group
AddMember(group) -> ::AddMember
AddSelf(group) -> ::AddMember
GenericWrite(group) -> AddMember
# GenericWrite(group) -> AddSelf
WriteDacl(group) -> ::DaclMemberShips
WriteDacl(group) -> ::DaclSelf
::DaclMemberShips(group) -> AddMember
::DaclSelf(group) -> AddSelf
::AddMember(group) -> apply_group

# Domain
AllExtendedRights(domain) -> GetChanges_GetChangesAll
AllExtendedRights(domain) -> GetChanges_GetChangesInFilteredSet
GetChanges_GetChangesAll(domain) -> ::DCSync
GetChanges_GetChangesInFilteredSet(domain) -> ::DCSync if parent.is_dc
::DCSync(domain) -> stop
# from GPOs
AdminTo(domain) -> ::DCSync # local Administrator

# From a GPO applied on the domain or if the user is in the BO group
# We can also target all computers
SeBackupPrivilege(domain) -> ::RegBackup \
    require_targets ta_dc \
    if BACKUP_OPERATORS in parent.groups

# FIXME: a simple user cannot RDP on the DC even if he is
# in the RDP Users group?
SeBackupPrivilege(domain) -> ::CanRDP_RegSave \
    require_targets ta_all_computers_in_domain \
    if BACKUP_OPERATORS not in parent.groups and \
        REMOTE_DESKTOP_USERS in parent.groups

# DC
GenericWrite(dc) -> AddKeyCredentialLink
AddKeyCredentialLink(dc) -> ::AddKeyCredentialLink
::AddKeyCredentialLink(dc) -> apply_with_ticket
::RegBackup(dc) -> apply_with_aes

# GPO
GenericWrite(gpo) -> ::GPOLogonScript          if DoGPOLogonScript
GenericWrite(gpo) -> ::GPOImmediateTask        if DoGPOImmediateTask
GenericWrite(gpo) -> ::GPODisableDefender      if DoGPODisableDefender
GenericWrite(gpo) -> ::GPOAddLocalAdmin        if DoGPOAddLocalAdmin
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

# From a GPO applied on an OU or on the 'Domain Controllers' container
SeBackupPrivilege(ou) -> __IsInBackupGroup \
    if BACKUP_OPERATORS in parent.restricted_groups_rids

SeBackupPrivilege(ou) -> __NotInBackupGroup \
    if BACKUP_OPERATORS not in parent.restricted_groups_rids

AdminTo(ou) -> AdminTo require_targets ta_all_computers_in_ou

__IsInBackupGroup(ou) -> ::RegBackup \
    require_targets ta_one_dc_in_ou \
    if target.sid == db.domain_controllers_guid

# Not on the 'Domain Controllers' container
__IsInBackupGroup(ou) -> ::RegBackup \
    require_targets ta_all_computers_in_ou \
    if target.sid != db.domain_controllers_guid

# The user has only the SeBackup privilege and is NOT in the Backup
# Operators group, then we need to RDP to enable the backup privilege
# It seems that the access is denied on the DC (if the GPO is applied on
# the 'Domain Controllers' container
__NotInBackupGroup(ou) -> ::CanRDP_RegSave \
    require_targets ta_all_computers_in_ou \
    if REMOTE_DESKTOP_USERS in parent.restricted_groups_rids

# Unimplemented
# https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory
# https://markgamache.blogspot.com/2020/07/exploiting-ad-gplink-for-good-or-evil.html
GenericWrite(ou) -> WriteGPLink
WriteGPLink(ou) -> ::WriteGPLink
::WriteGPLink(ou) -> stop

# Last chance
__WriteDacl(any) -> ::DaclFullControl if DefaultSetFullControl
__WriteDacl(any) -> WriteDacl         if not DefaultSetFullControl
::DaclFullControl(any) -> GenericAll
Owns(any) -> __WriteDacl
::WriteOwner(any) -> Owns
WriteOwner(any) -> ::WriteOwner
