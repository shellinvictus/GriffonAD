# FullControl, let Griffon choose the best scenario
GenericAll(any) -> AllExtendedRights
GenericAll(any) -> GenericWrite

# Unconstrained delegation
# It could be any computer instead of the dc. If we coerce the dc we are admin!
# TODO: delegation parameter on a user (actually only on computer)
AllowedToDelegate(many) -> ::AllowedToDelegateToAny \
        require_targets ta_dc
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

# TODO (already managed in lib/database.py)
# Distributed COM Users
# Cryptographic Operators
# Storage Replica Administrators

# 'Backup Operators'
SeBackup(many) -> ::SeBackup \
        require_targets ta_dc \
        if 551 in parent.groups
::SeBackup(dc) -> stop

PasswordNotReqd(user) -> apply_with_blank_passwd
PasswordNotReqd(computer) -> apply_with_blank_passwd

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
::ASREPRoasting(user) -> apply_with_cracked_passwd if target.np
::EnableNP(user) -> ::ASREPRoasting
::WriteSPN(user) -> ::Kerberoasting

# Computer

ReadLAPSPassword(computer) -> ::ReadLAPSPassword
::ReadLAPSPassword(computer) -> apply_with_aes

# RBCD
AllowedToAct(computer) -> ::AllowedToAct if parent.has_spn
AllowedToAct(computer) -> ::U2U
AddAllowedToAct(computer) -> ::RBCD
::RBCD(computer) -> ::AllowedToAct    require unprotected_owned_with_spn
::RBCD(computer) -> ::AllowedToAct    require add_computer   if not opt.noaddcomputer
::RBCD(computer) -> ::U2U             require owned_user_without_spn
::U2U(computer) -> ::AllowedToAct if parent.is_user
# return aes instead of password because it's easier (otherwise the password is in hexa)
::AllowedToAct(computer) -> apply_with_aes \
        if not parent.sensitive and not parent.protected \
        elsewarn "PARENT -> AllowedToAct(TARGET): PARENT is sensitive or protected"

AllowedToDelegate(computer) -> __AllowedToDelegate_ok \
        if not parent.sensitive and not parent.protected \
        elsewarn "PARENT -> AllowedToDelegate(TARGET): PARENT is sensitive or protected"

# Constrained delegations with protocol transition
# trustedtoauth = TRUSTED_TO_AUTH_FOR_DELEGATION
__AllowedToDelegate_ok(computer) -> ::AllowedToDelegate if parent.trustedtoauth

# Constrained delegations without protocol transition (kerberos only)
# SelfRBCD: parent modifies its own rbcd and allows to delegate from an other object (the require)
# Then a TGS (impersonated to admin) is requested by the require and passed to AllowedToDelegate
# It also works if trustedtoauth is True but it's to avoid duplicated paths
# TODO: U2U?
__AllowedToDelegate_ok(computer) -> ::SelfRBCD if not parent.trustedtoauth
::SelfRBCD(computer) -> ::AllowedToDelegate require_once unprotected_owned_with_spn_not_eq_parent
::SelfRBCD(computer) -> ::AllowedToDelegate require_once add_computer

# return aes instead of password because it's easier (otherwise the password is in hexa)
::AllowedToDelegate(computer) -> apply_with_aes

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

::ReadGMSAPassword(user) -> apply_with_aes
ReadGMSAPassword(user) -> ::ReadGMSAPassword

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
# Set the parent in the local Administrators group
::GPOAddLocalAdmin(gpo) -> apply_with_aes     require_targets ta_all_computers_in_ou

# OU: not implemented
GenericWrite(ou) -> WriteGPLink
WriteGPLink(ou) -> ::WriteGPLink
::WriteGPLink(ou) -> stop

# Last chance
__WriteDacl(any) -> ::DaclFullControl if not opt.nofull
__WriteDacl(any) -> WriteDacl         if opt.nofull
::DaclFullControl(any) -> GenericAll
Owns(any) -> __WriteDacl
::WriteOwner(any) -> Owns
WriteOwner(any) -> ::WriteOwner
