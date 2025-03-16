function New-RandomPassword($length) {
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
    $password = -join ((1..$length) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
    return ConvertTo-SecureString $password -AsPlainText -force
}

function Set-Full($parent, $target, $guid) {
    $objguid = '00000000-0000-0000-0000-000000000000'
    $inheritedobjguid = '00000000-0000-0000-0000-000000000000'
    $target_dn = $target.DistinguishedName
    $path = "AD:\$target_dn"
    $acl = Get-Acl -Path $path
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
        $parent.SID, `
        'GenericAll', `
        'Allow', `
        $objguid, `
        'All', `
        $inheritedobjguid
    $acl.AddAccessRule($ace)
    Set-Acl -Path $path -AclObject $acl
}

$DOMAIN = Get-ADDomain -Current LocalComputer

$FQDN = $DOMAIN.DNSRoot
$DOMAIN_DN = $DOMAIN.DistinguishedName
$OU_MAIN = 'OU=Main Department,' + $DOMAIN_DN
$OU_SERVERS = 'OU=Servers,' + $DOMAIN_DN

$USERS = @(
    'Alyx', 'Billy', 'Charly', 'Dexy', 'Emmy', 'Felyx', 'Geffrey',
    'Helya', 'Iryn', 'Jessy', 'Kelly', 'Lyam', 'Malory', 'Nyna',
    'Oryon', 'Perry', 'Quincy', 'Rey', 'Skye', 'Tracy', 'Uxya',
    'Vally', 'Wryn', 'Xyla', 'Yoan', 'Zoey', 'AGENT', 'PREPROD_USER'
)

$GROUPS = @('Direction', 'Sys', 'Mainteners', 'Secretary', 'Marketing')

#$guidmap = @{}
#$schemaPath = Get-ADRootDSE
#Get-ADObject -SearchBase $schemaPath.SchemaNamingContext `
#    -LDAPFilter '(schemaidguid=*)' `
#    -Properties lDAPDisplayName,schemaIDGUID | 
#    % {$guidmap[$_.lDAPDisplayName]=[System.GUID]$_.schemaIDGUID}

New-ADOrganizationalUnit -Name Servers `
    -ProtectedFromAccidentalDeletion $false
New-ADOrganizationalUnit -Name 'Main Department' `
    -ProtectedFromAccidentalDeletion $false

for ($i = 0; $i -lt $USERS.length; $i++) {
    $pass = New-RandomPassword 20
    New-ADUser -Name $USERS[$i] `
        -Enabled $true `
        -Path $OU_MAIN `
        -ChangePasswordAtLogon $false `
        -AccountPassword $pass `
        -PasswordNeverExpires $true
}

for ($i = 0; $i -lt $GROUPS.length; $i++) {
    New-ADGroup -Name $GROUPS[$i] `
        -Path $OU_MAIN `
        -GroupCategory Security `
        -GROUPScope Global
}

Move-ADObject -Identity (Get-ADComputer -identity PROD) -TargetPath $OU_SERVERS
Move-ADObject -Identity (Get-ADComputer -identity PREPROD) -TargetPath $OU_SERVERS
Move-ADObject -Identity (Get-ADComputer -identity DATABASE) -TargetPath $OU_SERVERS
Move-ADObject -Identity (Get-ADComputer -identity WEBSITE) -TargetPath $OU_SERVERS

New-ADServiceAccount -Name SVC `
    -PrincipalsAllowedToRetrieveManagedPassword @('PREPROD$', 'PROD$') `
    -DNSHostName "SVC.$FQDN" `
    -ManagedPasswordIntervalInDays 30 `
    -Enabled $true

Set-ADDefaultDomainPasswordPolicy -identity $FQDN -MinPasswordLength 1 -ComplexityEnabled $false
Set-ADAccountPassword -Identity Alyx -Reset `
    -NewPassword (ConvertTo-SecureString admin01. -AsPlainText -force)
Set-ADAccountPassword -Identity Tracy -Reset `
    -NewPassword (ConvertTo-SecureString Spring2025 -AsPlainText -force)
Add-ADGroupMember -Identity Direction -Members Geffrey
Add-ADGroupMember -Identity Sys -Members Malory,Kelly,Alyx,AGENT
Add-ADGroupMember -Identity Mainteners -Members Dexy,Rey
Add-ADGroupMember -Identity Secretary -Members Skye
Add-ADGroupMember -Identity Marketing -Members Emmy,Wryn,Iryn,Billy,Tracy
Add-ADGroupMember -Identity 'Account Operators' -Members Malory
Add-ADGroupMember -Identity 'Backup Operators' -Members Malory
Add-ADGroupMember -Identity 'Key Admins' -Members Malory
Add-ADGroupMember -Identity 'Domain Admins' -Members Alyx
Set-Full (Get-ADGroup -Identity Sys) (Get-ADGroup -Identity Direction)
Set-Full (Get-ADGroup -Identity Sys) (Get-ADGroup -Identity Mainteners)
Set-Full (Get-ADGroup -Identity Sys) (Get-ADGroup -Identity Secretary)
Set-Full (Get-ADGroup -Identity Marketing) (Get-ADComputer -Identity WEBSITE)
# Set-Full (Get-ADUser -Identity Rey) (Get-ADObject -Identity $OU_SERVERS)
Set-Full (Get-ADGroup -Identity Mainteners) (Get-ADServiceAccount -Identity SVC)
Set-Full (Get-ADGroup -Identity Mainteners) (Get-ADComputer -Identity WEBSITE)
Set-Full (Get-ADUser -Identity PREPROD_USER) (Get-ADComputer -identity PREPROD)
Set-Full (Get-ADServiceAccount -Identity SVC) (Get-ADComputer -identity PROD)
Set-ADUser -Identity AGENT -ServicePrincipalNames @{Add='LOCAL/AGENT'}
# add spn if added with addcomputer.py
Set-ADComputer -Identity PREPROD$ -ServicePrincipalNames @{Add='HOST/PREPROD'}
Set-ADComputer -Identity PROD$ -ServicePrincipalNames @{Add='HOST/PROD'}
Set-ADComputer -Identity DATABASE$ -ServicePrincipalNames @{Add='HOST/DATABASE'}
Set-ADAccountPassword -Identity AGENT -Reset `
    -NewPassword (ConvertTo-SecureString agent -AsPlainText -force)
Set-ADComputer -Identity PREPROD `
    -Add @{'msDS-AllowedToDelegateTo'=@('MSSQL/DATABASE', "MSSQL/DATABASE.$FQDN")}
Set-ADComputer -Identity PROD `
    -Add @{'msDS-AllowedToDelegateTo'=@('MSSQL/DATABASE', "MSSQL/DATABASE.$FQDN")}
Set-ADACCountControl -Identity PREPROD_USER -PasswordNotRequired $true
Set-ADAccountPassword -Identity PREPROD_USER -Reset `
    -NewPassword (New-Object System.Security.SecureString)
Set-ADComputer -Identity DATABASE -TrustedForDelegation $true
Set-ADACCountControl -Identity PREPROD$ -TrustedToAuthForDelegation $true
$gpo = New-GPO -name INSTALLER | new-gplink -target $OU_SERVERS |
    Set-GPPermissions -PermissionLevel gpoedit -TargetName "Sys" -TargetType Group
