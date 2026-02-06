GriffonAD
=========

![griffon version](/griffonad/assets/version-0.6.7.svg?raw=true)
![gpl](/griffonad/assets/gpl.svg?raw=true)
![offsec](/griffonad/assets/offsec.svg?raw=true)
![python](/griffonad/assets/python.svg?raw=true)

A new tool to exploit bad configurations in Active Directory (based on
Bloodhound json files).

Nothing is executed on the target, it generates commands for you and you just
have to copy-paste these commands (with a few modifications). The main goal is
to let the user a full control on what is modified: all commands are fully
commented and parameters to change are highlighted in red.

Griffon supports many scenarios, take a look into [config.ml](griffonad/config.ml) !

Challenge
---------

You can play with Griffon by installing a vulnerable AD: [lab](/lab/README.md).


Installation
============

You will need the latest version of impacket to use dacledit.py on some
scenarios of GriffonAD. The expected commit is fortra/impacket@bf2d749f49588183b7aee732276440fe018a417d.

## Installing with Venv

    python3 -m venv venv
    source venv/bin/activate
    git clone https://github.com/shellinvictus/GriffonAD
    git clone https://github.com/fortra/impacket
    cd impacket
    pip install -r requirements.txt
    python3 setup.py install
    cd ../GriffonAD
    pip install -r requirements.txt

## Installing with pipx
Make sure your current working directory is inside GriffonAD then run:

    pipx install .

    griffon --help

## Uninstalling GriffonAD with pipx
    pipx uninstall griffon

4 steps to Domain Admin
=======================

![steps](/griffonad/assets/steps.svg?raw=true)

Step 1
------

Retrieve Bloodhound json files with a collector (untested with SharpHound):

    ./bloodhound.py -u USER -d DOMAIN -p PASSWORD -ns DNS_IP -c DCOnly

Step 2: ACLs analysis
---------------------

Only interesting users are kept. If you have underlined yellowed users, that
sounds good!

    griffon *.json
    or
    griffon bloodhound.zip

- yellow user = can become an admin
- red user = an admin

![rights](/griffonad/assets/hvt.png?raw=true)

Other options:

- `--select FILTER`: display only targets where the name starts with FILTER
- `--groups`: display all groups with their rights (+ `--members`)
- `--ous`: display all ous with their gpo links (+ `--members`)
- `--graph`: open a js graph to view relations between objects
- `--sysvol PATH`: search for local members (Backup Operators and Administrators) and local privileges

> [!NOTE]
> Example on how Griffon displays the information with `--sysvol`:
>
> If there is a GPO applied on the OU `MY_OU` where Alice is defined as a member
> of Administrators (Policies / Windows Settings / Restricted Groups) and Alice
> has the privilege SeDebug, then new rights will be available:
>
>     Alice
>         (RestrictedGroups, [Administrators] -> MY_OU@CORP.LOCAL)
>         (AdminTo, MY_OU@CORP.LOCAL)
>         (SeDebugPrivilege, MY_OU@CORP.LOCAL)
>
> To retrieve SYSVOL, you can use this command:
>
>     echo -e "recurse\nprompt\nmget *" | smbclient -U 'DOMAIN/USER%PASSWORD' '\\IP\SYSVOL'

![graph](/griffonad/assets/graph.png?raw=true)

> [!TIP]
> About the `many` target: it means that you can have multiple targets.
> It depends of the right you have:
> 
> - `GenericAll`: on all users and groups with admincount=0 if the user is in the Account
> Operators group
> - `AddKeyCredentialLink`: on all users with admincount=0 if the user is in the Key Admins group
> - `AllowedToDelegate`: means an unconstrained delegation
> - `SeBackupPrivilege`: can access to DC/C$ (`FIXME` theorically also on all computers, does it requires RDP?)

> [!NOTE]
> Supported ACEs here: [supported](/doc/supported.md)

Step 3: Search paths
--------------------

From owned users, it reads the text file `owned`.

> [!TIP]
> Line format is:
>
> `SAMACCOUNTNAME:TYPE:SECRET`
>
> - `SAMACCOUNTNAME` : insensitive case, a computer ends with a `$`
> - `TYPE` = `password` | `aes` | `nt`
>
> A password for a computer MUST BE set in hex. The separator can be changed with the
> option `--sep` (you can put a string with more than one character).

    # Warning: if you put multiple secrets for one user, only the last one will be kept!
    cat owned
    WORKSTATION$:password:0d3c811f9c817a0cf3...
    Tracy:aes:1D5A2C4E52584F0A699D0853D2EBF8EBDB6713183D9A303AB8AAACB87818BDEE
    Tracy:aes:6AD07E6F0F25DE8906D444EEC50BD83C
    Tracy:nt:4869b177d39962457ff9fb185b35c5ba
    Tracy:password:Spring2025

    griffon lab/json/* --fromo

![fromo](/griffonad/assets/fromo.png?raw=true)

Other options:

- `--fromv`: from vulnerable users (NP users (only for unprotected users), blank
passwords, and kerberoastable users)
- `--from USER`: test paths from an arbitrary user
- `--rights`: view ACEs names instead of actions
- `--onlyadmin`: display only paths to domain admin (prefixed by `+`)
- `--no-follow`: don't try to continue on new owned targets but display all available
scenarios for the current target. For example: with a GenericAll on a user, you can
reset the password, add a shadow key credential... If this option is unset, it will
take the first scenario (in config.ml it's ForceChangePassword). With this option,
you will see all scenarios but without continuing the path on the new owned target.

> [!TIP]
> About the output:
>
> A path is a succession of action(s) to exploit one or many ACEs. The format is:
> `OWNED -> [REQUIRED_TARGET]::ACTION[REQUIRED_OBJECT](TARGET):RESULT_OBJECT`
>
> - `OWNED`: initialially from the `owned` file (or the user sets with `--from`)
> - `REQUIRED_TARGET` (optional): in some rare cases, Griffon choose a new target (check require_targets
> - in config.ml
> - `::ACTION`: one or many successive actions to exploit the ACE
> - `REQUIRED_OBJECT` (optional): sometimes the action needs another object to exploit the ACE
> - `TARGET`: the object we wan't to own
> - `RESULT_OBJECT`: it's often the same as `TARGET`, it means that now `TARGET` is owned

Step 4: Generate the script
---------------------------

    griffon lab/json/* --fromo -s0 --dc-ip 10.0.0.2

![script](/griffonad/assets/script.png?raw=true)


Embedded tools
==============

- `griffonad/tools/attr.py`: generic script to modify one ldap attribute
- `griffonad/tools/addspn.py`: modify the attribute servicePrincipalName
- `griffonad/tools/logonscript.py`: modify the attribute msTSInitialProgram
- `griffonad/tools/addmember.py`: modify the attribute member
- `griffonad/tools/toggleNP.py`: enable or disable the donotpreauth flag
- `griffonad/tools/getbyname.py`: get all attributes of one object
- `griffonad/tools/readpol.py`: export Registry.pol to json and rewrite the pol file 
- `griffonad/tools/xmltask.py`: generate an xml for schedule task (mimic a real xml)
- `griffonad/tools/scriptsini.py`: re-format a scripts.ini with correct encoding
- `griffonad/tools/gpttmpl.py`: re-format a GptTmpl.inf with correct encoding
- `griffonad/tools/readgmsa.py` (from gMSADumper.py): simplified and login parameters uniformization
- `griffonad/tools/aesKrbKeyGen.py`: login parameters uniformization


Customization
=============

The file config.ml is fully customizable, you can set your preferences based on
scenario priorities (more at [config.md](/doc/config.md)). You can also define
conditional predicates by adding flags with the parameter `--opt`. For example,
a flag was already defined in config.ml if you don't wan't to use the
ForceChangePassword. It will then fallback on the default next scenario which
is AddKeyCredentialLink.

    griffon lab/json/* --from MALORY --opt noforce

Available options:

- `--opt noforce`: no ForceChangePassword
- `--opt noaddcomputer`: don't use the scenario 'add a computer' with RBCD
- `--opt allgpo`: iterates on all gpo scenarios, by default it will use only the GPOAddLocalAdmin
- `--opt nofull`: if we have WriteDacl, give only specific right to continue (not FullControl)
- `--opt allkeys`: for the Key Admins group (+Enterprise), iterate on all users and computers

You can also write options in `config.py`.


Tests
=====

- badblood: 10000 users, 3000 computers, 100 groups
    - Json parsing + analysis = 2 seconds (4 cores, 8 threads, 1.6GHz)
    - Memory consumption peak = 150 MiB
    - the js graph is very slow when permissions are too random
- bloodhound-python
- rusthound


Credits
=======

- Impacket (the kerberos login function inside griffonad/tools/ldap_auth.py is a copy)
- https://github.com/Tw1sm/aesKrbKeyGen
- https://github.com/micahvandeusen/gMSADumper
- Bloodhound for the opsec comments


Disclaimer
==========

> [!CAUTION]
> GRIFFON IS FOR EDUCATIONAL OR RESEARCH PURPOSES ONLY. THE AUTHOR IS NOT
> RESPONSIBLE FOR ANY ILLEGAL ACTIVITIES AND DAMAGES.
