GriffonAD
=========

![griffon version](/assets/version-0.6.1.svg?raw=true)
![gpl](/assets/gpl.svg?raw=true)
![offsec](/assets/offsec.svg?raw=true)
![python](/assets/python.svg?raw=true)

A new tool to exploit bad configurations in Active Directory (based on
Bloodhound json files).

Nothing is executed on the target, it generates commands for you and you just
have to copy-paste these commands (with a few modifications). The main goal is
to let the user a full control on what is modified: all commands are fully
commented and parameters to change are highlighted in red.

Griffon supports many scenarios, take a look into [config.ml](config.ml) !

Challenge
---------

You can play with Griffon by installing a vulnerable AD: [lab](/lab/README.md).


Installation
============

    pip install -r requirements.txt
    cp tools/dacledit.py path_to_impacket/examples/


4 steps to Domain Admin
=======================

![steps](/assets/steps.svg?raw=true)

Step 1
------

Retrieve Bloodhound json files:

    ./bloodhound.py -u USER -d DOMAIN -p PASSWORD -ns DNS_IP -c DCOnly

> [!NOTE]
> Try with the option `--fakedb` or use jsons in [lab](/lab/README.md)`

Step 2: ACLs analysis
---------------------

Only interesting users are kept. If you have underlined yellowed users, that
sounds good!

    ./griffon.py *.json

![rights](/assets/hvt.png?raw=true)

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

![graph](/assets/graph.png?raw=true)

> [!TIP]
> About the `many` target: it means that you can have multiple targets.
> It depends of the right you have:
> 
> - `GenericAll`: on all users and groups with admincount=0 if in the Account
> Operators group
> - `AddKeyCredentialLink`: on all users with admincount=0 if in Key Admins group
> - `AllowedToDelegate`: means an unconstrained delegation
> - `SeBackupPrivilege`: can access to DC/C$ (theorically also on all computers, does it requires RDP?)

> [!NOTE]
> Supported ACEs here: [supported](/doc/supported.md)

Step 3: Search paths
--------------------

From owned users, it reads the text file `owned`.

> [!TIP]
> Line format of the file `owned`:
>
> `SAMACCOUNTNAME:TYPE:SECRET`
>
> - `SAMACCOUNTNAME` (insensitive)
> - `TYPE` = `password` | `aes` | `nt` (passwords are in hex for computers)
>
> The separator can be changed with the option `--sep` (you can put a string with
> more than one character).

    cat owned
    alice:password:User123-
    WORKSTATION_EXAMPLE$:password:9ddb7bfd6a2e49e184d36bd7...

    ./griffon.py *.json --fromo

![fromo](/assets/fromo.png?raw=true)

Other options:

- `--fromv`: from vulnerable users (NP users (only unprotected users), password
not required,  and kerberoastable users)
- `--from USER`: test paths from a user
- `--rights`: this is a flag to add with previous options. It allows you to view
rights instead of actions in paths (an action is prefixed by `::`)
- `--onlyadmin`: display only paths to domain admin (paths prefixed by the
- `--no-follow`: don't try to continue on owned targets but display all available
scenarios for one target.

> [!NOTE]
> With `--fakedb` try: `--fromo`, `--from 'desktop-1$'`, `--from 'server-1$'`,
> `--from 'server-2$'`, `--fromv`.


Step 4: Generate the script
---------------------------

    ./griffon.py *.json --fromo -s 001 --dc-ip 10.0.0.2

![script](/assets/script.png?raw=true)


Embedded tools
==============

- `./tools/attr.py`: generic script to modify one ldap attribute
- `./tools/addspn.py`: modify the attribute servicePrincipalName
- `./tools/logonscript.py`: modify the attribute msTSInitialProgram
- `./tools/addmember.py`: modify the attribute member
- `./tools/toggleNP.py`: enable or disable the donotpreauth flag
- `./tools/getbyname.py`: get all attributes of one object
- `./tools/readpol.py`: export Registry.pol to json and rewrite the pol file 
- `./tools/xmltask.py`: generate an xml for schedule task (mimic a real xml)
- `./tools/scriptsini.py`: re-format a scripts.ini with correct encoding
- `./tools/gpttmpl.py`: re-format a GptTmpl.inf with correct encoding
- `./tools/readgmsa.py` (from gMSADumper.py): simplified and login parameters uniformization
- `./tools/aesKrbKeyGen.py`: login parameters uniformization
- `./tools/dacledit.py`: -mask + bugfix (pull request to impacket in review)


Customization
=============

The file config.ml is fully customizable, you can set your preferences based on
scenario priorities (more at [config.md](/doc/config.md)). You can also define
conditional predicates by adding flags with the parameter `--opt`. For example,
a flag was already defined in config.ml if you don't wan't to use the
ForceChangePassword. It will then fallback on the default next scenario which
is AddKeyCredentialLink.

    ./griffon.py *.json --fromo --opt noforce 

Available options:

- `--opt noforce`: no ForceChangePassword
- `--opt noaddcomputer`: don't use the scenario 'add a computer' with RBCD
- `--opt allgpo`: iterates on all gpo scenarios, by default it will use only the GPOAddLocalAdmin
- `--opt nofull`: if we have WriteDacl, give only specific right to continue (not FullControl)
- `--opt allkeys`: for the Key Admins group (+Enterprise), iterate on all users and computers


Tests
=====

- badblood: 10000 users, 3000 computers, 100 groups
    - Json parsing + analysis = 2 seconds (4 cores, 8 threads, 1.6GHz)
    - Memory consumption peak = 150 MiB
    - the js graph is very slow when permissions are too random
- tested only with bloodhound-python


Credits
=======

- Impacket (the kerberos login function inside ./tools/ldap_auth.py is a copy)
- https://github.com/Tw1sm/aesKrbKeyGen
- https://github.com/micahvandeusen/gMSADumper
- Bloodhound for the opsec comments


Disclaimer
==========

> [!CAUTION]
> GRIFFON IS FOR EDUCATIONAL OR RESEARCH PURPOSES ONLY. THE AUTHOR IS NOT
> RESPONSIBLE FOR ANY ILLEGAL ACTIVITIES AND DAMAGES.
