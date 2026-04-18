GriffonAD
=========

![griffon version](/griffonad/assets/version-0.6.21.svg?raw=true)
![gpl](/griffonad/assets/gpl.svg?raw=true)
![offsec](/griffonad/assets/offsec.svg?raw=true)
![python](/griffonad/assets/python.svg?raw=true)

<img height="300" alt="griffon" src="https://github.com/user-attachments/assets/104b5742-168e-4e07-baa6-fb16f2011831" />

Generate low-level commands (mainly impacket) to exploit the Active
Directory easily: learn and control every steps. Interactive mode available
to select scenarios.

<img width="985" alt="path_kerb_svc" src="https://github.com/user-attachments/assets/cfc85acc-8f3c-41d4-bb16-7bb3ce49bfd5" />

[![asciicast](https://asciinema.org/a/860452.svg)](https://asciinema.org/a/860452)

Challenge
---------

You can play with Griffon by installing a vulnerable AD: [lab](/lab/README.md).
Write-ups are here on the [wiki](https://github.com/shellinvictus/GriffonAD/wiki).

Mind map
--------

Here is an example of all implemented scenarios for a user
([more here](https://github.com/shellinvictus/GriffonAD/wiki/GriffonAD-mind-map)):

<img width="4184" alt="user" src="https://github.com/user-attachments/assets/b189ee9b-a293-45c7-86fa-f180c9cb13c8" />

Installation
============

<details>
    
<summary>Installation</summary>

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
</details>


4 steps to Domain Admin
=======================

<img alt="steps" src="/griffonad/assets/steps.svg?raw=true" width="500">

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

- yellow user = a path to domain admin exists
- red user = an admin

Other options:

- `--select FILTER`: display only targets where the name starts with FILTER
- `--groups`: display all groups with their rights (+ `--members`)
- `--ous`: display all ous with their gpo links (+ `--members`)
- `--graph`: open a js graph to view relations between objects
- `--sysvol PATH`: search for local members (Backup Operators and Administrators) and local privileges
- `--desc`: display object descriptions

<details>
<summary>More on --sysvol</summary>

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

</details>

<details>
<summary>More on the `many` target</summary>

> [!NOTE]
> About the `many` target: it means that you can have multiple targets.
> It depends of the right you have:
> 
> - `GenericAll` = user is in the Account Operators group
> - `AddKeyCredentialLink`: user is in the Key Admins group
> - `SeBackupPrivilege`: user is in the Backup Operators group
> - `AllowedToDelegate`: unconstrained delegation

</details>

<img alt="graph" src="/griffonad/assets/graph.png?raw=true" width="500">


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
> A password for a computer MUST BE set in hex (it will be then converted to an aesKey).
> The separator can be changed with the option `--sep` (you can put a string with more
> than one character).

    # Warning: if you put multiple secrets for one user, only the last one will be kept!
    cat owned
    WORKSTATION$:password:0d3c811f9c817a0cf3...
    Tracy:aes:1D5A2C4E52584F0A699D0853D2EBF8EBDB6713183D9A303AB8AAACB87818BDEE
    Tracy:aes:6AD07E6F0F25DE8906D444EEC50BD83C
    Tracy:nt:4869b177d39962457ff9fb185b35c5ba
    Tracy:password:Spring2025

    griffon lab/json/* --fromo

Other options:

- `--fromv`: from vulnerable users (NP users (only for unprotected users), blank
passwords, and kerberoastable users)
- `--from USER`: test paths from an arbitrary user
- `--rights`: view ACE names instead of actions
- `--da`: display only paths to domain admin (prefixed by `+`)
- `--to`: display paths to the object.


Example with `--to`:

    griffon lab/json/* --to CORP.LOCAL

    ...
    ★PREPROD_USER —> ★PREPROD$ —> ★DATABASE$ —> ♦CORP.LOCAL
    ★DEXY —> ★SVC$ —> ★PROD$ —> ★DATABASE$ —> ♦CORP.LOCAL
    ★KELLY —> ★MAINTENERS —> ★SVC$ —> ★PROD$ —> ★DATABASE$ —> ♦CORP.LOCAL
    ★SYS —> ★MAINTENERS —> ★SVC$ —> ★PROD$ —> ★DATABASE$ —> ♦CORP.LOCAL
    ...


<details>
<summary>Path explanation</summary>

> [!NOTE]
> A path is a succession of action(s) to exploit one or many ACEs. The format is:
> `OWNED -> [REQUIRED_TARGET]::ACTION[REQUIRED_OBJECT](TARGET):RESULT_OBJECT`
>
> - `OWNED`: initialially from the `owned` file (or the user sets with `--from`)
> - `REQUIRED_TARGET` (optional): in some rare cases, Griffon choose a new target (check require_targets in config.ml)
> - `::ACTION`: one or many successive actions to exploit the ACE
> - `REQUIRED_OBJECT` (optional): sometimes the action needs another object to exploit the ACE
> - `TARGET`: the object we wan't to own
> - `RESULT_OBJECT`: it's often the same as `TARGET`, it means that now `TARGET` is owned

</details>


Step 4: Generate the script
---------------------------

Use the line number to generate the script and run the commands!

    griffon lab/json/* --fromo -s0 --dc-ip 10.0.0.2

Or use the interactive mode (only with `--from`):

    griffon lab/json/* --from TARGET -i --dc-ip 10.0.0.2


Embedded tools
==============

- `griffonad/tools/attr.py`: generic script to modify one ldap attribute
- `griffonad/tools/addGMSAReader.py`: add a user to read a GMSA password
- `griffonad/tools/aesKrbKeyGen.py`: login parameters uniformization
- `griffonad/tools/addmember.py`: modify the attribute member
- `griffonad/tools/addspn.py`: modify the attribute servicePrincipalName
- `griffonad/tools/getbyname.py`: get all attributes of one object
- `griffonad/tools/gpttmpl.py`: re-format a GptTmpl.inf with correct encoding
- `griffonad/tools/logonscript.py`: modify the attribute msTSInitialProgram
- `griffonad/tools/readpol.py`: export Registry.pol to json and rewrite the pol file 
- `griffonad/tools/readgmsa.py` (from gMSADumper.py): simplified and login parameters uniformization
- `griffonad/tools/scriptsini.py`: re-format a scripts.ini with correct encoding
- `griffonad/tools/toggleNP.py`: enable or disable the donotpreauth flag
- `griffonad/tools/toggleDisable.py`: toggle the flag ACCOUNTDISABLE
- `griffonad/tools/xmltask.py`: generate an xml for schedule task (mimic a real xml)


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
