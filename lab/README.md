Lab
===

Installation
------------

You need to install 4 Windows Servers (no needs to install specific services),
and join them to your domain:
- `DATABASE`
- `PREPROD`
- `PROD`
- `WEBSITE`

If you prefer you can simply add them with the script addcomputer.py, but you
will not be able to run some scenarios:

    addcomputer.py DOMAIN/USER:PASS -dc-ip IP -computer-name DATABASE -method SAMR
    addcomputer.py DOMAIN/USER:PASS -dc-ip IP -computer-name PREPROD -method SAMR
    addcomputer.py DOMAIN/USER:PASS -dc-ip IP -computer-name PROD -method SAMR
    addcomputer.py DOMAIN/USER:PASS -dc-ip IP -computer-name WEBSITE -method SAMR

Then run on the DC the script below (powershell -> run as administrator).
Don't look too much in create.ps1 if you don't want to be spoiled 🙂 !

    Set-ExecutionPolicy unrestricted
    .\create.ps1

> [!NOTE]
> `Alyx` is an administrator, his password is `admin01.` This account is not in the
> solution of this lab.


Challenge
---------

You have succeeded to get `Tracy`'s password! All ACEs have been dumped to json.

    cat owned
    Tracy:password:Spring2025

There are 3 main paths to domain admin (without `Alyx`), good luck!
