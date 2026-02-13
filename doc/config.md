# Griffon Mini Language

## Colors with vim

The suffix .ml stands for ocaml in vim. Add these lines to vim to display correctly
the config.ml file:

    syn match ocamlComment "#.*$"
    syn match ocamlKeyword "\<require\>" skipwhite skipempty nextgroup=ocamlFullMod
    syn match ocamlKeyword "\<require_for_auth\>" skipwhite skipempty nextgroup=ocamlFullMod
    syn match ocamlKeyword "\<require_targets\>" skipwhite skipempty nextgroup=ocamlFullMod
    syn match ocamlKeyword "\<require_once\>" skipwhite skipempty nextgroup=ocamlFullMod
    syn match ocamlKeyword "\<not\>" skipwhite skipempty nextgroup=ocamlFullMod
    syn match ocamlKeyword "\<elsewarn\>" skipwhite skipempty nextgroup=ocamlFullMod

Or add them at the end of `/usr/share/vim/vim*/syntax/ocaml.vim`


## Language syntax

A predicate is defined like as follows:

    Symbol(object) -> SymbolResult [require func_name] [if condition] [elsewarn]

`SymbolResult` can point to another symbol or a terminal symbol. If `SymbolResult`
is undefined, the predicate is ignored.

Supported objects: `user`, `computer`, `domain`, `dc`, `gpo`, `ou`, `group`,
`any`, `many`. The keyword `any` means that the predicate is applied on any
objects. The keyword `many` means that many targets are possible and a path
will be generated for all of them.

If a `condition` is present, the predicate is applied only if the result is true.
If a require is present, the predicate is applied only if an object is found by
the function.

If the name starts by `::` it means that the symbol is an action and it can
generate command lines (if it starts with `::_`, the symbol will not be printed
in the full path). If the name starts by `__` it means that the symbol is an
intermediate symbol. Otherwise the symbol is a Bloodhound right.

An intermediate symbol can be useful to implement conditional paths. Example:

    Right(user) -> __Temp      if cond1
    __Temp(user) -> ::Action1  if cond2
    __Temp(user) -> ::Action2  if cond3

`::Action1` is executed only if `cond1 and cond2` is true.

`::Action2` is executed only if `cond1 and not cond2 and cond3` is true.

### Require statements (see [require.md](/doc/require.md) for more explanations)

- `require`
- `require_for_auth`
- `require_once`
- `require_targets`

### Conditional statements

Supported operators: `and`, `not`, `or`, `in`, `+`, `-`, `/`, `*`

List of available flags for the conditional statement:
- `parent.has_spn`
- `parent.is_user`
- `parent.is_computer`
- `parent.is_dc`
- `parent.np`
- `parent.protected`
- `parent.sensitive`
- `parent.trustedtoauth`
- `parent.groups` (list, use it with the operator in)
- `target.has_spn`
- `target.np`
- `target.protected`
- `target.sensitive`
- `target.groups` (list, use it with the operator in)


## Terminal symbols

- `apply*`: assume we have now credentials on the target, so add the path
and apply its rights, if possible, to complete the path.
- `stop`: add the path and stop to find any new paths to a target

List of `apply*` symbols:
- `apply_with_forced_passwd`: the password of the target was reset
- `apply_with_ticket`: assume we have requested a ticket for the target
- `apply_with_aes`: assume we have the aes key of the target
- `apply_with_cracked_passwd`: assume we have cracked the password of the user
- `apply_group`: apply the rights of the group


## Predicates priority

Predicates are applied in the order as they are defined.

**Example 1**: Bob can `WriteDacl` and `ForceChangePassword` on Alice.

If we have these two predicates in this order:

    ::ForceChangePassword(user) -> apply_with_forced_passwd
    WriteDacl(user) -> ...
    ForceChangePassword(user) -> ::ForceChangePassword

The result is: `WriteDacl -> ::DaclResetPassword -> ForceChangePassword -> ::ForceChangePassword`

But if we define them in this order: 

    ::ForceChangePassword(user) -> apply_with_forced_passwd
    ForceChangePassword(user) -> ::ForceChangePassword
    WriteOwner(user) -> ...

The result is: `ForceChangePassword -> ::ForceChangePassword`

**Example 2**: apply `AddKeyCredentialLink` instead of `ForceChangePassword`.

    # Here the order is not important here because these are actions
    ::ForceChangePassword -> apply_with_forced_passwd
    ::AddKeyCredentialLink -> apply_with_ticket

Define the right `AddKeyCredentialLink` before `ForceChangePassword`

    AddKeyCredentialLink -> ::AddKeyCredentialLink
    ForceChangePassword -> ::ForceChangePassword

Don't forget to change the order of these predicates too:

    WriteDacl(user) -> ::DaclKeyCredentialLink
    WriteDacl(user) -> ::DaclResetPassword
    ...
    GenericWrite(user) -> AddKeyCredentialLink 
    AllExtendedRights(user) -> ForceChangePassword
    ...
    GenericAll(any) -> GenericWrite
    GenericAll(any) -> AllExtendedRights

**Example 3**: prefer `RBCD+U2U` over `RBCD+AddComputer`.

Set these lines in this order:

    AllowedToAct(computer) -> ::U2U               if owned.is_user       -> on top
    AllowedToAct(computer) -> ::AllowedToAct      if owned.has_spn
    ::RBCD(computer) -> ::U2U                     require owned_user     -> on top
    ::RBCD(computer) -> ::AllowedToAct            require add_computer
    ::RBCD(computer) -> ::AllowedToAct            require owned_with_spn


## Fork

It's possible to generate multiple scenarios for one right. You can use the operator
`=>` instead of `->`. The arrow can be placed on every predicates. Warning: don't use it
everywhere, the result is exponential and it can cause some duplicated paths!

**Example**: we have `A -> GenericAll(B)` and `B -> GenericAll(C)`

If we set a fork on `ForceChangePassword`: 

    GenericAll(any) -> AllExtendedRights
    GenericAll(any) -> GenericWrite
    ForceChangePassword(user) => apply_with_forced_passwd
    AddKeyCredentialLink(user) -> apply_with_ticket

We will get 4 paths (`ForceChangePassword` comes from `AllExtendedRights`):

    A -> ForceChangePassword(B):B -> ForceChangePassword(C)
    A -> ForceChangePassword(B):B -> AddKeyCredentialLink(C)
    A -> AddKeyCredentialLink(B):B -> ForceChangePassword(C)
    A -> AddKeyCredentialLink(B):B -> AddKeyCredentialLink(C)

Same fork, but with `GenericAll` reversed:

    GenericAll(any) -> GenericWrite
    GenericAll(any) -> AllExtendedRights
    ForceChangePassword(user) => apply_with_forced_passwd
    AddKeyCredentialLink(user) -> apply_with_ticket

The result is only one path. This is because the first checked predicate is
`GenericAll -> GenericWrite` and this one doesn't have a fork at the end of the
path. So the predicate `GenericAll -> AllExtendedRights` is never run.

    A -> AddKeyCredentialLink(B):B -> AddKeyCredentialLink(C)


## Flags

If you want to disable a predicate, you can comment it without errors.
If you want to change the priority of a predicate, move it.

You can set custom flags to disable some predicates (see for example
DefaultForceChangePassword).
