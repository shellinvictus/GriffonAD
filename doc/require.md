# Definitions

parent: the object is an instance of lib.database.Owned. Its rights are applied
and its credentials are used to authenticate (written as p= below).

target: the object is an instance of lib.database.LDAPObject or
lib.database.FakeLDAPObject. This is the object we want to own.

require function: all functions are defined in lib.require. require_targets must
return a list of LDAPObject. All others must return an Owned object. The convention
of require functions for require_targets is to prefix the name by `ta_`.

Format of the argument 'require' in lib.actions.x_Action.print:

    {
        'object': returned_object,
        'class_name': 'require_string_class_name',
        'original_target': target,    # only for require_targets
    }


# Explanation of a normal path

              p=Alice               p=Alice
    Alice ——> AllExtendedRights(Bob) ——> ForceChangePassword(Bob) ——> apply_with_passwd ——╮
    p (parent)                 target                                                     │
                                                                                          │
      ╭———————————————————————————————————————————————————————————————————————————————————╯
      │  Bob is now owned, it becomes the parent of future targets
      │  An Owned object for Bob is created with a custom password.
      │
      V     parent=Bob
    Bob ——> RIGHTS_OF_BOB ...


# require

The required object is used by the current predicate (here ::RBCD) to complete.
It's used as the parent for the next actions. The require function returns
an existing owned in the database or creates a new one.


                                           require add_computer    The add_computer function creates a
                                                   NEW             FakeLDAPObject and add it in the
                                                    │              owned database.
                                                    │—————————————╮
                                                    │             │
                                                    │             V
              p=Alice                      p=Alice  V          p=NEW
    Alice ——> AddAllowedToAct(DESKTOP) ——> ::RBCD(DESKTOP) ——> AllowedToAct(DESKTOP) ——╮ 
   p (parent)                 target                                                   │
                                                                                       │
      ╭————————————————————————————————————————————————————————————————————————————————╯
      │
      │    p=NEW
      ╰——> ::AllowedToAct(DESKTOP) ——> apply_with_aes ——╮
                                                        │
      ╭—————————————————————————————————————————————————╯
      │  DESKTOP is now owned, it becomes the parent of future targets
      │  An Owned object for DESKTOP is created with an aes key (assume
      │  we have secretsdump on DESKTOP).
      │
      V         p=DESKTOP
    DESKTOP ——> RIGHTS_OF_DESKTOP ...


# require_for_auth

This statement can change the parent of predicate and is used to authenticate
with this new object. Generally, it's not really useful excepted in the case we
don't have parent!

Here Bob has an SPN, so we can run the Kerberoasting scenario. If we run the
::Kerberoasting after a WriteSPN (because we have a GenericAll for example),
the ::Kerberoasting runs the require_for_auth in any cases.

apply_with_cracked_passwd assume you have cracked the ASREP Response for Bob
and you retrieve his password.


    require_for_auth any_owned    The any_owned function takes 
            OBJECT                 arbitrarily an owned user.
              │
              │
              V
     parent=OBJECT
     ::Kerberoasting(Bob) ——> apply_with_cracked_passwd ——╮
                    target                                │
                                                          │
      ╭———————————————————————————————————————————————————╯
      │ Bob is now owned.
      │
      V      p=Bob
     Bob ——> RIGHTS_OF_DESKTOP ...



# require_targets

This statement can be used with the 'many' type: it means we don't have a defined
target and it could be anything. The require_targets will search for interesting
targets to achieve the operation. require_targets should return a list of LDAPObject.


                     require_targets dc         The dc function returns the object
                            DC               corresponding to the DC in the ldap database.
                            │
                            │—————————————————————————————————————————————╮
                            │  search a target...                         │
                p=DESKTOP   V                                             V
    DESKTOP ——> AllowedToDelegate(many) ——> ::AllowedToDelegate(DC) ——> apply_with_aes ——╮
    parent                                                              target           │
                                                                                         │
      ╭——————————————————————————————————————————————————————————————————————————————————╯
      │  DC is now owned.
      │
      V
    DC ——> Admin!


# require_once

This statement is used once time, internally, by an action only. The parent and the
target are not modified. The result must be an Owned object.
