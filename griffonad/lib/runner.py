{# Jinja template #}
import copy
import griffonad.lib.require
import griffonad.lib.actions
import griffonad.config
from griffonad.lib.database import Owned, LDAPObject
from griffonad.lib.expression import rpn_eval

stack = []

{% set DEBUG = False %}

def do_rpn_eval(args, condition:list, parent:Owned, target:LDAPObject) -> int:
    vars = {}
    if target is not None:
        vars.update({
            'target.has_spn': len(target.spn) != 0,
            'target.np': target.np,
            'target.protected': target.protected,
            'target.sensitive': target.sensitive,
            'target.groups': target.group_rids,
            'target.trustedtoauth': target.trustedtoauth,
        })
    if parent is not None:
        vars.update({
            'parent.has_spn': len(parent.obj.spn) != 0,
            'parent.is_user': parent.obj.type == {{c.T_USER}},
            'parent.is_computer': parent.obj.type == {{c.T_COMPUTER}},
            'parent.is_dc': parent.obj.type == {{c.T_DC}},
            'parent.np': parent.obj.np,
            'parent.protected': parent.obj.protected,
            'parent.sensitive': parent.obj.sensitive,
            'parent.trustedtoauth': parent.obj.trustedtoauth,
            'parent.groups': parent.obj.group_rids,
        })
    for opt in args.opt:
        vars[opt] = True
    return rpn_eval(condition, vars)

{# Functions return True if a path was found
 # apply*: if the run failed, add at least a shortest path
 # fork feature: to simulate a fork, the return of a function will be ignored
 #}

def apply_with_forced_passwd(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_with_forced_passwd", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return False
    new_owned = Owned(target, secret=griffonad.config.DEFAULT_PASSWORD, secret_type={{c.T_SECRET_PASSWORD}})
    db.owned_db[new_owned.obj.name.upper()] = new_owned
    if not run(args, new_owned, new_owned.obj.rights_by_sid):
        paths.append(list(stack))
    del db.owned_db[new_owned.obj.name.upper()]
    stack.pop()
    return True

def apply_with_blank_passwd(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_with_blank_passwd", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return False
    new_owned = Owned(target, secret='', secret_type={{c.T_SECRET_PASSWORD}})
    db.owned_db[new_owned.obj.name.upper()] = new_owned
    if not run(args, new_owned, new_owned.obj.rights_by_sid):
        paths.append(list(stack))
    del db.owned_db[new_owned.obj.name.upper()]
    stack.pop()
    return True

def apply_group(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_group", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return False
    if not run(args, parent, target.rights_by_sid):
        paths.append(list(stack))
    stack.pop()
    return True

def apply_with_cracked_passwd(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_with_cracked_passwd", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return False
    new_owned = Owned(target, secret=f'{target.name.upper().replace("$","")}_CRACKED_PASSWORD', secret_type={{c.T_SECRET_PASSWORD}})
    db.owned_db[new_owned.obj.name.upper()] = new_owned
    if not run(args, new_owned, new_owned.obj.rights_by_sid):
        paths.append(list(stack))
    del db.owned_db[new_owned.obj.name.upper()]
    stack.pop()
    return True

def apply_with_ticket(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_with_ticket", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return False
    new_owned = Owned(target, krb_auth=True)
    db.owned_db[new_owned.obj.name.upper()] = new_owned
    if not run(args, new_owned, new_owned.obj.rights_by_sid):
        paths.append(list(stack))
    del db.owned_db[new_owned.obj.name.upper()]
    stack.pop()
    return True

def apply_with_aes(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_with_aes", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return False
    new_owned = Owned(target, secret=f'{target.name.upper().replace("$","")}_AESKEY', secret_type={{c.T_SECRET_AESKEY}})
    db.owned_db[new_owned.obj.name.upper()] = new_owned
    if not run(args, new_owned, new_owned.obj.rights_by_sid):
        paths.append(list(stack))
    del db.owned_db[new_owned.obj.name.upper()]
    stack.pop()
    return True

def stop(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "stop", target, None))
    paths.append(list(stack))
    stack.pop()
    if args.no_follow:
        return False
    return True

def apply_with_nthash(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_with_nthash", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return False
    new_owned = Owned(target, secret=f'{target.name.upper().replace("$","")}_NTHASH', secret_type={{c.T_SECRET_NTHASH}})
    db.owned_db[new_owned.obj.name.upper()] = new_owned
    if not run(args, new_owned, new_owned.obj.rights_by_sid):
        paths.append(list(stack))
    del db.owned_db[new_owned.obj.name.upper()]
    stack.pop()
    return True

printed_messages = set()
def warn(message:str, parent:Owned, target:LDAPObject):
    if target is None and parent is None:
        m = message
    elif parent is None:
        m = message.replace('TARGET', target.name)
    elif target is None:
        m = message.replace('PARENT', parent.obj.name)
    else:
        m = message.replace('TARGET', target.name).replace('PARENT', parent.obj.name)
    if m not in printed_messages:
        print(m)
        printed_messages.add(m)


{% for ty, symbols in ml.symbols_by_type.items() %}
{% for sym in symbols %}

{% set xxsym = sym|replace('::', 'xx')|replace('+', '_plus_') %}
{% set i = loop.index0 %}

{# run all symbol_results for a given symbol #}
def {{c.ML_TYPES_TO_STR[ty]}}_{{xxsym}}(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:

    {# detect loops #}
    if target is not None and target.name.upper() in db.owned_db:
        return False

    {% if DEBUG %}
    print(f'{parent.obj} -> {{xxsym}}', target, '{{c.ML_TYPES_TO_STR[ty]}}')
    {% endif %}

    if not args.no_follow and '{{sym}}' in executed_symbols:
        return False 

    stack.append((parent, '{{sym}}', target, None))
    executed_symbols.add('{{sym}}')
    found_one = False

    {# commit the action #}
    {% if sym.startswith('::') %}
    griffonad.lib.actions.x_{{sym|replace('::', '')|replace('+', '_plus_')}}.commit(target)
    {% endif %}

{# Take all predicates A -> B where another predicate exists with B -> ... (excluding
 # TERMINALS which don't have 'next' predicates)
 #}
{% for pred in ml.predicates_by_symbol_index[ty][i]
        if pred.symbol_result in symbols or
           pred.symbol_result in c.TERMINALS or
           pred.is_required_target %}

    {#print({{pred.do_fork}})#}

    {% if pred.symbol_result in c.TERMINALS %}
        {% set xxsymres = pred.symbol_result %}
    {% elif pred.is_required_target %}
        {# The function will be prefixed by the target type (see below in the 'for t in req') #}
        {% set xxsymres = pred.symbol_result|replace('::', 'xx')|replace('+', '_plus_') %}
    {% else %}
        {# continue with the same type #}
        {% set xxsymres = c.ML_TYPES_TO_STR[ty] + '_' + pred.symbol_result|replace('::', 'xx')|replace('+', '_plus_') %}
    {% endif %}

    {# manage the predicate condition #}
    {% if pred.condition is not none %}
    cond_ok = do_rpn_eval(args, {{pred.condition}}, parent, target)
    {% if pred.elsewarn != '' %}
    if not cond_ok:
        warn('{{pred.elsewarn}}', parent, target)
    {% endif %}
    {% endif %}

    {# manage all require statements #}
    {% if pred.require_class_name != '' %}

    req = griffonad.lib.require.x_{{pred.require_class_name}}.get(db, parent, target)

    {% if pred.elsewarn != '' %}
    if req is None:
        warn('{{pred.elsewarn}}', parent, target)
    {% endif %}

    {# check if the require and the condition are valid #}

    if {% if not pred.do_fork %}not found_one and {% endif %}req is not None{% if pred.condition is not none %} and cond_ok{% endif %}:

        {# require_targets: replace the original target by the require #}
        {% if pred.is_required_target %}

        if not isinstance(req, list):
            print(f'error: {{pred.symbol}} require_targets[{{pred.require_class_name}}] expected a list of targets, not {type(req)}')
            exit(0)

        {# for require_targets the result is a list #}
        for t in req:
            p = parent
            r = {'object': t, 'class_name': '{{pred.require_class_name}}', 'original_target': target}
            stack[-1] = (p, "{{pred.symbol}}", t, r)

            {# reset the executed_symbols (to set()) because the target changes #}

            {% if pred.symbol_result in c.TERMINALS %}

            if {{pred.symbol_result}}(args, set(), p, t):
                {% if not pred.do_fork %}
                found_one = True
                {% endif %}
                continue

            {% else %}

            {# t is the new target #}
            if t.type == {{c.T_DC}}:
                if dc_{{xxsymres}}(args, set(), p, t):
                    {% if pred.do_fork %}
                    pass
                    {% else %}
                    found_one = True
                    {% endif %}
            elif t.type == {{c.T_USER}}:
                if user_{{xxsymres}}(args, set(), p, t):
                    {% if pred.do_fork %}
                    pass
                    {% else %}
                    found_one = True
                    {% endif %}
            elif t.type == {{c.T_COMPUTER}}:
                if computer_{{xxsymres}}(args, set(), p, t):
                    {% if pred.do_fork %}
                    pass
                    {% else %}
                    found_one = True
                    {% endif %}
            elif t.type == {{c.T_DOMAIN}}:
                if domain_{{xxsymres}}(args, set(), p, t):
                    {% if pred.do_fork %}
                    pass
                    {% else %}
                    found_one = True
                    {% endif %}
            elif t.type == {{c.T_GPO}}:
                if gpo_{{xxsymres}}(args, set(), p, t):
                    {% if pred.do_fork %}
                    pass
                    {% else %}
                    found_one = True
                    {% endif %}
            elif t.type == {{c.T_GROUP}}:
                if group_{{xxsymres}}(args, set(), p, t):
                    {% if pred.do_fork %}
                    pass
                    {% else %}
                    found_one = True
                    {% endif %}
            elif t.type == {{c.T_OU}}:
                if ou_{{xxsymres}}(args, set(), p, t):
                    {% if pred.do_fork %}
                    pass
                    {% else %}
                    found_one = True
                    {% endif %}

            {% endif %}

        {# require_for_auth: replace the parent by the require object #}
        {% elif pred.is_required_for_auth %}

        if not isinstance(req, Owned):
            print(f'error: {{pred.symbol}} require_for_auth[{{pred.require_class_name}}] expected an Owned object, not a {type(req)}')
            exit(0)

        r = {'object': req, 'class_name': '{{pred.require_class_name}}'}
        {# replace the parent, used for the auth, by req #}
        stack[-1] = (req, "{{pred.symbol}}", target, r)
        {# replace the parent by req #}
        if {% if not pred.do_fork %}not found_one and {% endif %}{{xxsymres}}(args, executed_symbols, req, target):
            {% if pred.do_fork %}
            pass
            {% else %}
            found_one = True
            {% endif %}

        {# require_once: used only once time, internally, during the execution of the action #}
        {% elif pred.is_required_once %}

        if not isinstance(req, Owned):
            print(f'error: {{pred.symbol}} require_once[{{pred.require_class_name}}] expected an Owned object, not a {type(req)}')
            exit(0)

        r = {'object': req, 'class_name': '{{pred.require_class_name}}'}
        stack[-1] = (parent, "{{pred.symbol}}", target, r)
        if {% if not pred.do_fork %}not found_one and {% endif %}{{xxsymres}}(args, executed_symbols, parent, target):
            {% if pred.do_fork %}
            pass
            {% else %}
            found_one = True
            {% endif %}

        {# simple require, the require becomes the parent for the next actions (not the current) #}
        {% else %}

        if not isinstance(req, Owned):
            print(f'error: {{pred.symbol}} require[{{pred.require_class_name}}] expected an Owned object, not a {type(req)}')
            exit(0)

        r = {'object': req, 'class_name': '{{pred.require_class_name}}'}
        {# here parent is used for the authentication (the stack is used to generate the path
         # and the first value is the object we use to authenticate) #}
        stack[-1] = (parent, "{{pred.symbol}}", target, r) 
        {# replace the parent by req #}
        if {% if not pred.do_fork %}not found_one and {% endif %}{{xxsymres}}(args, executed_symbols, req, target):
            {% if pred.do_fork %}
            pass
            {% else %}
            found_one = True
            {% endif %}

        {% endif %}

    {# default: no require #}
    {% else %}

    if {% if not pred.do_fork %}not found_one and {% endif %}{% if pred.condition is not none %}cond_ok and {% endif %}{{xxsymres}}(args, executed_symbols, parent, target):
        {% if pred.do_fork %}
        pass
        {% else %}
        found_one = True
        {% endif %}

    {% endif %}

{% endfor %}

    {# end of the function #}

    {# rollback the action to avoid unwanted behavior on future paths #}
    {% if sym.startswith('::') %}
    griffonad.lib.actions.x_{{sym|replace('::', '')|replace('+', '_plus_')}}.rollback(target)
    {% endif %}

    {% if DEBUG %}
    print(f'##end {parent.obj} -> {{xxsym}}({target})', found_one)
    {% endif %}

    stack.pop()
    return found_one

{% endfor %}
{% endfor %}

{# apply all rights of parent #}
def run(args, parent:Owned, rights_by_sid:dict) -> bool:
    found_one = False

    {# apply all rights of parent #}
    for sid, rights in rights_by_sid.items():

        executed_symbols = set()

        if sid == 'many':
            {% for sym in ml.symbols_by_type[c.T_MANY] %}
            {% set xxsym = sym|replace('::', 'xx')|replace('+', '_plus_') %}
            if '{{sym}}' in rights:
                ret = many_{{xxsym}}(args, executed_symbols, parent)
                found_one |= ret
                if ret:
                    continue
            {% endfor %}
            continue

        if sid not in db.objects_by_sid:
            continue

        {# on a given right on a 'target' object, execute the correct function
         # in function of the target type #}
        target = db.objects_by_sid[sid]

        {% for ty, symbols in ml.symbols_by_type.items() if ty != c.T_MANY %}

        {% if loop.index0 == 0 %}
        if target.type == {{ty}}:
        {% else %}
        elif target.type == {{ty}}:
        {% endif %}

            {% for sym in symbols if sym[:2] != '::' %}
            if '{{sym}}' in rights:
                ret = {{c.ML_TYPES_TO_STR[ty]}}_{{sym|replace('+', '_plus_')}}(args, executed_symbols, parent, target)
                found_one |= ret
                if ret:
                    continue
            {% endfor %}

        {% endfor %}

    return found_one
