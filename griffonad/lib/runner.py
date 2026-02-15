{# Jinja template #}
import copy
import griffonad.lib.require
import griffonad.lib.actions
import griffonad.config
from griffonad.lib.database import Owned, LDAPObject
from griffonad.lib.expression import rpn_eval

stack = []

STATUS_FOUND_ONE = 0b01
STATUS_NOT_FOUND_ONE = 0b00
STATUS_FORK_FOUND_ONE = 0b11
STATUS_FORK_NOT_FOUND_ONE = 0b10
MASK_FOUND = 0b01
MASK_FORK = 0b10

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
    vars.update(args.consts)
    return rpn_eval(condition, vars)

{# Functions return True if a path was found
 # apply*: if the run failed, add at least a shortest path #}

def apply_with_forced_passwd(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_with_forced_passwd", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return STATUS_NOT_FOUND_ONE
    new_owned = Owned(target, secret=griffonad.config.DEFAULT_PASSWORD, secret_type={{c.T_SECRET_PASSWORD}})
    db.owned_db[new_owned.obj.name.upper()] = new_owned
    st = run(args, new_owned, new_owned.obj.rights_by_sid)
    if ~st & MASK_FOUND:
        paths.append(list(stack))
    del db.owned_db[new_owned.obj.name.upper()]
    stack.pop()
    return STATUS_FOUND_ONE

def apply_with_blank_passwd(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_with_blank_passwd", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return STATUS_NOT_FOUND_ONE
    new_owned = Owned(target, secret='', secret_type={{c.T_SECRET_PASSWORD}})
    db.owned_db[new_owned.obj.name.upper()] = new_owned
    st = run(args, new_owned, new_owned.obj.rights_by_sid)
    if ~st & MASK_FOUND:
        paths.append(list(stack))
    del db.owned_db[new_owned.obj.name.upper()]
    stack.pop()
    return STATUS_FOUND_ONE

def apply_group(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_group", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return STATUS_NOT_FOUND_ONE
    st = run(args, parent, target.rights_by_sid)
    if ~st & MASK_FOUND:
        paths.append(list(stack))
    stack.pop()
    return STATUS_FOUND_ONE

def apply_with_cracked_passwd(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_with_cracked_passwd", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return STATUS_NOT_FOUND_ONE
    new_owned = Owned(target, secret=f'{target.name.upper().replace("$","")}_CRACKED_PASSWORD', secret_type={{c.T_SECRET_PASSWORD}})
    db.owned_db[new_owned.obj.name.upper()] = new_owned
    st = run(args, new_owned, new_owned.obj.rights_by_sid)
    if ~st & MASK_FOUND:
        paths.append(list(stack))
    del db.owned_db[new_owned.obj.name.upper()]
    stack.pop()
    return STATUS_FOUND_ONE

def apply_with_ticket(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_with_ticket", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return STATUS_NOT_FOUND_ONE
    new_owned = Owned(target, krb_auth=True)
    db.owned_db[new_owned.obj.name.upper()] = new_owned
    st = run(args, new_owned, new_owned.obj.rights_by_sid)
    if ~st & MASK_FOUND:
        paths.append(list(stack))
    del db.owned_db[new_owned.obj.name.upper()]
    stack.pop()
    return STATUS_FOUND_ONE

def apply_with_aes(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_with_aes", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return STATUS_NOT_FOUND_ONE
    new_owned = Owned(target, secret=f'{target.name.upper().replace("$","")}_AESKEY', secret_type={{c.T_SECRET_AESKEY}})
    db.owned_db[new_owned.obj.name.upper()] = new_owned
    st = run(args, new_owned, new_owned.obj.rights_by_sid)
    if ~st & MASK_FOUND:
        paths.append(list(stack))
    del db.owned_db[new_owned.obj.name.upper()]
    stack.pop()
    return STATUS_FOUND_ONE

def stop(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "stop", target, None))
    paths.append(list(stack))
    stack.pop()
    if args.no_follow:
        return STATUS_NOT_FOUND_ONE
    return STATUS_FOUND_ONE

def apply_with_nthash(args, executed_symbols:set, parent:Owned, target:LDAPObject=None) -> bool:
    stack.append((parent, "apply_with_nthash", target, None))
    if args.no_follow:
        paths.append(list(stack))
        stack.pop()
        return STATUS_NOT_FOUND_ONE
    new_owned = Owned(target, secret=f'{target.name.upper().replace("$","")}_NTHASH', secret_type={{c.T_SECRET_NTHASH}})
    db.owned_db[new_owned.obj.name.upper()] = new_owned
    if not run(args, new_owned, new_owned.obj.rights_by_sid):
        paths.append(list(stack))
    del db.owned_db[new_owned.obj.name.upper()]
    stack.pop()
    return STATUS_FOUND_ONE

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

{% set xxsym = sym|replace('::', 'xx') %}
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
    status = STATUS_NOT_FOUND_ONE

    {# commit the action #}
    {% if sym.startswith('::') %}
    cla = griffonad.lib.actions.__dict__.get('x_{{sym|replace('::', '')}}', None)
    if cla is not None:
        cla.commit(target)
    {% endif %}

{# Take all predicates A -> B where another predicate exists with B -> ... (excluding
 # TERMINALS which don't have 'next' predicates)
 #}
{% for pred in ml.predicates_by_symbol_index[ty][i]
        if pred.symbol_result in symbols or
           pred.symbol_result in c.TERMINALS or
           pred.is_required_target %}

    {% if pred.symbol_result in c.TERMINALS %}
        {% set xxsymres = pred.symbol_result %}
    {% elif pred.is_required_target %}
        {# The function will be prefixed by the target type (see below in the 'for t in req') #}
        {% set xxsymres = pred.symbol_result|replace('::', 'xx') %}
    {% else %}
        {# continue with the same type #}
        {% set xxsymres = c.ML_TYPES_TO_STR[ty] + '_' + pred.symbol_result|replace('::', 'xx') %}
    {% endif %}

    {# manage the predicate condition #}
    {% if pred.condition is not none %}
    cond_ok = do_rpn_eval(args, {{pred.condition}}, parent, target)
    {% if pred.elsewarn is not none %}
    if not cond_ok:
        warn('{{pred.elsewarn}}', parent, target)
    {% endif %}
    {% endif %}

    {# manage all require statements #}
    {% if pred.require_class_name is not none %}

    req = griffonad.lib.require.x_{{pred.require_class_name}}.get(db, parent, target)

    {% if pred.elsewarn is not none %}
    if req is None:
        warn('{{pred.elsewarn}}', parent, target)
    {% endif %}

    {# check if the require and the condition are valid #}

    if status != STATUS_FOUND_ONE and req is not None{% if pred.condition is not none %} and cond_ok{% endif %}:

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

            st = {{pred.symbol_result}}(args, set(), p, t)

            {% else %}

            {# t is the new target #}
            if t.type == {{c.T_DC}}:
                st = dc_{{xxsymres}}(args, set(), p, t)
            elif t.type == {{c.T_USER}}:
                st = user_{{xxsymres}}(args, set(), p, t)
            elif t.type == {{c.T_COMPUTER}}:
                st = computer_{{xxsymres}}(args, set(), p, t)
            elif t.type == {{c.T_DOMAIN}}:
                st = domain_{{xxsymres}}(args, set(), p, t)
            elif t.type == {{c.T_GPO}}:
                st = gpo_{{xxsymres}}(args, set(), p, t)
            elif t.type == {{c.T_GROUP}}:
                st = group_{{xxsymres}}(args, set(), p, t)
            elif t.type == {{c.T_OU}}:
                st = ou_{{xxsymres}}(args, set(), p, t)

            {% endif %}

            status |= st & MASK_FOUND

        {% if pred.do_fork %}
        status |= MASK_FORK # fork
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
        st = {{xxsymres}}(args, executed_symbols, req, target)
        status = st | status & MASK_FOUND{% if pred.do_fork %} | MASK_FORK # fork{% endif %}

        {# require_once: used only once time, internally, during the execution of the action #}
        {% elif pred.is_required_once %}

        if not isinstance(req, Owned):
            print(f'error: {{pred.symbol}} require_once[{{pred.require_class_name}}] expected an Owned object, not a {type(req)}')
            exit(0)

        r = {'object': req, 'class_name': '{{pred.require_class_name}}'}
        stack[-1] = (parent, "{{pred.symbol}}", target, r)
        st = {{xxsymres}}(args, executed_symbols, parent, target)
        status = st | status & MASK_FOUND{% if pred.do_fork %} | MASK_FORK # fork{% endif %}

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
        st = {{xxsymres}}(args, executed_symbols, req, target)
        status = st | status & MASK_FOUND{% if pred.do_fork %} | MASK_FORK # fork{% endif %}

        {% endif %}

    {# default: no require #}
    {% else %}

    if status != STATUS_FOUND_ONE{% if pred.condition is not none %} and cond_ok{% endif %}:
        st = {{xxsymres}}(args, executed_symbols, parent, target)
        status = st | status & MASK_FOUND{% if pred.do_fork %} | MASK_FORK # fork{% endif %}

    {% endif %}

{% endfor %}

    {# end of the function #}

    {# rollback the action to avoid unwanted behaviors on future paths #}
    {% if sym.startswith('::') %}
    cla = griffonad.lib.actions.__dict__.get('x_{{sym|replace('::', '')}}', None)
    if cla is not None:
        cla.rollback(target)
    {% endif %}

    {% if DEBUG %}
    print(f'##end {parent.obj} -> {{xxsym}}({target})', found_one)
    {% endif %}

    stack.pop()
    return status

{% endfor %}
{% endfor %}

{# apply all rights of parent #}
def run(args, parent:Owned, rights_by_sid:dict) -> bool:
    status = STATUS_NOT_FOUND_ONE

    {# apply all rights of parent #}
    for sid, rights in rights_by_sid.items():

        executed_symbols = set()

        if sid == 'many':
            {% for sym in ml.symbols_by_type[c.T_MANY] %}
            {% set xxsym = sym|replace('::', 'xx') %}
            if '{{sym}}' in rights:
                st = many_{{xxsym}}(args, executed_symbols, parent)
                if st & MASK_FOUND:
                    status |= MASK_FOUND
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
            {% for sym in symbols %}
            {% if sym[:2] != '::' and sym[0] != '_' %}
            if '{{sym}}' in rights:
                st = {{c.ML_TYPES_TO_STR[ty]}}_{{sym}}(args, executed_symbols, parent, target)
                if st & MASK_FOUND:
                    status |= MASK_FOUND
                    {# don't continue if STATUS_FORK_FOUND_ONE #}
                    if st == STATUS_FOUND_ONE:
                        continue
            {% endif %}
            {% endfor %}
            pass {# if no symbols found, write something to avoid a syntax error #}

        {% endfor %}

    return status & MASK_FOUND
