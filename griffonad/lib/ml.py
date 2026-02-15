import os
import re
from jinja2 import Template

import griffonad.lib.consts as c
from griffonad.lib.expression import Expression


REGEX_PREDICATE = re.compile(
    r'^\s*(?P<symbol>[:_a-zA-Z0-9]+)' + \
    r'\s*\(\s*(?P<object_type>[a-z]+)\s*\)' + \
    r'\s*(?P<arrow>->|=>)' + \
    r'\s*(?P<symbol_result>[():_a-zA-Z0-9]+)' + \
    r'(\s+require(?P<require_suffix>_for_auth|_targets|_once)? ' + \
    r'(?P<require_class_name>[_.a-zA-Z0-9]+))?' + \
    r'(\s+if (?P<condition>[_ .a-zA-Z0-9()]+))?' + \
    r'(\s+elsewarn "(?P<elsewarn>[->< _=()$&:./,/*-+a-zA-Z0-9]+)")?' + \
    r'\s*(?P<comment>#.+)?$')

REGEX_SET = re.compile(
    r'^\s*set\s+(?P<varname>[a-zA-Z0-9_]+)' + \
    r'\s*=\s*' + \
    r'(?P<bool>true|false)$')


def index(list, search):
    try:
        return list.index(search)
    except:
        return -1


# The implementation of one predicate in config.ml
class Predicate():
    def __init__(self, symbol, object_type, symbol_result, require_class_name, condition,
                 elsewarn, is_required_for_auth, is_required_target, is_required_once,
                 do_fork):
        self.symbol = symbol
        self.object_type = object_type
        self.symbol_result = symbol_result
        if condition:
            self.condition = Expression(condition).compile()
        else:
            self.condition = None
        self.is_required_for_auth = is_required_for_auth
        self.is_required_target = is_required_target
        self.is_required_once = is_required_once
        self.require_class_name = require_class_name
        self.elsewarn = elsewarn
        self.do_fork = do_fork

    def __repr__(self):
        return f'{self.symbol}({self.object_type}) -> {self.symbol_result}'


class MiniLanguage():
    def __init__(self, args):
        # TODO: replace string types by int types

        # List of (left) symbols for each object type
        # This is a list to keep the order
        # Example: 'user' = ['GenericAll', 'ForceChangePassword', '::ForceChangePassword', ...]
        self.symbols_by_type = {
            c.T_USER: [],
            c.T_COMPUTER: [],
            c.T_DOMAIN: [],
            c.T_GROUP: [],
            c.T_GPO: [],
            c.T_DC: [],
            c.T_OU: [],
            c.T_CONTAINER: [],
            -1: [], # 'many'
        }
        # For an index i in symbols_by_type we have the Predicate object
        # at the same index
        # Example: 'user' = [predicate_of_GenericAll, predicate_of_ForceChange, ...]
        self.predicates_by_symbol_index = {
            c.T_USER: [],
            c.T_COMPUTER: [],
            c.T_DOMAIN: [],
            c.T_GROUP: [],
            c.T_GPO: [],
            c.T_DC: [],
            c.T_OU: [],
            c.T_CONTAINER: [],
            -1: [], # 'many'
        }
        # For each dict: get the list of 'left' symbols for a symbol result
        # dict({symbol_result: set(symbols)})
        # Example:
        # 'user' = {
        #     'ForceChangePassword': ['AllExtendedRights', '::DaclResetPassword'],
        #     'AllExtendedRights': ['GenericAll'],
        #     ...
        # }
        self.reversed_symbols = {
            c.T_USER: {},
            c.T_COMPUTER: {},
            c.T_DOMAIN: {},
            c.T_GROUP: {},
            c.T_GPO: {},
            c.T_DC: {},
            c.T_OU: {},
            c.T_CONTAINER: {},
            -1: {}, # 'many'
        }
        # Set of symbols on which a path exists to any apply_*
        # Example: 'user' = {'GenericAll', 'ForceChangePassword', '::AddKeyCredentialLink', ...}
        self.symbols_to_any_apply = {
            c.T_USER: set(),
            c.T_COMPUTER: set(),
            c.T_DOMAIN: set(),
            c.T_GROUP: set(),
            c.T_GPO: set(),
            c.T_DC: set(),
            c.T_OU: set(),
            c.T_CONTAINER: set(),
        }
        self.args = args
        self.args.consts = {}


    def __parse_file(self, filename):
        fd = open(filename, "r")
        n = 0

        while True:
            line = fd.readline()
            if line == '':
                break

            line = line.strip()
            n += 1

            if line.startswith('#') or not line:
                continue

            while line[-1] == '\\' and '#' not in line:
                new_line = fd.readline()
                if new_line == '':
                    break
                line = line[:-1] + ' ' + new_line.strip()
                n += 1

            res = REGEX_SET.match(line)
            if res is not None:
                self.args.consts[res['varname']] = res['bool'] == 'true'
                continue

            res = REGEX_PREDICATE.match(line)
            if not res:
                print(f'{filename}: syntax error at line {n}')
                print(line)
                exit(1)

            object_type = res['object_type']

            if object_type != 'any' and object_type not in c.ML_TYPES_FROM_STR:
                print(f'{filename}: unknown object type at line {n}')
                print(line)
                exit(1)

            p = Predicate(
                    res['symbol'],
                    object_type,
                    res['symbol_result'],
                    res['require_class_name'],
                    res['condition'],
                    res['elsewarn'],
                    res['require_suffix'] == '_for_auth',
                    res['require_suffix'] == '_targets',
                    res['require_suffix'] == '_once',
                    res['arrow'] == '=>')

            if object_type == 'any':
                types_to_apply = list(c.ML_TYPES_TO_STR.keys())
                types_to_apply.remove(c.T_MANY)
            else:
                types_to_apply = [c.ML_TYPES_FROM_STR[object_type]]

            for ty in types_to_apply:
                i = index(self.symbols_by_type[ty], p.symbol)
                if i == -1:
                    self.symbols_by_type[ty].append(p.symbol)
                    self.predicates_by_symbol_index[ty].append([])
                self.predicates_by_symbol_index[ty][i].append(p)

                if p.symbol_result in self.reversed_symbols[ty]:
                    self.reversed_symbols[ty][p.symbol_result].add(p.symbol)
                else:
                    self.reversed_symbols[ty][p.symbol_result] = {p.symbol}

    def __go_up_parent(self, ty, sym_set, parents):
        for sym_parent in parents:
            # for each parent, add them in the current set
            sym_set.add(sym_parent)
            if sym_parent in self.reversed_symbols[ty]:
                self.__go_up_parent(ty,
                        sym_set,
                        self.reversed_symbols[ty][sym_parent])

    # Not only direct symbols to apply. For example, there is a path from GenericAll to
    # apply_with_forced_passwd. So add it in the set.
    def __get_all_symbols_to_any_apply(self):
        for ty in self.symbols_to_any_apply.keys():
            for term in c.TERMINALS:
                if term in self.reversed_symbols[ty]:
                    self.__go_up_parent(ty,
                            self.symbols_to_any_apply[ty],
                            self.reversed_symbols[ty][term])

    def get_rights_to_apply(self, object_type):
        return self.symbols_to_any_apply[object_type]

    def compile(self, filename):
        self.__parse_file(filename)
        self.__get_all_symbols_to_any_apply()
        path_tpl = os.path.dirname(os.path.abspath(__file__)) + '/runner.py'
        code = Template(open(path_tpl, 'r').read()).render(ml=self, c=c)
        # remove empty lines
        self.code = "\n".join([s.rstrip() for s in code.split("\n") if s.rstrip()])

    def execute_user_rights(self, db, o):
        paths = []
        # The magic is here!
        code = self.code + '\nrun(args, parent, parent.obj.rights_by_sid)'
        exec(code, {
            'args': self.args,
            'parent': o,
            'db': db,
            'paths': paths
        })
        return paths

    # Start paths from owned objects
    def execute_owned(self, db):
        paths = []
        for user_name in sorted(db.owned_db.keys()):
            paths += self.execute_user_rights(db, db.owned_db[user_name])
        return paths

    def execute_function(self, db, target, action):
        paths = []
        funcname = f'{c.ML_TYPES_TO_STR[target.type]}_{action.replace("::", "xx")}'
        code = self.code + f'\n{funcname}(args, set(), None, target)'
        exec(code, {
            'args': self.args,
            'target': target,
            'db': db,
            'paths': paths
        })
        return paths

    # Start paths from users with the donotpreauth flag
    def execute_np(self, db):
        paths = []
        for o in db.iter_users():
            if o.np and o.type == c.T_USER:
                paths += self.execute_function(db, o, '::ASREPRoasting')
        return paths

    # Start paths from users with SPN
    def execute_user_spn(self, db):
        paths = []
        krbtgt = f'{db.domain.sid}-502'
        for o in db.iter_users():
            if o.spn and o.sid != krbtgt and o.type == c.T_USER:
                paths += self.execute_function(db, o, '::Kerberoasting')
        return paths

    def execute_password_not_required(self, db):
        paths = []
        for o in db.iter_users():
            if o.passwordnotreqd:
                paths += self.execute_function(db, o, '::BlankPassword')
        return paths
