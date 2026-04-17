# Mathematical expression parser to avoid code injection in the compiled program

from colorama import Style
Style.UNDERLINE = '\033[4m'

NUMBERS = set('0123456789')
CHARS = set('0123456789_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
BIN_OP = set('+-*/&|∈∉=≠') # operators are replaced by a single-char

# unaries are ! and — ('—' is for -NUMBER

DEBUG = False

def debug(s:str, depth:int):
    if DEBUG:
        tab = ' ' * 4 * depth
        print(tab, s)


class Var:
    def __init__(self, name):
        self.name = name

    def __len__(self):
        return len(self.name)

    def __repr__(self):
        return f'Var("{self.name}")'

    def __eq__(self, v):
        if not isinstance(v, Var):
            return False
        return self.name == v.name


class Str:
    def __init__(self, value):
        self.value = value

    def __len__(self):
        return len(self.value)

    def __repr__(self):
        return f'Str("{self.value}")'

    def __eq__(self, s):
        if not isinstance(s, Str):
            return False
        return self.value == s.value


# Reverse Polish Notation
def rpn_eval(polish:list, vars:dict={}) -> int:
    stack = []
    for x in polish:
        if isinstance(x, int):
            stack.append(x)

        elif isinstance(x, Var):
            if x.name in vars:
                stack.append(vars[x.name])
            else:
                print(f'error: undefined variable {x}')
                exit(0)

        elif isinstance(x, Str):
            stack.append(x.value)

        elif isinstance(x, str):
            if x in BIN_OP:
                r = stack.pop()
                l = stack.pop()
            else:
                val = stack.pop()

            match x:
                case '+':
                    stack.append(l + r)
                case '-':
                    stack.append(l - r)
                case '*': 
                    stack.append(l * r)
                case '/':
                    stack.append(l / r)
                case '&':
                    stack.append(l & r)
                case '|':
                    stack.append(l | r)
                case '∈':
                    stack.append(l in r)
                case '∉':
                    stack.append(l not in r)
                case '!':
                    stack.append(not val)
                case '—':
                    stack.append(- val)
                case '=':
                    stack.append(l == r)
                case '≠':
                    stack.append(l != r)
                case _:
                    print(f'error: unknown operator {x}')
                    exit(0)

    if len(stack) != 1:
        print(f'error: bad reverse polish notation on', polish)
        exit(0)
    return stack[0]


class Expression():
    def __init__(self, string):
        self.string = string
        self.stack = []
        self.debug = debug

    # Compile the string expression into a reverse polish notation (RPN)
    def compile(self) -> list:
        self.__cleanup_spaces()
        self.__expression(0, len(self.string), 0)
        debug(self.stack, 0)
        return self.stack

    # cleanup and replace operators by a single-char
    def __cleanup_spaces(self):
        self.string = self.string\
            .replace('==', '=')\
            .replace('!=', '≠')\
            .replace(' not in ', '∉')\
            .replace(')not in ', ')∉')\
            .replace(' not in(', '∉(')\
            .replace(')not in(', ')∉(')\
            .replace(' in ', '∈')\
            .replace(')in ', ')∈')\
            .replace(' in(', '∈(')\
            .replace(')in(', ')∈(')\
            .replace(' and ', '&')\
            .replace(')and ', ')&')\
            .replace(' and(', '&(')\
            .replace(')and(', ')&(')\
            .replace(' or ', '|')\
            .replace(')or ', ')|')\
            .replace(' or(', '|(')\
            .replace(')or(', ')|(')\
            .replace(' not ', '!')\
            .replace(')not ', ')!')\
            .replace(' not(', '!(')\
            .replace(')not(', ')!(')\
            .replace('not ', '!')\
            .replace('not(', '!(')\
            .replace(' ', '')

    def __rollback(self, n_stacked:int, depth:int):
        if not n_stacked:
            return
        debug(f'rollback {n_stacked}', depth)
        for i in range(n_stacked):
            self.stack.pop()

    """
    Implemented grammar:

    expression = booleq
    booleq = booleq '==/!=' boolor | boolor
    boolor = boolor 'or' booland | booland
    booland = booland 'and' boolin | boolin
    boolin = boolin '∈|∉' sum | sum
    sum = sum '+' product | sum '-' product | product
    product = factor '*' boolnot | factor '/' boolnot | factor
    boolnot = 'not' factor | factor
    factor = '(' booleq ')' | '-' number | number
    number = integer | true | false | var | string
    """

    # The returned tuple is: (bool, int)
    # bool: the grammar is valid or not
    # int: number of elements pushed on the stack, we need to unstack all of them
    # if the bool is False

    # Generic function for binary operators
    # check and return the result of "left_func OP right_func | default_func"
    # where grammar_rules_description[0] == left_func OP right_func
    #   and grammar_rules_description[1] == default_func
    def __generic(self, start:int, end:int, depth:int, func_name:str,
             grammar_rules_description:tuple, op:set,
             left_func, right_func, default_func) -> tuple:
        if start == end:
            return False, 0

        debug(f'enter {func_name}', depth)

        debug(f'1/try match "{self.string[start:end]}" to "{grammar_rules_description[0]}"', depth)

        ret = False
        n_stacked = 0
        j = end - 1

        depth += 1

        # do grammar_rules_description[0]
        # start from the end: it means read left to right
        # 8/4/2 -> (8/4) SPLIT_HERE 2
        while j >= start:
            # search until the operator and split the string to left and right parts
            if self.string[j] in op:
                left = f'{Style.UNDERLINE}{self.string[start:j]}{Style.RESET_ALL}'
                debug(f'check left "{left}" | "{self.string[j+1:end]}"', depth)

                ret, ns = left_func(start, j, depth + 1)

                if ret:
                    n_stacked += ns
                    break

                self.__rollback(ns, depth)
            j -= 1

        if ret:
            right = f'{Style.UNDERLINE}{self.string[j+1:end]}{Style.RESET_ALL}'
            debug(f'check right "{self.string[start:j]}" | "{right}"', depth)

            ret, ns = right_func(j + 1, end, depth + 1)

            n_stacked += ns

            if ret:
                debug(f'pushop "{self.string[j]}"', depth)
                self.stack.append(self.string[j])
                return ret, n_stacked + 1

        if not ret:
            self.__rollback(n_stacked, depth)

        depth -= 1

        # else if error, do grammar_rules_description[1]
        debug(f'2/try default "{self.string[start:end]}" to "{grammar_rules_description[1]}"', depth)
        return default_func(start, end, depth + 1)

    def __expression(self, start:int, end:int, depth:int) -> tuple:
        return self.__booleq(start, end, depth)

    def __booleq(self, start:int, end:int, depth:int) -> tuple:
        return self.__generic(
            start, end, depth, 'booleq',
            ["booleq ==/!= boolor", 'boolor'], {'=', '≠'},
            self.__booleq, self.__boolor, self.__boolor)

    def __boolor(self, start:int, end:int, depth:int) -> tuple:
        return self.__generic(
            start, end, depth, 'boolor',
            ["boolor | booland", 'booland'], {'|'},
            self.__boolor, self.__booland, self.__booland)

    def __booland(self, start:int, end:int, depth:int) -> tuple:
        return self.__generic(
            start, end, depth, 'booland',
            ["booland & boolin", 'boolin'], {'&'},
            self.__booland, self.__boolin, self.__boolin)

    def __boolin(self, start:int, end:int, depth:int) -> tuple:
        return self.__generic(
            start, end, depth, 'boolin',
            ["boolin in/notin sum", 'sum'], {'∈', '∉'},
            self.__boolin, self.__sum, self.__sum)

    def __sum(self, start:int, end:int, depth:int) -> tuple:
        return self.__generic(
            start, end, depth, 'sum',
            ["sum +- product", 'product'], {'+', '-'},
            self.__sum, self.__product, self.__product)

    def __product(self, start:int, end:int, depth:int) -> tuple:
        return self.__generic(
            start, end, depth, 'product',
            ["product */ boolnot", 'boolnot'], {'*', '/'},
            self.__product, self.__boolnot, self.__boolnot)

    def __boolnot(self, start:int, end:int, depth:int) -> tuple:
        debug('enter boolnot', depth)
        if self.string[start] == '!' and start < end + 1:
            res, n_stacked = self.__factor(start + 1, end, depth)
            if not res:
                self.__rollback(n_stacked, depth)
                return False, 0
            debug('pushop !', depth)
            self.stack.append('!')
            return True, n_stacked + 1
        return self.__factor(start, end, depth)

    def __factor(self, start:int, end:int, depth:int) -> tuple:
        debug('enter factor', depth)

        if self.string[start] == '(':
            debug(f"check: '(' expression ')' == {self.string[start:end]}", depth)
            par_count = 1
            j = start + 1
            while j < end:
                if self.string[j] == ')':
                    par_count -= 1
                    if par_count == 0:
                        break
                j += 1
            if par_count != 0:
                debug('err bad parenthesis', depth)
                return False, 0
            if j != end - 1:
                debug('err expected end of input', depth)
                return False, 0
            return self.__expression(start + 1, j, depth)

        if self.string[start] == '-':
            debug(f"check: '-' number == {self.string[start:end]}", depth)
            res, n_stacked = self.__factor(start + 1, end, depth)
            if not res:
                self.__rollback(n_stacked, depth)
                return False, 0
            debug('pushop —', depth)
            self.stack.append('—')
            return True, n_stacked + 1

        if self.string[start] == "'":
            if self.string[end-1] != "'":
                return False, 0
            x = self.string[start+1:end-1]
            debug(f'push {x}', depth)
            self.stack.append(Str(x))
            return True, 1

        if self.string[start] == '"':
            if self.string[end-1] != '"':
                return False, 0
            x = self.string[start+1:end-1]
            debug(f'push {x}', depth)
            self.stack.append(Str(x))
            return True, 1

        debug(f'enter number', depth)
        debug(f'check: number "{self.string[start:end]}"', depth + 1)
        return self.__number(start, end, depth + 1)

    def __number(self, start:int, end:int, depth:int) -> tuple:
        if self.string[start] in NUMBERS:
            x = self.__get_integer(start, end)
        elif self.string[start] in CHARS:
            x = self.__get_word(start, end)
        else:
            return False, 0

        if start + len(x) != end:
            return False, 0

        if self.string[start] in NUMBERS:
            debug(f'push {x}', depth)
            self.stack.append(int(x))
            return True, 1

        if x == 'true':
            x = 1
        elif x == 'false':
            x = 0

        debug(f'push {x}', depth)
        self.stack.append(x)
        return True, 1

    def __get_integer(self, start:int, end:int) -> str:
        i = start
        while i < end and self.string[i] in NUMBERS:
            i += 1
        return self.string[start:i]

    def __get_word(self, start:int, end:int) -> str:
        i = start
        j = i
        while i < end and self.string[i] in CHARS:
            i += 1
        res = self.string[start:i]
        if res in ['true', 'false']:
            return res
        return Var(res)


if __name__ == '__main__':
    # None means python computes differently boolean with integers and we can't verify
    # the exact result
    tests = [
        ('5-3', [5, 3, '-'], 2),
        ('1 in list', [1, Var("list"), '∈'], True),
        ('1 not in list', [1, Var("list"), '∉'], False),
        ('1000 in list', [1000, Var("list"), '∈'], False),
        ('1+2+3+4', [1, 2, '+', 3, '+', 4, '+'], 10),
        ('1*2*3*4', [1, 2, '*', 3, '*', 4, '*'], 24),
        ('1+2*3+4', [1, 2, 3, '*', '+', 4, '+'], 11),
        ('1*2+3+4', [1, 2, '*', 3, '+', 4, '+'], 9),
        ('1*2+3*4', [1, 2, '*', 3, 4, '*', '+'], 14),
        ('1+2+3*4', [1, 2, '+', 3, 4, '*', '+'], 15),
        ('(1+2)*3', [1, 2, '+', 3, '*'], 9),
        ('1+(2*3)', [1, 2, 3, '*', '+'], 7),
        ('1*(2+3)', [1, 2, 3, '+', '*'], 5),
        ('(1*2)+3', [1, 2, '*', 3, '+'], 5),
        ('not false and true', [0, '!', 1, '&'], 1),
        ('not true or true', [1, '!', 1, '|'], 1),
        ('a and b or 0', [Var("a"), Var("b"), '&', 0, '|'], False),
        ('2 * (3 + 1) * 7 and 8', [2, 3, 1, '+', '*', 7, '*', 8, '&'], None),
        ('1 and 2 * 5 + 7', [1, 2, 5, '*', 7, '+', '&'], None),
        ('1 * (3 and 0) * 7 + 5', [1, 3, 0, '&', '*', 7, '*', 5, '+'], 5),
        ('1 + 2 or 3+4*6 and 7*8 or 9*0', [1, 2, '+', 3, 4, 6, '*', '+', 7, 8, '*', '&', '|', 9, 0, '*', '|'], None),
        ('true and false or 123 * var1 + 789 * var2.attr', [1, 0, '&', 123, Var("var1"), '*', 789, Var("var2.attr"), '*', '+', '|'], None),
        ('true and(true or false)', [1, 1, 0, '|', '&'], True),
        ('8 / 4 / -2', [8, 4, '/', 2, '—', '/'], -1),
        ('5 + 2 == 7 * 2 - 7', [5, 2, '+', 7, 2, '*', 7, '-', '='], True),
        ('"abc" == "abc"', [Str("abc"), Str("abc"), '='], True),
    ]

    # print(Expression('1 in list').compile())
    # exit(0)

    vars_test = {'a': True, 'b': False, 'var1':5, 'var2.attr':6, 'list': [1,2,3]}

    print('compileok    resok    expr')
    for expr, expected, res in tests:
        compiled = Expression(expr).compile()
        val = rpn_eval(compiled, vars_test)

        if res is None:
            print(f'{compiled == expected:<12} ?        {expr}', end='')
        else:
            print(f'{compiled == expected:<12} {res == val:<8} {expr}', end='')

        if compiled != expected:
            print(f'   compiled={compiled}   expected={expected}')
        else:
            print()
