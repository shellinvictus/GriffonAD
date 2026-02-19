# Mathematical expression parser to avoid code injection in the compiled program

from colorama import Style
Style.UNDERLINE = '\033[4m'

NUMBERS = set('0123456789')
CHARS = set('0123456789_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
BIN_OP = set('+-*/&|∈∉')

DEBUG = False

def debug(s:str, depth:int):
    if DEBUG:
        tab = ' ' * 4 * depth
        print(tab, s)


# Reverse Polish Notation
def rpn_eval(polish:list, vars:dict={}) -> int:
    stack = []
    for x in polish:
        if isinstance(x, int):
            stack.append(x)
        elif isinstance(x, str):
            if x in BIN_OP:
                r = stack.pop()
                l = stack.pop()
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
                    stack.append(not stack.pop())
                case _:
                    if x in vars:
                        stack.append(vars[x])
                    elif x.startswith('opt.'): # undefined here, otherwise it should be present in vars
                        stack.append(False)
                    else:
                        print(f'error: undefined variable {x}')
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

    def __cleanup_spaces(self):
        self.string = self.string\
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
    all rules are left to right: is it really a problem for 'and' and 'or' ?

    expression = boolor 'or' expression | boolor
    boolor = booland 'and' boolor | boolor
    booland = boolin '∈|∉' booland |  '-' booland | boolin
    boolin = term '+' boolin | term '-' boolin | term
    term = factor '*' boolnot | factor '/' boolnot | factor
    boolnot = 'not' factor | factor
    factor = '(' expression ')' | number
    number = integer | true | false | var
    """

    # The returned tuple is: (bool, int)
    # bool: is the grammar rule returned an error?
    # int: number of elements pushed on the stack, we need to unstack all of them
    # if the bool is False

    # Generic function for binary operators
    def __generic_expression(self, start:int, end:int, depth:int, func_name:str,
                 grammar_rules_description:tuple, op:set, left_func) -> tuple:
        debug(f'enter {func_name}', depth)
        debug(f"check ({grammar_rules_description[0]}) match ('{self.string[start:end]}')", depth)

        ret = False
        n_stacked = 0
        j = start

        # do grammar_rules_description[0]
        # left to right
        while j < end:
            if self.string[j] in op:
                left = f'{Style.UNDERLINE}{self.string[start:j]}{Style.RESET_ALL}'
                debug(f'check left {left} | {self.string[j+1:end]}', depth)

                ret, ns = left_func(start, j, depth + 1)

                if ret:
                    n_stacked += ns
                    break

                self.__rollback(ns, depth)
            j += 1

        if ret:
            right = f'{Style.UNDERLINE}{self.string[j+1:end]}{Style.RESET_ALL}'
            debug(f'check right {self.string[start:j]} | {right}', depth)

            ret, ns = self.__generic_expression(
                    j + 1,
                    end,
                    depth + 1,
                    func_name,
                    grammar_rules_description,
                    op,
                    left_func)

            n_stacked += ns

            if ret:
                debug(f'pushop {self.string[j]}', depth)
                self.stack.append(self.string[j])
                return ret, n_stacked + 1

        if not ret:
            self.__rollback(n_stacked, depth)

        # else if error, do grammar_rules_description[1]
        debug(f"check ({grammar_rules_description[1]}) match ('{self.string[start:end]}')", depth)
        return left_func(start, end, depth + 1)

    def __expression(self, start:int, end:int, depth:int) -> tuple:
        return self.__generic_expression(
            start, end, depth, 'expression',
            ["boolor '|' expression", 'boolor'],
            {'|'}, self.__boolor)

    def __boolor(self, start:int, end:int, depth:int) -> tuple:
        return self.__generic_expression(
            start, end, depth, 'boolor',
            ["booland '&' boolor", 'booland'],
            {'&'}, self.__booland)

    def __booland(self, start:int, end:int, depth:int) -> tuple:
        return self.__generic_expression(
            start, end, depth, 'booland',
            ["boolin '(in/notin)' booland", 'boolin'],
            {'∈', '∉'}, self.__boolin)

    def __boolin(self, start:int, end:int, depth:int) -> tuple:
        return self.__generic_expression(
            start, end, depth, 'boolin',
            ["term '+-' boolin", 'term'],
            {'+', '-'}, self.__term)

    def __term(self, start:int, end:int, depth:int) -> tuple:
        return self.__generic_expression(
            start, end, depth, 'term',
            ["boolnot '*/' term", 'boolnot'],
            {'*', '/'}, self.__boolnot)

    def __boolnot(self, start:int, end:int, depth:int) -> tuple:
        debug('enter boolnot', depth)
        if self.string[start] == '!' and start < end + 1:
            res, n_stacked = self.__factor(start + 1, end, depth)
            if not res:
                self.__rollback(n_stacked, depth)
            debug('pushop !', depth)
            self.stack.append('!')
            return True, n_stacked + 1
        return self.__factor(start, end, depth)

    def __factor(self, start:int, end:int, depth:int) -> tuple:
        debug('enter factor', depth)

        if self.string[start] == '(':
            debug(f"check: '(' expression ')'  == {self.string[start:end]}", depth)
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

        debug(f'check: number  == {self.string[start:end]}', depth)
        return self.__number(start, end, depth)

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
        return self.string[start:i]

        s
if __name__ == '__main__':
    # None means python computes differently boolean with integers and we can't verify
    # the exact result
    tests = [
        ('5-3', [5, 3, '-'], 2),
        ('1 in list', [1, 'list', '∈'], True),
        ('1 not in list', [1, 'list', '∉'], False),
        ('1000 in list', [1000, 'list', '∈'], False),
        ('1+2+3+4', [1, 2, 3, 4, '+', '+', '+'], 10),
        ('1*2*3*4', [1, 2, 3, 4, '*', '*', '*'], 24),
        ('1+2*3+4', [1, 2, 3, '*', 4, '+', '+'], 11),
        ('1*2+3+4', [1, 2, '*', 3, 4, '+', '+'], 9),
        ('1*2+3*4', [1, 2, '*', 3, 4, '*', '+'], 14),
        ('1+2+3*4', [1, 2, 3, 4, '*', '+', '+'], 15),
        ('(1+2)*3', [1, 2, '+', 3, '*'], 9),
        ('1+(2*3)', [1, 2, 3, '*', '+'], 7),
        ('1*(2+3)', [1, 2, 3, '+', '*'], 5),
        ('(1*2)+3', [1, 2, '*', 3, '+'], 5),
        ('not false and true', [0, '!', 1, '&'], 1),
        ('not true or true', [1, '!', 1, '|'], 1),
        ('a and b or 0', ['a', 'b', '&', 0, '|'], False),
        ('2 * (3 + 1) * 7 and 8', [2, 3, 1, '+', 7, '*', '*', 8, '&'], None),
        ('1 and 2 * 5 + 7', [1, 2, 5, '*', 7, '+', '&'], None),
        ('1 * (3 and 0) * 7 + 5', [1, 3, 0, '&', 7, '*', '*', 5, '+'], 5),
        ('1 + 2 or 3+4*6 and 7*8 or 9*0', [1, 2, '+', 3, 4, 6, '*', '+', 7, 8, '*', '&', 9, 0, '*', '|', '|'], None),
        ('true and false or 123 * var1 + 789 * var2.attr', [1, 0, '&', 123, 'var1', '*', 789, 'var2.attr', '*', '+', '|'], None),
        ('true and(true or false)', [1, 1, 0, '|', '&'], True),
    ]

    print('compileok    resok    expr')
    for expr, compiled, res in tests:
        r1 = Expression(expr).compile()
        r2 = rpn_eval(r1, {'a': True, 'b': False, 'var1':5, 'var2.attr':6, 'list': [1,2,3]})
        print(r1 == compiled, '       ', res == r2 if res is not None else '?   ', '     ', expr, r1)
