from pwngen.parsers.ast import AST
from pwngen.parsers.pwnable import Vulnerabilities

ast = AST('code/babybof.c')

ast.get_func_calls("pwnable")
ast.get_func_calls("scanf")
ast.get_func_defs()

pwn = Vulnerabilities(ast)
print(pwn.checkbofs())