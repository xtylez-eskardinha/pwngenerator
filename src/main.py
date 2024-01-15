from pwngen.parsers.ast import AST
from pwngen.parsers.pwnable import Vulnerabilities

ast = AST('code/babybof.c')

print(ast.get_func_calls("pwnable"))
print(ast.get_func_calls("scanf"))
print(ast.get_func_defs())

pwn = Vulnerabilities(ast)
# print(pwn.checkbofs())