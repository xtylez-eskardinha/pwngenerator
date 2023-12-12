# Import external dependencies
from pycparser import parse_file, c_ast
from pwngen.parsers.visitors import funcDefs, funcCalls

class AST:

    def __init__(self, file: str):
        self._ast = self._parse_c(file)
        self._fndefs = funcDefs()
        self._fncalls_cache = {}
        self._fndefs_cache = {}

    def _parse_c(self, file: str):
        try:
            ast = parse_file(file, use_cpp=True, cpp_args=['-Iutils/fake_libc_include'])
            return ast
        except Exception as e:
            print("Couldn't parse file...", e)
            raise FileNotFoundError

    def get_ast(self):
        return self._ast

    def get_cached_calls(self) -> dict:
        return self._fncalls_cache

    def get_func_calls(self, name: str) -> dict:
        self._fncalls_cache[name] = funcCalls(name).visit(self._ast)
        print(self._fncalls_cache)
        return self._fncalls_cache[name]

    def get_func_defs(self) -> None:
        self._fndefs_cache = self._fndefs.visit(self._ast)

class Pwn:
    def __init__(self, code: AST):
        self._codeast = code
    
    def get_pwnable(self):
        return None