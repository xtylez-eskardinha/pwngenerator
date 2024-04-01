# Import external dependencies
from pycparser import parse_file, c_ast
from pwngen.parsers.utils import from_dict, to_dict
from pwngen.parsers.visitors import funcDefs, funcCalls

class AST:

    def __init__(self, file: str):
        self._ast = self._parse_c(file)
        self._fndefs = funcDefs()

    def _parse_c(self, file: str):
        try:
            ast = parse_file(file, use_cpp=True, cpp_args=['-Iutils/fake_libc_include'])
            return ast
        except Exception as e:
            print("Couldn't parse file...", e)
            raise FileNotFoundError

    def get_ast(self):
        return self._ast

    def get_func_calls(self, name: str) -> dict:
        funccall = funcCalls(name)
        funccall.visit(self._ast)
        return funccall.getFuncCalls()

    def get_func_defs(self) -> list:
        self._fndefs.visit(self._ast)
        return self._fndefs.getFuncDefs()
    
    def to_dict(self) -> dict:
        return to_dict(self._ast)
    
    def from_dict(self, ast: dict):
        self._ast = from_dict(ast)

class AstProcessor:

    def _get_declaration_names(self) -> list:
        returner = []
        if self._ast['body']['_nodetype'] != "Compound":
            return []
        return [ 
            item['name']
            for item in self._ast['body']['block_items']
            if item['_nodetype'] == "Decl"
        ]
    
    def _filter_declarations(self, declarations: list) -> list:
        returner = {
            "arrays": [],
            "vars": []
        }

        for item in self._ast['body']['block_items']:
            if item['type']['_nodetype'] == "ArrayDecl":
                returner['arrays'].append(item)
            elif item['type']['_nodetype'] == "TypeDecl":
                returner['vars'].append(item)
            else:
                continue

        return returner

    def __init__(self, c_ast: dict):
        self._ast = c_ast.copy()
        self._type = self._ast['_nodetype']

    def change_funcname(self, new_name: str):
        if not self._type == "FuncDef":
            print("Not a function definition")
            return False
        self._ast['decl']['name'] = new_name
        self._ast['decl']['type']['type']['declname'] = new_name
        return True
    
    def change_buffsize(self, size: int):
        declarations = self._get_declaration_names()
        filtered_declarations = self._filter_declarations(declarations)
        for decl in filtered_declarations.get('arrays', []):
            print(decl)
        # TODO


class Pwn:
    def __init__(self, code: AST):
        self._codeast = code
    
    def get_pwnable(self):
        return None
