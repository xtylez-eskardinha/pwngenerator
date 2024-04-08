# Import external dependencies
from pycparser import parse_file, c_ast
from pwngen.parsers.utils import from_dict, to_dict
from pwngen.parsers.visitors import funcDefs, funcCalls
import json

class AST:

    def __init__(self, file: str):
        self._ast = self._parse_c(file)
        self._astjson = to_dict(self._ast)

    def _parse_c(self, file: str):
        try:
            ast = parse_file(
                file,
                use_cpp=True,
                cpp_args=[
                    '-E',
                    '-nostdinc',
                    '-Iutils/fake_libc_include',
                ],
            )
            return ast
        except Exception as e:
            print("Couldn't parse file...", e)
            raise FileNotFoundError

    def get_ast(self):
        return self._ast

    def get_func_name_calls(self, name: str) -> dict:
        funccall = funcCalls(name)
        funccall.visit(self._ast)
        return funccall.getFuncCalls()

    def get_func_defs(self) -> list:
        self._fndefs.visit(self._ast)
        return self._fndefs.getFuncDefs()
    
    def to_dict(self) -> dict:
        return self._astjson
    
    def from_dict(self, ast: dict):
        self._ast = from_dict(ast)

class AstProcessor(AST):

    def __init__(self, file: str):
        super().__init__(file)
        self._typedefs, self._code = self._split_datatypes()

    def _split_datatypes(self) -> tuple[list, list]:
        typedefs = []
        code = []

        for x in self._astjson['ext']:
            if x['_nodetype'] == "Typedef":
                typedefs.append(x)
            else:
                code.append(x)

        return typedefs, code

    def _get_fn_defs(self) -> dict:
        return {
            self._get_fn_name(x) : x
            for x in self._code
            if x['_nodetype'] == "FuncDef"
        }
    
    def _parse_fn(self, block: dict) -> dict:
        returner = {
            "type" : [],
            "params" : {},
            "code" : []
        }

        decl_body = block['body']
        decl_type = block['decl']['type']
        if not isinstance(decl_type['args'], type(None)):
            decl_params = decl_type.get('args', {}).get('params', [])
        else:
            decl_params = []
        returner['type'] = decl_type['type']['type']['names']
        returner['params'] = {
            x['name']: x
            for x in decl_params
        }
        returner['code'] = decl_body.get('block_items', [])

        return returner

    def _parse_all_fn(self) -> dict:
        fndefs = self._get_fn_defs()

        return {
            x : self._parse_fn(fndefs[x]) 
            for x in self._get_fn_defs() 
        }

    def generate_code(self) -> dict:
        _, code = self._split_datatypes()
        return code

    def _get_fn_name(self, block: dict) -> str:
        return block.get('decl', {}).get('name')
    
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

    def get_all_fns(self) -> dict:
        return self._parse_all_fn()

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
