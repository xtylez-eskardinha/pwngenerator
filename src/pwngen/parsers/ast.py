# Import external dependencies
from pycparser import parse_file, c_ast
from pwngen.parsers.utils import Decls, from_dict, to_dict
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
                    "-E",
                    "-nostdinc",
                    "-Iutils/fake_libc_include",
                ],
            )
            return ast
        except Exception as e:
            print("Couldn't parse file...", e)
            raise FileNotFoundError

    def get_ast(self):
        return self._ast

    def get_fncalls_fndef(self, code: c_ast.FuncDef) -> list:
        fncalls = funcCalls()
        fncalls.visit(code)
        return fncalls.get_all_func_calls()

    def _get_func_name_calls(self, name: str) -> list:
        funccall = funcCalls()
        funccall.visit(self._ast)
        return funccall.get_func_call(name)

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
        self._funcs = self._get_fn_defs()
        self._globals = self._get_globals()
        self._vars = self._get_all_vars()
        self._fncalls = self._get_func_calls()

    def _split_datatypes(self) -> tuple[list, list]:
        typedefs = []
        code = []
        for x in self._ast.ext:
            if isinstance(x, c_ast.Typedef):
                typedefs.append(x)
            else:
                code.append(x)
        return typedefs, code

    def _get_fn_defs(self) -> dict:
        return {
            self._get_fn_name(x): x for x in self._ast if isinstance(x, c_ast.FuncDef)
        }

    def _get_globals(self) -> dict:
        results = {"structs": [], "vars": []}

        results["structs"] = {
            x.type.name: x
            for x in self._code
            if isinstance(x, c_ast.Decl) and isinstance(x.type, c_ast.Struct)
        }

        results["vars"] = {
            x.name: x
            for x in self._code
            if isinstance(x, c_ast.Decl) and not isinstance(x.type, c_ast.Struct)
        }

        return results

    def _parse_fn(self, block: c_ast.FuncDef) -> dict:
        returner = {"type": [], "params": {}, "code": []}

        decl_body = block.body
        decl_type = block.decl.type
        if decl_type.args is not None:
            decl_params = decl_type.args.params
        else:
            decl_params = []
        returner["type"] = decl_type.type.type.names
        returner["params"] = {x.name: x for x in decl_params}
        returner["code"] = decl_body.block_items

        return returner

    def _parse_all_fn(self) -> dict:
        fndefs = self._funcs

        return {x: self._parse_fn(fndefs[x]) for x in fndefs}

    def _get_all_vars(self) -> dict:
        parsed_fn = self._parse_all_fn()
        vars = {
            fn: [stm for stm in parsed_fn[fn]["code"] if isinstance(stm, Decls)]
            for fn in parsed_fn
        }
        vars["globals"] = [x for x in self.get_globals()["vars"].values()]

        return vars

    def generate_code(self) -> dict:
        _, code = self._split_datatypes()
        return code

    def _get_fn_name(self, block: c_ast.FuncDef) -> str:
        return block.decl.name

    def _parse_arraydecl(self, arraydecl: c_ast.ArrayDecl, scope: str = "") -> int:
        returner = -1
        if isinstance(arraydecl.dim, c_ast.ID):
            id = arraydecl.dim.name
            if id in self._globals["vars"]:
                decl = self._globals["vars"][id]
            if scope and scope in self._funcs:
                scopedecl = self._filter_fn_declarations(scope)["vars"]
                if id in scopedecl:
                    decl = scopedecl[id]
            returner = self.get_numdecl_value(decl)
        elif isinstance(arraydecl.dim, c_ast.Constant):
            returner = arraydecl.dim.value
        return int(returner)

    def _filter_fn_declarations(self, func: c_ast.FuncDef) -> dict:
        returner = {"arrays": {}, "vars": {}}

        for item in func.body.block_items:
            if isinstance(item, c_ast.Decl):
                if isinstance(item.type, c_ast.TypeDecl):
                    returner["vars"][item.name] = item
                elif isinstance(item.type, c_ast.ArrayDecl):
                    returner["arrays"][item.name] = item
            else:
                continue
        return returner

    def get_numdecl_value(self, numdecl: c_ast.Decl) -> int:
        if isinstance(numdecl.init, c_ast.Constant):
            return int(numdecl.init.value)
        else:
            return -1

    def get_arraydecl_size(
        self, decl: c_ast.Decl, scope: str = ""
    ) -> list[tuple[int, int]]:
        arraydim = 0
        returner = []

        if not isinstance(decl.type, c_ast.ArrayDecl):
            return returner

        arraydecl = decl.type

        while isinstance(arraydecl, c_ast.ArrayDecl):
            returner.append((arraydim, self._parse_arraydecl(arraydecl, scope)))
            arraydim += 1
            arraydecl = arraydecl.type

        return returner

    def filter_all_vars(self, kind) -> dict:
        return {
            fn: {var.name: var for var in self._vars[fn] if isinstance(var.type, kind)}
            for fn in self._vars
        }

    def _get_func_calls(self) -> dict:
        return {x: self._get_func_name_calls(x) for x in self._funcs}

    def get_all_fns(self) -> dict:
        return self._parse_all_fn()

    def change_funcname(self, func_name: str, new_name: str) -> bool:
        if not func_name in self._funcs:
            return False
        else:
            changer = self._funcs[func_name]
        changer.decl.name = new_name
        changer.decl.type.type.declname = new_name
        self._funcs[new_name] = self._funcs[func_name]
        self._funcs.pop(func_name, None)
        return True

    def change_buffsize(self, func_name: str, var_name: str, size: int):

        if not func_name in self._funcs:
            return False

        func = self._funcs.get(func_name)
        filtered_declarations = self._filter_declarations(func)

        buff = [decl for decl in filtered_declarations.get("arrays")]
        # for decl in filtered_declarations.get('arrays', []):
        #     print(json.dumps(decl))
        print(json.dumps(buff))
        # TODO

    def get_globals(self) -> dict:
        return self._globals

    def get_fn_defs(self) -> dict:
        return self._funcs

    def count_references(self) -> dict:
        returner = {}


class Pwn:
    def __init__(self, code: AST):
        self._codeast = code

    def get_pwnable(self):
        return None
