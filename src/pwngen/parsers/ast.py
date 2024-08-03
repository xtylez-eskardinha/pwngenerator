# Import external dependencies
from typing import Any
from pycparser import parse_file, c_ast, c_generator
from pwngen.parsers.utils import Decls, from_dict, to_dict, to_json
from pwngen.parsers.visitors import funcDefs, funcCalls
from z3 import *
import json


class AstProcessor:

    def __init__(self, file: str):
        self._file = file
        self._ast = self._parse_c(file)
        self._astjson = to_dict(self._ast)
        self._update_state()
        # self.create_stack(self._code)

    def _parse_c(self, file: str):
        try:
            ast = parse_file(
                file,
                use_cpp=True,
                cpp_args=[
                    "-E",
                    "-nostdinc",
                    "-Iutils/fake_libc_include",
                ], # type: ignore
            )
            return ast
        except Exception as e:
            print("Couldn't parse file...", e)
            raise FileNotFoundError

    def get_ast(self):
        return self._ast

    def get_all_fncalls_fndef(self, code: c_ast.FuncDef) -> list:
        fncalls = funcCalls()
        fncalls.visit(code)
        return fncalls.get_all_func_calls()

    def _get_func_name_calls(self, name: str) -> list:
        funccall = funcCalls()
        funccall.visit(self._ast)
        return funccall.get_func_call(name)

    def to_dict(self) -> dict:
        return self._astjson

    def from_dict(self, ast: dict):
        self._ast = from_dict(ast)

    def _update_state(self):
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

    def _preprocess_c(self) -> list[str]:
        with open(self._file, 'r') as f:
            return [
                line.strip() for line in f.readlines() 
                if line.startswith("#")
            ]

    def _get_first_decl(self) -> str:
        # with open(self._file, 'r') as f:
        #     lines = f.readlines()
        #     for line in lines:
        #         if line and not line.startswith("#"):
        #             return line.strip()
        # return ""
        for node in self._ast.ext:
            if not isinstance(node, c_ast.Typedef):
                if isinstance(node, c_ast.Decl):
                    return node.type.name
                elif isinstance(node, c_ast.FuncDef):
                    return node.decl.name
                else:
                    print(node)
        return ""

    def save_c(self, file: str):
        gen = c_generator.CGenerator()
        with open(file, 'w') as f:
            f.write('\n'.join(self._preprocess_c()))
            f.write('\n')
            to_write = gen.visit(self._ast)
            first_decl = self._get_first_decl()
            for i, line in enumerate(to_write.splitlines()):
                if first_decl in line.strip():
                    f.write('\n')
                    break
            f.write('\n'.join(to_write.splitlines()[i:]))
            print("File succesfuly created...", file)

    def _get_fn_defs(self) -> dict[str, Any]:
        return {
            self._get_fn_name(x): x for x in self._ast if isinstance(x, c_ast.FuncDef)
        }

    def _get_globals(self) -> dict[str, dict[str, c_ast.Decl | c_ast.Struct]]:
        results = {"structs": {}, "vars": {}}

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

    def _parse_fncall(self, fncall: c_ast.FuncCall, scope: str = "") -> dict:
        returner = {"name": fncall.name.name, "args": []}
        if not fncall.args:
            return returner

        for arg in fncall.args:
            if isinstance(arg, c_ast.ID):
                returner["args"].append(self._locate_id(arg, scope))
            elif isinstance(arg, c_ast.FuncCall):
                returner["args"].append(self._parse_fncall(arg, scope))
            elif isinstance(arg, c_ast.Constant):
                returner["args"].append(arg)
            else:
                returner["args"].append(arg)
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

    def get_all_vars(self) -> dict:
        return self._vars

    def generate_code(self) -> list:
        _, code = self._split_datatypes()
        return code

    def _get_fn_name(self, block: c_ast.FuncDef) -> str:
        return block.decl.name

    # TODO Improve and support more types
    def _gen_id(self, target: c_ast.FuncDef) -> c_ast.ID:
        return c_ast.ID(target.decl.name, None)

    def _locate_id(self, id: c_ast.ID, scope: str = "") -> c_ast.Decl | None:
        decl: c_ast.Decl | None = None
        if isinstance(id, c_ast.ID):
            name = id.name
            if name in self._globals["vars"]:
                decl = (
                    self._globals["vars"][name]
                    if isinstance(self._globals["vars"][name], c_ast.Decl)
                    else None
                ) # type: ignore
            if scope and scope in self._funcs:
                func: c_ast.FuncDef = self._funcs[scope]
                scopedecl = self._filter_fn_declarations(func)
                vars = scopedecl["vars"]
                arrays = scopedecl["arrays"]
                if name in vars or name in arrays:
                    decl = vars[name] if name in vars else arrays[name]

            if decl is None:
                print(id)

            return decl

    def _parse_arraydecl(self, arraydecl: c_ast.ArrayDecl, scope: str = "") -> int:
        returner = -1
        if isinstance(arraydecl.dim, c_ast.ID):
            decl = self._locate_id(arraydecl.dim, scope)
            if decl is not None:
                returner = self.get_numdecl_value(decl)
        elif isinstance(arraydecl.dim, c_ast.Constant):
            returner = arraydecl.dim.value
        return int(returner)

    def _change_arraydecl_dim(
        self, arraydecl: c_ast.ArrayDecl, size: int, scope: str = ""
    ) -> int:
        returner = -1
        if isinstance(arraydecl.dim, c_ast.ID):
            decl = self._locate_id(arraydecl.dim, scope)
            if decl is not None:
                returner = self.set_numdecl_value(decl, size)
        elif isinstance(arraydecl.dim, c_ast.Constant):
            arraydecl.dim.value = str(size)
            returner = arraydecl.dim.value
        return int(returner)

    def _filter_fn_declarations(self, func: c_ast.FuncDef) -> dict[str, Any]:
        returner = {"arrays": {}, "vars": {}}

        for item in func.body.block_items:
            if isinstance(item, c_ast.Decl):
                if isinstance(item.type, (c_ast.TypeDecl)):
                    returner["vars"][item.name] = item
                elif isinstance(item.type, (c_ast.ArrayDecl, c_ast.PtrDecl)):
                    returner["arrays"][item.name] = item
            else:
                continue
        return returner

    def get_var_fromid(self, id: c_ast.ID, scope: str = "") -> c_ast.Decl | None:
        return self._locate_id(id, scope)

    def get_fn_def_args(self, funcdef: c_ast.FuncDef):
        return funcdef.decl.type.args.params

    def get_numdecl_value(self, numdecl: c_ast.Decl) -> int:
        if isinstance(numdecl.init, c_ast.Constant):
            return int(numdecl.init.value)
        else:
            return -1

    def set_numdecl_value(self, numdecl: c_ast.Decl, size: int) -> int:
        if isinstance(numdecl.init, c_ast.Constant):
            numdecl.init.value = str(size)
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

    def get_fn_call_args(self, fn: c_ast.FuncCall) -> dict:
        returner = {}
        print(fn)
        if not isinstance(fn, c_ast.FuncCall):
            return returner
        else:
            return fn.args

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

    def change_stack_buffsize(
        self, var_name: str, dimension: int, size: int, func_name: str = "globals"
    ):
        self._update_state()
        if not func_name in self._vars:
            return False
        var = [x for x in self._vars[func_name] if x.name == var_name]
        if not var:
            return False

        dim = max(y for y, x in self.get_arraydecl_size(var[-1], func_name))

        if dim < dimension:
            return False

        decl = var[-1].type

        while dim != dimension:
            decl = decl.type
            dim -= 1

        return self._change_arraydecl_dim(decl, size, func_name)

    def get_globals(self) -> dict:
        return self._globals

    def get_fn_defs(self) -> dict[str, Any]:
        return self._funcs

    def count_references(self) -> dict:
        # TODO
        returner = {}
        return returner

    def insert_funcdef(self, func: c_ast.FuncDef):
        index = 0
        for i, ast in enumerate(self._ast.ext):
            if not isinstance(ast, c_ast.FuncDef):
                continue
            else:
                if self._get_fn_name(ast) == "main":
                    index = i
                    break
        self._ast.ext.insert(index, func)
        self._update_state()

class Pwn:
    def __init__(self, code: AstProcessor):
        self._codeast = code

    def get_pwnable(self):
        return None
