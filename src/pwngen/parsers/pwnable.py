from typing import Any
from pwngen.parsers.ast import AstProcessor
from pwngen.parsers.utils import *
from pycparser import c_parser

# class Funcs(object):
#     def __init__(self, code: AST):
#         self._codeast = code

#     def checkpwn(self):
#         for danger in self._dangerous:
#             pass
class Function(object):

    _argsize: int
    _in: int
    _out: int
    _size: int
    _fndef: c_ast.FuncDef
    _custom: list[str]
    _args: c_ast.ExprList

    def __init__(
        self,
        fndef: c_ast.FuncDef,
        in_idx: int,
        out_idx: int,
        args: c_ast.ExprList,
        custom: list[str] = [],
        size_idx: int = -1,
        arg_num: int = -1,
    ):
        self._argsize = arg_num
        self._in = in_idx
        self._out = out_idx
        self._size = size_idx
        self._custom = custom
        self._args = args
        self._fndef = fndef

    def _parse_args(self) -> dict[str, list[Any]]:
        returner = {}
        # if self._argsize == -1:
        #     return {
        #         "in": [self._args[self._in]],
        #         self._args[]
        #     }
        for arg in self._args:
            continue
        return returner

class Gets(Function):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
  
class Scanf(Function):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class Printf(Function):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class Dangerous:
    _arg_size: int
    _input: int
    _output: int
    _kinds: list[str]
    _vulns: list[str]
    _custom: list[str]

    def __init__(
            self,
            arg_size: int,
            input_arg: int,
            output_arg: int,
            fn_kinds: list[str],
            vuln_kinds: list[str],
            custom: list[str] = []
            ):
        self._arg_size = arg_size
        self._input = input_arg
        self._output = output_arg
        self._kinds = fn_kinds
        self._vulns = vuln_kinds
        self._custom = custom

    def get_args_length(self) -> int:
        return self._arg_size
    
    def get_input_arg(self) -> int:
        return self._input
    
    def get_output_arg(self) -> int:
        return self._output
    
    def get_fn_kinds(self) -> list[str]:
        return self._kinds
    
    def get_vuln_kinds(self) -> list[str]:
        return self._vulns
    
    def get_customs(self) -> list[str]:
        return self._custom

class Vulnerabilities(object):

    _dangerous = {
        "gets": {"args": 1, "out": 0, "kind": "input", "vuln": ["bof"]},
        "gets_s": {"args": 2, "out": 0, "size": 1, "kind": "input"},
        "fgets": {"args": 3, "in": 2, "size": 1, "out": 0},
        "strcpy": {"args": 2, "out": 0, "in": 1},
        "strcat": {
            "args": 2,
            "out": 0,
            "in": 1,
            "custom": ["bof_append_from_in_to_out"],
        },
        "sprintf": {
            "args": -1,
            "out": 0,
            "in": 1,
            "custom": ["bof_save_from_in_to_out", "format_if_in_size_less_args"],
        },
        "snprintf": {
            "args": -1,
            "out": 0,
            "size": 1,
            "in": 2,
            "custom": ["bof_save_from_in_to_out", "format_if_in_size_less_args"],
        },
        # "vsprintf": {
        # },
        # "vsnprintf",
        "scanf": {
            "args": -1,
            "in": 0,
            "out": 1,
            "custom": ["bof_if_out_size_less_in_size"],
        },
        "strncat": {
            "args": 3,
            "in": 0,
            "out": 1,
            "size": 2,
            "custom": ["bof_append_from_in_to_out_if_in_size_less_out_size"],
        },
        "strncpy": {
            "args": 3,
            "out": 0,
            "in": 1,
            "size": 2,
            "custom": ["bof_if_out_size_less_size"],
        },
    }

    _bof = [
        "gets",
        "gets_s",
        "fgets",
        "strcpy",
        "scanf",
        "strncat",
        "strcat",
        "strncpy",
        "snprintf",
    ]

    _leaks = [
        "printf",
        "sprintf"
    ]

    _input = [
        "gets",
        "gets_s",
        "scanf",
        "fgets"
    ]

    def _parse_vulns(self):
        return AstProcessor("code/vulnerable.c")

    def _vulnlist_to_dict(self, vulns_ast: dict[str, Any]) -> dict[str, Any]:
        return {vulns_ast[vuln].decl.name: vulns_ast[vuln] for vuln in vulns_ast}

    def _dict_to_ast(self, ast: dict):
        return from_json(ast)

    def __init__(self, ast: AstProcessor):
        self._ast = ast
        self._vulnast = self._parse_vulns()
        self._vulnfuncslist = self._vulnast.get_fn_defs()
        self._vulnfuncsdict = self._vulnlist_to_dict(self._vulnfuncslist)
        # print(self._vulnfuncsdict)

    def get_vulnerability_types(self) -> dict[str, list]:
        return {
            "input": self._input,
            "leak": self._leaks,
            "bof": self._bof
        }

    def get_vuln_fndefs(self):
        return self._vulnast.get_fn_defs()

    def get_dangerous(self) -> list[str]:
        return list(self._dangerous.keys())

    def change_args(self, fncall: c_ast.FuncCall, target: c_ast.FuncDef):
        fn = fncall.name.name
        if not fn in self._dangerous:
            return False
        else:
            params = self._dangerous.get(fn)

    def swap_funccalls(self, origin: c_ast.FuncCall, target: c_ast.FuncDef):
        origin.name.name = self._ast._gen_id(target)
        self._ast._update_state()

    # def checkbofs(self):
    #     return [func for func in self._bof if len(self._ast.get_func_calls(func)) > 0]

    # def get_function_bofs(self, function: str) -> dict:
    #     return self._ast.get_func_calls(function)


# class FormatPwn(Funcs):

#     dangerous = [
#         "printf",
#         "fprintf",
#         "vprintf",
#         "vfprintf",
#         "scanf",
#         "fscanf",
#         "sscanf",
#         "vsscanf"
#     ]

# class HeapPwn(Funcs):

#     dangerous = [
#         "malloc",
#         "free",
#         "realloc",
#         "calloc"
#     ]

# # class MiscPwn(Funcs):
