from pwngen.parsers.ast import AST
from pwngen.parsers.utils import *
from pycparser import c_parser

# class Funcs(object):
#     def __init__(self, code: AST):
#         self._codeast = code

#     def checkpwn(self):
#         for danger in self._dangerous:
#             pass


class Vulnerabilities(object):

    _dangerous = {
        "gets": {
            "args": 1,
            "out":0
        },
        "gets_s": {
            "args": 2,
            "out":0,
            "size":1
        },
        "strcpy": {
            "args": 2,
            "out":0,
            "in":1
        },
        "strcat": {
            "args": 2,
            "out":0,
            "in":1,
            "custom": [
                "bof_append_from_in_to_out"
            ]
        },
        "sprintf": {
            "args": -1,
            "out": 0,
            "in": 1,
            "custom": [
                "bof_save_from_in_to_out",
                "format_if_in_size_less_args"
            ]
        },
        "snprintf": {
            "args": -1,
            "out": 0,
            "size":1,
            "in":2,
            "custom": [
                "bof_save_from_in_to_out",
                "format_if_in_size_less_args"
            ]
        },
        # "vsprintf": {

        # },
        # "vsnprintf",
        "scanf": {
            "args":2,
            "in": 0,
            "out": 1,
            "custom": [
                "bof_if_out_size_less_in_size"
            ]
        },
        "strncat":{
            "args":3,
            "in": 0,
            "out":1,
            "size":2,
            "custom": [
                "bof_append_from_in_to_out_if_in_size_less_out_size"
            ]
        },
        "strncpy": {
            "args": 3,
            "out":0,
            "in": 1,
            "size":2,
            "custom": [
                "bof_if_out_size_less_size"
            ]
        }
    }

    _bof = [
        "gets",
        "gets_s",
        "strcpy",
        "scanf",
        "strncat",
        "strcat",
        "strncpy",
        "snprintf"
    ]

    def _parse_vulns(self):
        return AST("code/vulnerable.c")

    def _vulnlist_to_dict(self, vulns_ast: list) -> dict:
        return {
            vuln.decl.name : to_dict(vuln) for vuln in vulns_ast
        }
    
    def _dict_to_ast(self, ast: dict):
        return from_json(ast)

    def __init__(self, ast: AST):
        self._ast = ast
        self._vulnast = self._parse_vulns()
        self._vulnfuncslist = self._vulnast.get_func_defs()
        self._vulnfuncsdict = self._vulnlist_to_dict(self._vulnfuncslist)
        # print(self._vulnfuncsdict)

    def checkbofs(self):
        return [
            func for func in self._bof 
            if len(self._ast.get_func_calls(func)) > 0
        ]

        # for func in self._bof:
        #     vulnerable = len(self._ast.get_func_calls(func)) > 0
        #     print(func, vulnerable)

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
