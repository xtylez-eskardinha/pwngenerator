from pwngen.parsers.ast import AST

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

    def __init__(self, ast: AST):
        self._ast = ast
    
    def checkbofs(self):
        for func in self._bof:
            length = len(self._ast.get_func_calls(func))
            # print(length)

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
