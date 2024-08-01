from pwngen.logic.sast import SAST
from pwngen.parsers.ast import AstProcessor
from pwngen.parsers.pwnable import Vulnerabilities
from pycparser import c_ast
from random import randint

class VulnGen:

    _ast: AstProcessor
    _sast: SAST
    _vulns: Vulnerabilities

    def __init__(self, ast: AstProcessor, difficulty: int = 0):
        self._ast = ast
        self._sast = SAST(self._ast)
        self._vulns = self._sast.get_vulns_class()
        self._sast.create_stack()
        self._difficulty = difficulty

    def _func_generator(self, kind: str) -> c_ast.FuncDef:
        danger = self._vulns.get_vuln_fndefs()
        vuln_kinds = self._vulns.get_vulnerability_types()
        vuln_kind = ""
        if kind == "ret2win":
            return danger["ret2win"]
        for possible in vuln_kinds:
            if kind in vuln_kinds[possible]:
                vuln_kind = possible
        # print(f'{vuln_kind}_gets_bof')
        if self._difficulty == 0:
            return danger[f'{vuln_kind}_gets_bof']
        else:
            return danger[f'{vuln_kind}_gets_bof_canary']

    def _set_orig_bufsize(
            self,
            orig_buff: c_ast.ID,
            orig_fn_scope: str,
            dest_fndef: str,
            ):
        out_var = self._ast.get_var_fromid(orig_buff, orig_fn_scope)
        print(out_var)
        if isinstance(out_var, c_ast.Decl):
            size = self._ast.get_arraydecl_size(out_var, orig_fn_scope)[-1]
            self._ast.change_stack_buffsize("buffer", size[0], size[1], dest_fndef)
            return True
        else:
            return False

    def _change_args(self, fncall: c_ast.FuncCall, fndef: c_ast.FuncDef) -> None:
        func_descr = self._vulns._dangerous.get(fncall.name.name)
        if func_descr:
            if func_descr['args'] > 1:
                fncall.args.exprs = [
                    fncall.args.exprs[func_descr['out']]
                ]
        return None

    def _change_vuln_bufsize(self, func_name: str):
        self._ast.change_stack_buffsize("filler", 0, randint(2**6, 2**10), func_name)

    def _swap_funcs(self, fncall: c_ast.FuncCall, fndef: c_ast.FuncDef):
        fncall.name.name = fndef.decl.name

    def _process_problems(self) -> bool:
        modified = []
        problems = self._sast.get_problems()
        if self._difficulty == 0:
            ret2win = self._func_generator("ret2win")
            self._ast.insert_funcdef(ret2win)
        if not problems:
            return False
        for problem in problems:
            kind = problem.get_fn_name()
            fncall = problem.get_fncall()
            problem_scope = problem.get_fn_scope()
            new_func = self._func_generator(kind)
            if not new_func:
                continue
            self._ast.insert_funcdef(new_func)
            self._ast.change_funcname(new_func.decl.name, "input_1")
            self._change_args(fncall, new_func)
            buf_arg = fncall.args.exprs[0]
            self._swap_funcs(fncall, new_func)
            self._change_vuln_bufsize(new_func.decl.name)
            self._set_orig_bufsize(buf_arg, problem_scope, new_func.decl.name)
        return True
        # print(problems)
        # print(self._vulns._vulnfuncsdict)

    def inject_vulns(self):
        return self._process_problems()
    
    def change_problem(self):
        return
    
    def set_difficulty(self, level: int):
        self._difficulty = level

    def get_compiler_syntax(self, data_model: str = "32") -> list[str]:
        returner = [f"-m{data_model}"]
        if self._difficulty == 0:
            returner.append("-static")
            returner.append("-fno-stack-protector")
            returner.append("-no-pie")
            returner.append("-z noexecstack")
        if self._difficulty > 1:
            returner.append("-z execstack")
        if self._difficulty > 2:
            returner.append("-fstack-protector-strong")
        if self._difficulty > 3:
            returner.append("-fPIE -pie")
        return returner
        return ' '.join(returner)