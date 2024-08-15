from copy import deepcopy
import itertools
from typing import Any
from pwngen.logic.sast import SAST, Problem
from pwngen.parsers.ast import AstProcessor
from pwngen.parsers.exprs import ExprList
from pwngen.parsers.pwnable import Vulnerabilities
from pycparser import c_ast
from random import randint, choice

class Vuln:
    _fncall: c_ast.FuncCall
    _fndef: c_ast.FuncDef
    _kind: str
    
    def __init__(
            self,
            fncall: c_ast.FuncCall,
            fndef: c_ast.FuncDef,
            kind: str):
        self._fncall = fncall
        self._fndef = fndef
        self._kind = kind

class VulnGen:

    _ast: AstProcessor
    _sast: SAST
    _vulns: Vulnerabilities
    _gen: list[Vuln]

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
            return deepcopy(danger[f'{vuln_kind}_{kind}_bof'])
        else:
            return deepcopy(danger[f'{vuln_kind}_{kind}_bof_canary'])

    def _set_orig_bufsize(
            self,
            orig_buff: c_ast.ID | c_ast.UnaryOp,
            orig_fn_scope: str,
            dest_fndef: str,
            ):
        if isinstance(orig_buff, c_ast.UnaryOp):
            orig_buff = orig_buff.expr
        out_var = self._ast.get_var_fromid(orig_buff, orig_fn_scope) # type: ignore
        if isinstance(out_var, c_ast.Decl):
            size = self._ast.get_arraydecl_size(out_var, orig_fn_scope)[-1]
            self._ast.change_stack_buffsize("buffer", size[0], size[1], dest_fndef)
            return True
        else:
            return False

    def _adapt_format_args(self, fn_descr: dict, fndef: c_ast.FuncDef, args: c_ast.ExprList):
        return

    def _change_args(self, fncall: c_ast.FuncCall, fndef: c_ast.FuncDef) -> None:
        func_descr = self._vulns._dangerous.get(fncall.name.name)
        if func_descr:
            if func_descr['args'] > 1:
                fncall.args.exprs = [
                    fncall.args.exprs[func_descr['out']]
                ]
            elif func_descr['args'] == -1:
                fncall.args.exprs = fncall.args.exprs[func_descr['out']:]
            if len(fncall.args.exprs) > 1:
                self._adapt_format_args(func_descr, fndef, fncall.args.exprs) # type: ignore
        return None

    def _change_vuln_bufsize(self, func_name: str):
        self._ast.change_stack_buffsize("filler", 0, randint(2**6, 2**10), func_name)

    def _swap_funcs(self, fncall: c_ast.FuncCall, fndef: c_ast.FuncDef):
        fncall.name.name = fndef.decl.name

    def _modify_fmtstr_args(self, problem: Problem):
        fndef = self._func_generator(
            f"input_{problem.get_fn_name()}_custom_bof")
        fncall = problem.get_fncall()
        fndef_args = fndef.decl.args
        fncall_args = problem.get_args()

    def _merge_fmtstr(self, text: list[str], formats: list[str]) -> list[str]:
        merged = list(itertools.chain(*zip(text, formats)))
        if len(text) > len(formats):
            merged.append(text[-1])
        return merged

    def _divide_fmtstr(
            self,
            problem: Problem
            ) -> tuple[int, list[c_ast.FuncCall]] | tuple[int, None]:
        returner = []
        possible, text, fmt_str = problem.parse_fmt_str()
        if not fmt_str:
            return -1, None
        vuln = choice(fmt_str)
        idx = possible.index(vuln)
        text_const = deepcopy(problem.get_args().exprs[0])
        func_pre = deepcopy(problem)
        func_post = deepcopy(problem)
        pre_args = func_pre.get_args()
        post_args = func_post.get_args()
        pre_args.exprs = pre_args.exprs[1:idx+1]
        if len(pre_args.exprs) != 0:
            text_pre = deepcopy(text_const)
            inserter = self._merge_fmtstr(text[:idx], possible[:idx])
            text_pre.value = f'"{"".join(inserter)}"'
            pre_args.exprs.insert(0, text_pre)
            returner.append(func_pre.get_fncall())
        post_args.exprs = post_args.exprs[idx+2:]
        if len(post_args.exprs) != 0:
            text_post = deepcopy(text_const)
            inserter = self._merge_fmtstr(text[idx+1:], possible[idx+1:])
            text_post.value = f'"{"".join(inserter)}"'
            post_args.exprs.insert(0, text_post)
            returner.append(func_post.get_fncall())
        return idx, returner
        # return args_copy.exprs.pop(idx+1)

    def _process_problems(self) -> bool:
        modified = []
        problems = self._sast.get_problems()
        # print(self._ast._fncalls)
        if self._difficulty == 0:
            ret2win = self._func_generator("ret2win")
            self._ast.insert_fndef(ret2win)
        if not problems:
            return False
        for problem in problems:
            self.create_problem(problem)
            
        return True
        # print(problems)
        # print(self._vulns._vulnfuncsdict)

    def _create_vuln(self, problem: Problem):
        kind = problem.get_fn_name()
        fncall = problem.get_fncall()
        problem_scope = problem.get_fn_scope()
        new_func = self._func_generator(kind)
        if not new_func:
            return False
        self._ast.insert_fndef(new_func)
        self._ast.change_funcname(new_func.decl.name, f"input_{randint(0, 100)}")
        self._change_args(fncall, new_func)
        buf_arg = fncall.args.exprs[0]
        # if fncall.name.name == "scanf":
        #     buf_arg = fncall.args.exprs[1]
        self._swap_funcs(fncall, new_func)
        self._change_vuln_bufsize(new_func.decl.name)
        self._set_orig_bufsize(buf_arg, problem_scope, new_func.decl.name)

    def create_problem(self, problem: Problem):
        if not problem.is_real_problem():
            vuln_idx, new_problems = self._divide_fmtstr(problem)
            if not new_problems:
                return False
            prob_scope = problem.get_fn_scope()
            fn_idx = self._ast.locate_fncall(
                problem.get_fncall(), prob_scope)
            prob_args = problem.get_args()
            prob_name = problem.get_fn_name()
            if vuln_idx == 0:
                self._ast.insert_funccall(fn_idx+1, new_problems[0], prob_scope)
            elif vuln_idx < len(prob_args.exprs)-2:
                self._ast.insert_funccall(fn_idx, new_problems[0], prob_scope)
                self._ast.insert_funccall(fn_idx+2, new_problems[1], prob_scope)
            else:
                self._ast.insert_funccall(fn_idx, new_problems[0], prob_scope)
            prob_pos, prob_text, prob_fmtstr = problem.parse_fmt_str()
            prob_args.exprs[0].value = f'"{prob_pos[vuln_idx]}"'
            del prob_args.exprs[vuln_idx+2:]
            del prob_args.exprs[1:vuln_idx+1]
        self._create_vuln(problem)
        return True

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
            returner.append("-zexecstack")
        if self._difficulty > 1:
            returner.append("-znoexecstack")
        if self._difficulty > 2:
            returner.append("-fstack-protector-strong")
        if self._difficulty > 3:
            returner.append("-fPIE -pie")
        return returner
