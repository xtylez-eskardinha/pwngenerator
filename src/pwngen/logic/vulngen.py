from copy import deepcopy
import itertools
from typing import Any
from pwngen.logic.sast import SAST, Problem
from pwngen.parsers.ast import AstProcessor
from pwngen.parsers.pwnable import Vulnerabilities
from pycparser import c_ast
from random import randint, choice
import structlog

logger = structlog.get_logger(__file__)

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
    _inject_leak: bool

    def __init__(self, ast: AstProcessor, difficulty: int = 0, leak: bool = False):
        self._ast = ast
        self._sast = SAST(self._ast)
        self._vulns = self._sast.get_vulns_class()
        self._sast.create_stack()
        self._difficulty = min(difficulty, 5)
        self._inject_leak = difficulty > 2 or leak

    def _func_generator(self, kind: str) -> c_ast.FuncDef:
        danger = self._vulns.get_vuln_fndefs()
        vuln_kinds = self._vulns.get_vulnerability_types()
        vuln_kind = ""
        if kind == "ret2win":
            return danger["ret2win"]
        elif kind == "easy_leak":
            return danger["easy_leak"]
        for possible in vuln_kinds:
            if kind in vuln_kinds[possible]:
                vuln_kind = possible
        # print(f'{vuln_kind}_gets_bof')
        if self._difficulty == 0:
            return deepcopy(danger[f'input_{kind}_{vuln_kind}'])
        else:
            return deepcopy(danger[f'input_{kind}_{vuln_kind}_canary'])

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
            if isinstance(out_var.type, c_ast.ArrayDecl):
                size = self._ast.get_arraydecl_size(out_var, orig_fn_scope)[-1]
                self._ast.change_stack_buffsize("buffer", size[0], size[1], dest_fndef)
                return True
        else:
            return False

    def _adapt_format_args(self, fn_descr: dict, fndef: c_ast.FuncDef, args: c_ast.ExprList):
        return

    def _test_args(self, fncall: c_ast.FuncCall, problem_scope: str) -> bool:
        func_descr = self._vulns._dangerous.get(fncall.name.name)
        if func_descr:
            if func_descr['out'] >= 0:
                buf_arg = fncall.args.exprs[func_descr['out']]
        if isinstance(buf_arg, c_ast.UnaryOp):
            buf_arg = buf_arg.expr
        buf_var = self._ast.get_var_fromid(buf_arg, problem_scope)
        return isinstance(buf_var.type, c_ast.ArrayDecl)

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

    def _generate_exprlist(self, args: list[c_ast.ID | c_ast.Constant]) -> c_ast.ExprList:
        return c_ast.ExprList(exprs=args)

    def _generate_fncall_raw(self, fn: str, args: c_ast.ExprList | None) -> c_ast.FuncCall:
        fncall = c_ast.FuncCall(
            c_ast.ID(name=fn), args=args
        )
        logger.debug("Raw FNCall generated", fncall=str(fncall))
        return fncall

    def _generate_fncall_fndef(self, fndef: c_ast.FuncDef) -> c_ast.FuncCall:
        fn_name = fndef.decl.name
        fncall = c_ast.FuncCall(
            c_ast.ID(name=fn_name), args=None)
        logger.debug("FNCall generated", fncall=str(fncall))
        return fncall

    def _process_problems(self) -> bool:
        modified = []
        problems = self._sast.get_problems()
        logger.info("Starting processing problems", difficulty=self._difficulty, num_problems=len(problems))
        # print(self._ast._fncalls)

        if not problems:
            logger.error("No problems found...")
            return False
        for problem in problems:
            logger.info(
                "Processing problem",
                fn_name=problem.get_fn_name(),
                fn_scope=problem.get_fn_scope())
            modified.append(self.create_problem(problem))

        if self._difficulty < 2:
            ret2win = self._func_generator("ret2win")
            self._ast.insert_fndef(ret2win)
            logger.info("ret2win injected!")
        elif self._inject_leak:
            printf_leak_origin = self._func_generator("easy_leak")
            printf_leak_call = printf_leak_origin.body.block_items[0]
            # printf_args = c_ast.Constant(
            #     type='string', value='Here you have a gift: %x %x %x %x %x %x %x %x %x %x %x %x\n')
            # self._ast.insert_fndef(printf_leak)
            # printf_leak_call = self._generate_fncall_fndef(printf_leak)
            self._ast.insert_funccall(0, printf_leak_call, modified[0])
            logger.info("Stack leak injected :)")

        return True
        # print(problems)
        # print(self._vulns._vulnfuncsdict)

    def _create_vuln(self, problem: Problem) -> str:
        vuln_name = f"input_{randint(0, 100)}"
        kind = problem.get_fn_name()
        fncall = problem.get_fncall()
        problem_scope = problem.get_fn_scope()
        if not self._test_args(fncall, problem_scope):
            return ""
        new_func = self._func_generator(kind)
        if not new_func:
            return ""
        self._ast.insert_fndef(new_func)
        self._ast.change_funcname(new_func.decl.name, vuln_name)
        self._change_args(fncall, new_func)
        buf_arg = fncall.args.exprs[0]
        # if fncall.name.name == "scanf":
        #     buf_arg = fncall.args.exprs[1]
        self._swap_funcs(fncall, new_func)
        self._change_vuln_bufsize(new_func.decl.name)
        self._set_orig_bufsize(buf_arg, problem_scope, new_func.decl.name)
        # logger.debug("Debugging vuln", )
        return vuln_name

    def create_problem(self, problem: Problem):
        if problem.is_real_problem():
            logger.info("Problem might not be a real problem, analyzing context")
            vuln_idx, new_problems = self._divide_fmtstr(problem)
            if not new_problems:
                logger.warning("This problem isnt explotable...", fn_name=problem.get_fn_name(), args=problem.get_args())
                return False
            logger.info("Problem vulnerability index and problems found", vuln_idx=vuln_idx, new_problems=new_problems)
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
        return self._create_vuln(problem)

    def inject_vulns(self):
        return self._process_problems()
    
    def change_problem(self):
        return
    
    def set_difficulty(self, level: int):
        self._difficulty = level

    def get_compiler_syntax(self, data_model: str = "32") -> list[str]:
        returner = [f"-m{data_model}"]
        if self._difficulty > 3:
            returner.append("-fstack-protector-strong")
            returner.append("-pie")
            returner.append("-znoexecstack")
        elif self._difficulty > 2:
            returner.append("-fstack-protector-strong")
            returner.append("-pie")
            returner.append("-znoexecstack")
            returner.append("-static")
        elif self._difficulty > 1:
            returner.append("-fstack-protector-strong")
            returner.append("-no-pie")
            returner.append("-static")
        elif self._difficulty > 0:
            returner.append("-fno-stack-protector")
            returner.append("-znoexecstack")
            returner.append("-static")
            returner.append("-no-pie")
        elif self._difficulty >= 0:
            returner.append("-static")
            returner.append("-fno-stack-protector")
            returner.append("-no-pie")
            returner.append("-zexecstack")
        return returner
