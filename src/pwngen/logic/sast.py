from typing import Any
from pwngen.parsers.ast import AstProcessor
from pycparser import c_ast
from z3 import Not
from pwngen.parsers.pwnable import Vulnerabilities
import structlog
import re

logger = structlog.get_logger(__file__)


class Problem:
    _stack: list[Any]
    _fn: str
    _scope: str
    _call: c_ast.FuncCall
    _unsure: list[str]
    _args: c_ast.ExprList

    def __init__(
            self,
            stack: list[Any],
            fn: str,
            scope: str,
            call: c_ast.FuncCall
            ):
        self._stack = stack
        self._fn = fn
        self._scope = scope
        self._call = call
        self._unsure = [
            "scanf",
            "printf"
        ]
        self._args = self._call.args
        logger.info("Problematic case generated", fn=fn, scope=scope)

    def get_stack(self) -> list[Any]:
        return self._stack
    
    def get_fn_name(self) -> str:
        return self._fn
    
    def get_fn_scope(self) -> str:
        return self._scope
    
    def get_fncall(self) -> c_ast.FuncCall:
        return self._call

    def get_args(self) -> c_ast.ExprList:
        return self._args

    def is_real_problem(self) -> bool:
        args = self._args
        len_args = len(args.exprs) != 2
        sure = self._fn in self._unsure
        return sure and len_args

    def parse_fmt_str(self) -> tuple[list[str], list[str], list[str]]:
        args = self._args
        parameter = args.exprs[0].value.strip().strip('\"')
        # formats = re.findall(r"%[0-9]*[diouxefgcs]", parameter)
        # text = re.split(r"%[0-9]*[diouxefgcs]", parameter)
        # fmt_str = re.findall(r"%[0-9]*[cs]", parameter)
        formats = re.findall(r"(?<!%)%(?!%)[0-9]*[diouxefgcs]", parameter)
        text = re.split(r"(?<!%)%(?!%)[0-9]*[diouxefgcs]", parameter)
        fmt_str = re.findall(r"(?<!%)%(?!%)[0-9]*[cs]", parameter)
        logger.debug("Testing formats", formats=formats, text=text, fmt_str=fmt_str)
        print(formats, text, fmt_str)
        return formats, text, fmt_str

    def analyze_context(self) -> bool:
        possible, text, fmt_str = self.parse_fmt_str()
        return True if fmt_str else False
        
class SAST:

    _ast: AstProcessor
    _bof: list[str]
    _problem: list[Problem]
    _vars = dict

    def __init__(self, ast: AstProcessor):
        self._ast = ast
        self._vulns = Vulnerabilities(self._ast)
        self._bof = [
            "gets",
            "gets_s",
            "strcpy",
            "scanf",
            "strncat",
            "strcat",
            "strncpy",
            "snprintf",
        ]
        self._problem = []
        self._stack = []
        self._vars = {}
        logger.info("Initializing SAST")

    def _parse_assignment(
        self, ast: c_ast.Assignment, scope: str = "globals"
    ) -> tuple[str, str, str | None, list | None]:
        assert isinstance(ast, c_ast.Assignment)
        logger.debug("Parsing assignment", ast=type(ast), scope=scope)
        var = ast.lvalue

        while isinstance(var, c_ast.ID):
            var = var.name
        op = ast.op
        value = None
        args = None
        if isinstance(ast.rvalue, c_ast.FuncCall):
            value = ast.rvalue.name.name
            # print(ast.rvalue)
            args = [
                (
                    x.name
                    if isinstance(x, c_ast.ID)
                    else x.value if not isinstance(x, c_ast.Cast) else None
                )
                for x in ast.rvalue.args.exprs
            ]
        elif isinstance(ast.rvalue, c_ast.ID):
            value = ast.rvalue.name
        return var, op, value, args

    def _parse_binaryop(self, op: c_ast.BinaryOp):
        # print(op)
        left = op.left
        right = op.right
        op = op.op
        if isinstance(left, c_ast.Assignment):
            left, _, _, _ = self._parse_assignment(left)
        elif isinstance(left, c_ast.BinaryOp):
            left = self._parse_binaryop(left)
        elif isinstance(left, c_ast.FuncCall):
            left = "255"
        else:
            left = left.name if "name" in dir(left) else left.value
        if isinstance(right, c_ast.BinaryOp):
            right = self._parse_binaryop(right)
        else:
            right = right.name if "name" in dir(right) else right.value
        # print(" ".join([left, op, right]))
        return " ".join([str(left), str(op), str(right)])

    def _get_cond(self, ast: c_ast.If):
        logger.debug("Parsing if conditions", ast=type(ast))
        if isinstance(ast.cond, c_ast.FuncCall):
            return f"{ast.cond.name.name} == 255"
        else:
            cond = self._parse_binaryop(ast.cond)
        # print(cond)
        return cond

    def _parse_typedecl(self, ast: c_ast.TypeDecl, scope: str = "globals"):
        logger.debug("Parsing type declaration", ast=type(ast), scope=scope)
        # print(ast)
        if isinstance(ast.type, c_ast.Struct):
            return ast.type.name
        if isinstance(ast.type, c_ast.IdentifierType):
            return ast.type.names

    # def _parse_arraydecl(self, ast: c_ast.ArrayDecl, scope: str = "globals"):
    #     if isinstance(ast, c_ast.ArrayDecl):

    def _parse_decl(self, ast: c_ast.Decl | c_ast.ArrayDecl, scope: str = "globals"):
        logger.debug("Parsing declaration", ast=type(ast), scope=scope)
        if scope not in self._vars:
            self._vars[scope] = {}

        if isinstance(ast.type, c_ast.ArrayDecl):
            if isinstance(ast.type.type, c_ast.ArrayDecl):
                self._parse_decl(ast.type, scope)
            if isinstance(ast.type.type, c_ast.TypeDecl):
                self._vars[scope][ast.type.type.declname] = {
                    "type": self._parse_typedecl(ast.type.type, scope),
                }
                return None

            self._vars[scope][ast.name]["dim"] = self._ast.get_arraydecl_size(
                ast, scope
            )
            self._vars[scope][ast.name]["init"] = ast.init

        if isinstance(ast.type, c_ast.PtrDecl):
            # TODO
            return
        if isinstance(ast.type, c_ast.TypeDecl):
            self._vars[scope][ast.name] = {
                "type": self._parse_typedecl(ast.type, scope),
                "init": ast.init,
            }
        return

    def _parse_fndecl(self, ast: c_ast.FuncDecl):
        return self._parse_typedecl(ast.type)

    def _parse_fndef(self, ast: c_ast.FuncDef):
        logger.debug("Parsing function definition", func=ast.decl.name)
        kind = self._parse_fndecl(ast.decl)
        scope = ast.decl.name
        logger.debug("Changing scope for function declaration", scope=scope)
        return scope, kind

    def create_stack(
        self,
        ast: (
            list
            | c_ast.Decl
            | c_ast.Assignment
            | c_ast.FuncCall
            | c_ast.If
            | c_ast.For
            | c_ast.While
            | c_ast.DoWhile
            | c_ast.Return
            | c_ast.TernaryOp
            | c_ast.UnaryOp
            | c_ast.Compound
            | None
        ) = None,
        stack: list = [],
        scope: str = "globals",
    ):
        logger.debug("Parsing the stack...", scope=scope, ast=type(ast))
        # print(self._problem)
        if ast is None and not stack:
            ast = self._ast._code

            # print(ast)
        if isinstance(ast, list):
            for item in ast:
                self.create_stack(item, stack, scope)
            return
        elif isinstance(ast, (c_ast.Decl, c_ast.DeclList)):
            if isinstance(ast, c_ast.DeclList):
                # print(ast)
                for i in ast.decls:
                    # print(i)
                    self._parse_decl(i, scope)
            else:
                self._parse_decl(ast, scope)
            return
        elif isinstance(ast, c_ast.Assignment):
            # TODO
            var, op, value, args = self._parse_assignment(ast, scope)
            # print(var, op, value, args)
            return
        elif isinstance(ast, c_ast.FuncCall):
            if ast.name.name in self._vulns.get_dangerous():
                tmp = stack[:]
                self._problem.append(
                    Problem(tmp, ast.name.name, scope, ast)
                )
        elif isinstance(ast, c_ast.If):
            cond = self._get_cond(ast)
            stack.append(cond)
            self.create_stack(ast.iftrue, stack, scope)
            stack.pop()
            stack.append(cond)
            self.create_stack(ast.iffalse, stack, scope)
            stack.pop()
        elif isinstance(ast, (c_ast.For, c_ast.While, c_ast.DoWhile)):
            if isinstance(ast, c_ast.For):
                self.create_stack(ast.init, stack, scope)
                self.create_stack(ast.next, stack, scope)
            self.create_stack(ast.cond, stack, scope)
            self.create_stack(ast.stmt, stack, scope)
            return
        elif isinstance(ast, c_ast.Return):
            # TODO
            return
        elif isinstance(ast, c_ast.FuncDef):
            # TODO Fill ARGs
            scope, kind = self._parse_fndef(ast)
            self.create_stack(ast.body, stack, scope)
            return
        elif isinstance(ast, (c_ast.UnaryOp, c_ast.TernaryOp)):
            # TODO
            return
        elif isinstance(ast, c_ast.Compound):
            for block in ast.block_items:
                self.create_stack(block, stack, scope)
        else:
            return

    def get_problems(self):
        return self._problem

    def process_stack(self):
        for problem in self._problem:
            print(problem)

    def get_vulns_class(self) -> Vulnerabilities:
        return self._vulns