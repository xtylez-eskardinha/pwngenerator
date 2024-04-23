from pwngen.parsers.ast import AstProcessor
from pycparser import c_ast
from z3 import Not


class SAST:

    _ast: AstProcessor
    _bof: list[str]
    _problem: list
    _vars = dict

    def __init__(self, ast: AstProcessor):
        self._ast = ast
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

    def _parse_assignment(
        self, ast: c_ast.Assignment
    ) -> tuple[str, str, str, list | None]:
        assert isinstance(ast, c_ast.Assignment)
        var = ast.lvalue.name
        op = ast.op
        args = None
        if isinstance(ast.rvalue, c_ast.FuncCall):
            value = ast.rvalue.name.name
            # print(ast.rvalue)
            args = [
                x.name if isinstance(x, c_ast.ID) else x.value if not isinstance(x, c_ast.Cast) else None
                for x in ast.rvalue.args.exprs
            ]
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
        return " ".join([left, op, right])

    def _get_cond(self, ast: c_ast.If):
        if isinstance(ast.cond, c_ast.FuncCall):
            return f"{ast.cond.name.name} == 255"
        else:
            cond = self._parse_binaryop(ast.cond)
        # print(cond)
        return cond

    def _parse_typedecl(self, ast: c_ast.TypeDecl, scope: str = "globals"):
        if isinstance(ast, c_ast.Struct):
            return ast.type.name
        if isinstance(ast, c_ast.IdentifierType):
            return ast.type.names

    # def _parse_arraydecl(self, ast: c_ast.ArrayDecl, scope: str = "globals"):
    #     if isinstance(ast, c_ast.ArrayDecl):


    def _parse_decl(self, ast: c_ast.Decl, scope: str = "globals"):
        if scope not in self._vars:
            self._vars[scope] = {}

        if isinstance(ast.type, c_ast.ArrayDecl):
            if isinstance(ast.type.type, c_ast.ArrayDecl):
                self._parse_decl(ast.type, scope)
            if isinstance(ast.type.type, c_ast.TypeDecl):
                self._vars[scope][ast.type.type.declname] = {
                    "type" : self._parse_typedecl(ast.type.type),
                }
                return 

            self._vars[scope][ast.name]["dim"] = self._ast.get_arraydecl_size(ast, scope)
            self._vars[scope][ast.name]["init"] = ast.init

        if isinstance(ast.type, c_ast.PtrDecl):
            # TODO
            return
        if isinstance(ast.type, c_ast.TypeDecl):
            self._vars[scope][ast.name] = {
                "type": self._parse_typedecl(ast.type),
                "init": ast.init,
            }
        return

    def _parse_fndecl(self, ast: c_ast.FuncDecl):
        return self._parse_typedecl(ast.type)

    def _parse_fndef(self, ast: c_ast.FuncDef):
        kind = self._parse_fndecl(ast.decl)
        scope = ast.decl.name
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
        scope: str = "globals"
    ):
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
            return
        elif isinstance(ast, c_ast.FuncCall):
            if ast.name.name in self._bof:
                tmp = stack[:]
                self._problem.append(
                    [
                        tmp,
                        ast.name.name,
                        # TODO ARGS
                    ]
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
            print(scope)
            return
        elif isinstance(ast, (c_ast.UnaryOp, c_ast.TernaryOp)):
            # TODO
            return
        elif isinstance(ast, c_ast.Compound):
            for block in ast.block_items:
                self.create_stack(block, stack, scope)
        else:
            return
