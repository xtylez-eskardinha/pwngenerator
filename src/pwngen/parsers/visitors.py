# Import external dependencies
from pycparser import c_ast


class funcDefs(c_ast.NodeVisitor):

    def __init__(self):
        self._fncdefs = []

    def visit_FuncDef(self, node):
        self._fncdefs.append(node)
        # print('%s at %s' % (node.decl.name, node.decl.coord))
        # print(node)

    def getFuncDefs(self) -> list:
        return self._fncdefs


class funcCalls(c_ast.NodeVisitor):
    def __init__(self):
        self._funccalls = []

    def visit_FuncCall(self, node):
        # if node.name.name not in self._funccalls:
        #     self._funccalls[node.name.name] = []

        self._funccalls.append(node)
        # print(node)
        # Visit args in case they contain more func calls.
        if node.args:
            self.visit(node.args)
        # print(node)
        # return dict(node)
        # display(node.decl)
        # display(node.body)

    def get_all_func_calls(self) -> list:
        return self._funccalls

    def get_func_call(self, funcname: str) -> list:
        return [x for x in self._funccalls if x.name.name == funcname]
