# Import external dependencies
from pycparser import c_ast

class funcDefs(c_ast.NodeVisitor):

    # def __init__(self, funcname):
    #     self.funcname = funcname

    def visit_FuncDef(self, node):
        print('%s at %s' % (node.decl.name, node.decl.coord))
        # print(node)

class funcCalls(c_ast.NodeVisitor):
    def __init__(self, funcname):
        self.funcname = funcname

    def visit_FuncCall(self, node):
        if node.name.name == self.funcname:
            print('%s called at %s' % (self.funcname, node.name.coord))
            return node
            # print(node)
        # Visit args in case they contain more func calls.
        if node.args:
            self.visit(node.args)
        # print(node)
        # return dict(node)
        # display(node.decl)
        # display(node.body)