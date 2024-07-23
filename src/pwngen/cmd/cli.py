from pwngen.cmd.args import Args
from pwngen.logic.vulngen import VulnGen
from pwngen.parsers.ast import AstProcessor
from pwngen.pwn.exploit import Exploit
from argparse import Namespace
from typing import Any
import random

class CLI:
    _args: dict[str, Any]

    def __init__(self):
        self._args = self._parse_args(Args().parse_args())
        self._proc_args()
        
    def _parse_args(self, args: Namespace) -> dict[str, Any]:
        return vars(args)

    def _proc_args(self):
        if self._args.get('version'):
            print("version")
            return 0
        if self._args.get('seed'):
            random.seed(self._args['seed'])
    
    def _interactive(self) -> int:
        try:
            return 0
        except Exception as e:
            print(e)
            return 1

    def _noninteractive(self) -> int:
        try:
            ast = AstProcessor(self._args['input'])
            generator = VulnGen(ast)
            generator.inject_vulns()
            ast.save_c('test.c')
            gcc_flags = generator.get_compiler_syntax()
            return 0
        except Exception as e:
            print(e)
            return 1

    def cli(self):
        return self._interactive() if self._args.get('interactive') else self._noninteractive()


# if __name__ == '__main__':