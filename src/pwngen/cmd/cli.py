from pwngen.cmd.args import Args
from pwngen.logic.vulngen import VulnGen
from pwngen.parsers.ast import AstProcessor
from pwngen.pwn.exploit import Exploit
from pwngen.pwn.compiler import Compiler
from argparse import Namespace
from typing import Any
import random
import structlog

logger = structlog.get_logger(__file__)

class CLI:
    _args: dict[str, Any]

    def __init__(self):
        logger.info("Initializing pwngenerator")
        logger.debug("Parsing args")
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
        logger.info("Initializing non-interactive CLI")
        try:
            ast = AstProcessor(self._args['input'])
            logger.info("C File loaded")
            generator = VulnGen(ast, self._args['difficulty'])
            logger.info("VulnGenerator loaded")
            logger.info("Trying to inject vulns...")
            if not generator.inject_vulns():
                logger.error("Unable to inject vulns...")
                logger.warning("Exiting program...")
                exit(1)
            logger.info("Vulns injected")
            output = self._args.get("output", "out")
            c_input = self._args.get("input", "")
            gcc_flags = generator.get_compiler_syntax()
            ast.save_c(f"{output}.c", gcc_flags)
            logger.info("Source code saved", output_file=f"{output}.c", compiler_flags=gcc_flags)
            if self._args.get('compile'):
                input_file = f"{output}.c"
                logger.info("Compiling program", input_file=input_file, compiler_flags=gcc_flags)
                compiler = Compiler(args=gcc_flags, c_input=input_file, output=output)
                compiler.compile()
                logger.info("Program compiled", output_file=f"{output}.o")
            return 0
        except Exception as e:
            print("Error", e)
            return 1

    def cli(self):
        return self._interactive() if self._args.get('interactive') else self._noninteractive()


# if __name__ == '__main__':