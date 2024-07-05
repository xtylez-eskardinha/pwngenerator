from pwngen.cmd.args import Args
from argparse import Namespace
from typing import Any
import random

class CLI:
    _args: dict[str, Any]

    def __init__(self):
        self._args = self._parse_args(Args().parse_args())
        self._proc_args()
        self.cli(interactive=self._args['interactive'])
        
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
            return 0
        except Exception as e:
            print(e)
            return 1

    def cli(self, interactive: bool = False):
        return self._interactive() if interactive else self._noninteractive()


# if __name__ == '__main__':