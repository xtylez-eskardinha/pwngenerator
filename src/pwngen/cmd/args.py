from argparse import ArgumentParser, Namespace
import os.path

class Args:

    def __init__(self):
        self._parser = ArgumentParser(
            prog="pwngenerator",
            description="Program for mutating C inputs into exploitable outputs"
        )

        self._parser.add_argument(
            "--version",
            help="Prints current version",
            action='version',
            version='%(prog)s 0.1.0'
        )

        self._parser.add_argument(
            "-i", "--input",
            required=True,
            type=lambda x: self._is_valid_file(x),
            help="C file to process"
        )

        self._parser.add_argument(
            "-c", "--compile",
            default=False,
            type=bool,
            help="Wether to compile vulnerable C code to binary"
        )

        self._parser.add_argument(
            "-o", "--output",
            type=str,
            help="Location for the output binary or C file"
        )

        self._parser.add_argument(
            "-s", "--seed",
            help="Seed to use for random number generator",
            type=int,
            required=False
        )

    def _is_valid_file(self, arg):
        if not os.path.isfile(arg):
            self._parser.error(f"The file {arg} does not exist!")
        else:
            return arg

    def parse_args(self) -> Namespace:
        return self._parser.parse_args()
    
