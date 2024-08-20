from subprocess import CalledProcessError, run as execute
import os

class Compiler():
    _args: list[str]
    _output: str
    _compiler: str
    _input: str

    def __init__(self, args: list[str], c_input: str, output: str, compiler: str = "gcc"):
        self._args = args
        self._output = output
        self._compiler = compiler
        self._input = c_input
    
    def compile(self):
        real_output = f"{self._output}.o"
        all_args = self._args + [f"-o{real_output}"] + [self._input]
        all_args.insert(0, self._compiler)
        try:
            execute(
                args=all_args,
                check=True,
                # env={'PATH': str(os.environ)}
            )
        except CalledProcessError as e:
            if e.stdout:
                print(e.stdout)
            if e.stderr:
                print(e.stderr)