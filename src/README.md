# PWNGenerator

Project

## Initialization

For initializing the repository, you need to have `Poetry` installed, if you do have it installed, you can use `poetry install` to get all the dependencies.

## Execution

After you have initialized the `poetry` dir, you can use `poetry run -- python3 main.py` to invoke the program.

You can use the `-h` flag to check for more info

```
usage: pwngenerator [-h] [--version] -i INPUT [--remote-addr REMOTE_ADDR] [-c]
                    -o OUTPUT [-s SEED]

Program for mutating C inputs into exploitable outputs

options:
  -h, --help            show this help message and exit
  --version             Prints current version
  -i INPUT, --input INPUT
                        C file to process
  --remote-addr REMOTE_ADDR
                        Address in which the binary exposes the communication
                        port, for example, localhost:54447
  -c, --compile         Wether to compile vulnerable C code to binary
  -o OUTPUT, --output OUTPUT
                        Location and name, without extension, for the output
                        binary and C file, binary outputs with .o and source
                        with .c
  -s SEED, --seed SEED  Seed to use for random number generator

```