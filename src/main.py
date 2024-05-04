import time
from pwngen.logic.graph import Graph
from pwngen.logic.sast import SAST
from pwngen.parsers.ast import AstProcessor
from pwngen.parsers.pwnable import Vulnerabilities
from pycparser import parse_file, c_ast
import json

from pwngen.pwn.debugger import Debugger
from pwngen.pwn.exploit import Exploit


# exp = Exploit("code/babybof.o", delay=0.5)
# exp._dbg.set_breakpoint("get_input", False)
exp = Exploit("code/agenda.o", addr="localhost", port=54471, delay=1)
exp._dbg.set_breakpoint("fork")
exp._dbg.set_breakpoint("list_events")
exp._dbg.finish_breakpoint()


# exp._dbg.finish_breakpoint()
# exp._dbg.continue_until("main")
# print(exp.search_symbol("execme"))
# print(exp.search_text("/bin/bash"))
# print(exp.search_symbol("system"))
# exp._dbg.record_start()
# exp._dbg.set_breakpoint("get_input")
# print(exp._dbg._gdb.inferiors())
print("A")
# print(exp._dbg.recvline().decode())
exp._dbg.send_custom_cyclic(512, f"add {'A'*40} {'A'*40} {'A'*40} ")
# print("B")
exp._dbg.send_custom_cyclic(512, f"add {'A'*40} {'A'*40} {'A'*40} ")
print("C")
print("D")
# time.sleep(2)
# exp._dbg.continue_until("list_events")
exp.sendline("list")
exp._dbg.finish_breakpoint()
exp._dbg._exec_gdb("inferior 2")
time.sleep(5)
exp._dbg.send_custom_cyclic(512, f"add {'A'*40} {'A'*40} {'A'*40} ")
# print("B")
exp._dbg.send_custom_cyclic(512, f"add {'A'*40} {'A'*40} {'A'*40} ")
exp.sendline("list")
print(exp.search_bof("list_events", False))

# exp._dbg.finish_breakpoint()
print("C")
print("D")
print("E")
# print(exp.search_bof("get_input", True, 256))
# exp._dbg.continue_until("add_event")
# exp._dbg._exec_gdb("break thread 2")
# exp.sendline("list")

# exp._dbg.continue_until("list_events","sprintf")
exp._dbg.get_bt()
# exp._dbg._threads[1].switch()
exp._dbg.get_bt()

# print(exp._dbg._gdb.inferiors())
# print(exp._dbg._gdb.selected_inferior())
print("F")
# exp._dbg.record_goto_start()
# exp._dbg.record_delete()

# print(deb._proc.corefile)
time.sleep(20)
# print(deb.get_pc())
# print(deb.get_pc_v2())
# print(deb.checksec())
# deb.set_breakpoint("get_input")
# deb.finish_breakpoint()
# # deb.finish_breakpoint()
# print(deb.get_bt())
# deb.finish_breakpoint()
# print(deb.send_cyclic(128))
# bt = deb.get_bt()
# print(deb.find_cyclic_bt())


# print(hex(deb._gdb.selected_frame().level()))


# print(deb.get_pc_v2())
# deb._io.sendline(b"y")
# print(deb.get_arch())
# print(deb.get_pc())
# deb.set_breakpoint("get_input")
# current = deb.get_frame()
# print(current.level())
# print(current.read_register("eip"))
# time.sleep(2)
# deb._io.sendline(b"A" * 128)
# deb.finish_breakpoint()
# deb.finish_breakpoint()
# print(deb.exec_gdb("bt"))


# deb.finish_breakpoint(False)
# current = deb.get_frame()
# print(current.older().name())
# deb.finish_breakpoint()

# print(deb.exec_gdb("info frame"))
# ast = AstProcessor("code/agenda.c")

# # print(json.dumps(ast.generate_code()))
# # print(json.dumps(ast._funcs))

# func_defs = ast.get_fn_defs()
# main_vars = ast._filter_fn_declarations(func_defs["main"])
# all_vars = ast.get_all_vars()
# graph = Graph(ast)
# sast = SAST(ast)
# # print(ast._vars)
# sast.create_stack()
# sast.process_stack()
# print(sast._problem)
# print(sast._vars)
# ast.create_stack(ast.get_ast())
# vals = [
#     ast._parse_fncall(x, "main") for x in ast.get_all_fncalls_fndef(ast._funcs["main"])
# ]
# print(vals)

# print(ast.change_stack_buffsize("events", 0, 600))
# arrays = ast._vars


# ast.change_buffsize("add_event", "pepegrillo", 3)
# print(json.dumps(ast._funcs))

# print(ast.get_func_calls("pwnable"))
# print(ast.get_func_calls("scanf"))
# print(ast.get_func_defs())

# print(ast.get_func_calls())
# pwn = Vulnerabilities(ast)
# print(pwn.checkbofs())
# print(pwn.get_function_bofs(pwn.checkbofs()[0]))
# # print(pwn.checkbofs())
