from pwnlib.gdb import debug, attach, Gdb, Breakpoint
import pwnlib.gdb
from pwnlib.elf.elf import ELF
from pwnlib.elf.corefile import Core
from pwnlib.util.cyclic import cyclic, cyclic_find
from time import sleep

# from gdb import Frame
from pwnlib.tubes.process import process
from pwnlib.tubes.remote import remote
from pwnlib.context import context


class Debugger(object):
    _bin: str
    _pid: int
    _proc: process
    _io: process | remote
    _gdb: Gdb
    _elf: ELF
    _core: Core
    _cyclic: bytes
    _delay: float
    _breakpoints: dict[str, Breakpoint]
    _threads: list

    def __init__(self, bin: str, addr: str = "", port: int = -1, delay: float = 0.2):
        self._bin = bin
        self._pid = -1
        self._delay = delay
        self._addr = addr
        self._port = port
        self._threads = []
        self._breakpoints = {}
        self._init_gdbserver()
        if  self._addr and self._port > 0:
            self._gdb.Breakpoint("accept", temporary=True)
            self.finish_breakpoint(False)
            sleep(5)
            self._io = remote(self._addr, self._port)
        # self._init_gdb()

    def _init_gdbserver(self):
        if self._bin:
            self._proc = debug(
                args=self._bin,
                api=True,
                gdbscript="""
                    set pagination off
                    set detach-on-fork off
                    set follow-fork-mode child
                    set schedule-multiple on
                    break main
                    c
                    """,
            )
            self._gdb = self._proc.gdb
            self._init_dbg()

            # self._gdb =
        else:
            raise Exception("Cannot initialize GDB")

    def _init_gdb(self):
        if self._bin:
            self._proc = process(self._bin)
            _, self._gdb = attach(
                self._proc,
                exe=self._bin,
                api=True,
                gdbscript="""
                    set detach-on-fork on
                    set follow-fork-mode child
                    break main
                    run
                    """,
            )
            self._init_dbg()

            # self._gdb =
        else:
            raise Exception("Cannot initialize GDB")

    def _init_dbg(self):
        if self._proc:
            # self._proc = process(self._bin)
            self._io = self._proc
            self._elf = ELF(self._bin)
            context.clear(binary=self._elf)
            # self._gdb.events.stop.connect(self.fork_connect)
            self._threads.append(self._gdb.selected_thread())

    def _get_corefile(self):
        self._core = self._proc.corefile  # type: ignore

    def _exec_gdb(self, command: str):
        sleep(self._delay)
        return self._gdb.execute(command, False, True)

    def _kill_gdb(self):
        sleep(self._delay)
        self._gdb.quit()

    def _interrupt(self):
        if self._gdb.stopped.is_set():
            return
        while not self._gdb.stopped.is_set():
            self._gdb.interrupt_and_wait()
            sleep(1)

    def checksec(self):
        return {
            "asan": self._elf.asan,
            "aslr": self._elf.aslr,
            "arch": self._elf.arch,
            "canary": self._elf.canary,
            "endian": self._elf.endian,
            "msan": self._elf.msan,
            "nx": self._elf.nx,
            "relro": self._elf.relro,
            "static": self._elf.statically_linked,
        }

    def reconnect(self):
        self._io = remote(self._addr, self._port) if isinstance(self._io, remote) else self._proc

    def restart(self):
        self._init_gdbserver()
        self._init_dbg()
        if self._addr and self._port > 0:
            self._io = remote(self._addr, self._port)

    def get_elf(self) -> ELF:
        return self._elf

    def get_pc(self):
        sleep(self._delay)
        return hex(self._gdb.newest_frame().pc())

    def delete_breakpoints(self):
        print(self._breakpoints)
        for bp in self._breakpoints:
            self._breakpoints[bp].delete()

    def get_bt(self) -> list:
        sleep(self._delay)
        returner = []
        frame = self._gdb.newest_frame()
        while frame:
            returner.append((frame.name(), hex(frame.pc())))
            frame = frame.older()
        return returner

    def checkpoint(self):
        sleep(self._delay)
        text = self._exec_gdb("checkpoint 1")
        print(text)

    def get_checkpoints(self):
        sleep(self._delay)
        self._exec_gdb("record stop")

    def checkpoint_restart(self):
        sleep(self._delay)
        self._exec_gdb("restart 1")

    def record_delete(self):
        sleep(self._delay)
        self._exec_gdb("record delete")

    def finish_breakpoint(self, wait: bool = False):
        sleep(self._delay)
        self._gdb.continue_and_wait() if wait else self._gdb.continue_nowait()

    def delete_breakpoint(self, func: str):
        self._breakpoints[func].delete()
        del self._breakpoints[func]

    def set_breakpoint(self, func: str, temporary: bool = False):
        sleep(self._delay)
        # self._interrupt()
        # self._breakpoints[func] = self._gdb.Breakpoint(func, temporary=True)
        # self._gdb.continue_and_wait()
        bp = self._gdb.Breakpoint(func, temporary=temporary)
        self._breakpoints[func] = bp

    def send(self, data: bytes) -> None:
        self._io.send(data)

    def sendline(self, data: bytes) -> None:
        sleep(self._delay)
        self._io.sendline(data)

    def send_custom_cyclic(self, size: int, pre: str = "", post: str = ""):
        self._cyclic = cyclic(size).decode()  # type: ignore
        print(f"{pre}{self._cyclic}{post}".encode())
        self._io.sendline(f"{pre}{self._cyclic}{post}".encode())

    def send_cyclic(self, size: int) -> bytes:
        self._cyclic = cyclic(size)  # type: ignore
        self._io.sendline(self._cyclic)  # type: ignore
        return self._cyclic  # type: ignore

    def get_current_fn(self):
        sleep(self._delay)
        self._interrupt()
        return self._gdb.newest_frame().name()

    def find_cyclic(self, data: bytes) -> int:
        return cyclic_find(int(data, 16))

    def find_cyclic_bt(self) -> int:
        bt = self.get_bt()
        for fn, addr in bt:
            if not fn:
                return self.find_cyclic(addr)
        return -1

    def get_breakpoints(self) -> dict:
        return self._breakpoints

    def continue_until(self, fn: str):
        breakpoints = self.get_breakpoints()
        if fn not in breakpoints:
            self.set_breakpoint(fn, True)
        while self._gdb.interrupt_and_wait() == None:
            print(self.get_current_fn())
            if self.get_current_fn() != fn:
                try:
                    self.finish_breakpoint(True)
                    sleep(2)
                    # self._gdb.continue_and_wait()
                except Exception as e:
                    print(e)
            else:
                break

    def recvline(self):
        return self._io.recvline()

    def recv(self, size: int) -> bytes:
        return self._io.recv(size)

    def recvall(self, timeout: int = 5) -> bytes | None:
        return self._io.recvall(timeout)

    def fork_connect(self, event):
        if event.inferior_thread is not None:
            thread = event.inferior_thread
        else:
            thread = self._gdb.selected_thread()
        if thread not in self._threads:
            self._threads.append(thread)
        print(self._threads)

    def signal_connect(self, event):
        print(self.get_bt())


# class RemoteDebugger(Debugger):

#     def __init__(self, bin: str, addr: str, port: int, delay: float = 0.1):
#         super().__init__(bin, delay)
#         self._gdb.Breakpoint("accept", temporary=True)
#         self.finish_breakpoint(False)
#         sleep(5)
#         self._io = remote(addr, port)


# class NewBreakpoint(gdb.Breakpoint):

#     def __init__(self, function, name):
#         self._func = function
#         self._name = name

#         # clear invalid (relative) names
#         if "+0x" in self.locname or "-0x" in self.locname:
#             self.locname = "???"

#         super(NewBreakpoint, self).__init__ (function=function, label=name)

#     def stop(self):
#         returner = []
#         frame = gdb.newest_frame()
#         while frame:
#             returner.append((frame.name(), hex(frame.pc())))
#             frame = frame.older()
#         print(returner)
