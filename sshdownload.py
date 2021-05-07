from pwn import *


if(!argv[1] ):
    print("Enter absolutete path!")
    exit(1)

s = ssh()
