---
layout: post
title: Cheat sheet for pwn/rev challenges
categories: [Reversing, Pwn]
published: true
---

This post is a brief cheat sheet for solving CTF pwn and reversing challenges.

## Online Tools

- [https://libc.blukat.me/](https://libc.blukat.me/)
- [http://shell-storm.org/shellcode/](http://shell-storm.org/shellcode/)
- [https://github.com/0xb0bb/karkinos](https://github.com/0xb0bb/karkinos)
- [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)
- [https://docs.pwntools.com/en/stable/intro.html](https://docs.pwntools.com/en/stable/intro.html)

## GDB

```plaintext
r < payload.bin
r < <(script.py)
info file
info address main
```

```plaintext
define hook-stop    Do this every time you break
x/32x $sp           examine 32 bytes as hex at the top of stack
x/16i $pc           examine 16 instructions coming up next
end
```

```plaintext
/x  hex
/s  string
/t  binary
/i  instruction

/a  address
/d  decimal
```

```plaintext
b *0xdeadbeef
info registers  ( i r )
backtrace       ( bt )
si
fin
info frame
```

## Analysis Shell commands

```bash
ltrace ./vuln
sudo dmesg -C
sudo dmesg -t

rabin2 -I ./vuln
rabin2 -z ./vuln
radare2 ./vuln -A

nm ret2win | grep ' t ']
```

## Pwn Shell commands

```bash
(python3 script.py; cat) | ./vuln
```

## Radare

```plaintext
afl     list functions
iI      info
ii      imports
izz     list all strings
izz~a   grep for a

afl~sym.main
pdf @sym.main

/R ret
/R pop rdi; ret
```

## Registers 64 bit

Linux:

```plaintext
RDI
RSI
RDX
RCX
R8
R9
rest onto stack
```

Windows:

```plaintext
RCX
RDX
R8
R9
rest onto stack
```

Return val is in EAX or RAX

| 32  |     |     | 0   |
| --- | --- | --- | --- |  |
| EAX | EAX | EAX | EAX |
|     |     | AX  | AX  |
|     |     | ah  | al  |

## Stack 32 bit

|                      |           |              |
| -------------------- | --------- | ------------ |
| stack growth to here |           |              |
|                      |           |              |
| local var 2          | ebp - 0xc | <- ESP       |
| local var 1          | ebp - 8   |              |
| local var 0          | ebp - 4   |              |
| saved EBP            |           |
| saved EIP            | ebp + 4   |              |
| param 0              | ebp + 8   |              |
| param 1              | ebp + 0xc |              |
| old local var 2      |           | <- saved EBP |
|                      |           |              |
| High address         |           |              |
|                      |           |              |

## Tips

```plaintext
Don't confuse the stack and heap :)
When going from 32 to 64, EBP also grows
```
