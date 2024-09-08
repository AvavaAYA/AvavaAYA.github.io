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

首先回过头来思考内核漏洞利用的目标，之所以能够实现提权是因为操作系统本身也不过是一种软件，是位于物理内存中的代码和数据，在**分级保护域**（*保护环，Rings*）的设计思路下 CPU 在执行操作系统内核代码时拥有**高权限环境**（*Ring 0*），而在运行用户代码时通常运行在**低权限环境**（*Ring 3*）。

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
