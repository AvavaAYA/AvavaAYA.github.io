---
title: GLIBC - 基础补充 - 多线程 && TLS && ret2dlresolve
date: 2024-03-14 08:15:38
tags: Glibc
category: Glibc
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

> 在 glibc 中，线程有自己的 arena，但是 arena 的个数是有限的，一般跟处理器核心个数有关，假如线程个数超过 arena 总个数，并且执行线程都在使用，那么该怎么办呢。Glibc 会遍历所有的 arena，首先是从主线程的 main_arena 开始，尝试 lock 该 arena，如果成功 lock，那么就把这个 arena 给线程使用。[1]

# ret2dlresolve

## 问题：简述 ret2dlresolve 的使用场景与限制条件

refer to: [ctf-wiki](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve/), [ret2dl-runtime-resolve详细分析(32位&64位) . ~ha1vk~](https://blog.csdn.net/seaaseesa/article/details/104478081)

# 补充

面试时还多次问到了「你知不知道有什么保护可以阻止栈溢出」类似的问题，我只回答了一个 canary。但结束后仔细一想 fortify 其实也是，作为 GCC 提供的源码级别的保护，可以通过编译选项 `-D_FORTIFY_SOURCE={0,1,2}` 选择开启级别，会将 printf、read、memcpy 等函数编译成 `__read_chk` 等函数，若 `nbytes > buflen`，则会直接 `SIGABRT` 结束程序运行。

> 作为源码级别的保护，我一直下意识地把它当做 ~~消除漏洞~~ 而非保护，就没回答上来，不知道还有没有其它的答案。

此外面试时似乎会很在意技术博客里的内容，以后还是要好好写（（

对于方向的问题我好像答得很不好，不过我好像也一直不太确定做什么。之前看 browser pwn 感觉学习资料太少就转内核了，这次面试的时候我也把自己的方向往 kernel 上去说，但是对方好像更想要浏览器的新人（。总归固定下自己的方向比较好，精力是有限的，如果不出意外的话我会继续研究内核，感觉这里面有很多东西可以学习。

# References

[1.] [线程PWN之gkctf2020 GirlFriendSimulator](https://blog.csdn.net/seaaseesa/article/details/107581574) . ~ha1vk~
[2.] [V8 沙箱绕过](https://jayl1n.github.io/2022/02/27/v8-sandbox-escape/) . ~jayl1n~
