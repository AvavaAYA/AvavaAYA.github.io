---
id: Kernel-How2Kernel-0x02-heap-basics
aliases: []
tags:
  - Kernel
  - tutorial
date: 2024-10-23 14:30
draft: false
title: "Kernel - How2Kernel 0x02: 内核堆基础与 SLUB 分配器"
---

> 来到堆利用部分，其实从上手做题的角度而言，内核堆常用的 slub 分配器并不难打。近期笔者在国内外大小比赛中连续遇到了 kernel 题，都是 ~~权限设置问题的非预期~~ + 简单 UAF 后打 tty 的 revenge， ~~做一道题拿两道的分~~ 。
>
> 相比于用户态新版本 glibc 中繁琐的保护，同样基于 freelist 的 slub 分配器在默认情况下还是非常好打的（后面也会讨论 Hardened freelist、Random freelist 等保护机制及其绕过）。而针对 Buddy System 的利用方法则在后面的博客中讨论。

> [!todo] 
> **Linux Kernel Pwn 系列博客预计包括：**
> 
> - [x] [[Kernel-How2Kernel-0x00-Foundation|Environment and Basic LPE]]
>     - 基础知识
>     - 一些常见的非预期解
>     - Kernel 提权常见思路
> - [x] [[Kernel-How2Kernel-0x01-ROP|ROP and pt-regs]]
>     - 基本 ROP 链的构造
>     - `pt_regs` 结构体的利用
>     - ret2dir 与直接映射区
> - [x] [[Kernel-How2Kernel-0x02-heap-basics|slub 分配器]]
>     - 内核堆概述
> - [ ] 跨缓存的溢出与跨页的堆风水
> - [ ] Buddy System
>     - PageJack - Page UAF

---

# Linux 内核内存管理概述

对于 Linux 内核内存，自顶向下分为 `node (pglist_data) -> zone -> page` 三级结构，通过粗粒度的 Buddy System 和细粒度的 SLAB 两套分配器来进行管理：

## Buddy System

作为更加底层的管理器，Buddy System 是区级别的内存管理系统，以 **页** 为粒度进行内存分配，并管理所有物理内存。

在内存的分配与释放方面，Buddy System 按照空闲页面的连续大小进行分阶管理，表现为 [zone 结构体](https://elixir.bootlin.com/linux/v6.11.4/source/include/linux/mmzone.h#L943)中的 `free_area`：

```c
#ifndef CONFIG_ARCH_FORCE_MAX_ORDER
#define MAX_PAGE_ORDER 10
#else
#define MAX_PAGE_ORDER CONFIG_ARCH_FORCE_MAX_ORDER
#endif

#define NR_PAGE_ORDERS (MAX_PAGE_ORDER + 1)
struct zone {
    //...
    struct free_area    free_area[NR_PAGE_ORDERS];
```

其中每块内存大小的计算方式为 $2^{order} \cdot PGSIZE$，

**分配时** ：

1. 对齐大小，从 order 对应下标的链表中取出连续的内存页；
2. 如果没有，则向上找更大的去分割一半，直到分割出一块 order 对应大小的块。

**释放时** ：

1. 将连续的内存页释放到对应大小的链表中；
2. 尝试合并内存页，合成到更高 order 的链表中。

> [!INFO] 
> [arttnba3 ✌️](https://arttnba3.cn/) 的[系列博客](https://arttnba3.cn/2022/06/30/OS-0X03-LINUX-KERNEL-MEMORY-5.11-PART-II/) 中对 linux 内核内存管理做了很详细的介绍，可以参考学习 ~~（有一些非常有趣抽象的表达，很难绷）~~ 。
> 
> *本文中会引用一些示意图，侵删：*

![[/static/kernel-0x02-0.png]]

当然，上述分配释放的逻辑还相对简陋，很容易出现内存碎片，因此内核中还有一套 **内存迁移** 的逻辑在一个持续运行的线程中完成内存页面的迁移，以减少碎片提高空间利用率。

## SLAB 分配器

回到本文讨论的重点，SLAB 分配器实际上由「机制复杂，效率不高的最初版」slab、「用于嵌入式场景的极简版」slob、「优化后的通用版」slub 三者组成，在大部分情况下会看到 `CONFIG_SLUB=y`，表明采用 slub 分配器。

上述三者的顶层 API 是一致的（内部实现可能不同，例如 slab 和 slub 对 `kmem_cache` 存在不同定义）。下面重点讨论现实场景与 CTF 题目中常见的 slub 分配器：

### Slub 分配器

Slub 是更细粒度、面向数据对象的堆管理器。初始化时分配器向 Buddy System 申请一块内存（被称为一个 slub），其中被划分为多个大小相等的 object，分配给拥有同一标志位的同大小数据对象使用。

![[/static/kernel-0x02-1.png]]

# References

1. [OS.0x00 Linux Kernel I：Basic Knowledge](https://arttnba3.cn/2021/02/21/OS-0X00-LINUX-KERNEL-PART-I/) . *[arttnba3](https://arttnba3.cn/)*
2. [Kernel Pwn Heap Basics](https://blog.wingszeng.top/kernel-pwn-heap-basics-buddy-system-and-slub/) . _[wings](https://blog.wingszeng.top/)_
