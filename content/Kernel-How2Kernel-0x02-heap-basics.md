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

> 来到堆利用部分，其实从上手做题的角度而言，内核堆常用的 slub 分配器并不难打。近期笔者在国内外大小比赛中连续遇到了 kernel 题，都是 ~~`/sbin` 目录权限设置有问题的非预期~~ + 简单 UAF 后打 tty 的 revenge， ~~做一道题拿两道题的分~~ 。
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
