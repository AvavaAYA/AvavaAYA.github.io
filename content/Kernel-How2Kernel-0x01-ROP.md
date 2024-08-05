---
id: Kernel-How2Kernel-0x01-ROP
aliases: []
tags:
  - Kernel
  - tutorial
date: 2024-03-18 19:02:34
draft: true
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

---


