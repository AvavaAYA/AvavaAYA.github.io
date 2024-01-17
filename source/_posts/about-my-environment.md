---
title: Pwn Environment on NixOS
date: 2024-01-12 12:36:02
tags:
  - Others
  - tutorial
category:
  - Others
---

> 最近在环境上遭受了很多挫折🙁，决定用 Nix 统一一下配置

# Installation (tmpfs as root)

> 决定尝试一下 tmpfs as root，延长磁盘寿命的同时保持根目录干净。

NixOS 可以仅使用 `/boot` 和 `nix` 分区来启动，这种特性允许我们对根文件系统进行一些有趣的尝试。经过在网上的搜索我看到了两种思路：

1. **使用 ZFS 快照清空根文件系统**：
   - 基于 [Graham 提出的「erase your darlings」](https://grahamc.com/blog/erase-your-darlings/)，每次启动时都使用 ZFS 快照来清空根文件系统。
   - 可以在系统运行时创建快照，并且在每次启动时回滚到一个空的状态。这样即使某些文件在一次启动过程中丢失，仍然可以从快照中恢复它们，同时保持系统的「干净」状态。
2. **使用 tmpfs 作为根文件系统**：
   - tmpfs 即我这里采用的方法，是一种基于内存的文件系统，它在每次重启后都会清空。
   - 使用 tmpfs 的优点是系统非常快速，因为所有的读写操作都在 RAM 中进行。但缺点是所有更改（包括用户文件和系统配置）在重启后都会消失，除非它们被特意配置为持久化存储。

综合考虑下来，`tmpfs as root` 似乎是一个最优的安装 nixos 的方案：迅速、干净的同时减少磁盘上编译的次数从而提高磁盘寿命~~（说起来 NixOS 和 Gentoo 这种编译操作非常频繁的发行版似乎对硬盘使用寿命有一定影响）~~。

## Partition

### Legacy boot

首先还是在虚拟机上熟悉一段时间再换到真机上，因此这里还是采用 Legacy Boot 而非 UEFI，分区部分和普通 NixOS 安装没什么不同：

```bash
# 创建分区表
parted /dev/sda -- mklabel msdos

# /boot 位于 /dev/sda1
parted /dev/sda -- mkpart primary ext4 1M 512M
parted /dev/sda -- set 1 boot on

# /nix 位于 /dev/sda2
parted /dev/sda -- mkpart primary ext4 512MiB 100%
```

### 格式化分区

```bash
# /boot partition for legacy boot
mkfs.ext4 /dev/sda1

# /nix partition
mkfs.ext4 /dev/sda2
```

## 挂载

直接挂载 tmpfs 作为根目录，接下来挂载刚刚创建的两个分区，此外还要让配置文件目录和日志目录持久保存。

```bash
# Mount your root file system
mount -t tmpfs none /mnt

# Create directories
mkdir -p /mnt/{boot,nix,etc/nixos,var/log}

# Mount /boot and /nix
mount /dev/sda1 /mnt/boot
mount /dev/sda2 /mnt/nix

# Create a directory for persistent directories
mkdir -p /mnt/nix/persist/{etc/nixos,var/log}

# Bind mount the persistent configuration / logs
mount -o bind /mnt/nix/persist/etc/nixos /mnt/etc/nixos
mount -o bind /mnt/nix/persist/var/log /mnt/var/log
```

## 配置
