---
title: Pwn Cheatsheet
date: 2024-03-05 15:02:18
tags:
  - Cheatsheet
  - PWN
  - Kernel
---

> I have been using NixOS on all my devices, so the following blog is about dealing with user-level and kernel-level pwn challenges on NixOS through fish scripts and nix configurations.

# User-level Pwn

I have a python module named lianpwn, which is based on pwncli and pwntools. There're a few lambdas and helper classes defined in it:

```python
from pwncli import *

lg_inf = lambda s: print("\033[1m\033[33m[*] %s\033[0m" % (s))
lg_err = lambda s: print("\033[1m\033[31m[x] %s\033[0m" % (s))
# lg_suc = lambda s: print("\033[1m\033[32m[+] %s\033[0m" % (s))
lg_suc = lambda s_name, s_val: print(
    "\033[1;33;40m %s --> 0x%x \033[0m" % (s_name, s_val)
)
i2b = lambda c: str(c).encode()
# lg = lambda s: print("\033[1;31;40m %s --> 0x%x \033[0m" % (s, eval(s, globals())))
lg = lambda s_name, s_val: print("\033[1;31;40m %s --> 0x%x \033[0m" % (s_name, s_val))
debugB = lambda: input("\033[1m\033[33m[ATTACH ME]\033[0m")


def lg_dict(data):
    for key, value in data.items():
        lg(key, value)


def debugPID(io):
    try:
        lg("io.pid", io.pid)
        input()
    except Exception as e:
        lg_err(e)
        pass


# strfmt
class strFmt:
    def __init__(self):
        self.current_n = 0

    def leak_by_fmt(
        self,
        count,
        elf_idx=-1,
        libc_idx=-1,
        stack_idx=-1,
        separater=b".",
        new_line=True,
        identify=b"^",
    ):
        payload = identify + (b"%p" + separater) * count
        if new_line:
            payload += b"\n"
        s(payload)
        ru(identify)
        res = {}
        for i in range(count):
            temp_res = ru(separater, drop=True)
            if b"nil" in temp_res:
                continue
            temp_res = int(temp_res, 16)
            lg("temp_res", temp_res)
            if i == elf_idx:
                res["elf"] = temp_res
                lg_suc("addr_in_elf", temp_res)
            elif i == libc_idx:
                res["libc"] = temp_res
                lg_suc("addr_in_libc", temp_res)
            elif i == stack_idx:
                res["stack"] = temp_res
                lg_suc("addr_in_stack", temp_res)
        return res

    def generate_hn_payload(self, distance, hn_data):
        hn_data = hn_data & 0xFFFF
        offset = (distance // 8) + 6
        if hn_data > self.current_n:
            temp = hn_data - self.current_n
        elif hn_data < self.current_n:
            temp = 0x10000 - self.current_n + hn_data
        elif hn_data == self.current_n:
            return b"%" + i2b(offset) + b"hn"
        self.current_n = hn_data
        return b"%" + i2b(temp) + b"c%" + i2b(offset) + b"$hn"

    def generate_hhn_payload(self, distance, hhn_data):
        hhn_data = hhn_data & 0xFF
        offset = (distance // 8) + 6
        if hhn_data > self.current_n:
            temp = hhn_data - self.current_n
        elif hhn_data < self.current_n:
            temp = 0x100 - self.current_n + hhn_data
        elif hhn_data == self.current_n:
            return b"%" + i2b(offset) + b"hhn"
        self.current_n = hhn_data
        return b"%" + i2b(temp) + b"c%" + i2b(offset) + b"$hhn"
```

After that, here comes the simple template:

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


ia()
```

## Other Dynamic Libraries

It often suffers when coming to missing libs in NixOS, but I've got several solutions.

The easiest way is to use nix-shell:

```nix
with import <nixpkgs> { };
stdenv.mkDerivation {
  name = "fhs";
  buildInputs = with pkgs; [
    pkg-config
    # glibc.static
    zlib.static
    libffi
    libtool
    ghc
    gcc
    ocaml
    libseccomp
    liburing
  ];
}
```

However, the above way can only help compile c code with certain libs, such as libseccomp. The ultimate solution is to get such so from docker and copy to local environment. After that, patch it to any glibc version you want with patchelf. I also have a light tool called [patch4pwn](https://github.com/AvavaAYA/autopatch-flake).

```bash
❯ cat ./Dockerfile
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libc6-dev

WORKDIR /app

❯ cat ./rundocker.fish
#!/usr/bin/env bash

docker build -t ubuntu-gcc .
docker run -it --rm -v $(pwd):/app ubuntu-gcc
```

---

# Kernel-level Pwn

Here's my kernel pwn template:

```bash
❯ ls
build.sh  exp.c  initgdb.sh
❯ cat ./build.sh
#!/usr/bin/env bash

set -e

echo $buildPhase
eval $buildPhase
cp ./exp ../rootfs/exp
cd ../rootfs
find . -print0 | cpio --null -ov --format=newc >../rootfs.cpio
cd ..
./run.sh

❯ cat exp.c
// author: @eastXueLian
// usage : eval $buildPhase
// You can refer to my nix configuration for detailed information.

#include "libLian.h"

extern size_t user_cs, user_ss, user_rflags, user_sp;

int main() {
    save_status();

    get_shell();
    return 0;
}

❯ cat ./initgdb.sh
#!/usr/bin/env bash

sudo -E pwndbg ./vmlinux.bin -ex "set architecture i386:x86-64" \
        -ex "target remote localhost:1234" \
        -ex "add-symbol-file ./rootfs/vuln.ko $1" \
        -ex "c"
```

## Upload

It's always suffering to upload our compiled elfs to the remote server. The following script is still improving:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Remote: ./exp.py remote ip:port -nl

import subprocess
from lianpwn import *
from base64 import b64encode, b64decode
from pwncli import *

cli_script()

io: tube = gift.io

commands = []

lg_inf("compiling exp.c")
if subprocess.run("musl-gcc -static -o exp.bin exp.c", shell=True).returncode:
    lg_err("compile error")
lg_suc("compile finished")

exp_data_list = []
SPLIT_LENGTH = 0x100
with open("./exp.bin", "rb") as f_exp:
    exp_data = b64encode(f_exp.read()).decode()
lg_inf("Data length: " + str(len(exp_data)))
for i in range(len(exp_data) // SPLIT_LENGTH):
    exp_data_list.append(exp_data[i * SPLIT_LENGTH : (i + 1) * SPLIT_LENGTH])
if not len(exp_data) % SPLIT_LENGTH:
    exp_data_list.append(exp_data[(len(exp_data) // SPLIT_LENGTH) :])


#  commands.append("cd rwdir; touch ./exp.b64")
#  for i in exp_data_list:
#  commands.append("echo -n '" + i + "'>> ./exp.b64")
#  commands.append("base64 -d ./exp.b64 > ./exp; chmod +x ./exp; ./exp")
#  commands.append("cat ./flag")

for i in commands:
    sl(i)

lg_suc(str(len(commands)) + " commands sent.")
ia()
```

## Compilation

It's simple to start a compilation environment:

```nix
{ pkgs ? import <nixpkgs> { } }:

pkgs.stdenv.mkDerivation {
  name = "linux-kernel-build";
  nativeBuildInputs = with pkgs; [
    getopt
    flex
    bison
    gcc
    gnumake
    bc
    pkg-config
    binutils
    perl
  ];
  buildInputs = with pkgs; [ elfutils ncurses openssl zlib ];
}
```

When compiling loadable kernel modules (LKM, with .ko as filename extension), the first step is to fetch linux source code from [https://github.com/gregkh/linux/tags](https://github.com/gregkh/linux/tags) (easier to locate certain linux version).

After that, write c code with following template:

```c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("eastXueLian");

static int __init YOURNAME_init(void) {
    return 0;
}

static void __exit YOURNAME_exit(void) {}

module_init(YOURNAME_init);
module_exit(YOURNAME_exit);
```

Makefile is also required for LKMs:

```Makefile
obj-m += exp.o

all:
	make -C /home/eastxuelian/compiling/linux-6.8-rc4 M=$(PWD) modules

clean:
	make -C /home/eastxuelian/compiling/linux-6.8-rc4 M=$(PWD) clean
```

# New Methods for Packaging Kernel Pwn

> Actually we have got good pwn templates for a long period of time, but when reproducing a kernel challenge from bi0sCTF-2024 [1]. I found a brand new configuration for accelerating kernel pwn debugging. If you are challenge setters, you can also refer to this blog to improve challengers' pwning experience.

## Using `.img` Instead of `.cpio`

`.img` files (`.ext3` in the mentioned case from bi0sCTF-2024) are much easier to deal with, though their size might be larger than `.cpio` files.

Provided with `rootfs.img`, challengers can perform real-time operations on it through following commands:

```bash
mkdir ./rootfs
sudo mount -o loop rootfs.img ./rootfs/
```

The challengers can use following commands to create such image files:

```bash
# Create plain image
dd if=/dev/zero of=rootfs.img bs=1M count=1024
mkfs.ext3 rootfs.img

# mount and alter it
mkdir ./rootfs
sudo mount -o loop rootfs.img ./rootfs/

# eject image
sudo umount ./rootfs/
```

## Attaching Exploit to Qemu

Instead of copying files to rootfs directory, the palindromatic challenge from bi0sCTF-2024 provides a new way:

run.sh

```bash
#!/bin/sh
qemu-system-x86_64 \
    \ # ...
    -drive file=rootfs.ext3,format=raw \
    -drive file=exploit,format=raw \
    \ # ...
```

init

```bash
[ -e /dev/sdb ] && cat /dev/sdb >/bin/pwn
chmod 755 /bin/pwn
```

Through the above configuration, we can enter `pwn` in qemu and run the exploit locally.

---

# References

\[1\] [bi0sCTF-2024 - palindromatic](https://github.com/teambi0s/bi0sCTF/tree/main/2024/Pwn/palindromatic) . _[K1R4](https://twitter.com/justk1R4)_
\[2\] [pwn-scripts](https://github.com/AvavaAYA/pwn-scripts) . _[eastXueLian](eastxuelian.nebuu.la)_
