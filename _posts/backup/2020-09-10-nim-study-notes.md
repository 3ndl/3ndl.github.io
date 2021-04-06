---
title: Nim Manual Study Notes
key: cfdc66e3edd21bb4f06a7684deb0db7f
tags:
  - Nim
  - Notes
date: 2020-09-10 19:39:13
---

Nim 是一种静态类型的、编译型、系统编程语言。它结合了其他成熟语言的成功概念。（如 Python、Ada 和 Modula）


## 词法元素

Nim 词法元素由（字符串）字面值、标识符、关键字、注释、操作符、和其它标点符号构成。

### 字符串和字符字面量

字符串字面值通过双引号括起来；字符字面值用单引号。特殊字符通过 `\` 转义: `\n` 表示换行， `\t` 表示制表符等.

```nim
r"C:\program files\nim" # 原始字符串字面量，\ 不转义
'''hello\world''' # 长字符串字面量，\ 不转义
```

### 注释

- 单行注释：`#`、文档注释 `##`

- 多行注释：`#[....]#`、`discard '''xxxx'''`

### 数字

- 下划线：`1_000_000` 一百万
- 浮点字面值：`1.0e9` 十亿
- 进制：`0b` `0o` `0x`

## var 语句

```nim
var x, y: int # 声明 x 和 y 拥有类型 ``int``
var
  x, y: int
  # 可以有注释
  a, b, c: string
```

## 赋值语句

```nim
var x = "abc" # 引入一个新变量 `x` 并且赋值给它
x = "xyz"     # 赋新值给 `x`
var x, y = 3  # 给变量 `x` 和 `y` 赋值 3
```

## 常量

```nim
const x = "abc"
const
  x = 1
  # 这也可以有注释
  y = 2
  z = y + 5 # 计算是可能的
```

## let 语句

let 语句像 var 语句一样但声明的符号是 `单赋值` 变量：初始化后它们的值将不能改变。

```nim
let x = "abc" # 引入一个新变量 `x` 并绑定一个值
x = "xyz"     # 非法: 给 `x` 赋值
```

let 和 const 的区别在于: let 引入一个变量不能重新赋值。 const 表示 **强制编译期求值并放入数据段**:

```nim
const input = readLine(stdin) # 错误: 需要常量表达式
let input = readLine(stdin)   # 可以
```

## 流程控制语句

### if 语句

```nim
let name = readLine(stdin)
if name == "":
  echo "Poor soul, you lost your name?"
elif name == "name":
  echo "Very funny, your name is name."
else:
  echo "Hi, ", name, "!"
```

### Case 语句

```nim
let name = readLine(stdin)
case name
of "":
  echo "Poor soul, you lost your name?"
of "name":
  echo "Very funny, your name is name."
of "Dave", "Frank": # 对于分支允许使用逗号分隔的值列表
  echo "Cool name!"
else:
  echo "Hi, ", name, "!"
```

case 语句可以处理整型、其它序数类型和字符串。对整型或序数类型值，也可以用范围：

```nim
from strutils import parseInt

echo "A number please: "
let n = parseInt(readLine(stdin))
case n
of 0..2, 4..7: echo "The number is in the set: {0, 1, 2, 4, 5, 6, 7}"
of 3, 8: echo "The number is 3 or 8"
else: discard # 空 discard 语句 => 什么都不做
```

### While 语句

```nim
echo "What's your name? "
var name = readLine(stdin)
while name == "":
  echo "Please tell me your name: "
  name = readLine(stdin)
```

### For 语句

```nim
echo "Counting to ten: "
for i in countup(1, 10): # 倒数  countdown(10, 1)
  echo i
# --> Outputs 1 2 3 4 5 6 7 8 9 10 on different lines
for i in 1..10: # 1..10
for i in 0..<10: # 零索引计数 0..9 -> for i in 0..<s.len
for index, item in ["a", "b"].pairs:
  echo item, " at index ", index
# => a at index 0
# => b at index 1
```

### 作用域和块语句

```nim
while false:
  var x = "hi"
echo x # 不行
block myblock:
  var x = "hi"
echo x # 不行
```

### Break 语句

```nim
block myblock:
  echo "entering block"
  while true:
    echo "looping"
    break # 跳出循环,但不跳出块
  echo "still in block"

block myblock2:
  echo "entering block"
  while true:
    echo "looping"
    break myblock2 # 跳出块 (和循环)
  echo "still in block"
```

### Continue 语句

```nim
while true:
  let x = readLine(stdin)
  if x == "": continue
  echo x
```

### When 语句

when 语句几乎等价于 if 语句, 但有以下区别:

- 每个条件必须是常量表达式，因为它被编译器求值。
- 分支内的语句不打开新作用域。
- 编译器检查语义并仅为属于第一个求值为 true 的条件生成代码。

when 语句在写平台特定代码时有用，类似于 C 语言中的 `#ifdef` 结构。

```nim
when system.hostOS == "windows":
  echo "running on Windows!"
elif system.hostOS == "linux":
  echo "running on Linux!"
elif system.hostOS == "macosx":
  echo "running on Mac OS X!"
else:
  echo "unknown operating system"
```

## 语句和缩进

简单语句不必缩进（不能包含其它语句：属于简单语句的赋值, 过程调用或 return 语句），复杂语句必须缩进，避免歧义。

```nim
# 单个赋值语句不需要缩进:
if x: x = false

# 嵌套 if 语句需要缩进:
if x:
  if y:
    y = false
  else:
    y = true

# 需要缩进, 因为条件后有两个语句：
if x:
  x = false
  y = false
```

表达式为了更好的可读性可以在某些地方缩进：

```nim
if thisIsaLongCondition() and
    thisIsAnotherLongCondition(1,
       2, 3, 4):
  x = true
```

用小括号和分号 (;) 可以在只允许表达式的地方使用语句：

```nim
const fac4 = (var x = 1; for i in 1..4: x *= i; x)
```

## 过程（procedure）

```nim
proc yes(question: string): bool =
  echo question, " (y/n)"
  while true:
    case readLine(stdin)
    of "y", "Y", "yes", "Yes": return true
    of "n", "N", "no", "No": return false
    else: echo "Please be clear: yes or no"

if yes("Should I delete all your important files?"):
  echo "I'm sorry Dave, I'm afraid I can't do that."
else:
  echo "I think you know what the problem is just as well as I do."
```

### Result 变量

一个返回值的过程有一个隐式 result 变量声明代表返回值。一个没有表达式的 return 语句是 return result 的简写。 result 总在过程的结尾自动返回如果退出时没有 return 语句.

```nim
proc sumTillNegative(x: varargs[int]): int =
  for i in x:
    if i < 0:
      return
    result = result + i

echo sumTillNegative() # echos 0
echo sumTillNegative(3, 4, 5) # echos 12
echo sumTillNegative(3, 4 , -1 , 6) # echos 7
```

### 形参

形参在过程体中不可改变，这允许编译器以最高效的方式实现参数传递。如果在一个过程内需要可以改变的变量，它必须在过程体中用 `var` 声明:

```nim
# 遮蔽形参名
proc printSeq(s: seq, nprinted: int = -1) =
  var nprinted = if nprinted == -1: s.len else: min(nprinted, s.len)
  for i in 0 .. <nprinted:
    echo s[i]
```

如果过程需要为调用者修改实参，可以用 var 参数:

```nim
proc divmod(a, b: int; res, remainder: var int) =
  res = a div b        # 整除
  remainder = a mod b  # 整数取模操作

var
  x, y: int
divmod(8, 5, x, y) # 修改 x 和 y
echo x
echo y
```

### Discard 语句

Nim 不允许静默地丢弃一个返回值，通过 discard 指定即可：

```nim
discard yes("May I ask a pointless question?")
```

返回类型可以被隐式地忽略如果调用的方法、迭代器已经用 discardable pragma 声明过：

```nim
proc p(x, y: int): int {.discardable.} =
  return x + y

p(3, 4) # now valid
```

### 命名参数

```nim
proc createWindow(x, y, width, height: int; title: string;
                  show: bool): Window =
   ...

var w = createWindow(show = true, title = "My Application",
                     x = 0, y = 0, height = 600, width = 800)
```

### 默认值

```nim
proc createWindow(x = 0, y = 0, width = 500, height = 700,
                  title = "unknown",
                  show = true): Window =
   ...

var w = createWindow(title = "My Application", height = 600, width = 800)
```

### 重载过程

Nim 提供类似 C++ 的过程重载能力：

```nim
proc toString(x: int): string = ...
proc toString(x: bool): string =
  if x: result = "true"
  else: result = "false"

echo toString(13)   # calls the toString(x: int) proc
echo toString(true) # calls the toString(x: bool) proc
```

### 操作符

```nim
proc `$` (x: myDataType): string = ...
# 现在$操作符对myDataType生效，重载解析确保$对内置类型像之前一样工作。
```

### 前向声明

```nim
proc even(n: int): bool # 前向声明

proc odd(n: int): bool =
  assert(n >= 0) # 确保我们没有遇到负递归
  if n == 0: false
  else:
    n == 1 or even(n-1)

proc even(n: int): bool =
  assert(n >= 0) # 确保我们没有遇到负递归
  if n == 1: false
  else:
    n == 0 or odd(n-1)
```

## 迭代器

```nim
iterator countup(a, b: int): int =
  var res = a
  while res <= b:
    yield res
    inc(res)
```

迭代器看起来像过程，但有几点重要的差异：

- 迭代器只能从循环中调用。
- 迭代器不能包含 return 语句（过程不能包含 yield 语句）。
- 迭代器没有隐式 result 变量。
- 迭代器不支持递归。
- 迭代器不能前向声明，因为编译器必须能够内联迭代器。（这个限制将在编译器的未来版本中消失。）

## 基本类型

### 布尔值

bool: true / flase，操作符 `not`, `and`, `or`, `xor`, `<`, `<=`, `>`, `>=`, `!=`, `==`。

### 字符

char: 1 byte, ord(char) -> int, chr(int) -> char, $char -> string.

### 字符串

字符串变量（string）可改变，Nim 中字符串有长度限制，以零结尾。获取字符串长度 `.len`，字符串赋值产生拷贝，拼接字符串可使用 `&` 和 `add` 进行追加。

### 整型

Nim有以下内置整型：

```nim
int int8 int16 int32 int64 uint uint8 uint16 uint32 uint64
```

默认整型是 `int` 。整型字面值可以用 `类型前缀` 来指定一个非默认整数类型：

```nim
let
  x = 0     # x 是 ``int``
  y = 0'i8  # y 是 ``int8``
  z = 0'i64 # z 是 ``int64``
  u = 0'u   # u 是 ``uint``
```

多数常用整数用来计数内存中的对象，所以 int 和指针具有相同的大小。

整数支持通用操作符 `+ - * div mod < <= == != > >=` 。 也支持 `and or xor not` 操作符，并提供按位操作。 左移用 `shl` ，右移用 `shr` 。位移操作符实参总是被当作无符号整型。普通乘法或除法可以做算术位移。

### 浮点

Nim 有这些内置浮点类型：`float float32 float64`。默认浮点类型是`float`。在当前的实现， float 是 64 位。

```nim
var
  x = 0.0      # x 是 ``float``
  y = 0.0'f32  # y 是 ``float32``
  z = 0.0'f64  # z 是 ``float64``
```

**自动类型转换**在表达式中使用不同类型时执行：短类型转换为长类型。整数类型不会自动转换为浮点类型，反之亦然。使用 `toInt` 和 `toFloat` 过程来转换。

```nim
var
  x: int32 = 1.int32   # 与调用 int32(1) 相同
  y: int8  = int8('a') # 'a' == 97'i8
  z: float = 2.5       # int(2.5) 向下取整为 2
  sum: int = int(x) + int(y) + int(z) # sum == 100
```

## 内部类型表示

```nim
var
  myBool = true
  myCharacter = 'n'
  myString = "nim"
  myInteger = 42
  myFloat = 3.14
echo myBool, ":", repr(myBool)
# --> true:true
echo myCharacter, ":", repr(myCharacter)
# --> n:'n'
echo myString, ":", repr(myString)
# --> nim:0x10fa8c050"nim"
echo myInteger, ":", repr(myInteger)
# --> 42:42
echo myFloat, ":", repr(myFloat)
# --> 3.1400000000000001e+00:3.1400000000000001e+00
```

## 高级类型

在 Nim 中新类型可以在 type 语句里定义：

```nim
type
  biggestInt = int64      # 可用的最大整数类型
  biggestFloat = float64  # 可用的最大浮点类型
```

### 枚举

枚举类型的变量只能赋值为枚举指定的值。这些值是有序符号的集合。每个符号映射到内部的一个整数类型。第一个符号用运行时的 0 表示，第二个用 1，以此类推。例如：

```nim
type
  Direction = enum
    north, east, south, west

var x = south     # `x`是`Direction`; 值是`south`
echo x            # 向标准输出写"south"
```

枚举的符号可以被限定以避免歧义：`Direction.south`。`$` 操作符可以将任何枚举值转换为它的名字， `ord` 过程可以转换为它底层的整数类型。

### 序数类型

枚举、整型、 char、 bool（和子范围）叫做序数类型。序数类型有一些特殊操作：

|Operation|Comment|
|:-:|:-:|
|ord(x)|	返回表示 x 的整数值|
|inc(x)|	x 递增1|
|inc(x, n)|	x 递增 n; n 是整数|
|dec(x)|	x 递减1|
|dec(x, n)|	x 递减 n; n 是整数|
|succ(x)|	返回 x 的下一个值|
|succ(x, n)|	返回 x 后的第n个值|
|pred(x)|	返回 x 的前一个值|
|pred(x, n)|	返回 x 前的第n个值|

inc, dec, succ 和 pred 操作通过抛出 EOutOfRange 或 EOverflow 异常而失败。

### 子范围

一个子范围是一个整型或枚举类型值（基本类型）的范围。例如：

```nim
type
  MySubrange = range[0..5]
```

MySubrange 是只包含 0 到 5 的 int 范围。赋任何其它值给 MySubrange 类型的变量是编译期或运行时错误。允许给子范围赋值它的基类型，反之亦然。

### 集合类型

集合的基类型只能是固定大小的序数类型，它们是:

- `int8`-`int16`
- `uint8`/`byte`-`uint16`
- `char`
- `enum`

```nim
type
  CharSet = set[char]
var
  x: CharSet
x = {'a'..'z', '0'..'9'} # 构造一个包含'a'到'z'和'0'到'9'的集合
```

|操作符|含义|
|:-:|:-:|
|A + B	|并集|
|A * B	|交集|
|A - B	|差集|
|A == B	|相等|
|A <= B	|子集|
|A < B	|真子集|
|e in A	|元素|
|e notin A	|A不包含元素e|
|contains(A, e)	|包含元素e|
|card(A)	|A的基 (集合A中的元素数量)|
|incl(A, elem)	|同 A = A + {elem}|
|excl(A, elem)	|同 A = A - {elem}|

### 位字段

```nim
type
  MyFlag* {.size: sizeof(cint).} = enum # 枚举
    A
    B
    C
    D
  MyFlags = set[MyFlag] # 集合

proc toNum(f: MyFlags): int = cast[cint](f) # 强转
proc toFlags(v: int): MyFlags = cast[MyFlags](v)

assert toNum({}) == 0
assert toNum({A}) == 1
assert toNum({D}) == 8
assert toNum({A, C}) == 5
assert toFlags(0) == {}
assert toFlags(7) == {A, B, C}
```

### 数组

```type
type
  IntArray = array[0..5, int] # 一个索引为 0..5 的数​组
var
  x: IntArray
x = [1, 2, 3, 4, 5, 6]
for i in low(x)..high(x): # 最小/大索引
  echo x[i]
```

```nim
type
  Direction = enum
    north, east, south, west
  BlinkLights = enum
    off, on, slowBlink, mediumBlink, fastBlink
  LevelSetting = array[north..west, BlinkLights]
var
  level: LevelSetting
level[north] = on
level[south] = slowBlink
level[east] = fastBlink
echo repr(level)  # --> [on, fastBlink, slowBlink, off]
echo low(level)   # --> north
echo len(level)   # --> 4
echo high(level)  # --> west
```

```nim
type
  LightTower = array[1..10, array[north..west, BlinkLights]]
type
  IntArray = array[0..5, int] # 一个索引为0..5的数​组
  QuickArray = array[6, int]  # 一个索引为0..5的数​组
var
  x: IntArray
  y: QuickArray
x = [1, 2, 3, 4, 5, 6]
y = x
for i in low(x)..high(x):
  echo x[i], y[i]
```

### 序列

序列类似数组但是动态长度，可以在运行时改变。因为序列是大小可变的它们总是分配在堆上，被垃圾回收。

序列总是以从零开始的 int 类型索引。 len , low 和 high 操作符也可用于序列。 x\[i\] 标记可以用于访问 x 的第i个元素。

序列可以用数组构造器 `[]` 数组到序列操作符 `@` 构成。另一个为序列分配空间的方法是调用内置 newSeq 过程。

```nim
var
  x: seq[int] # 整数序列引用
x = @[1, 2, 3, 4, 5, 6] # @ 把数组转成分配在堆上的序列
```

```nim
for value in @[3, 4, 5]:
  echo value
# --> 3
# --> 4
# --> 5

for i, value in @[3, 4, 5]:
  echo "index: ", $i, ", value:", $value
# --> index: 0, value:3
# --> index: 1, value:4
# --> index: 2, value:5
```

### 开放数组

> 注意: 开放数组只用于形参。

```nim
var
  fruits:   seq[string]       # 字符串序列用 '@[]' 初始化
  capitals: array[3, string]  # 固定大小的字符串数组

capitals = ["New York", "London", "Berlin"]   # 数组 'capitals' 允许只有三个元素的赋值
fruits.add("Banana")          # 序列 'fruits' 在运行时动态扩展
fruits.add("Mango")

proc openArraySize(oa: openArray[string]): int =
  oa.len

assert openArraySize(fruits) == 2     # 过程接受一个序列作为形参
assert openArraySize(capitals) == 3   # 也可以是一个数组
```

### 可变参数

varargs 参数像开放数组形参。 它也表示实现传递数量可变的实参给过程。编译器将实参列表自动转换为数组：

```nim
proc myWriteln(f: File, a: varargs[string]) =
  for s in items(a):
    write(f, s)
  write(f, "\n")

myWriteln(stdout, "abc", "def", "xyz")
# 编译器转为:
myWriteln(stdout, ["abc", "def", "xyz"])
```
转换只在可变形参是过程头部的最后一个形参时完成。它也可以在这个情景执行类型转换：

```nim
proc myWriteln(f: File, a: varargs[string, `$`]) =
  for s in items(a):
    write(f, s)
  write(f, "\n")

myWriteln(stdout, 123, "abc", 4.0)
# 编译器转为:
myWriteln(stdout, [$123, $"abc", $4.0])
```

在示例中 `$` 适用于任何传递给形参 a 的实参。注意 `$` 适用于空字符串指令。

### 切片

```nim
var
  a = "Nim is a progamming language"
  b = "Slices are useless."

echo a[7..12] # --> 'a prog'
b[11..^2] = "useful"
echo b # --> 'Slices are useful.'
```

```nim
"Slices are useless."
 |          |     |
 0         11    17   使用索引
^19        ^8    ^2   使用^
```

`b[0..^1]` == `b[0..b.len-1]` == `b[0..<b.len]` -> `^1` <=> `b.len-1`

### 对象

```nim
type
  Person = object
    name: string
    age: int

var person1 = Person(name: "Peter", age: 30)

echo person1.name # "Peter"
echo person1.age  # 30

var person2 = person1 # 复制person 1

person2.age += 14

echo person1.age # 30
echo person2.age # 44


# 顺序可以改变
let person3 = Person(age: 12, name: "Quentin")

# 不需要指定每个成员
let person4 = Person(age: 3)
# 未指定的成员将用默认值初始化。本例中它是一个空字符串。
doAssert person4.name == ""
```

在定义的模块外可见的对象字段需要加上 `*` :

```nim
type
  Person* = object # 其它模块可见
    name*: string  # 这个类型的字段在其它模块可见
    age*: int
```

### 元组

```nim
type
  # 类型表示一个人:
  # 一个人有名字和年龄。
  Person = tuple
    name: string
    age: int
  
  # 等价类型的语法。
  PersonX = tuple[name: string, age: int]
  
  # 匿名字段语法
  PersonY = (string, int)

var
  person: Person
  personX: PersonX
  personY: PersonY

person = (name: "Peter", age: 30)
# Person和PersonX等价
personX = person

# 用匿名字段创建一个元组：
personY = ("Peter", 30)

# 有匿名字段元组兼容有字段名元组。
person = personY
personY = person

# 通常用于短元组初始化语法
person = ("Peter", 30)

echo person.name # "Peter"
echo person.age  # 30

echo person[0] # "Peter"
echo person[1] # 30

# 你不需要在一个独立类型段中声明元组。
var building: tuple[street: string, number: int]
building = ("Rue del Percebe", 13)
echo building.street

# 下面的行不能编译，它们是不同的元组。
#person = building
# --> Error: type mismatch: got (tuple[street: string, number: int])
#     but expected 'Person'
```

元组只有在变量赋值期间可以解包:

```nim
import os

let
  path = "usr/local/nimc.html"
  (dir, name, ext) = splitFile(path)
  baddir, badname, badext = splitFile(path)
echo dir      # 输出 `usr/local`
echo name     # 输出 `nimc`
echo ext      # 输出 `.html`
# 下面输出同样的行:
# `(dir: usr/local, name: nimc, ext: .html)`
echo baddir
echo badname
echo badext
```

### 引用和指针类型

Nim 区分 **被追踪** 和 **未追踪** 引用。未追踪引用也被称为 **指针** 。追踪的引用指向垃圾回收堆里的对象，未追踪引用指向手动分配对象或内存中其它地方的对象。因此未追踪引用是 **不安全的**。 为了某些低级的操作（例如，访问硬件），未追踪的引用是必须的。

追踪的引用用 `ref` 关键字声明；未追踪引用用 `ptr` 关键字声明。

空 `[]` 下标标记可以用来**解引用**一个引用，表示获取引用指向的内容。`.`（访问一个元组/对象字段操作符）和 `[]` (数组/字符串/序列索引操作符）操作符为引用类型执行隐式解引用操作：

```nim
type
  Node = ref object
    le, ri: Node
    data: int
var
  n: Node
new(n)
n.data = 9
# 不必写n[].data; 实际上n[].data是不提倡的!
```

为了分配一个新追踪的对象，必须使用内置过程 new 。 为了处理未追踪内存， 可以用 alloc, dealloc 和 realloc，如果一个引用指向 nothing, 它的值是 `nil`。

### 过程类型

过程类型是指向过程的指针。 `nil` 是过程类型变量允许的值。Nim 使用过程类型达到 函数式编程技术。

```nim
proc echoItem(x: int) = echo x

proc forEach(action: proc (x: int)) =
  const
    data = [2, 3, 5, 7, 11]
  for d in items(data):
    action(d)

forEach(echoItem)
```

## 模块

Nim 支持用模块的概念把一个程序拆分成片段。每个模块在它自己的文件里。模块实现了 信息隐藏和编译隔离 。一个模块可以通过 `import` 语句访问另一个模块符号。 只有标记了星号(`*`)的顶级符号被导出：

```nim
# Module A
var
  x*, y: int

proc `*` *(a, b: seq[int]): seq[int] =
  # 分配新序列：
  newSeq(result, len(a))
  # 两个序列相乘：
  for i in 0..len(a)-1: result[i] = a[i] * b[i]

when isMainModule:
  # 测试序列乘 ``*`` :
  assert(@[1, 2, 3] * @[1, 2, 3] == @[1, 4, 9])
```

模块限定：

```nim
# Module A
var x*: string

# Module B
var x*: int

# Module C
import A, B
write(stdout, x) # error: x 有歧义
write(stdout, A.x) # okay: 用了限定

var x = 4
write(stdout, x) # 没有歧义: 使用模块 C 的 x
```

### 排除符号

```nim
import mymodule except y
```

### From 语句

```nim
from mymodule import x, y, z # --> x()
from mymodule as m import nil # --> m.x()
```

### Include 模块

include 语句和导入一个模块做不同的基础工作：它只包含一个文件的内容。 include 语句在把一个大模块拆分为几个文件时有用：

```nim
include fileA, fileB, fileC
```
