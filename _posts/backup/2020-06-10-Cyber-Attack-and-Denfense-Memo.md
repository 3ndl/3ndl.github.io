---
title: 网络攻击与防御课程复习笔记
key: ea0d2dbad06ccbd274e093855014225c
tags:
  - Course
date: 2020-06-10 19:53:34
---

**- 考试相关 -**

- 考核形式：平时 50% + 期末 50%
  - 平时：课堂问答、作业 + 报告
  - 期末：笔试（闭卷，多代码分析，需实践）

- 考题类型：
  - 论述题（`30%`） 3 * 10'
  - 材料分析题（`20%`） 1 * 20'
  - 代码分析题（`50%`） 1 * 20'（Web） + 1 * 30'（BIN）

- 分值分布：
  - Web 40'
  - BIN 40'
  - Mobile 20'

## 0x01 Web Security

### OWASP TOP 10

开放式 Web 应用程序安全项目（OWASP，Open Web Application Security Project）是一个非盈利的全球性安全组织，致力于应用软件的安全研究。使命是使应用软件更加安全，使企业组织能够对应用安全风险做出更清晰的决策。

\> http://www.owasp.org.cn/owasp-project/2017-owasp-top-10

![](/assets/images/move/2020-06-10-20-11-10.png)

#### A1 注入

将**不受信任的数据**作为命令或查询的一部分发送到解析器时，会产生诸如 SQL 注入、NoSQL 注入、OS 注入和 LDAP 注入的注入缺陷。攻击者的恶意数据可以诱使解析在没有适当授权的情况下执行非预期命令或访问数据。

![](/assets/images/move/2020-06-10-20-23-00.png)

![](/assets/images/move/2020-06-10-20-24-03.png)

简单说，ORM 就是通过实例对象的语法，完成关系型数据库的操作的技术，是"对象-关系映射"（Object/Relational Mapping） 的缩写。ORM 把数据库映射成对象。

~~~
数据库的表（table） --> 类（class）
记录（record，行数据）--> 对象（object）
字段（field）--> 对象的属性（attribute）
~~~

参考链接：[ORM 实例教程](http://www.ruanyifeng.com/blog/2019/02/orm-tutorial.html)


#### A2 失效的身份认证

通常，通过错误使用应用程序的身份认证和会话管理功能，攻击者能够破译**密码、密钥**或**会话令牌**，或者利用其它开发缺陷来暂时性或永久性冒充其他用户的身份。

![](/assets/images/move/2020-06-10-20-31-36.png)

![](/assets/images/move/2020-06-10-20-32-29.png)



#### A3 敏感数据泄露

许多 Web 应用程序和 API 都无法正确保护敏感数据，例如：财务数据、医疗数据和 **个人敏感信息（PII）** 数据。攻击者可以通过窃取或修改未加密的数据来实施信用卡诈骗、身份盗窃或其他犯罪行为。未加密的敏感数据容易受到破坏，因此，我们需要对敏感数据加密，这些数据包括：传输过程中的数据（是否明文传输）、存储的数据（是否加密）以及浏览器的交互数据。

![](/assets/images/move/2020-06-10-20-36-51.png)

![](/assets/images/move/2020-06-10-20-38-59.png)



#### A4 XML 外部实体（XXE）

许多较早的或配置错误的 XML 处理器评估了 XML 文件中的外部实体引用。攻击者可以利用外部实体窃取使用 URI 文件处理器的内部文件和共享文件、监听内部扫描端口、执行远程代码和实施拒绝服务攻击。

![](/assets/images/move/2020-06-10-20-40-37.png)

![](/assets/images/move/2020-06-10-20-50-07.png)



#### A5 失效的访问控制

未对通过身份验证的用户实施恰当的访问控制。攻击者可以利用这些缺陷访问未经授权的功能或数据，例如：访问其他用户的帐户、查看敏感文件、修改其他用户的数据、更改访问权限等。

![](/assets/images/move/2020-06-10-20-59-56.png)
![](/assets/images/move/2020-06-10-20-59-43.png)

#### A6 安全配置错误

安全配置错误是最常见的安全问题，这通常是由于不安全的默认配置、不完整的临时配置、开源云存储、错误的 HTTP 标头配置以及包含敏感信息的详细错误信息所造成的。因此，我们不仅需要对所有的操作系统、框架、库和应用程序进行安全配置，而且必须及时修补和升级它们。

![](/assets/images/move/2020-06-10-21-01-58.png)

#### A7 跨站脚本（XSS）

当应用程序的新网页中包含**不受信任的、未经恰当验证或转义**的数据时，或者使用可以创建 HTML 或 JavaScript 的浏览器 API 更新现有的网页时，就会出现 XSS 缺陷。XSS 让攻击者能够在受害者的浏览器中执行脚本，并劫持用户会话、破坏网站或将用户重定向到恶意站点。

![](/assets/images/move/2020-06-10-21-04-15.png) 

#### A8 不安全的反序列化

不安全的反序列化会导致远程代码执行。即使反序列化缺陷不会导致远程代码执行，攻击者也可以利用它们来执行攻击，包括：重播攻击、注入攻击和特权升级攻击。

![](/assets/images/move/2020-06-10-21-05-52.png)

#### A9 使用含有已知漏洞的组件

组件（例如：库、框架和其他软件模块）拥有和应用程序相同的权限。如果应用程序中含有已知漏洞的组件被攻击者利用，可能会造成严重的数据丢失或服务器接管。同时，使用含有已知漏洞的组件的应用程序和 API 可能会破坏应用程序防御、造成各种攻击并产生严重影响。

![](/assets/images/move/2020-06-10-21-06-58.png)

#### A10 不足的日志记录和监控

不足的日志记录和监控，以及事件响应缺失或无效的集成，使攻击者能够进一步攻击系统、保持持续性或转向更多系统，以及篡改、提取或销毁数据。大多数缺陷研究显示，缺陷被检测出的时间超过 200 天，且通常通过外部检测方检测，而不是通过内部流程或监控检测。

![](/assets/images/move/2020-06-10-21-08-22.png)

### 代码审计

![](/assets/images/move/2020-06-10-21-16-03.png)

![](/assets/images/move/2020-06-10-21-17-10.png)


### 渗透测试

渗透测试（Pentration Testing）：一种通过模拟攻击者的技术与方法，挫败目标系统的安全控制措施并获取访问控制权的安全测试方法。

渗透测试执行标准（`PTES`: Pentration Testing Execution Standard）：

1. **前期交互**阶段（Pre-Engagement Interaction）

  确定渗透测试范围、目标、限制条件与服务合同细节。

2. **情报收集**阶段（Information Gathering）

  获取目标网络拓扑、系统配置、安全防御措施等信息。

3. **威胁建模**阶段（Threat Modeling）

  针对获取的信息进行威胁建模与攻击规划。

4. **漏洞分析**阶段（Vulnerability Analysis）

  综合分析汇总的情报信息，从漏扫结果、服务查点信息等，找出可实施攻击的点。

5. **渗透攻击**阶段（Exploitation）

  利用找出的系统漏洞入侵系统，获取访问控制权限。

6. **后渗透**阶段（Post Exploitation）

  根据目标组织业务经营模式、保护资产形式等自主设计攻击目标，寻找客户组织最具价值和尝试安全保护的信息和资产，最终实施能造成重要业务影响的攻击。

7. **报告**阶段（Reporting）

  凝聚所有阶段获取到的关键情报信息、探测和发掘出的系统安全漏洞、成功的渗透过程，同时站在防御者角度上分析安全体系中最薄弱的环节及修补与升级技术方案。

### 权限提升

利用操作系统或者应用软件中的程序错误、设计缺陷或配置不当来获取受保护资源的高级访问权限。

#### Windows

一般提权步骤：

1. 获取一个低权限 shell

2. 利用 MSF Meterpreter getsystem 进行提权

3. MSF 中利用 Windows 版本提权漏洞

4. systeminfo 查看安装了哪些补丁

5. 查找相关提权 exp

6. 应用程序提权 Serv-u、Mysql ...

常见提权手段：

- 内核漏洞提权（Win32k.sys）
- 操作系统漏洞
  DLL 劫持、窃取 Token、窃取管理员密码、可执行文件路径未被引号包裹、允许非特权用户以 system 权限运行 MSI 文件 AlwaysInstallElevated
  - **DLL 劫持**
    通过劫持某些以高权限启动的程序中导入的动态链接库，达到以高权限执行恶意操作的目的。
    由于可执行模块的输入表只包含 DLL 名而没有它的路径名，因此加载程序会在磁盘中寻找 DLL，顺序为：
    - 当前文件夹下 => 系统目录（C:\system32）=> 环境变量各目录（$PATH）
  - **窃取 Windows Access Token**
    access token（访问令牌）是 Windows 安全性的一个概念，包含此登录会话的安全信息。用户登录时，系统创建一个访问令牌，然后以该用户身份运行的所有进程都拥有一个该令牌的拷贝。该令牌唯一表示该用户、用户组和用户权限（类似 Cookie）。
    通过窃取高权限用户的 Token，可以获得高权限。
    工具；[Tokenvator](https://github.com/0xbadjuju/Tokenvator)
  - **可执行文件路径未被引号包裹**
    假如一个服务（注册表等的记录值）的名称中包含空格，但没有引号包裹
    ~~~
    C:\Program Files\Target.exe
    ~~~
    当 Windows 尝试启动服务时，会按照如下顺序：
    - C:\Program.exe
    - C:\Program Files.exe
    - C:\Program Files\Target.exe
    
    假如把恶意 exe 放在这些路径下，那么系统级服务重启时，便会以高权限执行任意文件。
  - **AlwaysInstallElevated**
    **>** [利用 AlwaysInstallElevated 提权的测试分析](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8AlwaysInstallElevated%E6%8F%90%E6%9D%83%E7%9A%84%E6%B5%8B%E8%AF%95%E5%88%86%E6%9E%90/)
    微软允许非授权用户以 SYSTEM 权限运行安装文件（MSI）, 在测试环境启用 AlwaysInstallElevated，命令如下：
    ```cmd
    reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
    ```
- 应用程序漏洞
  SMB、MySQL、Serv-U、etc.

#### Linux（$->#）

一般步骤：

1. 查看内核版本
  ~~~
  uname -a
  cat /proc/version
  ~~~

2. 检查是否有配置不当，如低权限用户对高权限用户的读写权，或者某些 SUID 程序可执行 bash

3. 应用程序提权（Apache、Tomcat、MySQL、Redis、MongoDB）

常见提权手段：

- 内核提权
  - **脏牛漏洞（CVE-2016-5195）**
    Linux 内核的内存子系统在处理写时复制（copy-on-write，COW）时产生了条件竞争。恶意用户可利用该漏洞，对只读内存映射进行写访问来获取最高权限。

- 系统提权

  - **SUID 程序提权**
    `SUID`（设置用户 ID）是赋予文件的一种权限，它会出现在文件拥有者权限的执行位上，**具有这种权限的文件会在其执行时，使调用者暂时获得该文件拥有者的权限。**
    但是，如果某些现有的二进制文件和实用程序具有 SUID 权限的话，就可以在执行时将权限提升为 root。具有提权功能的Linux可执行文件包括：
    ~~~
    Nmap、Vim、find、Bash、More、Less、Nano、cp
    ~~~
    以下命令可以找到正在系统上运行的所有 SUID 可执行文件。准确的说，这个命令将从 `/` 目录中查找具有 SUID 权限位且属主为 root 的文件并输出它们，然后将所有错误重定向到 `/dev/null`(或称空设备，在类 Unix 系统中是一个特殊的设备文件，它丢弃一切写入其中的数据（但报告写入操作成功），读取它则会立即得到一个 EOF），从而仅列出该用户具有访问权限的那些二进制文件。
    ```cmd
    find / -user root -perm -4000 -print 2>/dev/null
    find / -perm -u=s -type f 2>/dev/null
    find / -user root -perm -4000 -exec ls -ldb {} ;
    ```
    以上所有二进制文件都将以 root 用户权限来执行，因为它们的权限中包含 `s`，并且它们的属主为 root。

  - **修改用户属性（文件权限配置不当）**
    
  - **修改 /etc/passwd**
    用户口令优先读取 /etc/passwd，而后才是 /etc/shadow，假如拥有 /etc/passwd 的写权限的话，则可修改：
    ~~~
    #用户名:口令:用户标识号:组标识号:注释性描述:主目录:登录 shell
    root:x:0:0:root:/root:/bin/bash
    ~~~
    为：
    ~~~
    #用户名:口令:用户标识号:组标识号:注释性描述:主目录:登录 shell
    root:[passwd encrypted]:0:0:root:/root:/bin/bash
    ~~~
  - **修改 root 用户 ssh 密钥**
    加入对 /root/.ssh/ 有写权限，则可将自己的 ssh 密钥写入 /root/.ssh/authorized_keys，实现 ssh 免密码登录。如 Redis 未授权访问漏洞写入 ssh 密钥（Redis 一般以 root 权限启动）。
  - **通配符提权**
    \> [利用通配符进行 Linux 本地提权](https://www.freebuf.com/articles/system/176255.html)
![](/assets/images/move/2020-06-10-23-23-26.png)
  - **应用程序提权**

#### 数据库 UDF 提权

**>** [udf 提权原理详解](https://www.cnblogs.com/litlife/p/9030673.html)

`UDF`: User-defined function，即用户自定义函数。是通过添加新函数，对 MySQL 的功能进行扩充，性质就象使用本地 MySQL 函数如 abs() 或 concat()。udf 在 MySQL `5.1` 以后的版本中，存在于 `mysql/lib/plugin` 目录下，文件后缀为 `.dll`，常用 C 语言编写。

前提条件：

1. 获得 root 账户密码

2. 数据库开启 plugin

3. 数据库监听公网

**- 如何防御提权 -**

- 及时打补丁

- 启动 Web、DB 服务时以低权限启动（最小权限原则）

- 服务只监听 127.0.0.1 （不要开放在公网）

## 0x02 Reverse Enginee

要求：能分析汇编语言代码，能书写简单的汇编代码

~~~
字节序
汇编基础（给定代码能说明其含义）
调用约定（相关的汇编代码分析和栈的变化情况）
简单的软件保护技术举例
Windows 内核管理
~~~

### 逆向工程概述

#### 字节序与编码

\> [理解字节序](https://www.ruanyifeng.com/blog/2016/11/byte-order.html)

计算机硬件有两种储存数据的方式：大端字节序（big endian）和小端字节序（little endian）。

举例来说，数值 0x2211 使用两个字节储存：高位字节是 0x22，低位字节是 0x11。

- 大端字节序：**低地址存放高字节，高地址存放低字节**，这是人类读写数值的方法。

- 小端字节序：**低地址存放低字节，高地址存放高字节**，即以 0x1122 形式储存。

同理，0x1234567 的大端字节序和小端字节序的写法如下图：

![](/assets/images/move/2020-06-11-15-24-22.png)

计算机电路先处理低位字节，效率比较高，因为计算都是从低位开始的。所以，计算机的内部处理都是小端字节序。

对于 char[] 字符数组，在内存中连续，不管是大端序还是小端序，存储顺序都是一样的。

栈区填充：

循环执行将 EAX 的值填入 EDI 对应的内存空间中：

```assmble
lea edi,dword ptr ss:[ebp-50]   ;EDI存放循环操作起始地址
mov ecx,14                      ;循环次数
mov eax,0xCCCCCCCC              ;填入的值
rep stosd
```

- rep 以 ECX 为计数器。

- stosb / stosw / stosd 把 AL / AX / EAX 的值填入 EDI 指向的内存空间中，同时 EDI 向标志寄存器 DF 的方向增加或减少。

- CC 指令：INT 3 中断的机器码。

编码相关：

- ANSI 字符集：1 Byte、Unicode 字符集：2 Byte。

- Window API 最终都要转化成 Unicode 。

- \\Windows\System32 下存放原生的 64 位映像文件。

- \\Windows\SysWOW64 下存放 32 位的系统文件。WOW：Windows-on-Windows 64-bit，为 64 位 Windows OS 的子系统。

#### 栈的脏数据

函数栈退出以后，原有栈空间的局部变量不会被自动清除，成为栈的**噪音**或**脏数据**。

#### 汇编基础

- 栈（stack）：从高地址向低地址生长。

- 栈帧（stack frame）：程序运行时栈中分配的内存块，专门用于特定的函数调用。

栈帧的大致结构：

```asm
; 函数序言
push    ebp        ;函数开始（使用 EBP 前先把已有值保存到栈中）
mov     ebp,esp    ;保存当前 ESP 到 EBP 中
sub     esp,0x10
​
; ……
; 函数体
; ……              ;无论 ESP 怎么变化，EBP 都保持不变，可以安全访问函数的局部变量、参数
​
; 函数尾声
mov     esp,ebp   ;将函数起始地址返回到 ESP 中
pop     ebp       ;函数返回前弹出保存在栈中的 EBP 值
ret               ;函数停止
```

调用一个函数时的操作步骤：

1. Caller 将 Callee 所需**参数**放入函数所采用的**调用约定**的指定位置。

2. Caller 将控制权转交给 Callee ，然后**返回地址**被保存到程序栈或 CPU 寄存器中。

3. Callee 为局部变量分配空间。

4. Callee 执行操作。

5. Callee 完成操作，释放局部变量的栈空间。

6. Callee 将控制权返还给 Caller（ret）。


**AT&T 汇编指令 enter、leave、call、ret：**

`enter` 相当于 Intel 中的：

```asm
push    ebp
mov     ebp,esp
```

`leave` 是 enter 的相反的过程：

```asm
mov     esp,ebp
pop     ebp
```

`call` 保存当前 EIP 后修改 EIP 的值，相当于：

```asm
push    eip
mov     eip,<function address>
```

`ret` 只要恢复 EIP，相当于：

```asm
pop     eip
```

漏洞代码：

```c
//vuln.c
#include <stdio.h>
#include <string.h>
int main(int argc, char* argv[]) {
        /* [1] */ char buf[256];
        /* [2] */ strcpy(buf,argv[1]);
        /* [3] */ printf("Input:%s\n",buf);
        return 0;
}
```
反汇编：
```asm
(gdb) disassemble main
Dump of assembler code for function main:
   0x08048414 <+0>:	push   %ebp                    //backup caller's ebp
   0x08048415 <+1>:	mov    %esp,%ebp               //set callee's ebp to esp
   0x08048417 <+3>:	and    $0xfffffff0,%esp        //栈对齐
   0x0804841a <+6>:	sub    $0x110,%esp             //stack space for local variables
   0x08048420 <+12>:	mov    0xc(%ebp),%eax          //eax = argv
   0x08048423 <+15>:	add    $0x4,%eax               //eax = &argv[1]
   0x08048426 <+18>:	mov    (%eax),%eax             //eax = argv[1]
   0x08048428 <+20>:	mov    %eax,0x4(%esp)          //strcpy arg2 
   0x0804842c <+24>:	lea    0x10(%esp),%eax         //eax = 'buf'
   0x08048430 <+28>:	mov    %eax,(%esp)             //strcpy arg1
   0x08048433 <+31>:	call   0x8048330 <strcpy@plt>  //call strcpy
   0x08048438 <+36>:	mov    $0x8048530,%eax         //eax = format str "Input:%s\n"
   0x0804843d <+41>:	lea    0x10(%esp),%edx         //edx = buf
   0x08048441 <+45>:	mov    %edx,0x4(%esp)          //printf arg2
   0x08048445 <+49>:	mov    %eax,(%esp)             //printf arg1
   0x08048448 <+52>:	call   0x8048320 <printf@plt>  //call printf
   0x0804844d <+57>:	mov    $0x0,%eax               //return value 0
   0x08048452 <+62>:	leave                          //mov ebp, esp; pop ebp; 
   0x08048453 <+63>:	ret                            //return => pop eip
End of assembler dump.
```

堆栈布局：

![](/assets/images/move/2020-06-11-23-15-16.png)

#### 调用约定

调用约定：指定调用方放置函数所需参数的具体位置。

![](/assets/images/move/2020-06-11-15-51-28.png)


函数支持可变参数的前提：调用方清理堆栈。

注意：

- x86 __fastcall 前两个参数传入 ECX 和 EDX。
- x64 __fastcall 前四个参数传入 RCX、EDX、R8、R9。

IDA 中，把参数和局部变量自动识别成类似 arg_0、var_4 的形式：

- arg_ 代表参数，都是正数。

- var_ 代表局部变量，都是负数。

**Q：如何区分是 __cdecl 还是 __stdcall ?**

- __cdecl 调用方清理堆栈（外，适合参数变量可变）：
  ```
  call    <function_name>
  add     esp,10h
  ```
- __stdcall 被调用方清理堆栈（内，适合参数个数固定）：
  ```
  retn    10h
  ```

**Others：**

系统调用？从用户模式进入内核模式。

Linux x86 使用 int 0x80 或 sysenter 指令。其他 x86 可能只有 sysenter 指令。

非优化编译器使用 EBP 寻址。

优化：使用 ESP 寻址。（减少代码，提高速度）

### 软件保护技术基础

常见的软件保护技术：

1. **序列号**

2. **警告窗口（Nag）**

3. **时间限制**

4. **菜单功能限制**

5. **KeyFile 保护**

6. **网络验证**

7. **只运行一个实例**


### Windows 内核基础

用户态（Ring 3）、核心态（Ring 0）。用户态下所有动态链接库（USER32.DLL、KERNEL32.DLL、GDI32.DLL）都会经由 NTDLL.DLL 映射到核心态执行体。

![](/assets/images/move/2020-06-11-16-42-08.png)

- USER32 ：用户界面相关应用程序接口。

- GDI32.DLL ：图形用户界面相关程序。

- KERNEL32.DLL ：内存管理、数据 I/O 操作、中断处理。

UEFI（Unified Extensible Firmware Interface, 同意的可扩展固件接口）相当于一个微型 OS，能直接读取分区中的文件。不需要 MBR（主引导记录）

![](/assets/images/move/2020-06-11-16-45-28.png)

- smss.exe ：会话管理器子系统，第一个用户模式进程。

- csrss.exe ：客户端/服务器运行时子系统。主要负责 Win32 控制台的处理和界面关闭，是关键的系统操作。

- winlogon ：用户的登陆和注销支持。

- lsass ：本地安全授权子系统。

- services.exe ：服务子系统。


## 0x03 Mobile Network Security

~~~
移动网络的分类和安全风险
WLAN 安全机制-- WEP，IEEE 802.11i（WPA、WPA2、CCMP、TKIP、认证密钥交换、四步握手）
移动通信安全机制-- GSM 3G, 4G
~~~


### WLAN 安全机制

#### WEP

WEP 是 Wired Equivalent Privacy的 简称，**有线等效保密（WEP）协议**是对在两台设备间无线传输的数据进行加密的方式，用以防止非法用户窃听或侵入无线网络。

- 加密过程

1. 生成一个 `IV`（24 位），与共享密钥 `SK`（40 位）连接在一起作为种子密钥。使用 `RC4` 算法生成密钥流。
2. 使用数据冗余校验算法 `CRC32` （低配版的哈希函数）计算明文数据的 `ICV`。
3. 明文和 `ICV` 连接起来，与密钥流异或得到密文。

![](/assets/images/move/2020-06-11-21-38-30.png)

- 解密过程

![](/assets/images/move/2020-06-11-21-42-02.png)

加密算法是：明文 || ICV ⊕ 密钥流 → 密文

解密算法是：密文 ⊕ 密钥流 → 明文 || ICV

ICV 这时候就有用了，通过同样的算法（CRC32）计算收到的明文的 ICV'，验证一下 ICV 是否和 ICV' 相同，以验证数据完整性：

- 相同，则认为数据未经篡改。

- 不相同，则认为数据不完整，丢弃这个包。

**- 安全缺陷 -**

1. **RC4 算法的使用**
  RC4 存在大量的弱密钥（每 256 个 RC4 密钥中就有 1 个是弱密钥）。

2. **WEP 没有抗重放机制**
  WEP 协议帧中无序列号，无法确定协议帧的顺序。
  WEP 的完整性保护只应用于数据载荷，而不保护源地址、目的地址等，攻击者可以伪造这些信息，进行重放。

3. **SV 的产生与分发**

  - IV(24) SK(40) 相当于 5 字符，10 位十六进制。

  - IV(24) SK(104) 相当于 13 字符，26 位十六进制。

  对于 SK，厂商一般提供两种方式：

  - 用户直接输入 5 或 13 个字符（用户一般这么干）
  - 或者输入比特（或十六进制），比较麻烦

  考虑可打印字符有的个数，生成器的设计缺陷导致 40 比特的 SK 只有 21 比特的安全性（**穷举**）

  普通用户喜欢用姓名、生日、电话等作为密钥词组（**字典**）

  SK 为 WLAN 用户共享，且很少变动（**泄露**）

4. **IV 空间太小**
  使用 IV 的目的：为每个数据包创建一个新的、不重复的**数据包密钥**。
  若使用相同的 IV || SK 加密两个消息，则 C_1 ⊕ C_2 = P_1 ⊕ P_2。若一个明文已知，那么另一个明文也暴露了。
  24 bit 的 IV 有 2^24 种可能，假设 IV 的生成是完全随机的，结合密码学中生日攻击知识，当发送的包超过 2^12 = 5000 个时，IV 就会开始重复，很快就会出现 IV 冲突。

5. **CRC32 是线性的**
![](/assets/images/move/2020-06-11-21-51-05.png)
  在 k 未知的情况下，可任意篡改未知明文的密文，且能保证 ICV 值的正确性。

**- 认证机制 -**

`AP`: Access Point, 接入点

- 开放系统认证：直接把密钥以明文的形式发给认证方（路由器）

- 共享密钥认证：挑战/响应机制：

  - 客户端向 AP 发送认证请求。
  - AP 向客户端发送明文挑战帧。
  - 客户端用 WEP 密钥加密该挑战，并发送给 AP。
  - AP 发送认证响应。

#### IEEE 802.11i


**-加密机制-`TKIP` 暂时密钥完整性协议 -**

使 WEP 设备能够通过软件升级来支持 TKIP （既要解决兼容，又要解决 WEP 的安全缺陷），是包裹在 WEP 外的一套算法。

TKIP 的改进：

- IV：24 → 48

- SK：40 → 104

- 引入 4 个新算法

  - 单包密钥生成算法：防止弱密钥的产生
  - MIC：防止数据被非法篡改
  - 具有序列功能的 IV ：抗重放
  - Rekeying：防止 IV 重用

加密过程：

![](/assets/images/move/2020-06-11-22-12-32.png)

解密过程：

![](/assets/images/move/2020-06-11-22-13-51.png)


Q：在 IEEE802.11i 协议中并没有使用共享密钥作为加密和解密的密钥，那么加密和解密的密钥是如何生成的？

A：IEEE802.11i 的认证和密钥交换协议（AKE）

  - **AKE 协议流程与结构**
  - **四步握手协议**

两种模式：

- 预共享密钥模式（WPA-PSK/WPA2-PSK，个人版）
- **企业模式**

![](/assets/images/move/2020-06-11-22-41-25.png)

申请者（STA，相当于你的设备），认证者（AP，相当于路由器），认证服务器（AS）

- APnonce：AP 生成的随机数

- Snonce：申请者生成的随机数

- APA：AP 地址

- SA：申请者地址

- PRF：伪随机函数

- PMK：对主密钥

- PTK：对瞬时（临时）密钥，最终用于加密单播数据的密钥。512 位，结构如下：

![](/assets/images/move/2020-06-11-22-51-14.png)

- GMK：组主密钥

- GTK：组瞬时（临时）密钥，最终用于加密广播/组播数据的密钥。

- MIC：消息认证码

![](/assets/images/move/2020-06-11-22-48-53.png)

![](/assets/images/move/2020-06-11-22-49-00.png)

STA 通过网络发现找到 AP，与 AS 共享一个对主密钥 PMK，AS 将 PMK 安全传送到 AP。

1. AP 生成一个随机数 APnonce，发送给 STA 。
2. STA 生成一个随机数 Snonce，利用 （APnonce, Snonce, PMK, APA, SA）生成对瞬时密钥 PTK。将 Snonce 和 MIC（由 PTK 中 KCK 生成）发送给 AP 。AP 收到 Snonce 和 MIC 后，使用相同的方法生成 PTK，并利用 PTK 中的 KCK 验证 MIC 。若验证失败，则结束过程。
3. 验证成功后，AP 将 APnonce 和 MIC 发送给 STA 。
4. STA 收到后，执行相同的检查工作，确认 AP 和自己有相同的 PMK，确认成功后向 AP 回发一个 MIC 。

### GSM

![](/assets/images/move/2020-06-11-23-04-31.png)

![](/assets/images/move/2020-06-11-23-05-08.png)

![](/assets/images/move/2020-06-11-23-05-19.png)

**- 参考 -**

\[1\] [ComyDream](https://comydream.github.io/)

