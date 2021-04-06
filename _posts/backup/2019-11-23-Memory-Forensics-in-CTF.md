---
title: CTF 中常见的内存取证工具使用方法
key: 4b5565862aeeaf89b18fb6dcfaa0e578
tags:
  - CTF
  - Msic
date: 2019-11-23 20:39:18
---

## Volatility

volatility 是一款内存取证和分析工具，可以对 Procdump 等工具 dump 出来的内存进行分析，并提取内存中的文件。该工具支持 Windows 和 Linux，Kali 下面默认已经安装。volatility 的许多功能由其内置的各种插件来实现，例如查看当前的网络连接，命令行中的命令，记事本中的内容等等。

- [Volatility / Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)

```bash
volatility -f <文件名> -–profile=<配置文件> <插件> [插件参数] 
```

### Image Identification

#### imageinfo

`imageingo` 标识操作系统，Service Pack和硬件体系结构（32位或64位），其输出用于在使用其他插件时将参数传递给 `-profile = PROFILE` 的建议配置文件。

```bash
volatility -f 1.raw imageinfo
```

![](/assets/images/move/2019-11-23-20-50-03.png)

### Processes and DLLs

#### pslist

`pslist` 将遍历由PsActiveProcessHead指向的双向链接列表，并显示偏移量，进程名称，进程ID，父进程ID，线程数，句柄数以及进程启动和退出时的日期/时间。 从2.1版本开始，它还显示会话ID，以及进程是否为Wow64进程（它在64位内核上使用32位地址空间）。

![](/assets/images/move/2019-11-23-21-02-53.png)

#### pstree

`pstree` 命令用于以树形形式查看进程列表。它使用与 pslist 相同的技术枚举进程，因此也不会显示隐藏或未链接的进程。子进程使用缩进和句点表示。

![](/assets/images/move/2019-11-23-21-06-00.png)

#### cmdscan

`cmdscan` 插件在 XP / 2003 / Vista / 2008 上的 csrss.exe 和 Windows 7 上的 conhost.exe 的内存中搜索攻击者通过控制台外壳（cmd.exe）输入的命令。 这是最强大的命令之一，无论他们是通过 RDP 会话打开 cmd.exe 还是通过网络后门代理到命令 Shell 的代理输入/输出，您都可以使用它们来获取对受害者系统上攻击者操作的了解。

![](/assets/images/move/2019-11-23-21-10-45.png)


### Process Memory

#### memdump

`memdump` 插件用于将进程中的所有内存驻留页面提取到单个文件中，指定输出目录 `-D` 或 `--dump-dir = DIR`。

```bash
volatility -f 1.raw --profile=WinXPSP2x86 memdump -p 4 -D dump/
```

#### iehistory

`iehistory` 插件可恢复 IE 历史记录 index.dat 缓存文件的片段。 它可以找到基本访问的链接（通过 FTP 或 HTTP），重定向的链接（--REDR）和已删除的条目（--LEAK）。 它适用于加载和使用 wininet.dll 库的任何进程，而不仅仅是 Internet Explorer。 通常包括 Windows 资源管理器，甚至包括恶意软件样本。 


### Kernel Memory and Objects

#### filescan

`filescan` 插件使用 pool tag 在物理内存中查找 FILE_OBJECT，即使 rootkit 正在将文件隐藏在磁盘上，或 rootkit 挂钩了一些 API 函数以隐藏实时系统上的打开句柄，也可以找到打开的文件。 输出显示 FILE_OBJECT 的物理偏移量，文件名，指向对象的指针数量，指向对象的句柄数量以及授予对象的有效权限。

![](/assets/images/move/2019-11-23-21-24-36.png)

#### dumpfiles

在访问和使用文件时，OS 将文件缓存在内存中以提高系统性能。`dumpfiles` 插件可从内存中提取出这些文件。

```bash
  -r REGEX, --regex=REGEX
                        Dump files matching REGEX
  -i, --ignore-case     Ignore case in pattern match
  -o OFFSET, --offset=OFFSET
                        Dump files for Process with physical address OFFSET
  -Q PHYSOFFSET, --physoffset=PHYSOFFSET
                        Dump File Object at physical address PHYSOFFSET
  -D DUMP_DIR, --dump-dir=DUMP_DIR
                        Directory in which to dump extracted files
  -S SUMMARY_FILE, --summary-file=SUMMARY_FILE
                        File where to store summary information
  -p PID, --pid=PID     Operate on these Process IDs (comma-separated)
  -n, --name            Include extracted filename in output file path
  -u, --unsafe          Relax safety constraints for more data
  -F FILTER, --filter=FILTER
                        Filters to apply (comma-separated)
```

![](/assets/images/move/2019-11-23-21-29-48.png)




### Something else

#### netscan

`netscan` 用于扫描建立的连接和套接字，类似于 netstat，打印 TCP端点、TCP侦听器、UDP端点和UDP侦听器。它区分IPv4和IPv6，打印本地和远程 IP 、本地和远程端口、套接字绑定或建立连接的时间以及当前状态。

#### hashdump

`hashdump` 插件用于提取和解密存储在注册表中的缓存域凭据。

![](/assets/images/move/2019-11-23-20-57-03.png)

#### screenshot

`screenshot` 显示GDI样式的截屏。 

![](/assets/images/move/2019-11-23-20-52-01.png)

## Foremost

Foremost 是基于文件开始格式，文件结束标志和内部数据结构进行恢复文件的程序。

```bash
foremost [-v|-V|-h|-T|-Q|-q|-a|-w-d] [-t] [-s] [-k] [-b] [-c] [-o] [-i <file]
```
```bash
-V - 显示版权信息并退出
-t - 指定文件类型. (-t jpeg,pdf ...)
-d - 打开间接块检测 (针对UNIX文件系统)
-i - 指定输入文件 (默认为标准输入)
-a - 写入所有的文件头部, 不执行错误检测(损坏文件)
-w - 向磁盘写入审计文件，不写入任何检测到的文件
-o - 设置输出目录 (默认为为输出)
-c - 设置配置文件 (默认为 foremost.conf)
-q - 启用快速模式. 在512字节边界执行搜索.
-Q - 启用安静模式. 禁用输出消息.
-v - 详细模式. 向屏幕上记录所有消息。
```

### 扫描误删文件

```bash
foremost -t png -i 1.raw
```

### 恢复内存中dump文件

```
foremost pid.dump
```



\- **参考** \-

\[1\] [内存取证工具volatility用法与实战 - ShaoBaoBaoR](http://shaobaobaoer.cn/archives/693/memory-forensics-tool-volatility-usage-and-practice)

