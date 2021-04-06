---
title: Linear Feedback Shift Register
key: 2ed622c9e1a05d5337c73f1cfe24d547
tags:
  - Crypto
  - Course
date: 2019-12-25 22:27:31
---

#### LFSR

在密码学中，**流密码**（Stream cipher），又译为**流加密**、**数据流加密**，是一种对称加密算法，加密和解密双方使用相同伪`随机加密数据流`（pseudo-random stream）作为**密钥**，明文数据每次与密钥数据流顺次对应加密，得到密文数据流。实践中数据通常是一个位（bit）并用异或（xor）操作加密。

该算法解决了对称加密完善保密性（perfect secrecy）的实际操作困难。**完善保密性**由克劳德·香农于 1949 年提出。由于完善保密性要求密钥长度不短于明文长度，故而实际操作存在困难，改由较短数据流通过特定算法得到密钥流。

**伪随机密钥流**（keystream）由一个随机的`种子`（seed）通过算法（称为：PRG，pseudo-random generator）得到，k 作为种子，则 G(k) 作为实际使用的密钥进行加密解密工作。为了保证流加密的安全性，PRG 必须是不可预测的。弱算法包括 glibc random() 函数，线性同余生成器（linear congruential generator）等。

实际序列密码使用的密钥位序列 $s_{1}, s_{2}, ...$ 是通过具有某种属性的密钥流生成器得到的。一种得到长伪随机序列的简单方法就是使用**线性反馈移位寄存器**（LFSR）, LFSR 很容易使用硬件实现，许多序列密码都是使用 LFSR 来实现的，但不是全部。

#### 构成

一个 LFSR 有若干时钟存储原件（触发器）和一个反馈路径组成，存储原件的数目给出了 LFSR 的度。换言之，一个拥有 m 个触发器的 LFSR 可以称为`度为 m `。反馈网络计算移位寄存器中某些触发器的 XOR 和，并将其作为上一个触发器的输入。

![](/assets/images/move/2019-12-25-22-43-20.png)

如果这里的反馈函数是线性的，我们则将其称为 LFSR，此时该反馈函数可以表示为：

$$ f(a_{1},a_{2}, ..., a_{n}) = c_{1}a_{1} \oplus c_{2}a_{2} \oplus ... \oplus c_{n}a_{n}$$

其中$c_{i}=0$或$1$，$⊕$表示异或（模二加）。

（例）加密过程:

```py
# R 为初始状态，mask 为掩码
def LFSR(R, mask):
    # 把 R 左移一位后低32位（即抹去 R 的最高位，然后在 R 的最低位补 0）的值赋给 output 变量
    output = (R << 1) & 0xffffffff
    # 把传入的 R 和 mask 做按位与运算，运算结果取低 32 位，将该值赋给 i 变量
    i = (R & mask) & 0xffffffff
    # 从 i 的最低位向 i 的最高位依次做异或运算，将运算结果赋给 lastbit 变量
    lastbit = 0
    while i!= 0:
        lastbit ^= (i & 1)
        i = i >> 1
    # 将 output 变量的最后一位设置成 lastbit 变量的值。
    output ^= lastbit 
    # output 即经过一轮 LFSR 之后的新序列，lastbit 即经过一轮 LFSR 之后输出的一位
    return (output, lastbit)
```

#### 性质

LFSR 寄存器的空间状态受限于寄存器位数最大只能达到 $2^{n}$，去除初始状态之后有 $2^{n}-1$ 即可到达循环节。

**>> 度长为 $m$ 的 LFSR 可产生的最大周期序列长度为 $2^{m}-1$**.

选取最大不可约多项式进行验证：

```py
#-*- coding: utf-8 -*-
# 本原多项式样本值 (0, 1, 3, 5, 16)
from operator import eq

def LFSR(p_x, seq):
    s = 0
    for i in p_x:
        s ^= seq[i - 1] # i - 1
    for i in range(len(seq) - 1):
        seq[i] = seq[i + 1] # seq 1,2,...,n <-
    seq[-1] = s

if __name__ == "__main__":
    # 特征多项式 P(x)
    # P_x = list(input("Please Input P(x) >> "))
    # 本源多项式
    P_x = list((0, 1, 3, 5, 16))
    p_x = P_x[1:]
    # seq = input("Please Input Sequence >> ")
    # 寄存器的初始状态 seq
    seq = [(_ % 2) for _ in range(P_x[-1])]
    cmp = [(_ % 2) for _ in range(P_x[-1])]
    cnt = 0
    while True:
        LFSR(p_x, seq)
        cnt += 1
        if eq(seq, cmp):
            print seq
            print cnt
            break
```

运行结果:

![](/assets/images/move/2019-12-25-23-15-45.png)


#### 参看

\[1\] [深入分析CTF中的LFSR类题目（一）](https://www.anquanke.com/post/id/181811)


