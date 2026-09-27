# 搜索建议处的 XSS（注入点在 JS 字符串里）

## 这一题在教什么

**转义必须匹配最终上下文。**

看服务端把用户输入放在了哪儿：

```html
<script>
  var recentQuery = "<你搜的关键词>";
</script>
```

这个位置有两个反直觉的地方，叠在一起才构成这一题：

| # | 事实 | 后果 |
|---|---|---|
| 一 | 这是 **JS 上下文**，不是 HTML 上下文 | 「HTML 转义」在这里是错的 —— 它管不到 JS 的语法 |
| 二 | `<script>` 是**原始文本元素**，里面的 HTML 实体**不解码** | `&lt;/script&gt;` **关不掉**它；但**原文的** `</script>` 能 |

第二点最反直觉：

> 唯一能打断这个 script 元素的，是一个**不带任何转义的** `</script>`。

## 漏洞在哪

`module.py`：

```python
embedded = json.dumps(q, ensure_ascii=False)      # 只处理了 JS 语法
```

`json.dumps` 做的是 **JS 层面**的序列化：引号、反斜杠、控制字符都处理了。
但它**不知道这段 JSON 还要嵌进 HTML 的 `script` 元素里**。

而对 HTML 解析器来说，`</script>` 的语义不是"JS 字符串里的几个字符"，
是「**结束这个元素**」。

配套的过滤器也拦错了东西：

```python
RULES = [("script 开始标签", r"(?i)<\s*script")]
```

它拦的是**开始**标签，而漏洞用的是**结束**标签 —— 两个不同的字符串。

## 怎么打通

### 第一步：看清位置

搜点什么，然后**看页面源代码**。你会看到：

```html
var recentQuery = "你的输入";
```

它在 `<script>` 里面 —— 这是个 JS 上下文。

### 第二步：验证 HTML 转义在这里没用

搜 `&lt;b&gt;`，看页面源码里 script 那一段 —— 它**原样**是 `&lt;b&gt;`，
没有被解码成 `<b>`。

原因就是"原始文本元素"：在 `<script>` 里，浏览器只找 `</script`，
所有 HTML 实体都不解码。

### 第三步：只用结束标签

```
</script><img src=x onerror=alert(1)>
```

拼出来：

```html
var recentQuery = "</script><img src=x onerror=alert(1)>";
```

浏览器的处理顺序：

1. `var recentQuery = "` 开始一段脚本
2. 遇到 `</script>` —— **script 元素结束**（它不管你还在不在 JS 字符串里）
3. 后面的 `<img src=x onerror=...>` 被当成**普通 HTML**
4. `src=x` 加载失败 → `onerror` 执行

过滤器一次都没命中 —— 它拦的是 `<script`，没有斜杠。

## 为什么 `json.dumps` 不够（这一题的核心）

`json.dumps` 处理了"这段数据要当 JS 解析"这件事，
但没处理"这段 JSON 要嵌进 HTML 的 `script` 元素里"这件事。

**一个值从用户输入到最终被解析，中间会经过好几层。每一层有自己的语法。
转义只管得住你正在写的那一层。**

| 你写在哪 | 需要什么转义 |
|---|---|
| HTML 正文 | HTML 实体（`&lt;`） |
| HTML 属性值里 | HTML 实体 + 引号 |
| **`<script>` 里的 JS 字符串** | **`<` → `\u003c`**（这样才不会被 HTML 解析器当成标签） |
| `<script>` 外联文件里 | 同上（但那个文件不经过 HTML 解析，所以只需要 JS 转义） |
| URL 里 | URL 编码 |
| CSS 里 | CSS 转义 |

## 怎么修

**一、按最终上下文转义。**

Flask / Jinja 的 `|tojson` 就是干这个的：

```jinja
var recentQuery = {{ q | tojson }};
```

它会把 `<` 转成 `\u003c` —— 在 JS 里是同一个字符串，在 HTML 里不再是结束标签。

手写的话：

```python
safe = (json.dumps(q, ensure_ascii=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026"))
```

**二、别把数据塞进内联 `<script>`。**

更好的做法是把数据放在一个 `data-*` 属性或者 `<template>` 里，
用 `|tojson` 输出到属性值里（那里 HTML 转义就够了），再由 JS 读出来。

或者干脆用接口拿：

```html
<div id="app" data-query="{{ q | e }}"></div>
<script>var q = document.getElementById("app").dataset.query;</script>
```

`|e`（HTML 转义）在这里**是对的** —— 因为上下文是 HTML 属性。

**三、注意 `</script` 还要考虑大小写和空格。**

HTML 解析器识别 `</script` 时：大小写不敏感，而且 `</script foo>` 也算。
所以如果你要自己做过滤，得按 HTML 的词法规则做，不是按你以为的那个字符串。

—— 这一条本身就是在说明"别自己做过滤"。

**四、CSP 兜底。**

```
Content-Security-Policy: script-src 'self' 'nonce-xxx'
```

一个不带 `unsafe-inline` 的严格 CSP 能直接废掉内联 `<script>` 和注入的标签。

## 顺手想想

- 如果服务端用的是 `html.escape(q)`（把 `<` 转成 `&lt;`）再嵌进 `script`，
  这一题还成立吗？为什么？
- 如果那个值是嵌在**单引号**的 JS 字符串里（`var q = '<你的输入>';`），
  而服务端只转义了双引号呢？payload 要改成什么？
- 如果服务端用的是 `|tojson`，还有别的路吗？
  （提示：`tojson` 处理的是 `<`，那 `\u2028` 呢？现代浏览器还怕它吗？）
- 为什么说"这一题跟 XSS 的类型无关"？
  （提示：它既不是反射型也不是存储型 —— 它是**上下文**问题）
