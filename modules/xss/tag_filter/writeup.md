# 带标签过滤的 XSS（删除式）

## 这一题在教什么

过滤器分两类，绕过思路**完全不同**：

| | 拦截（block） | 删除（strip） |
|---|---|---|
| 做法 | 命中就不执行 | 把命中的片段剪掉，剩下的照常存/渲染 |
| 目标 | 让规则**匹配不到** | 让剪完之后**又拼回来** |
| 危险程度 | 中 | **高**——删除是可逆的 |
| 例子 | `sqli/keyword_filter` | 这一题 |

**"删除"比"拦截"危险得多**，因为攻击者可以构造"删掉之后正好拼出危险内容"
的输入。这一题的两个解法都建立在这上面。

## 过滤层

`module.py`：

```python
RULES = [
    ("script 标签",  r"(?is)<\s*/?\s*script[^>]*>"),
    ("img 标签",     r"(?is)<\s*img[^>]*>"),
    ("svg 标签",     r"(?is)<\s*svg[^>]*>"),
    ("脚本伪协议",   r"(?is)(javascript|vbscript|data)\s*:"),
    ("常见弹窗函数", r"(?is)\b(alert|confirm|prompt)\b"),
]
```

页面上会把「删前 / 删后」都打给你看 —— 这就是这一题最有价值的反馈。

先确认它的性质：写 `<script>fetch('/')</script>` 进去，删完什么都不剩。
所以它是**删除**，不是拦截。

## 解法一：嵌套写法（让它自己把标签拼回来）

```
<scr<script>ipt>fetch('/')</scr</script>ipt>
```

规则删的是 `<script ...>` 这个**整体**。把输入拆开看：

```
<scr | <script> | ipt>          删掉中间 → <script>
</scr | </script> | ipt>        删掉中间 → </script>
```

删完剩下：

```html
<script>fetch('/')</script>
```

完美闭合。浏览器拿到的是一个真正的 script 标签。

**为什么这招管用**：过滤器用的是"匹配 → 删除"，而删除改变了字符串的
**结构**。它删掉的那一段，恰好是让两边接起来变成危险内容的那一段。

> 这个手法对所有 `re.sub` / `replace` / `strip_tags` 式的过滤器都成立。
> 早年 `PHP` 的 `strip_tags()` 和很多语言的"HTML 净化"函数都栽在这里。
> 正确的做法是**解析**（真的按 HTML 语法建树），而不是**替换**。

## 解法二：换一层（让浏览器再解析一次）

```
<iframe srcdoc="&lt;svg/onload=fetch('/')&gt;"></iframe>
```

`srcdoc` 属性的值会被浏览器**当成一段独立 HTML 再解析一遍**。
所以实体编码在它里面会被解码成真正的标签。

过滤器看到的是什么？一个实体编码的字符串：

| 规则 | 命中吗 | 为什么 |
|---|---|---|
| `script 标签` | 没有 | 文本里没有 `<script`，只有 `&lt;svg` |
| `img` / `svg` 标签 | 没有 | 文本里没有字面的 `<svg` |
| 脚本伪协议 | 没有 | 没有 `javascript:` |
| 常见弹窗函数 | 没有 | 用的是 `fetch`，不是 `alert` / `confirm` / `prompt` |

所以它一字不动地放行。**渲染**这一步才把 `&lt;` 解成 `<`、把整段当成
HTML 解析，`<svg onload=...>` 才真正出现并执行。

**这一招教的是**：过滤器的检测和输出的解析**不是同一个上下文**。
过滤器看的是"字符串长什么样"，浏览器看的是"这段字符串会被解析成什么"。
两者的差距就是绕过空间。

同类容器还有：

```html
<object data="data:text/html,<svg onload=...>">
<embed src="data:text/html,<svg onload=...>">
<meta http-equiv="refresh" content="0;url=data:text/html,<svg onload=...>">
<iframe srcdoc="&lt;script&gt;...&lt;/script&gt;">
```

## 解法三：找一个它压根没想到的标签

过滤器只列了 `script` / `img` / `svg` 三个标签，以及事件处理器、脚本伪协议、弹窗函数。

`<video>` 它没列。而 `<video>` 里的 `<source>` 支持 `onerror`：

```html
<video><source onerror=fetch('/')></video>
```

过滤器**一条规则都不命中** —— 没有 `script`/`img`/`svg` 标签，没有脚本伪协议，
用的是 `fetch` 不是弹窗函数。

> 这条是实测跑出来的：把一批真实 XSS 向量逐个喂给过滤器，
> `<video><source onerror=...>` 的命中列表是空的 —— 过滤器完全没看到它。
>
> **这就是黑名单的本质**：你没法枚举"所有能执行 JS 的标签和属性"，
> 因为这份清单是浏览器实现的全部历史累积，而且还在变。

## 判定用的检测器（这一题的设计说明）

`module.py` 里有一个 `EXECUTABLE` 正则和一个 `looks_executable()`。
它们**故意跟 `RULES` 完全独立**，而且比 `RULES` 严格。

原因很简单：这一题要判的是"过滤器有没有被绕过"。如果判定复用过滤器自己的
逻辑，那过滤器漏掉的东西判定也会一起漏掉 —— 那就成自证清白了。

`looks_executable()` 会看两种形态：原文，以及 `html.unescape()` 之后的样子。
后者是为了接住 srcdoc 那类"编码起来塞进容器"的绕过 —— 它们在原文里
确实没有可执行标记，解码之后才有。

**检测器的每一条都要求标记出现在真实的标签 / 属性上下文里。**
这不是随手写的，是踩出来的：最早的版本只写 `on\w+\s*=`，结果纯文本
`onerror= 只是文字` 也被判成可执行 —— 学习者随便打一行字就"通关"了。

```python
# 错的：只看几个字符
r"on\w+\s*=\s*[^\s>]"

# 对的：要求它在一个标签的属性位置上
r"<\s*[a-z][^>]*?[\s/]on\w+\s*=\s*[^\s>]"
```

**这个细节本身就是一课**：判别"这算不算攻击"的时候，
"字符串里有没有某个子串"几乎总是错的答案 —— 你得看**结构**。
（跟 `sqli/keyword_filter` 那条 `union select` 规则是同一个道理。）

## 怎么修

**一、输出时按上下文转义，别做输入净化。**

这一题只要把 `|safe` 去掉就没了：

```jinja
<p>{{ r['body'] }}</p>
```

**二、真想允许一部分 HTML，用解析式的净化库，别自己写正则。**

```python
import bleach

bleach.clean(user_html, tags=["b", "i", "u", "a"], attributes={"a": ["href"]})
```

`bleach` 是**先解析成树再按白名单删节点**，所以"剪掉中间一段"这类
攻击对它无效 —— 因为节点已经被正确解析出来了，不存在"接起来"的机会。

**三、别用 `re.sub` 做安全过滤。** 这是这一题的根因。三个理由：

1. 删除可逆（解法一）
2. 字符串检测和上下文解析脱节（解法二）
3. HTML 的语法太复杂（属性、注释、CDATA、异常闭合），正则描述不了

**四、CSP 兜底。**

```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

注意 `script-src` 要**加上 `'unsafe-inline'` 才能执行内联脚本**，
所以一个严格的 CSP 能直接废掉 `<script>` 和 `<svg onload>`。
但要注意 `unsafe-eval`、`nonce` 泄漏、以及 JSONP 端点这些绕过面。

## 顺手想想

- 如果过滤器改用"先解析再白名单"（bleach 那套），解法一还成立吗？为什么？
- 解法二靠的是"浏览器再解析一次"。还有哪些地方会二次解析？
  （提示：`<template>`、`innerHTML` 赋值、`document.write`、`<noscript>`）
- 这一题的判定检测器认 5 类可执行标记。如果学习者用一个**没被列出**的
  向量打通了（比如纯 CSS 的 `expression()`，或者 `<form><button formaction=javascript:...>`），
  会怎样？这是不是判定写得太窄了？
- 为什么"把所有危险标签都加进黑名单"永远做不完？
