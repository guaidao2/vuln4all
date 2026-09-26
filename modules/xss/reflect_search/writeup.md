# 搜索框的反射型 XSS

## 这一题在教什么

「转义 / 编码」这四个字，看文档很容易懂、上手很容易懵。这题就是让你亲手看到：

**用户输入被当成代码解析，和被当成文字显示，差别到底有多大。**

「反射型」的意思是：payload 不落库，就在你这次请求的响应里原样弹回来。

## 漏洞在哪

`templates/search.html`：

```jinja
<p>你搜索的内容：{{ keyword | safe }}</p>
```

关键是那个 `|safe`。Jinja2 **默认会自动转义**，正常写 `{{ keyword }}` 的话，
你输入的 `<` 会被转成 `&lt;`，浏览器就只会把它当普通文字。

`|safe` 明确告诉 Jinja「这段别动，原样输出」—— 保护就这么没了。

同一件事在别的栈里长这样：

| 栈 | 默认安全吗 | 危险写法 |
|---|---|---|
| Jinja2 / Flask | 安全（自动转义） | `\|safe`、`Markup()` |
| Django 模板 | 安全（自动转义） | `\|safe`、`mark_safe()` |
| PHP | 不安全 | 直接 `echo $_GET['q']` |
| 前端 JS | 不安全 | `innerHTML = q` |

## 怎么打通

**第一步，先确认标签真的能生效**（这一步是无害的，但很重要）：

```
<b>hello</b>
```

页面上「hello」变成了粗体 —— 说明你写的标签被浏览器当成标签解析了。

**第二步，换成能执行代码的东西**：

```
<script>alert(document.cookie)</script>
```

弹框出来就是通了。

有些浏览器会拦地址栏里带的脚本，换这个一定行：

```
<img src=x onerror=alert(document.cookie)>
```

## 为什么这里有洞很严重

现在弹的是 `document.cookie`，看着像玩具。但在真实场景里，攻击者能做的是：

- 偷走你的 session cookie，直接冒充你登录
- 在页面里插一个假登录框，把你的密码骗走
- 用你的身份发请求（CSRF 不用另找路子了，XSS 比它强）

**XSS 通常比 CSRF 更严重，因为它能读页面内容、能读 cookie（非 HttpOnly 的）。**

## 怎么修

回到默认：**别用 `|safe`**。

```jinja
<p>你搜索的内容：{{ keyword }}</p>
```

如果确实需要输出 HTML（比如富文本），就必须**先做 HTML 净化**，
用白名单过滤标签和属性，而不是自己写正则：

```python
import bleach

cleaned = bleach.clean(
    user_html,
    tags=["b", "i", "u", "p", "br", "a"],
    attributes={"a": ["href"]},
)
```

配套的纵深防御：

1. `SESSION_COOKIE_HTTPONLY = True`（这题已经开了）—— 让 JS 读不到 session cookie。
   注意：HttpOnly 只能挡住「偷 cookie」，挡不住 XSS 本身。
2. `Content-Security-Policy` 响应头 —— 能大幅降低 XSS 的危害，但配起来容易出错，
   当补充手段用。
3. 输出到什么上下文，就用什么上下文的转义：HTML 里、属性里、`<script>` 里、
   CSS 里、URL 里，规则都不一样。

## 顺手想想

- 如果输入不是反射到 HTML 里，而是反射到 `<script>var q = "..."</script>` 里面，
  `<script>alert(1)</script>` 还有用吗？你会怎么写？
- 「存储型 XSS」和这题差在哪？为什么它更危险？
- 如果表单是 `<input value="{{ keyword }}">`，转义规则和 `<p>` 里一样吗？
  （提示：属性值、引号闭合）
