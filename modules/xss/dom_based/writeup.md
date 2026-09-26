# 欢迎页里的 DOM 型 XSS

## 这一题在教什么

**有些 XSS 在响应体里一个字都看不到。**

反射型你会 curl 一下、在返回的 HTML 里找到 payload、然后确认。
这一题不一样：服务端**完全不碰**你给的那段字符串，是浏览器上的 JS
自己从地址栏读出来、用 `innerHTML` 拼进页面的。

所以这一题真正教的是一件事：**看响应体判断不了 XSS，得读前端代码。**

（也正因为如此，DOM 型 XSS 特别容易在代码审计、WAF 规则、访问日志里被漏掉 ——
服务端这边从头到尾看不到任何异常。）

## 漏洞在哪

页面里的那段 JS：

```js
var raw = "";
if (location.hash.length > 1) {
  raw = decodeURIComponent(location.hash.slice(1));
} else {
  raw = new URLSearchParams(location.search).get("name") || "";
}
document.getElementById("greet").innerHTML = "你好，" + raw + "！";
```

两个地方合起来才是洞：

1. **输入来自哪里**：`location.hash` / `location.search` —— 攻击者能完全控制
2. **结果放进了什么**：`innerHTML` —— 它会把字符串当 HTML 解析，标签会被创建出来

把 `innerHTML` 换成 `textContent`，这一题就没了 —— 因为 `textContent` 只当文本。

## 怎么打通

payload 直接给在地址栏：

```
?name=<img src=x onerror=alert(1)>
#<img src=x onerror=alert(1)>
```

两种都能触发。区别只在于**服务端看不看得见**：

| 形式 | 会发给服务器吗 | 服务器日志里能看到吗 |
|---|---|---|
| `?name=...` | 会 | 会 |
| `#...`（fragment） | **不会** | 看不到 |

fragment 从来不会离开浏览器。所以用 `#` 的时候，服务端连"你带了 payload"都不知道。

> 这一题两种写法都能记上进度。`#` 那条路是靠**页面里的 JS 自己回报一句**
> 实现的 —— 真实网站当然不会有这种回报通路，所以真实环境里
> fragment 型的 DOM XSS 在服务端**完全没有痕迹**。这正是它难查的原因，
> 也是为什么这一题的判定不能只靠"看服务端收到了什么"。

## 怎么确认它真的执行了

页面上有个面板会告诉你"响应体里有没有你给的那段字符串"。答案是**没有**。

你也可以自己验：

```bash
curl -s 'http://<靶场>/v/xss/dom_based/?name=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E' | grep -c 'onerror'
# 0
```

响应里没有，但浏览器里弹窗了。差别在于：那段 HTML 是**浏览器自己造出来的**，
不是服务器发过来的。

## DOM 型 XSS 的其他常见位置

`innerHTML` 只是最经典的一个。同一个套路还有：

```js
element.outerHTML = userInput
element.insertAdjacentHTML("beforeend", userInput)
document.write(userInput)
eval(userInput)
setTimeout(userInput, 100)          // 传字符串的时候会当代码执行
new Function(userInput)
$(selector).html(userInput)          // jQuery 的 .html() 等价于 innerHTML
location.href = userInput            // 这个是 open redirect / javascript: 协议
```

**输入的来源**也一样重要：`location.hash` / `location.search` / `location.pathname` /
`document.referrer` / `window.name` / `postMessage` 的数据 / 本地存储。
后两个尤其要小心 —— 它们能让 payload 完全不出现在 URL 里。

## 怎么修

**一、能用 `textContent` 就别用 `innerHTML`。**

```js
document.getElementById("greet").textContent = "你好，" + raw + "！";
```

**二、真要插 HTML，先净化。**

```js
import DOMPurify from "dompurify";
element.innerHTML = DOMPurify.sanitize(userInput);
```

自己写正则过滤 HTML 是绕过的重灾区（`<svg>`、`<math>`、属性里的编码、
标签解析器的各种边缘行为），别自己造。

**三、注意"前端过滤"靠不住。**

一个很常见的错法：在赋值前用 JS 把 `<script>` 替换掉。这挡不住
`<img onerror>`、`<svg onload>`、以及各种编码变体。

**四、服务端依然要有防线。**

就算这个 XSS 完全发生在浏览器里，服务端还能做两件有价值的事：

- `SESSION_COOKIE_HTTPONLY = True` —— XSS 读不到 session cookie（但读得到页面内容）
- `Content-Security-Policy` —— 限制脚本来源，能大幅削弱 XSS 的威力

CSP 对 DOM 型 XSS 尤其有用，因为它拦的是"执行"这一步，不管 payload 从哪来的。

## 顺手想想

- 如果这段 JS 用的是 `location.pathname`，payload 会长什么样？
  （提示：路径里的某些字符会被浏览器先解码）
- `textContent` 一定安全吗？想想它被放进 `<script>` 标签里会怎样。
- 为什么浏览器要把 fragment 留在客户端？（历史原因是什么，副作用是什么）
- 如果一个站点所有输入都做了服务端转义，DOM 型 XSS 还存在吗？
