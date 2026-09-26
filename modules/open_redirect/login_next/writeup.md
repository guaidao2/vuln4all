# 登录跳转处的开放重定向

## 这一题在教什么

**「跳到哪里」是一个信任动作。**

受害者看到的是自家域名下的链接，点下去却到了攻击者的站点。这个洞本身不泄露数据，
但它是**钓鱼的放大器**，而且经常和 OAuth / SSO 的 `redirect_uri` 校验一起出现 ——
那才是真正能拿走 token 的场景。

这一题的看点是那层校验：**写得很认真，但两条规则各有一个漏洞。**

## 漏洞在哪

`module.py`：

```python
def looks_internal(next_url):
    if next_url.startswith("/"):       # 规则一
        return True
    if OWN_HOST in next_url:           # 规则二
        return True
    return False
```

两条都在"拦截"那一侧。要打的东西就是：**有没有写法能同时满足某一条规则、又不是站内？**

## 绕法一：协议相对 URL

```
next=//evil.example/
```

它**以 `/` 开头**，所以规则一说"这是站内相对路径"。

但 `//host/path` 不是路径 —— 它是**协议相对 URL**：省略了协议，浏览器会补上
当前页面的协议（`http` 或 `https`），然后跳到 `evil.example`。

```
// 开头的不是「路径」，是「省略了协议的主机」
```

验证：

```bash
curl -i -X POST -d 'user=alice&password=alice123' \
     --data-urlencode 'next=//evil.example/' '<登录地址>'
# 看 Location 头
```

## 绕法二：子串匹配，没做域名边界检查

```
next=https://vuln4all.local.evil.example/
```

它"提到了"自家域名，所以规则二放行。

**但域名是从右往左读的。** 最右边那段才是顶级域：

| 域名 | 谁拥有它 |
|---|---|
| `partner.example` | `example` 这个顶级域下的 `partner` |
| `vuln4all.local.evil.example` | **`evil.example`** 下的 `vuln4all.local` |

两个串完全不同，但 `"vuln4all.local" in "vuln4all.local.evil.example"` 是 `True`。

> 这个坑跟 `cors/credentials` 和 `ssrf` 那两道是同一类的：
> **凡是用"字符串里有没有"来判断"域名是不是我的"，都是错的。**
> 域名必须**解析**出来，然后按段（或者干脆整串精确）比较。

## 还有哪些畸形写法值得试

这一题的解法里列了一批。它们的实际效果**取决于浏览器**：

```
//evil.example/
///evil.example/
////evil.example/
https://evil.example/
https:/evil.example/                    浏览器会补上缺的斜杠
https:///evil.example/                  同上
\\evil.example/                         有些浏览器把 \ 当 / 处理
https://vuln4all.local@evil.example/    @ 前面是用户信息，后面才是主机
https://evil.example#vuln4all.local     用 fragment 骗字符串检查
https://evil.example/?vuln4all.local
%09//evil.example/                      前面加个空白
```

**这正是开放重定向这个洞的特点：能不能打，由客户端决定。**

所以修的时候思路要反过来 —— 不要问"哪种写法能绕过我的校验"，
而要问"**我要不要允许自定义跳转目标**"：

- 如果不需要 → 直接砍掉这个功能，或者只允许一个固定列表（`/home`、`/settings`）
- 如果需要 → 用**白名单路径**，而不是"判断目标是不是站外"

## 怎么修

**一、白名单，而不是黑名单。**

```python
ALLOWED_PATHS = {"/home", "/settings", "/orders"}

next_url = request.form.get("next", "/home")
if next_url not in ALLOWED_PATHS:
    next_url = "/home"
```

注意这是**精确匹配**。不要写成 `if next_url.startswith("/")`。

**二、如果一定要支持任意站内路径，就用"解析 + 校验"：**

```python
from urllib.parse import urlsplit

def safe_next(next_url, default="/home"):
    if not next_url:
        return default
    # 必须是以单个 / 开头的**绝对路径**
    if not next_url.startswith("/") or next_url.startswith("//"):
        return default
    if "\\" in next_url or next_url.startswith("/\\"):
        return default
    parts = urlsplit(next_url)
    # 解析之后不该有 scheme、不该有 netloc
    if parts.scheme or parts.netloc:
        return default
    return next_url
```

关键在于**解析之后再看**：`urlsplit("//evil.example/")` 的 `netloc` 是 `evil.example`，
所以它会被挡掉。而靠 `startswith("/")` 是挡不住的。

**三、别用"跳转"来实现"回到原页面"，用会话里的记录。**

登录前把用户想去的页面记在服务端 session 里：

```python
session["after_login"] = request.path        # 只记路径，不记完整 URL
# 登录成功后
return redirect(session.pop("after_login", "/home"))
```

这样 `next` 根本不从客户端来 —— 整个漏洞类别消失。这是最干净的做法。

**四、注意它和其他洞的组合。**

开放重定向最常见的真实危害是配合别的：

- **OAuth / SSO**：`redirect_uri` 校验不严 → 授权码被送到攻击者那里
- **SSRF**：服务端"跟跳转"时，"开放重定向"就是一个把请求引到内网的跳板
- **钓鱼**：自家域名下的链接可信度远高于陌生的域名

所以它单独看是低危，组合起来经常是中高危。

## 顺手想想

- 如果登录页在 `https://` 下，`next=//evil.example/` 会跳到 `https://evil.example/`
  还是 `http://`？为什么？
- `next=/\evil.example/`（反斜杠）在 Chrome 和 Firefox 里行为一样吗？
  这对"修漏洞"意味着什么？
- 如果开放重定向的目标站本身还有个开放重定向，能绕过一个"白名单"吗？
- OAuth 的 `redirect_uri` 校验如果用"`startswith` 且没做完整匹配"，
  攻击者能怎么利用？（提示：`https://client.example` vs `https://client.example.evil`）
