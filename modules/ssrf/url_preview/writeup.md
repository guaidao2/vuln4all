# 链接预览处的 SSRF

## 这一题在教什么

SSRF 的本质是**信任边界被绕过**：

> 服务端有一堆「只有它自己够得着」的资源。只要能让它替你发请求，
> 那些资源就通过它暴露给了你。

这一题还顺带教你**白名单校验怎么被绕过** —— 这是 SSRF 真正难的部分，
「有没有 SSRF」很容易看，难的是「校验写得对不对」。

## 这道题的结构

| 挂载点 | 路径 | 是什么 |
|---|---|---|
| 主入口 | `/v/ssrf/url_preview/` | 聊天应用，带一个有洞的抓取功能 |
| 内网后台 | `/internal-admin/` | 只接受来自 `127.0.0.1` 的请求，不在清单页上 |

内网后台的防护是 `if request.remote_addr not in ("127.0.0.1", "::1"): 403`。
**这个防护本身没问题** —— 它模仿的是真实的网络隔离（只监听回环、或防火墙只放本网段）。
问题在于：服务器**自己**发起的请求，`remote_addr` 就是 `127.0.0.1`。

## 漏洞在哪

`module.py`：

```python
if ALLOW_TOKEN not in url:          # ALLOW_TOKEN = "img.vuln4all.local"
    error = "只允许抓取 %s 上的图片"
```

**它检查的是整串 URL 里有没有这个子串，根本没去解析 host。**

然后抓取那一侧才真正解析 URL（模块里用 `urlsplit` + `http.client`，
和 `requests` / `curl` 的行为一致：`@` 前面是 userinfo，`@` 后面才是主机）。
**校验时和连接时对同一个 URL 的理解不一致，就是漏洞。**

> 顺带一句值得记住的细节：Python 的 `urllib.request` 其实**不**会剥离 userinfo ——
> 它会把 `a@b` 整串当主机名拿去解析，和浏览器/curl 的行为不一样。
> 所以这种绕过能不能成，取决于目标用的是哪个 HTTP 客户端。
> 手搓客户端时尤其要注意「校验用什么解析、连接用什么解析」必须一致。

## 怎么打通

```
http://img.vuln4all.local@127.0.0.1:8800/internal-admin/
                          ^^^^^^^^^^^^^ 真正被连接的主机
```

URL 的结构是 `scheme://userinfo@host:port/path`。`@` 前面是**用户名**，
`@` 后面才是**主机**。

- 校验代码：整串里有 `img.vuln4all.local` → 放行
- urllib：连的是 `127.0.0.1:8800` → 打到内网后台

页面上的「服务端解析出的主机」会实时告诉你 `parsed_host` 是什么，
方便你对答案。

端口用你地址栏里的那个。

## 同类绕过（换个目标都用得上）

```
http://2130706433/            127.0.0.1 的十进制整数形式
http://0x7f000001/            十六进制
http://017700000001/          八进制
http://127.1/                 省略写法
http://[::1]/                 IPv6 回环
http://127.0.0.1.nip.io/      DNS 通配解析
http://allowed.com#@evil.com  用 fragment 截断（有些解析器会看错）
http://evil.com/allowed.com   把白名单串塞进路径
http://allowed.com.evil.com   子域名后缀混淆
```

**还有一类跟 URL 写法无关的绕过：**

- **跳转绕过**：白名单域名上放一个 302 跳到你想要的地址。所以抓取必须禁跳转。
- **DNS 重绑定**：第一次解析返回合法 IP 通过校验，第二次解析返回 `127.0.0.1`。
  所以校验和连接必须用**同一个**已解析的 IP。

## 怎么修

**第一步：真正解析，并且精确比较。**

```python
from urllib.parse import urlsplit

parsed = urlsplit(url)
if parsed.scheme not in ("http", "https"):
    abort(400)
host = (parsed.hostname or "").lower().rstrip(".")
if host not in ALLOWED_HOSTS:          # 精确集合，不是子串
    abort(400)
```

注意 `parsed.hostname` 会把 userinfo 剥掉、把 `2130706433` 归一化吗？**不会全部归一化** ——
所以还得往下走。

**第二步：解析到 IP 之后再检查，并且用这个 IP 去连**（防 DNS 重绑定）：

```python
import ipaddress, socket

ip = ipaddress.ip_address(socket.gethostbyname(host))
if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
    abort(400)
# 然后用这个 ip 去建连接（或者用能锁住已解析 IP 的客户端配置）
```

**第三步：禁跳转。**

```python
# requests: allow_redirects=False
# urllib: 自定义 HTTPRedirectHandler 直接抛错
```

**第四步（最狠，也最靠谱）：网络层隔离。**

- 抓取服务单独跑，放在一个**没有内网路由**的网段/容器里
- 出站只允许白名单 IP 和端口，其余全 drop
- 云环境里 `169.254.169.254` 强制 IMDSv2

**应用层校验永远会漏，网络层隔离才是兜底。**

## 顺手想想

- 如果抓取功能只返回「是不是图片」这个布尔值，没有回显内容，SSRF 还能用吗？
  （提示：盲 SSRF、时间盲注、带外）
- 如果目标只能是 `http://`，危害会小多少？
- `request.remote_addr` 在反向代理后面会是什么？这对「只允许本机」的判定有什么影响？
