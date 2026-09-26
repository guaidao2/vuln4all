"""JWT 的 `kid` 头注入。

业务场景是"多密钥轮换的开放 API"：为了能平滑换密钥，签名密钥按名字存在
一个目录里，token 头部的 `kid` 字段告诉服务端"用哪一把"。

这个设计本身是合理的（真实系统都这么干）。坑在实现上：
**`kid` 被直接当成了文件路径**，没有做任何规范化。

于是攻击者可以让服务端去读一个**内容已知**的文件当密钥 —— 最经典的目标是
`/dev/null`（内容恒为空）。密钥一旦已知，"验签"就形同虚设。

这跟 `jwt/alg_none` 是同一类问题的两个不同面：
  · 那道题：验签算法从 token 自己声明的 `alg` 里读
  · 这一题：验签**密钥**从 token 自己声明的 `kid` 里推
共同点：**安全决策的参数不该由被验证的对象自己提供。**
"""

import base64
import hashlib
import hmac
import json
import os

from vuln4all import Vuln, jsonify, render_template, request

KEY_DIR = "keys"

#: 轮换中的密钥。名字就是 kid。
ACTIVE_KID = "rotate-2026.key"
ACTIVE_SECRET = b"k-2026-8f31ac47b0e2d95c"

GOAL = "伪造一个 role=admin 的 token 并通过鉴权"

#: 判定用的标记。只有 admin 才看得到。
ADMIN_MARKER = "ADMIN-AREA-7c4f"

#: 普通账号，用来让做题的人看到 token 长什么样。
USERS = {"alice": ("alice123", "user"), "carol": ("carol123", "user")}


# ------------------------------------------------------------------ JWT 工具
#
# 手搓的，不引入额外依赖 —— 这样 token 的每个字节都是看得见的。
def b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64d(text):
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def sign(header, payload, key):
    head = b64e(json.dumps(header, separators=(",", ":")).encode())
    body = b64e(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = ("%s.%s" % (head, body)).encode()
    mac = hmac.new(key, signing_input, hashlib.sha256).digest()
    return "%s.%s.%s" % (head, body, b64e(mac))


def load_key(base, kid):
    """按 kid 从密钥目录里取签名密钥。

    `base` 是密钥目录的**绝对路径**，必须传进来 —— 见 verify() 的说明。

    ↓↓↓ 洞就在这里 ↓↓↓

    `kid` 直接当成了路径。没有做任何规范化，也没要求它必须是目录里的普通文件名。

    ↑↑↑ 正确做法：
        1. `kid` 必须先在白名单里（或者只能匹配 `[A-Za-z0-9_.-]+`）
        2. 拼完路径之后 resolve()，检查解析结果还在密钥目录里
        3. **更根本的**：密钥不该由 token 自己指定 ——
           服务端知道"当前活跃的密钥是哪一把"，让 token 只是标识、
           让服务端自己去查表，而不是让 token 决定去读哪个文件 ↑↑↑
    """
    path = os.path.join(base, kid)
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return None


def verify(token, base):
    """返回 (claims, error)。

    `base` 是密钥目录的绝对路径，**必须传进来，不能靠相对路径** ——
    相对路径是相对进程当前工作目录的，而 CWD 不一定是这道题的数据目录。
    （这一条是实测踩出来的：之前用相对的 \"keys\" 时，
    正常签发的 token 也一样验不过。）
    """
    if not token:
        return None, "没有 token"
    parts = token.split(".")
    if len(parts) != 3:
        return None, "token 不是三段"
    head_b64, body_b64, mac_b64 = parts
    try:
        header = json.loads(b64d(head_b64))
        payload = json.loads(b64d(body_b64))
    except Exception:  # noqa: BLE001
        return None, "头部或者载荷不是合法 base64/JSON"
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None, "头部和载荷都必须是 JSON 对象"

    if header.get("alg") != "HS256":
        return None, "只接受 HS256"

    # ↓↓↓ 密钥由 token 自己声明的 kid 决定 ↓↓↓
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        return None, "缺少 kid"
    key = load_key(base, kid)
    if key is None:
        return None, "kid 指向的密钥读不到：%s" % kid
    # ↑↑↑ ↑↑↑

    signing_input = ("%s.%s" % (head_b64, body_b64)).encode()
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    try:
        got = b64d(mac_b64)
    except Exception:  # noqa: BLE001
        return None, "签名不是合法 base64"
    if not hmac.compare_digest(expected, got):
        return None, "签名不对（用的 kid = %s）" % kid

    return payload, None


class KidInjection(Vuln):
    info = {
        "name": "JWT 的 kid 头注入",
        "author": ["guaidao2"],
        "cwe": "CWE-347",
        "owasp": "A02:2021 - Cryptographic Failures",
        "difficulty": "困难",
        "description": (
            "开放 API 用 JWT 鉴权。为了支持密钥轮换，token 头部的 `kid` "
            "字段告诉服务端「用哪一把密钥」。\n"
            "而服务端把 `kid` 直接当成了文件路径 —— "
            "于是可以让它去读一个**内容已知**的文件当密钥。"
        ),
        "hint": (
            "先登录拿一个正常的 token，把它按 `.` 拆成三段，每段做 base64url 解码：\n"
            "  python3 -c \"import base64,sys,json;\"\\\n"
            "    \"print(json.loads(base64.urlsafe_b64decode(sys.stdin.read()+'==')))\"\n"
            "看头部里有哪些字段 —— 其中一个告诉服务端「用哪把钥匙」。\n"
            "然后问关键的一句：**那个字段的值会被服务端拿去干什么？**\n"
            "（试试给它一个目录里不存在的名字，看看报错说了什么。）\n"
            "再往下想：如果那个值被当成**路径**用了，而路径可以指向**任何地方**……"
            "有没有哪个文件的内容是已知的、而且正好能当密钥用？"
        ),
        "solution": (
            "一、先看清 token。登录之后页面上会给出 token 原文，\n"
            "   把它拆成三段分别 base64url 解码。头部长这样：\n\n"
            "   {\"alg\": \"HS256\", \"typ\": \"JWT\", \"kid\": \"rotate-2026.key\"}\n\n"
            "   `kid` 就是「用哪把密钥」。\n\n"
            "二、确认它是被当路径用的：把 kid 改成一个不存在的名字，\n"
            "   报错会说「kid 指向的密钥读不到：xxx」—— 这就说明它在读文件。\n\n"
            "三、关键一步：找一个**内容为空、而且路径已知**的文件。\n"
            "   最经典的是 `/dev/null` —— 读出来永远是空字节串。\n\n"
            "   于是 `kid = \"/dev/null\"` 会让服务端用**空密钥**验签。\n"
            "   而空密钥是攻击者知道的，所以他能签出任意内容。\n\n"
            "四、用空密钥签一个 role=admin 的 token：\n\n"
            "   import base64, hashlib, hmac, json\n\n"
            "   def b64e(b):\n"
            "       return base64.urlsafe_b64encode(b).rstrip(b'=').decode()\n\n"
            "   header = {\"alg\": \"HS256\", \"typ\": \"JWT\", \"kid\": \"/dev/null\"}\n"
            "   payload = {\"user\": \"alice\", \"role\": \"admin\"}\n"
            "   head = b64e(json.dumps(header, separators=(',', ':')).encode())\n"
            "   body = b64e(json.dumps(payload, separators=(',', ':')).encode())\n"
            "   mac = hmac.new(b\"\", (head + '.' + body).encode(), hashlib.sha256).digest()\n"
            "   print(head + '.' + body + '.' + b64e(mac))\n\n"
            "五、拿这个 token 去调接口（页面上给了两种带 token 的方式）：\n\n"
            "   curl -H 'Authorization: Bearer <token>' <接口地址>\n\n"
            "   拿到 admin 数据就通关了。\n\n"
            "还能读哪些文件当密钥？（只要内容已知就行）\n"
            "  · /dev/null            内容恒为空 —— 最省事，密钥就是 b\"\"\n"
            "  · /proc/self/environ   内容你能猜到一部分？不行，但它能泄露信息\n"
            "  · ../../../etc/hostname  如果你知道主机名（常常是默认值）\n"
            "  · 一个你能写进去的文件（比如有上传功能、或者日志）\n"
            "  · 相对路径 `` 或者 `.`    读到目录 → 读失败\n"
            "  还有一类：**读到密钥目录里另一把你已经知道内容的密钥**\n"
            "  （轮换的时候旧密钥常常没删）。\n\n"
            "其他 `kid` 相关的变体：\n"
            "  · `kid` 直接当 SQL 查（`SELECT key FROM keys WHERE kid='...'`）→ SQL 注入\n"
            "  · `kid` 指向一个可预测的路径（/keys/1、/keys/2）→ 枚举到一把弱密钥\n"
            "  · `kid` 指向攻击者能上传的文件 → 自己写密钥\n\n"
            "这一题真正的教训（跟 `jwt/alg_none` 是一对）：\n"
            "  **安全决策的参数不该由被验证的对象自己提供。**\n"
            "  · `alg` 由 token 说 → 那就别信，只允许你配置的那一种\n"
            "  · `kid` 由 token 说 → 那就别拿它当路径，用它**查表**，\n"
            "    表里没有就用默认密钥（或者直接拒绝）\n"
            "  这两条合起来就是一句话：**验证方决定怎么验，不是被验证方。**"
        ),
        "refs": [
            "https://portswigger.net/web-security/jwt",
            "https://cwe.mitre.org/data/definitions/347.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        key_dir = ctx.workspace / KEY_DIR
        key_dir.mkdir(parents=True, exist_ok=True)
        (key_dir / ACTIVE_KID).write_bytes(ACTIVE_SECRET)
        # 轮换时留下的旧密钥 —— 真实环境里很常见，也是一个可以利用的点
        (key_dir / "rotate-2025.key").write_bytes(b"k-2025-retired-1a2b3c4d")

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        keys = str(ctx.workspace / KEY_DIR)

        @app.route("/")
        def index():
            return render_template(
                "index.html",
                token="",
                claims=None,
                error=None,
                result=None,
                active_kid=ACTIVE_KID,
                keys_dir=keys,
            )

        @app.route("/login", methods=["POST"])
        def login():
            user = request.form.get("user", "")
            password = request.form.get("password", "")
            record = USERS.get(user)
            if not record or record[0] != password:
                return render_template(
                    "index.html", token="", claims=None, error="用户名或密码不对",
                    result=None, active_kid=ACTIVE_KID, keys_dir=keys,
                )
            token = sign(
                {"alg": "HS256", "typ": "JWT", "kid": ACTIVE_KID},
                {"user": user, "role": record[1], "iat": 1772000000},
                ACTIVE_SECRET,
            )
            return render_template(
                "index.html", token=token, claims={"user": user, "role": record[1]},
                error=None, result=None, active_kid=ACTIVE_KID, keys_dir=keys,
            )

        @app.route("/api/me")
        def api_me():
            auth = request.headers.get("Authorization", "")
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            if not token:
                token = request.args.get("token", "")

            claims, error = verify(token, keys)
            if claims is None:
                return jsonify({"error": error}), 401

            is_admin = claims.get("role") == "admin"
            if is_admin:
                # 判定：一个自称 admin 的 token **通过了验签**
                ctx.progress.mark(GOAL)

            return jsonify(
                {
                    "user": claims.get("user"),
                    "role": claims.get("role"),
                    "data": (
                        {"admin_marker": ADMIN_MARKER, "users_total": 214}
                        if is_admin
                        else {"note": "普通用户只能看到自己"}
                    ),
                }
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
