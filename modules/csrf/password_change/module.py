"""个人中心改密码处的 CSRF —— 一道题里有两个站点。

受害者站：需要登录才能用的个人中心，改密码接口只看 session，不看请求从哪来。
攻击者站：一个"恶意页面"，你一旦打开它，它就用**你的浏览器**去提交改密码请求。

这是 vuln4all 里第一个用多挂载点的题目，也是用来压测契约的那一道。
"""

import sqlite3

from vuln4all import Vuln, redirect, render_template, request, session, url_for

EVIL_PASSWORD = "pwned-by-csrf"


class PasswordChange(Vuln):
    info = {
        "name": "改密码处的 CSRF",
        "author": ["vuln4all"],
        "cwe": "CWE-352",
        "owasp": "A01:2021 - Broken Access Control",
        "description": (
            "这题有两个站点：一个是需要登录的个人中心，一个是攻击者放的恶意页面。"
            "个人中心的「改密码」接口完全不看请求是从哪来的 —— 只要浏览器带着你的 "
            "session cookie 过来，它就照改不误。"
        ),
        "hint": (
            "先用 bob / password123 登进个人中心，确认能改自己的密码。"
            "然后退出登录状态看看：改密码的请求里，除了 session cookie，"
            "服务端还凭什么判断'这是本人主动发起的'？如果什么都不看，"
            "那让别人替你发这个请求就行了。"
        ),
        "solution": (
            "1. 打开个人中心（主入口），用 bob / password123 登录。\n"
            "2. 打开攻击者站点 /evil-site/ —— 页面会自动向个人中心提交一个改密码请求。\n"
            "3. 回到个人中心，你就成了「密码被改但自己没动过手」。\n"
            "   新密码是 %s，旧密码已经不好使了。\n\n"
            "原理：改密码接口只检查 session，不检查请求来源。浏览器带着受害者站的 "
            "cookie 发请求，服务端就认为是本人在操作。\n"
            "注意：这里 SameSite=Lax 也挡不住，因为两个站点在同一个 host 下，"
            "对浏览器来说属于同一个 site。" % EVIL_PASSWORD
        ),
        "refs": [
            "https://owasp.org/www-community/attacks/csrf",
            "https://portswigger.net/web-security/csrf",
        ],
        # 第二个入口挂在 /evil-site/，而不是默认的 /v/csrf/password_change/attacker/。
        # 这是为了更像"另一个站点"，顺便演示 info["mounts"] 的用法。
        "mounts": {"attacker": {"path": "/evil-site"}},
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / "portal.db"))
        con.executescript(
            """
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            );
            INSERT INTO users (username, password) VALUES
                ('bob',   'password123'),
                ('alice', 'alice-secret');
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        portal = ctx.flask(__name__)
        evil = ctx.flask(__name__, mount="attacker")
        db_path = str(ctx.workspace / "portal.db")

        def password_of(username):
            con = sqlite3.connect(db_path)
            try:
                row = con.execute(
                    "SELECT password FROM users WHERE username = ?", (username,)
                ).fetchone()
                return row[0] if row else None
            finally:
                con.close()

        def set_password(username, new_password):
            con = sqlite3.connect(db_path)
            try:
                con.execute(
                    "UPDATE users SET password = ? WHERE username = ?",
                    (new_password, username),
                )
                con.commit()
            finally:
                con.close()

        # ------------------------------------------------------ 受害者站

        @portal.route("/")
        def index():
            if session.get("user"):
                return redirect(url_for("profile"))
            return render_template("portal_login.html", error=None)

        @portal.route("/login", methods=["POST"])
        def login():
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if password_of(username) == password:
                session["user"] = username
                return redirect(url_for("profile"))
            return render_template("portal_login.html", error="用户名或密码不对")

        @portal.route("/profile")
        def profile():
            if not session.get("user"):
                return redirect(url_for("index"))
            notice = session.pop("notice", None)
            return render_template(
                "portal_profile.html",
                user=session["user"],
                notice=notice,
                evil_url=ctx.url("attacker", "/"),
            )

        @portal.route("/change-password", methods=["POST"])
        def change_password():
            # ↓↓↓ 洞在这里：只看 session，不看 CSRF token，也不看 Referer/Origin ↓↓↓
            if not session.get("user"):
                return redirect(url_for("index"))

            new_password = request.form.get("new_password", "")
            if not new_password:
                session["notice"] = "新密码不能为空"
            else:
                set_password(session["user"], new_password)
                session["notice"] = "密码已经改成：%s" % new_password
            return redirect(url_for("profile"))

        @portal.route("/logout")
        def logout():
            session.clear()
            return redirect(url_for("index"))

        # ------------------------------------------------------ 攻击者站

        @evil.route("/")
        def evil_index():
            return render_template(
                "evil_index.html",
                # 跨挂载点的链接必须走 ctx.url()，不能手写路径
                victim_url=ctx.url("", "/profile"),
                target=ctx.url("", "/change-password"),
                evil_password=EVIL_PASSWORD,
            )

        return {"": portal, "attacker": evil}
