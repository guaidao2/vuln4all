"""合作方接口的 CORS 配置错误。

业务场景是"给合作方站点提供一个只读接口"。为了让合作方的 JS 能读到数据，
接口在响应里加了 CORS 头。

两个错叠在一起：

  1. 白名单是**子串匹配**，没有做域名边界检查 ——
     所以 `https://partner.example.evil.example` 也被当成"合作方"
  2. 放行的时候把请求里的 Origin **原样反射**回去，并且带上了
     `Access-Control-Allow-Credentials: true`

第 2 条才是根本问题：**反射 Origin + 允许带凭据** = "谁来问都告诉它
'你可以带着用户的 Cookie 读这个响应'"。第 1 条只是让攻击者更容易凑出
一个能过白名单的 Origin。

说明一下验证方式：这个靶场是单进程单源，浏览器里构造不出真正的跨源请求，
所以这一题是用 `curl -H 'Origin: ...'` 看响应头来验证的 ——
这也正是你手工确认 CORS 配置时该用的办法。
"""

import re
import sqlite3
from urllib.parse import urlsplit

from vuln4all import Vuln, jsonify, make_response, render_template, request, session

DB_NAME = "partner.db"

#: 唯一合法的合作方源。注意它必须带协议，且没有结尾斜杠。
LEGIT_ORIGIN = "https://partner.example"

#: 开发写的"白名单"。这一题故意做成子串匹配。
ALLOWED = (LEGIT_ORIGIN,)

GOAL = "让服务端对一个不属于合作方的 Origin 回出「允许带凭据跨源读」"

USERS = {"alice": "alice123"}


class CorsCredentials(Vuln):
    info = {
        "name": "合作方接口的 CORS 配置错误",
        "author": ["guaidao2"],
        "cwe": "CWE-942",
        "owasp": "A01:2021 - Broken Access Control",
        "difficulty": "进阶",
        "description": (
            "只读接口为了让合作方的 JS 能读，加了 CORS 头。"
            "但它把请求里的 Origin 原样反射回去，还带上了"
            "`Access-Control-Allow-Credentials: true`。\n"
            "于是任何能凑出一个「看起来像合作方」的 Origin 的站点，"
            "都能带着受害者的 Cookie 读出这个接口的数据。"
        ),
        "hint": (
            "先登录，然后用 curl 看看接口对不同的 Origin 分别回什么头：\n"
            "  curl -i -H 'Origin: https://partner.example'      <接口地址>\n"
            "  curl -i -H 'Origin: https://evil.example'         <接口地址>\n"
            "然后想：白名单是怎么判断「这是不是合作方」的？\n"
            "如果它只检查「Origin 里有没有出现合作方的域名」，"
            "那你能构造出一个「含它、但不是它」的 Origin 吗？\n"
            "至于 cookies：浏览器什么时候会带着凭据发跨源请求？"
            "服务端要回什么头才允许 JS 读到响应体？"
        ),
        "solution": (
            "一、先看清楚它对不同 Origin 的反应：\n\n"
            "   curl -i -H 'Origin: https://evil.example' \\\n"
            "        -b 'session=...' 'http://<靶场>/v/cors/credentials/api/me'\n"
            "   会发现 evil.example 被拒（没有 CORS 头）。\n\n"
            "   换成合法合作方：\n"
            "   curl -i -H 'Origin: https://partner.example' ...\n"
            "   会发现它**把 Origin 原样反射**了，还带了\n"
            "   Access-Control-Allow-Credentials: true。\n\n"
            "二、找白名单的判断方式。把能过和不能过的 Origin 对比一下就知道：\n"
            "   它做的是**子串匹配**。那么构造一个「包含合作方域名、"
            "但不是合作方」的 Origin：\n\n"
            "   Origin: https://partner.example.evil.example\n\n"
            "   （域名是**从右往左**读的，最右边那段才是顶级域 ——"
            "   `partner.example.evil.example` 属于 evil.example，不属于 partner.example。）\n\n"
            "   服务端一样会把它反射回来 + 带上允许凭据的头。\n\n"
            "三、这时候浏览器会做什么（这一题的真正后果）：\n\n"
            "   攻击者站点 evil.example 上的 JS 里写：\n"
            "     fetch('http://<靶场>/v/cors/credentials/api/me',\n"
            "           {credentials: 'include'})\n"
            "       .then(r => r.text()).then(sendToAttacker)\n\n"
            "   浏览器带着受害者的 Cookie 发出去，服务端回了\n"
            "   `ACAO: https://partner.example.evil.example` +\n"
            "   `ACAC: true` —— 浏览器一看「这是我自己」，就把响应体交给 JS 了。\n"
            "   然后把读到的数据 POST 回攻击者服务器。\n\n"
            "   **两个头缺一不可**：\n"
            "     · 只有 ACAO 没有 ACAC → 浏览器拒绝带 Cookie，也拒绝把\n"
            "       响应交给 JS（匿名请求还是能读到公开数据，但读不到个人数据）\n"
            "     · 只有 ACAC 没有匹配的 ACAO → 一样被拒\n"
            "     · 两个都有、而且 ACAO 指向攻击者 → 通了\n\n"
            "别的白名单写法及其绕过（值得一起记住）：\n"
            "  · origin.endswith('partner.example')      → https://evil-partner.example\n"
            "  · origin.startswith('https://partner')    → https://partner.evil.example\n"
            "  · re.match(r'https://.*\\.partner.example', origin)\n"
            "      点没转义 → 用「任意字符」替代点：https://evilXpartnerYexample\n"
            "  · 只比对 origin 的 host 部分，忘了协议 → 用 http:// 也能过\n"
            "  · 把 'null' 也放进白名单 → 沙箱 iframe / data: URL 的 Origin 就是 null"
        ),
        "refs": [
            "https://portswigger.net/web-security/cors",
            "https://owasp.org/www-community/attacks/CORSAttack",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE secrets (
                username TEXT PRIMARY KEY,
                api_key  TEXT NOT NULL,
                balance  TEXT NOT NULL
            );
            INSERT INTO secrets (username, api_key, balance) VALUES
                ('alice', 'PA-APIKEY-3f91bd', '128600.00');
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def me():
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            try:
                return con.execute(
                    "SELECT username, api_key, balance FROM secrets WHERE username = ?",
                    (session["user"],),
                ).fetchone()
            finally:
                con.close()

        def apply_cors(resp, origin):
            """按"白名单"决定要不要放行跨源读。

            ↓↓↓ 洞就在这里：两条都错 ↓↓↓
            """
            if not origin:
                return resp
            # 一、白名单做成子串匹配 —— 没有做域名边界检查
            if any(allowed in origin for allowed in ALLOWED):
                # 二、把 Origin 原样反射，并且允许带凭据
                resp.headers["Access-Control-Allow-Origin"] = origin
                resp.headers["Access-Control-Allow-Credentials"] = "true"
                resp.headers["Vary"] = "Origin"
            # ↑↑↑ 正确做法：Origin 必须**精确等于**白名单里的一项
            #     （用 urlsplit 取 scheme + netloc 再比），
            #     而且允许带凭据那条要慎用 ↑↑↑
            return resp

        @app.route("/")
        def index():
            origin = request.headers.get("Origin", "")
            return render_template(
                "index.html",
                logged_in=bool(session.get("user")),
                user=session.get("user"),
                origin=origin,
                legit=LEGIT_ORIGIN,
                api_url=ctx.url("", "/api/me"),
                data=None,
            )

        @app.route("/login", methods=["POST"])
        def login():
            user = request.form.get("user", "")
            password = request.form.get("password", "")
            if USERS.get(user) == password:
                session["user"] = user
            return render_template(
                "index.html",
                logged_in=bool(session.get("user")),
                user=session.get("user"),
                origin="",
                legit=LEGIT_ORIGIN,
                api_url=ctx.url("", "/api/me"),
                data=None,
            )

        @app.route("/logout")
        def logout():
            session.clear()
            return render_template(
                "index.html", logged_in=False, user=None, origin="",
                legit=LEGIT_ORIGIN, api_url=ctx.url("", "/api/me"), data=None,
            )

        @app.route("/api/me", methods=["GET", "OPTIONS"])
        def api_me():
            origin = request.headers.get("Origin", "")

            if request.method == "OPTIONS":
                resp = make_response("", 204)
                if any(allowed in origin for allowed in ALLOWED):
                    resp.headers["Access-Control-Allow-Origin"] = origin
                    resp.headers["Access-Control-Allow-Credentials"] = "true"
                    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
                    resp.headers["Access-Control-Allow-Headers"] = (
                        request.headers.get("Access-Control-Request-Headers", "*")
                    )
                    resp.headers["Vary"] = "Origin"
                return resp

            if not session.get("user"):
                resp = jsonify({"error": "未登录"})
                resp.status_code = 401
                return apply_cors(resp, origin)

            row = me()
            resp = jsonify(
                {
                    "username": row["username"],
                    "api_key": row["api_key"],
                    "balance": row["balance"],
                }
            )
            resp = apply_cors(resp, origin)

            # 判定：一个**不是**合法合作方的 Origin，却拿到了带凭据的放行
            if (
                origin
                and origin != LEGIT_ORIGIN
                and resp.headers.get("Access-Control-Allow-Origin") == origin
                and resp.headers.get("Access-Control-Allow-Credentials") == "true"
            ):
                ctx.progress.mark(GOAL)

            return resp

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}


_ = (re, urlsplit)  # 正确做法里要用到的两个模块，留个记号
