"""内部工具站的垂直越权。

跟 `idor/order_detail` 的区别：

  · IDOR 那道是**水平越权** —— 同级别的用户之间换一个 id，看别人的数据
  · 这一题是**垂直越权** —— 低权限用户拿到了高权限才该有的功能

两者都用"URL 里改点东西"的方式打，但防护思路不一样：水平越权要检查"这数据是不是你的"，
垂直越权要检查"你这个角色允不允许调这个接口"。
"""

import sqlite3

from vuln4all import Vuln, redirect, render_template, request, session, url_for

DB_NAME = "ops.db"

#: 通关目标名。mark() 和 check() 共用同一个常量，免得拼错字。
GOAL = "用普通用户身份调到了只有管理员该能用的导出接口"

#: 只有管理员才该看到的东西。它出现在普通用户的响应里 = 垂直越权成立。
SENTINEL = "OPS-EXPORT-ONLY"

USERS = {
    "bob": ("bob123", "user"),
    "carol": ("carol123", "user"),
    "opsadmin": ("opsadmin-9f2c", "admin"),
}


class AdminEndpoint(Vuln):
    info = {
        "name": "普通用户调到了管理员接口（垂直越权）",
        "author": ["guaidao2"],
        "cwe": "CWE-862",
        "owasp": "A01:2021 - Broken Access Control",
        "difficulty": "进阶",
        "description": (
            "导出接口只检查了「你登录了吗」，没检查「你是什么角色」。"
            "前端把管理员菜单藏起来了 —— 但藏起来不是权限控制。"
        ),
        "hint": (
            "先看这个页面的 HTML 源码。菜单里有些条目被 CSS 藏住了 —— "
            "前端隐藏只是不给看，不是不给用。\n"
            "顺着那些隐藏的链接想一想：那个接口自己是怎么判断"
            "「你有没有资格调它」的？"
        ),
        "solution": (
            "一、用 bob / bob123 登录（普通用户）。\n\n"
            "二、在页面上右键「查看页面源代码」（或者 curl 一下），"
            "会看到菜单里有个被 style=\"display:none\" 藏起来的链接：\n"
            "   /v/idor/admin_endpoint/admin/export\n\n"
            "三、直接访问它，或者用 curl 带着 bob 的 cookie 请求：\n"
            "   curl -b 'session=...' 'http://<靶场>/v/idor/admin_endpoint/admin/export'\n"
            "   你会拿到那份本该只有管理员能看的导出数据。\n\n"
            "为什么能成：那个接口里只有\n"
            "   if not session.get('user'): 拒绝\n"
            "没有对 role 的任何判断。\n\n"
            "顺带对比一下：\n"
            "  · 水平越权（IDOR）：换一个对象的 id，看别人的数据\n"
            "    防护 = 每次取数据都带上 owner 条件\n"
            "  · 垂直越权（这一题）：换一个功能入口，用别人的权限\n"
            "    防护 = 每个敏感接口都检查角色，而且检查要在服务端做\n"
            "两者经常同时出现，要找的洞也不一样。"
        ),
        "refs": [
            "https://portswigger.net/web-security/access-control/vertical-privilege-escalation",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE staff (
                username TEXT PRIMARY KEY,
                realname TEXT NOT NULL,
                phone    TEXT NOT NULL,
                salary   INTEGER NOT NULL
            );
            INSERT INTO staff (username, realname, phone, salary) VALUES
                ('bob',      '鲍勃',   '13800000001', 18000),
                ('carol',    '卡罗尔', '13800000002', 21000),
                ('opsadmin', '运维管理员', '13900000000', 32000);
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def export_rows():
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            try:
                return con.execute(
                    "SELECT username, realname, phone, salary FROM staff ORDER BY username"
                ).fetchall()
            finally:
                con.close()

        @app.route("/")
        def index():
            if not session.get("user"):
                return render_template("login.html", error=None)
            return redirect(url_for("console"))

        @app.route("/login", methods=["POST"])
        def login():
            user = request.form.get("user", "")
            password = request.form.get("password", "")
            record = USERS.get(user)
            if record and record[0] == password:
                session["user"] = user
                session["role"] = record[1]
                return redirect(url_for("console"))
            return render_template("login.html", error="用户名或密码不对")

        @app.route("/console")
        def console():
            if not session.get("user"):
                return redirect(url_for("index"))
            return render_template(
                "console.html",
                user=session["user"],
                role=session.get("role"),
                export_url=url_for("admin_export"),
                export_only=SENTINEL,
            )

        @app.route("/admin/export")
        def admin_export():
            # ↓↓↓ 洞就在这里：只检查"登录了"，没检查"是不是管理员" ↓↓↓
            if not session.get("user"):
                return redirect(url_for("index"))
            # ↑↑↑ 少了一句：if session.get("role") != "admin": abort(403) ↑↑↑

            if session.get("role") != "admin":
                # 记录：普通用户调到了管理员接口 —— 这就是垂直越权
                ctx.progress.mark(GOAL)

            return render_template(
                "export.html",
                rows=export_rows(),
                user=session["user"],
                role=session.get("role"),
                marker=SENTINEL,
            )

        @app.route("/logout")
        def logout():
            session.clear()
            return redirect(url_for("index"))

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
