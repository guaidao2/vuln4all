"""登录处的 SQL 注入 —— 最经典的那道题。

这一题故意把用户名/密码直接拼进 SQL 语句，让学习者亲手体验
「闭合引号 + 注释掉后半句」是怎么回事。
"""

import sqlite3

from vuln4all import Vuln, redirect, render_template, request, session, url_for

#: 通关目标名。mark() 和 check() 共用同一个常量，免得拼错字。
GOAL = "以 admin 身份登录，绕过了密码检查"


class LoginBypass(Vuln):
    info = {
        "name": "登录处的 SQL 注入",
        "author": ["guaidao2"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "difficulty": "入门",
        "description": (
            "登录页把用户名和密码直接拼进了 SQL 语句，没有任何参数化。"
            "你可以构造输入，让这条查询无论如何都返回一行 —— 于是不用密码就进去了。"
        ),
        "hint": (
            "先在用户名里敲一个单引号（'）提交，看看页面报什么错。"
            "错误信息里会把真正执行的 SQL 语句贴出来，照着它想："
            "怎么让 WHERE 后面的判断永远为真，或者干脆把密码那一半注释掉。"
        ),
        "solution": (
            "用户名填：admin' --\n"
            "密码随便填（比如 1），提交。\n\n"
            "原理：拼出来的语句变成\n"
            "  SELECT username, role FROM users WHERE username = 'admin' --' AND password = '1'\n"
            "SQL 里 -- 是行注释，后面那半句被注释掉了，只剩 username='admin' 成立。\n"
            "其他能通的写法：admin' or '1'='1' --、' or 1=1 --"
        ),
        "refs": [
            "https://portswigger.net/web-security/sql-injection",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        """造一张用户表。reset 之后会重新跑一遍。"""
        db_path = ctx.workspace / "app.db"
        con = sqlite3.connect(str(db_path))
        con.executescript(
            """
            CREATE TABLE users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                role     TEXT NOT NULL
            );
            INSERT INTO users (username, password, role) VALUES
                ('admin', 'S3cr3t-Adm1n-P4ss', 'admin'),
                ('alice', 'alice123',          'user'),
                ('bob',   'bob-the-builder',   'user');
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / "app.db")

        def query(sql):
            con = sqlite3.connect(db_path)
            try:
                return con.execute(sql).fetchone()
            finally:
                con.close()

        @app.route("/", methods=["GET", "POST"])
        def index():
            error = None
            sql = None

            if request.method == "POST":
                username = request.form.get("username", "")
                password = request.form.get("password", "")

                # ↓↓↓ 洞就在这里：用户输入被直接拼进了 SQL 语句 ↓↓↓
                sql = (
                    "SELECT username, role FROM users "
                    "WHERE username = '%s' AND password = '%s'" % (username, password)
                )
                # ↑↑↑ 正确写法是 con.execute("... WHERE username = ? AND password = ?", (u, p)) ↑↑↑

                try:
                    row = query(sql)
                except sqlite3.Error as exc:
                    # 故意把报错和真正执行的 SQL 都漏出去 —— 这正是新手该学的东西
                    row = None
                    error = "数据库报错：%s\n实际执行的语句：%s" % (exc, sql)

                if row is not None:
                    session["user"] = row[0]
                    session["role"] = row[1]
                    # 记进度。check() 读的就是这个，所以它不用去问某个浏览器。
                    if row[1] == "admin":
                        ctx.progress.mark(GOAL)
                    return redirect(url_for("welcome"))
                if error is None:
                    error = "用户名或密码错误"
                    sql = None

            return render_template("login.html", error=error, sql=sql)

        @app.route("/welcome")
        def welcome():
            if not session.get("user"):
                return redirect(url_for("index"))
            return render_template(
                "welcome.html",
                user=session.get("user"),
                role=session.get("role"),
                is_admin=session.get("role") == "admin",
            )

        @app.route("/logout")
        def logout():
            session.clear()
            return redirect(url_for("index"))

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
