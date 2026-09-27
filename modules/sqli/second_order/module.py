"""个人中心改密码处的二次注入。

业务场景是"个人主页改密码"。

这一题的看点在于：**注入点不在你能直接控制的输入上。**

看流程：

  1. 注册 —— 用户名**参数化**写进库。所以你把 `admin'--` 当用户名注册进去，
     它就是一个合法的字符串，一点问题都没有。
  2. 登录 —— 也是参数化的。
  3. 改密码 —— 这一句长这样：

       UPDATE users SET password = ? WHERE username = '<从库里读出来的用户名>'

     SET 那里参数化了（是的，开发知道要参数化），
     但 `WHERE` 里的用户名是**拼**进去的。

开发者为什么会这么写？因为那个用户名"是从数据库里读出来的"。
在他心里：

    用户输入 = 不可信
    数据库里的数据 = 可信

**二次注入就是专门打这个错觉的。** 数据一旦进过库，
它就被贴上"可信"的标签 —— 而它的来源其实是用户。
"""

import sqlite3

from vuln4all import Vuln, render_template, request, session

DB_NAME = "portal.db"

#: admin 的初始密码。它被改掉 = 通关。
ADMIN_PASSWORD = "ADMIN-ORIGINAL-8f31"

GOAL = "从自己注册的账号出发，把 admin 的密码改掉"


class SecondOrder(Vuln):
    info = {
        "name": "改密码处的二次注入",
        "author": ["guaidao2"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "difficulty": "困难",
        "description": (
            "注册和登录都用了参数化 —— 所以你把 `admin'--` 当用户名注册进去，"
            "它会老老实实存成一个字符串。\n"
            "但**改密码**那一句只参数化了一半：`SET` 用了 `?`，"
            "而 `WHERE` 里的用户名是拼上去的。\n"
            "那个用户名是从库里读出来的 —— 开发者觉得「库里的数据可信」。"
        ),
        "hint": (
            "一、先在页面上走一遍正常流程：注册一个账号 → 登录 → 改密码。\n"
            "二、注意看三个功能的 SQL 分别是怎么写的（页面上都显示出来了）。\n"
            "    注册和登录是参数化的；**改密码那一句只参数化了一半。**\n"
            "三、然后问最关键的一句：\n"
            "    拼进 `WHERE` 的那个用户名，**它是从哪来的？**\n"
            "    如果我能控制它的内容，我能让那条 UPDATE 变成什么样子？\n"
            "四、注册的时候故意把用户名写成 `admin'--` 试试。\n"
            "    （注意：注册是参数化的，所以它会原样存进去 —— 这一步是「安全」的。）"
        ),
        "solution": (
            "一、注册一个用户名带 payload 的账号：\n\n"
            "     用户名：admin'--\n"
            "     密码：  随便\n\n"
            "   注册用的是参数化（`INSERT ... VALUES (?, ?)`），\n"
            "   所以 `admin'--` 就是一个普通的字符串，存进去了，一点问题没有。\n\n"
            "二、用这个账号登录。登录也是参数化的，正常。\n\n"
            "三、然后**改密码**。这一步服务端拼出的是：\n\n"
            "     UPDATE users SET password = ? WHERE username = 'admin'--'\n\n"
            "   `--` 把后面那个引号注释掉了，于是条件变成：\n\n"
            "     WHERE username = 'admin'\n\n"
            "   —— 它改的是 **admin 那一行**，不是你自己的。\n\n"
            "四、现在用 `admin` + 你刚设的新密码登录，就进去了。\n\n"
            "为什么这题叫「二次」：\n\n"
            "   第一次：你把 payload 交给服务端（注册）。它被**安全地存起来**了。\n"
            "   第二次：服务端**从库里把它取出来**，当可信数据用（拼进 SQL）。\n\n"
            "   两次之间隔了一个「入库出库」，而开发者的信任判断就发生在那中间：\n"
            "   「这是我自己库里的数据，不是我刚收到的用户输入。」\n\n"
            "为什么这类洞特别难发现：\n\n"
            "  · **扫描器基本扫不出来。** 它对注册接口发 `admin'--`，看响应 ——\n"
            "    响应完全正常（参数化，存得好好的）。它对改密码接口发\n"
            "    `admin'--`，也看不出问题（那是个密码字段，被参数化了）。\n"
            "    洞只在「先做 A 再做 B」这个**序列**里存在。\n"
            "  · **代码审查很容易漏。** 你单独看改密码那段代码，\n"
            "    `WHERE username = '<row[\"username\"]>'` —— 你会觉得没问题，\n"
            "    因为 `row` 是数据库读出来的。\n"
            "  · **静态分析也难。** 污点分析要么把「来自数据库」当干净（漏报），\n"
            "    要么就得跨函数跨请求追踪（误报爆炸）。\n\n"
            "哪里最容易出现二次注入（一张清单）：\n\n"
            "  · 注册时存用户名，之后用来拼 SQL（改密码、发消息、加好友）\n"
            "  · 存文件名/路径，之后用来拼读文件的路径\n"
            "  · 存 URL/host，之后用来拼跳转或者抓取\n"
            "  · 存模板片段，之后渲染（那是存储型 SSTI）\n"
            "  · 存 HTML 片段，之后 `|safe` 输出（那是存储型 XSS）\n"
            "  · 存日志字段，之后用来检索\n\n"
            "  **共同点：只要有「入库 → 出库 → 再使用」这条链，就要重新问一遍「它可信吗」。**\n\n"
            "怎么修：\n\n"
            "  这一句应该两处都参数化：\n\n"
            "    con.execute(\"UPDATE users SET password = ? WHERE username = ?\",\n"
            "                (new_password, row[\"username\"]))\n\n"
            "  原则只有一句：**参数化看的是「这个位置是值还是语法」，\n"
            "  跟「这个数据从哪来」没有关系。**\n"
            "  从库里读出来的东西一样要参数化 —— 因为它最终来自用户。"
        ),
        "refs": [
            "https://portswigger.net/web-security/sql-injection/second-order",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role     TEXT NOT NULL DEFAULT 'user'
            );
            CREATE TABLE sqllog (
                id   INTEGER PRIMARY KEY AUTOINCREMENT,
                step TEXT NOT NULL,
                sql  TEXT NOT NULL
            );
            """
        )
        con.execute(
            "INSERT INTO users (username, password, role) VALUES (?,?,?)",
            ("admin", ADMIN_PASSWORD, "admin"),
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def connect():
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            return con

        def log_sql(step, sql):
            """把每一步拼出来的 SQL 记下来 —— 这一题的教学主体就是这几句。"""
            con = sqlite3.connect(db_path)
            try:
                con.execute("INSERT INTO sqllog (step, sql) VALUES (?,?)", (step, sql))
                con.commit()
            finally:
                con.close()

        def recent_log():
            con = connect()
            try:
                return [
                    dict(r)
                    for r in con.execute(
                        "SELECT step, sql FROM sqllog ORDER BY id DESC LIMIT 12"
                    )
                ][::-1]
            finally:
                con.close()

        def admin_password():
            con = connect()
            try:
                row = con.execute(
                    "SELECT password FROM users WHERE username = 'admin'"
                ).fetchone()
                return row["password"] if row else None
            finally:
                con.close()

        def render(note=None, error=None, rows=None, admin_pwned=False):
            return render_template(
                "index.html",
                user=session.get("user"),
                note=note,
                error=error,
                rows=rows or [],
                log=recent_log(),
                admin_pwned=admin_pwned,
                admin_row=admin_password(),
            )

        @app.route("/")
        def index():
            return render(admin_pwned=admin_password() != ADMIN_PASSWORD)

        @app.route("/register", methods=["POST"])
        def register():
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not username or not password:
                return render(error="用户名和密码都要填")

            # 注意：这里是**参数化**的。所以 payload 会被原样存成一个字符串 ——
            # 这一步本身没有问题。问题在别处（看 /password）。
            sql = "INSERT INTO users (username, password) VALUES (?, ?)"
            con = connect()
            try:
                with con:
                    con.execute(sql, (username, password))
            except sqlite3.IntegrityError:
                return render(error="这个用户名已经有人用了")
            finally:
                con.close()

            log_sql("注册", "%s        -- 参数化：%r" % (sql, (username, password)))
            return render(note="注册成功：%s。现在去登录。" % username)

        @app.route("/login", methods=["POST"])
        def login():
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            sql = "SELECT username, role FROM users WHERE username = ? AND password = ?"
            con = connect()
            try:
                row = con.execute(sql, (username, password)).fetchone()
            finally:
                con.close()
            log_sql("登录", "%s        -- 参数化：%r" % (sql, (username, password)))
            if row is None:
                return render(error="用户名或密码不对")
            session["user"] = row["username"]
            return render(note="已登录：%s" % row["username"])

        @app.route("/logout", methods=["POST"])
        def logout():
            session.clear()
            return render(note="已退出")

        @app.route("/password", methods=["POST"])
        def change_password():
            if not session.get("user"):
                return render(error="先登录")

            new_password = request.form.get("new_password", "")
            if not new_password:
                return render(error="新密码不能是空的")

            con = connect()
            try:
                # 第一步：参数化地把"当前用户"读出来 —— 这一步是对的
                me = con.execute(
                    "SELECT username FROM users WHERE username = ?",
                    (session["user"],),
                ).fetchone()
                if me is None:
                    return render(error="登录状态失效了，请重新登录")
                stored_username = me["username"]

                # ↓↓↓ 洞就在这里：`SET` 参数化了，`WHERE` 是拼的 ↓↓↓
                sql = (
                    "UPDATE users SET password = ? WHERE username = '%s'"
                    % stored_username
                )
                con.execute(sql, (new_password,))
                con.commit()
                # ↑↑↑ 正确做法：两处都参数化 ——
                #     "UPDATE users SET password = ? WHERE username = ?",
                #     (new_password, stored_username)
                #
                #     关键认知：**参数化看的是"这个位置是值还是语法"，
                #     跟"这个数据从哪来"没关系。**
                #     从库里读出来的东西一样要参数化 —— 因为它最终来自用户。 ↑↑↑
            finally:
                con.close()

            log_sql("改密码", sql + "        -- ← 注意这里：用户名是拼进去的")
            return render(
                note="密码已更新。",
                admin_pwned=admin_password() != ADMIN_PASSWORD,
            )

        @app.route("/清空日志", methods=["POST"])
        def clear_log():
            con = sqlite3.connect(db_path)
            try:
                con.execute("DELETE FROM sqllog")
                con.commit()
            finally:
                con.close()
            return render()

        @app.route("/users")
        def users():
            con = connect()
            try:
                rows = [
                    dict(r)
                    for r in con.execute("SELECT id, username, role FROM users ORDER BY id")
                ]
            finally:
                con.close()
            return render(rows=rows)

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        """直接从库里推：admin 的密码还是不是原来那个。

        不需要记"谁做了什么" —— admin 的密码变了，只能是二次注入的结果。
        """
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        try:
            row = con.execute(
                "SELECT password FROM users WHERE username = 'admin'"
            ).fetchone()
        except sqlite3.Error:
            return {GOAL: False}
        finally:
            con.close()
        return {GOAL: row is not None and row[0] != ADMIN_PASSWORD}
