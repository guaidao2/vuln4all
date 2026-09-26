"""产品留言板里的存储型 XSS。

跟反射型的区别不在 payload，在**payload 存在哪**：

  · 反射型：payload 在你这次请求的 URL 里，响应里弹一下，然后就没了
  · 存储型：payload 落到了服务器的数据库里，之后**每一次**打开这个页面都会触发

所以这一题打完要做的事是：把地址栏清干净，刷新 —— 它还在响。
"""

import re
import sqlite3
from datetime import datetime

from vuln4all import Vuln, render_template, request

DB_NAME = "board.db"

#: 通关目标名。mark() 和 check() 共用同一个常量，免得拼错字。
GOAL = "往留言板里塞了一条会被执行的消息"

#: 什么样的留言算"这是攻击载荷"。要的是真的标签，光写 javascript: 不算。
PAYLOAD = re.compile(
    r"(?is)<\s*script\b"                 # <script>
    r"|<\s*[a-z][^>]*\son\w+\s*="        # 标签里带 on* 事件处理器
)


def read_bodies(ctx):
    """读出所有留言正文。给请求处理和 check() 共用。"""
    con = sqlite3.connect(str(ctx.workspace / DB_NAME))
    try:
        return [row[0] or "" for row in con.execute("SELECT body FROM messages")]
    finally:
        con.close()


class StoredGuestbook(Vuln):
    info = {
        "name": "留言板里的存储型 XSS",
        "author": ["guaidao2"],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "difficulty": "入门",
        "description": (
            "留言板把内容原样存进数据库，再原样渲染回页面。"
            "跟反射型不同的地方是：payload 留在了服务器上，"
            "之后每一次打开这个页面都会再执行一遍。"
        ),
        "hint": (
            "先发一条普通留言看看它怎么显示。然后注意你输入的内容是被"
            "原样渲染进 HTML 的 —— 试着发一条 `&lt;b&gt;粗体&lt;/b&gt;`。\n"
            "另一半是：发完之后**把地址栏清干净**再刷新，看看它还在不在。"
        ),
        "solution": (
            "在留言框里发：\n"
            "  <script>alert(document.cookie)</script>\n"
            "有些浏览器会拦，那就换：\n"
            "  <img src=x onerror=alert(document.cookie)>\n\n"
            "然后关键的一步：**把地址栏里的参数清掉，直接刷新页面**。\n"
            "弹窗还会出来 —— 因为这段内容已经存在数据库里了，不在 URL 里。\n\n"
            "这就是存储型和反射型的区别：\n"
            "  · 反射型要诱导受害者点一个带 payload 的链接\n"
            "  · 存储型只要受害者打开那个页面就行（不用点任何特别的东西）\n"
            "  后者明显更容易得手，所以危害通常更大。"
        ),
        "refs": [
            "https://portswigger.net/web-security/cross-site-scripting/stored",
            "https://owasp.org/www-community/attacks/xss/",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE messages (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                author  TEXT NOT NULL,
                body    TEXT NOT NULL,
                created TEXT NOT NULL
            );
            INSERT INTO messages (author, body, created) VALUES
                ('产品组', '新版搜索页上线了，有问题在这里留言。', '2026-01-05 10:12'),
                ('运维组', '周三凌晨会做一次数据库维护，预计十分钟。', '2026-01-06 18:40');
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def all_messages():
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            try:
                return con.execute(
                    "SELECT author, body, created FROM messages ORDER BY id"
                ).fetchall()
            finally:
                con.close()

        def add_message(author, body):
            con = sqlite3.connect(db_path)
            try:
                con.execute(
                    "INSERT INTO messages (author, body, created) VALUES (?, ?, ?)",
                    (author, body, datetime.now().strftime("%Y-%m-%d %H:%M")),
                )
                con.commit()
            finally:
                con.close()

        @app.route("/", methods=["GET", "POST"])
        def index():
            if request.method == "POST":
                author = request.form.get("author", "").strip() or "匿名"
                body = request.form.get("body", "").strip()
                if body:
                    add_message(author, body)

            messages = all_messages()
            armed = sum(1 for m in messages if PAYLOAD.search(m["body"] or ""))
            return render_template(
                "index.html",
                messages=messages,
                armed_count=armed,
                stored_payload=armed > 0,
            )

        @app.route("/clear", methods=["POST"])
        def clear():
            con = sqlite3.connect(db_path)
            try:
                con.execute("DELETE FROM messages")
                con.commit()
            finally:
                con.close()
            return render_template(
                "index.html", messages=[], armed_count=0, stored_payload=False
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        """直接从数据库推 —— 不用记进度。

        能从业已存在的状态推出来的就别另存一份：留言被清掉了，进度自然就回退了。
        """
        try:
            bodies = read_bodies(ctx)
        except sqlite3.Error:
            return {GOAL: False}
        return {GOAL: any(PAYLOAD.search(body) for body in bodies)}
