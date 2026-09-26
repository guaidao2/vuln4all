"""订单详情处的越权访问（IDOR）。

登录成自己，把 URL 里的订单号换一个，就看到别人的订单了。
这一题想让新手分清「认证」和「授权」不是一回事。
"""

import sqlite3

from vuln4all import Vuln, redirect, render_template, request, session, url_for


class OrderDetail(Vuln):
    info = {
        "name": "改个数字看别人的订单（IDOR）",
        "author": ["vuln4all"],
        "cwe": "CWE-639",
        "owasp": "A01:2021 - Broken Access Control",
        "description": (
            "订单详情页用 URL 里的订单号直接去查数据，查到了就给你看 —— "
            "完全没检查这个订单是不是你的。"
            "登录本身没问题，问题出在「登录之后能看什么」。"
        ),
        "hint": (
            "登录进去看自己的订单，注意地址栏里的 /order/1001 这种数字。"
            "服务端拿到这个数字之后，有没有问过一句「这单是当前登录用户的吗」？"
            "把它改成相邻的数字试试。"
        ),
        "solution": (
            "1. 用 alice / alice123 登录，进「我的订单」，点开一个订单，\n"
            "   地址栏大概是 /order/1001。\n"
            "2. 把 1001 改成 1003 或 1004 —— 那是 bob 的订单，但你照样看到了。\n\n"
            "原理：服务端拿到 order_id 就直接查库，WHERE 条件里只有订单号，"
            "没有当前用户。改成 WHERE id = ? AND owner = ? 就堵上了。"
        ),
        "refs": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            "https://portswigger.net/web-security/access-control/idor",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / "shop.db"))
        con.executescript(
            """
            CREATE TABLE orders (
                id      INTEGER PRIMARY KEY,
                owner   TEXT NOT NULL,
                item    TEXT NOT NULL,
                amount  REAL NOT NULL,
                note    TEXT NOT NULL
            );
            INSERT INTO orders (id, owner, item, amount, note) VALUES
                (1001, 'alice', '机械键盘',      499.00, '发到公司'),
                (1002, 'alice', '显示器支架',    129.00, ''),
                (1003, 'bob',   '「内部福利」礼品卡', 9999.00, '备注：这张卡只发给我们组，别外传'),
                (1004, 'bob',   '人体工学椅',   1888.00, '');
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / "shop.db")

        def fetch(sql, args=()):
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            try:
                return con.execute(sql, args).fetchall()
            finally:
                con.close()

        @app.route("/")
        def index():
            if not session.get("user"):
                return render_template("shop_login.html", error=None)
            return redirect(url_for("orders"))

        @app.route("/login", methods=["POST"])
        def login():
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            accounts = {"alice": "alice123", "bob": "bob123"}
            if accounts.get(username) == password:
                session["user"] = username
                return redirect(url_for("orders"))
            return render_template("shop_login.html", error="用户名或密码不对")

        @app.route("/orders")
        def orders():
            if not session.get("user"):
                return redirect(url_for("index"))
            rows = fetch(
                "SELECT id, item, amount FROM orders WHERE owner = ? ORDER BY id",
                (session["user"],),
            )
            return render_template("shop_orders.html", user=session["user"], orders=rows)

        @app.route("/order/<int:order_id>")
        def order_detail(order_id):
            if not session.get("user"):
                return redirect(url_for("index"))

            # ↓↓↓ 洞就在这里：WHERE 里只有订单号，没有 owner ↓↓↓
            rows = fetch("SELECT * FROM orders WHERE id = ?", (order_id,))
            # ↑↑↑ 应该是：WHERE id = ? AND owner = ? , (order_id, session["user"]) ↑↑↑

            if not rows:
                return render_template("shop_notfound.html", order_id=order_id), 404

            row = rows[0]
            return render_template(
                "shop_order.html",
                order=row,
                # 页面自己知道这不是你的订单 —— 但服务端已经先把数据给它了
                stolen=row["owner"] != session["user"],
            )

        @app.route("/logout")
        def logout():
            session.clear()
            return redirect(url_for("index"))

        return {"": app}
