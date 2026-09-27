"""订单查询处的数字型注入。

业务场景是"物流单号查询"：填一个单号，看这一单的状态。

这一题教一件事：**引号不是注入的必要条件。**

前面几道 SQLi 都是字符型 —— 输入被包在 `'...'` 里，payload 得先用一个引号
把字符串闭合掉。所以很多人形成一个错觉：

    「把用户输入里的引号转义掉，就安全了」

这一题的注入点是**数字型**的。查询长这样：

    SELECT ... FROM orders WHERE id = <输入>

用户输入直接落在数字位置，**一个引号都不需要**：

    1 OR 1=1

引号转义在这里一点用都没有 —— 因为 payload 里根本没有引号。
"""

import sqlite3

from vuln4all import Vuln, render_template, request, session

DB_NAME = "logistics.db"

#: 登录用的账号。alice 只能看自己的单。
USERS = {"alice": "alice123", "carol": "carol123"}

#: 别人的订单里才会出现的东西。它出现在 alice 的页面上 = 越界读到了。
OTHER_PHONE = "13900008888"

GOAL = "绕过 WHERE 里的归属过滤，读到不属于自己的订单"


class NumericInjection(Vuln):
    info = {
        "name": "订单查询处的数字型注入",
        "author": ["guaidao2"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "difficulty": "入门",
        "description": (
            "物流单号查询把输入直接拼进 `WHERE owner = '<自己>' AND id = <输入>`。\n"
            "归属过滤是写在 SQL 里的，所以直接猜别人的 id 猜不到。\n"
            "而那个数字位置**不需要引号** —— 很多人以为「注入要先闭合一个引号」，"
            "于是「把引号转义掉」成了唯一的防御。数字型注入不需要引号，"
            "这条防御在这里一点用都没有。"
        ),
        "hint": (
            "先正常查一个单号，看页面显示什么。\n"
            "然后注意一件事：试着输入 `1` 和 `1-0` 和 `2-1` —— 它们的结果一样吗？\n"
            "如果一样，说明服务端把你的输入**当成算式算了**，而不是当成字符串比。\n"
            "接下来想：既然是个数字位置，那前面几道题里那个用来闭合字符串的引号，\n"
            "这里还需要吗？\n"
            "（如果你想试 `' OR 1=1 --`，会发现它没用 —— 想想为什么。）"
        ),
        "solution": (
            "一、先做个最简单的探测：\n\n"
            "    1        正常返回单号 1\n"
            "    1-0      跟 1 一样  ← 说明输入被当成算式求值了\n"
            "    2-1      还是跟 1 一样\n\n"
            "   这三条组合起来就说明：这是个数字位置，不是字符串位置。\n\n"
            "二、既然是数字位置，那就**不需要引号**：\n\n"
            "    2 OR 1=1\n\n"
            "   拼出来的语句是：\n"
            "     SELECT ... FROM orders WHERE owner = 'alice' AND id = 2 OR 1=1\n"
            "   注意最后那半句 `OR 1=1` —— SQL 里 **AND 比 OR 结合得紧**，\n"
            "   所以它等价于：\n"
            "     (owner = 'alice' AND id = 2) OR 1=1\n"
            "   恒真。所有订单都出来了，包括别人的。\n\n"
            "   这就是为什么「多加一个 AND 条件」挡不住 OR 注入：\n"
            "   你以为写了两道锁，实际上 OR 把最后一道整个短路掉了。\n\n"
            "   别的等价写法（哪个顺手用哪个）：\n"
            "     1 OR id>0\n"
            "     1 OR 1\n"
            "     0 OR 1=1\n"
            "   注意 `1 OR 1=1 --` 里的 `--` 在这里没用（甚至可能弄坏语句），\n"
            "   因为没有字符串要闭合、也没有后半句注释掉。\n\n"
            "三、如果登录成 carol 再试，会发现 carol 也能看到 alice 的单 ——\n"
            "   这条注入完全绕过了「你只能看自己的单」这个前提。\n\n"
            "为什么「转义引号」在这里无效：\n\n"
            "  转义引号的逻辑是「把 `'` 变成 `''`（或者 `\\'`）」。\n"
            "  可这一题的 payload 里**没有引号**。\n"
            "  你把引号处理得再完美，`1 OR 1=1` 照样原样送进 SQL。\n\n"
            "  这就是为什么正确做法是**参数化**而不是转义：\n"
            "  参数化管的是「这里是一个值，不是 SQL 语法」这件事，\n"
            "  它跟这个位置是数字还是字符串**没有关系**。\n\n"
            "顺带说个真实世界的常见组合：\n\n"
            "  很多代码是这样写的：\n"
            "    \"SELECT ... WHERE id = \" + request.args[\"id\"]      # 数字型，不用引号\n"
            "    \"SELECT ... WHERE name = '\" + escape(q) + \"'\"       # 字符型，转义了\n\n"
            "  第二个位置看起来「做了防护」，但第一个位置裸奔。\n"
            "  而开发者的注意力往往全在「我转义了引号」上。"
        ),
        "refs": [
            "https://portswigger.net/web-security/sql-injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE orders (
                id       INTEGER PRIMARY KEY,
                owner    TEXT NOT NULL,
                item     TEXT NOT NULL,
                phone    TEXT NOT NULL,
                status   TEXT NOT NULL
            );
            INSERT INTO orders (id, owner, item, phone, status) VALUES
                (1, 'alice', '机械键盘',   '13800001111', '运输中'),
                (2, 'carol', '人体工学椅', '13900008888', '已签收'),
                (3, 'dave',  '显示器',     '13700007777', '待发货');
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def query(sql):
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            try:
                return [dict(r) for r in con.execute(sql)]
            finally:
                con.close()

        def render(rows=None, note=None, error=None, raw_sql=None, typed=""):
            return render_template(
                "index.html",
                user=session.get("user"),
                rows=rows or [],
                note=note,
                error=error,
                raw_sql=raw_sql,
                typed=typed,
                other_phone=OTHER_PHONE,
            )

        @app.route("/")
        def index():
            return render()

        @app.route("/login", methods=["POST"])
        def login():
            user = request.form.get("user", "")
            password = request.form.get("password", "")
            if USERS.get(user) == password:
                session["user"] = user
                return render(note="已登录：%s" % user)
            return render(error="用户名或密码不对")

        @app.route("/logout", methods=["POST"])
        def logout():
            session.clear()
            return render(note="已退出")

        @app.route("/query", methods=["POST"])
        def do_query():
            typed = request.form.get("order_id", "").strip()
            if not typed:
                return render(error="填一个单号")

            user = session.get("user")
            if not user:
                return render(error="先登录才能查单")

            # 归属过滤是**写在 SQL 里**的 —— 所以直接猜 id 猜不到别人的单。
            #
            # ↓↓↓ 洞就在这里：那个数字位置**不需要引号**，而且拼接优先级帮了攻击者 ↓↓↓
            sql = (
                "SELECT id, owner, item, phone, status FROM orders "
                "WHERE owner = '%s' AND id = %s" % (user, typed)
            )
            # ↑↑↑ 正确做法：con.execute(
            #         "... WHERE owner = ? AND id = ?", (user, typed))
            #
            #     注意拼出来的条件是：
            #         owner = 'alice' AND id = 2 OR 1=1
            #     SQL 里 AND 比 OR 结合得紧，所以它等价于：
            #         (owner = 'alice' AND id = 2) OR 1=1
            #     —— 恒真。这就是为什么"多写一个 AND 条件"挡不住 OR 注入。 ↑↑↑
            #     注意参数化跟"这里是不是数字"没关系 —— 它管的是
            #     "这是一个值，不是 SQL 语法" 这件事 ↑↑↑

            try:
                rows = query(sql)
                error = None
            except sqlite3.Error as exc:
                rows = []
                # 这一题会给报错 —— 好让你看清语句被拼成了什么样
                error = "%s: %s" % (type(exc).__name__, exc)

            # 判定：结果里出现了**不属于自己**的订单。
            # 注意不能写成"出现了某个手机号" —— 那样直接猜 id=2 就命中了，
            # 而那是越权（IDOR），不是注入。
            if any(r.get("owner") != user for r in rows):
                ctx.progress.mark(GOAL)

            return render(rows=rows, raw_sql=sql, error=error, typed=typed)

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
