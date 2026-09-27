"""数据看板的表名处注入 —— 参数化管不到标识符。

业务场景是"运营数据看板"：从下拉框里选一张表，把它的内容导出来看看。

这一题的洞不在"值"上，在**标识符**上。看这两个东西的区别：

    SELECT * FROM orders  WHERE id = ?        ← orders 是标识符，? 是值
                        ↑                       ↑
              参数化管不到这里        参数化管得到这里

SQL 的参数化（`?` 占位符）**只能用在"值"的位置**：数字、字符串、日期。
表名、列名、`ORDER BY` 的目标 —— 这些都是**语法结构**，不能当参数传。

所以"我用了参数化"不等于"我没有注入"。**只要有一个标识符来自用户输入，
参数化就漏了一个口子。**

开发者的防护是一份表名黑名单，而他的比较方式是"整串相等"——
这留下了两条路：**加个 schema 限定**，或者**换成子查询**。
"""

import sqlite3

from vuln4all import Vuln, render_template, request

DB_NAME = "dashboard.db"

#: 看板上"允许导出"的表。
PUBLIC_TABLES = ("orders", "products", "shipments")

#: 开发的"防护"：不许导出这些表。**整串比较**，而且去掉了大小写。
BLOCKED_TABLES = ("users", "accounts", "secrets")

#: 只有 users 表里才有这串东西。它出现在导出结果里 = 读到了。
SENTINEL = "DASH-OPS-4c81f2"

GOAL = "把黑名单里的 users 表读出来"


class IdentifierInjection(Vuln):
    info = {
        "name": "数据看板表名处的注入",
        "author": ["guaidao2"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "difficulty": "进阶",
        "description": (
            "运营看板让你选一张表导出。表名被拼进 `SELECT * FROM <表名>` —— "
            "而**表名是标识符，不是值**，所以参数化在这里用不上。\n"
            "开发者的防护是一份黑名单，比较方式是整串相等。那就有两条路绕过去。"
        ),
        "hint": (
            "先正常导出一张表，看页面把拼出来的 SQL 显示出来了没有。\n"
            "然后注意那个位置在 SQL 里叫什么：它不是「值」，是**标识符**。\n"
            "想一想：`SELECT * FROM ?` 在 SQL 里合法吗？\n"
            "（不合法 —— 那开发者只能怎么做？）\n"
            "接下来看那份黑名单：它是怎么比较的？\n"
            "  一、如果它比的是「整串等于 users」，那 `main.users` 算不算等于？\n"
            "  二、如果它比的是字符串，那 `(SELECT ... )` 这种**子查询**呢？\n"
            "顺便：SQLite 里的表名是区分大小写的吗？"
        ),
        "solution": (
            "一、先确认这个位置能拼东西、并且看清报错：\n\n"
            "     table=orders       正常\n"
            "     table=users        被黑名单拦下\n"
            "     table=nosuch       报错：no such table: nosuch\n\n"
            "二、绕过一：**加 schema 限定**。\n\n"
            "     table=main.users\n\n"
            "   黑名单比的是「整串等于 `users`」，而 `main.users` 不等于它 ——\n"
            "   于是放行。但 SQLite 完全认这个写法（`main` 就是主库的名字）。\n\n"
            "    顺便可以先确认一下有哪些库：`pragma_database_list`。\n\n"
            "三、绕过二：**换成子查询**。\n\n"
            "     table=(SELECT * FROM users)\n\n"
            "   拼出来是：SELECT * FROM (SELECT * FROM users)\n"
            "   一样不等于 `users`，一样被放行。而结果一模一样。\n\n"
            "四、绕过三：**大小写**。\n\n"
            "     table=USERS\n\n"
            "   SQLite 的标识符**大小写不敏感**（`USERS` 能匹配到 `users`），\n"
            "   而这个黑名单做了 `.lower()` —— 所以这一条被挡住了。\n"
            "   **但要知道它为什么没成**：换个项目、换种写法，它就可能成。\n"
            "   「黑名单做了大小写归一」和「黑名单没做」是完全不同的两件事。\n\n"
            "五、先枚举再动手（更真实的打法）：\n\n"
            "     table=sqlite_master      不在黑名单里，能导出 → 拿到全部表名\n"
            "     table=pragma_table_info('users')   → 拿到 users 的全部列名\n\n"
            "   注意 `sqlite_master` 和 `pragma_*` **都不在**那份黑名单里：\n"
            "   黑名单只列了几个「敏感表名」，没有列「元数据表」。\n"
            "   而元数据恰恰是攻击者的起点。\n\n"
            "这一题的教训：\n\n"
            "  · **参数化只能用在「值」的位置。** 标识符（表名、列名、排序目标）\n"
            "    天然用不了它 —— 所以那里必须用**白名单**：\n"
            "      if table not in PUBLIC_TABLES: table = PUBLIC_TABLES[0]\n"
            "  · 黑名单在标识符这一层几乎必然失败：schema 限定、子查询、\n"
            "    大小写、加引号（`\"users\"`）、方括号（`[users]`）、\n"
            "    甚至 `pragma_table_info` 都能绕。\n"
            "  · 元数据表（`sqlite_master` / `pragma_*`）如果没被显式处理，\n"
            "    它就是一个免费的侦察通道。"
        ),
        "refs": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE users (
                id       INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            );
            INSERT INTO users (username, password) VALUES
                ('admin', '%s'),
                ('carol', 'carol-pw');

            CREATE TABLE orders (
                id     INTEGER PRIMARY KEY,
                item   TEXT NOT NULL,
                total  REAL NOT NULL
            );
            INSERT INTO orders (item, total) VALUES
                ('机械键盘', 499.0), ('显示器', 1299.0);

            CREATE TABLE products (
                id    INTEGER PRIMARY KEY,
                name  TEXT NOT NULL,
                stock INTEGER NOT NULL
            );
            INSERT INTO products (name, stock) VALUES
                ('机械键盘', 12), ('显示器', 3);

            CREATE TABLE shipments (
                id     INTEGER PRIMARY KEY,
                carrier TEXT NOT NULL,
                status  TEXT NOT NULL
            );
            INSERT INTO shipments (carrier, status) VALUES
                ('顺丰', '运输中'), ('京东', '已签收');
            """
            % SENTINEL
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def run(sql):
            con = sqlite3.connect(db_path)
            try:
                cur = con.execute(sql)
                cols = [d[0] for d in (cur.description or [])]
                return cols, [list(r) for r in cur.fetchall()]
            finally:
                con.close()

        def render(table="", cols=None, rows=None, raw_sql=None,
                   blocked=None, error=None):
            return render_template(
                "index.html",
                table=table,
                cols=cols or [],
                rows=rows or [],
                raw_sql=raw_sql,
                blocked=blocked,
                error=error,
                public_tables=list(PUBLIC_TABLES),
                blocked_tables=list(BLOCKED_TABLES),
            )

        @app.route("/")
        def index():
            cols, rows = run("SELECT * FROM orders")
            return render(table="orders", cols=cols, rows=rows,
                          raw_sql="SELECT * FROM orders")

        @app.route("/export", methods=["POST"])
        def export():
            table = request.form.get("table", "").strip()

            # 开发的"防护"：黑名单，整串比较（去掉了大小写）
            if table.lower() in BLOCKED_TABLES:
                return render(table=table, blocked=table,
                              error="这张表不允许导出")

            # ↓↓↓ 洞就在这里：表名是**标识符**，参数化用不上，只能拼 ↓↓↓
            sql = "SELECT * FROM %s" % table
            # ↑↑↑ 正确做法：白名单 ——
            #     if table not in PUBLIC_TABLES: 直接拒绝 ↑↑↑

            try:
                cols, rows = run(sql)
                error = None
            except sqlite3.Error as exc:
                cols, rows = [], []
                error = "%s: %s" % (type(exc).__name__, exc)

            if any(SENTINEL in str(cell) for row in rows for cell in row):
                ctx.progress.mark(GOAL)

            return render(table=table, cols=cols, rows=rows,
                          raw_sql=sql, error=error)

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
