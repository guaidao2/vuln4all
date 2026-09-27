"""商品列表排序处的注入。

业务场景是"商品列表可以按列排序"：`sort=price`。

这一题的注入点在 `ORDER BY` 后面 —— 这个位置很特殊：

  1. **UNION 用不了。** UNION 要求前后列数一致，而这里的列是由原查询定的，
     你没有地方去"接"一张新表。
  2. **它照样能读数据。** 靠的是**排序结果本身**：
     `ORDER BY CASE WHEN <条件> THEN price ELSE name END`
     条件的真假会让行序变化 —— 这就是一个布尔信道。
     更省事的用法是：**直接按一个隐藏列排序**，行序就把那个列的相对大小泄露了。
  3. **参数化管不到它。** `ORDER BY ?` 在 SQL 里是无效的 ——
     排序目标是**标识符**，不是**值**。

这一题的洞就在最后一句话上：开发者只能拼字符串，而他的"防护"是一份列名黑名单。
"""

import sqlite3

from vuln4all import Vuln, render_template, request

DB_NAME = "shop.db"

#: 查询里真正会取出来的四列。第 4 列是隐藏列，页面上不显示。
COLUMNS = ("id", "name", "price", "internal_grade")

#: 页面上给用户选的排序列（合法的两个）。
PUBLIC_SORTS = ("name", "price")

#: 开发的"防护"：不许按这些列排序。注意是**子串匹配**。
BLOCKED = ("internal_grade", "grade", "users", "password", "sqlite")

GOAL = "让商品按那列隐藏的「内部评级」排出来（行序会把它的相对大小泄露出去）"


class OrderByInjection(Vuln):
    info = {
        "name": "商品排序处的注入",
        "author": ["guaidao2"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "difficulty": "进阶",
        "description": (
            "商品列表可以按列排序，而排序参数被直接拼在 `ORDER BY` 后面。\n"
            "这个位置很特别：**UNION 用不了**（列数由原查询定），"
            "**参数化也管不到**（标识符不能当参数）——"
            "但它照样能把隐藏的数据泄露出去，因为**排序结果本身就是输出**。"
        ),
        "hint": (
            "先正常按 `name` 和 `price` 排一下，看清页面的行序。\n"
            "然后试着不按列名、改按**列号**排（`ORDER BY 1`、`ORDER BY 2`、……）。\n"
            "顺便：如果列号超出范围，SQLite 的报错会告诉你什么？\n"
            "（那句话里有这一题的关键信息。）\n"
            "最后想一个问题：**排序结果是不是一种输出？**\n"
            "如果服务端不告诉你某个值是多少，但告诉你「谁比谁大」，"
            "那你知道了什么？"
        ),
        "solution": (
            "一、先确认这个位置存在，并且看清列数：\n\n"
            "     sort=name      正常\n"
            "     sort=price     正常\n"
            "     sort=internal_grade  被黑名单拦下\n"
            "     sort=9               报错：\n"
            "       '9th ORDER BY term out of range - should be between 1 and 4'\n\n"
            "   最后那句报错**直接告诉你表里有 4 列**。这是很常见的一类泄露：\n"
            "   报错信息本身就是一张地图。\n\n"
            "二、黑名单是按**子串**匹配列名的。那就别用列名 —— 用**列号**：\n\n"
            "     sort=4\n\n"
            "   `ORDER BY 4` 就是「按第 4 列排」，而第 4 列正好是 internal_grade。\n"
            "   黑名单只拦名字，拦不到位置。\n\n"
            "   另一条路：SQLite 的标识符**大小写不敏感**，而黑名单是区分的：\n"
            "     sort=INTERNAL_GRADE\n"
            "   一样能排出来。\n\n"
            "三、为什么「排个序」就等于泄露了数据：\n\n"
            "   服务端从来没有把 internal_grade 的值写进响应。\n"
            "   但它把**行序**写进了响应 —— 而行序是那个值的一个函数。\n"
            "   所以你能推出**相对大小**：谁比谁高、谁最低。\n\n"
            "   3 行的话你能拿到完整排名；30 行的话你还能二分。\n"
            "   这跟盲注是同一件事：**信道不一定是「值本身」，也可以是「值的某个函数」**。\n\n"
            "四、如果目标是读一个**标量**（比如某个密码），这个位置也能做：\n\n"
            "     sort=CASE WHEN substr((SELECT password FROM users WHERE username='admin'),1,1)='S'\n"
            "               THEN price ELSE name END\n\n"
            "   条件为真时按 price 排、为假时按 name 排 ——\n"
            "   页面的行序会变。于是你就有了一个布尔信道，一位一位把密码问出来。\n"
            "   （这一条在 `sqli/boolean_blind` 那道题里会展开。）\n\n"
            "这一题的教训：\n\n"
            "  · **UNION 不是唯一的数据出口。** 排序、报错、耗时、行数、页面大小……\n"
            "    任何「会因为数据而变」的东西都是信道。\n"
            "  · **参数化管不到标识符。** `ORDER BY ?` 在 SQL 里无效。\n"
            "    所以这里必须用**白名单**：\n"
            "      if sort not in (\"name\", \"price\"): sort = \"name\"\n"
            "    黑名单在这一层是错的工具 —— 这一题就是证明：\n"
            "    列名可以换成列号、换成大小写变体、换成表达式。"
        ),
        "refs": [
            "https://portswigger.net/web-security/sql-injection",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE products (
                id             INTEGER PRIMARY KEY,
                name           TEXT NOT NULL,
                price          REAL NOT NULL,
                internal_grade INTEGER NOT NULL
            );
            INSERT INTO products (id, name, price, internal_grade) VALUES
                (1, '机械键盘',   499.0,  70),
                (2, '显示器',    1299.0,  95),
                (3, '人体工学椅', 1888.0,  55),
                (4, '鼠标垫',      39.0,  88),
                (5, '无线鼠标',    129.0, 62);
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def run(sql):
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            try:
                return [dict(r) for r in con.execute(sql)]
            finally:
                con.close()

        def hidden_order():
            """按隐藏列排出来的 id 顺序 —— 判定用的基准。"""
            return [
                r["id"]
                for r in run(
                    "SELECT id FROM products ORDER BY internal_grade"
                )
            ]

        def render(rows=None, sort=None, raw_sql=None, blocked=None, error=None):
            return render_template(
                "index.html",
                rows=rows or [],
                sort=sort or "",
                raw_sql=raw_sql,
                blocked=blocked,
                error=error,
                public_sorts=PUBLIC_SORTS,
                blocked_words=list(BLOCKED),
            )

        @app.route("/")
        def index():
            return render(rows=run("SELECT * FROM products ORDER BY name"), sort="name")

        @app.route("/list", methods=["POST"])
        def list_products():
            sort = request.form.get("sort", "name").strip()

            # 开发的"防护"：不许按这些列排。子串匹配，而且区分大小写。
            hit = next((w for w in BLOCKED if w in sort), None)
            if hit is not None:
                return render(blocked=hit, sort=sort, error="这个排序列不允许")

            # ↓↓↓ 洞就在这里：排序列是**标识符**，参数化管不到，只能拼 ↓↓↓
            sql = (
                "SELECT %s FROM products ORDER BY %s"
                % (", ".join(COLUMNS), sort)
            )
            # ↑↑↑ 正确做法：白名单 —— sort 必须是 PUBLIC_SORTS 里的一个，
            #     否则退回默认值。这里用黑名单是错的工具：列名可以换成
            #     列号、大小写变体、或者一个表达式。 ↑↑↑

            try:
                rows = run(sql)
                error = None
            except sqlite3.Error as exc:
                rows = []
                error = "%s: %s" % (type(exc).__name__, exc)

            if rows:
                got = [r["id"] for r in rows]
                if got == hidden_order():
                    ctx.progress.mark(GOAL)

            return render(rows=rows, sort=sort, raw_sql=sql, error=error)

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
