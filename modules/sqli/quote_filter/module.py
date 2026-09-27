"""库存查询处的注入 —— 过滤掉引号、注释和 UNION 之后。

这一题是"过滤器绕过"那一组的 SQLi 版（跟 `sqli/keyword_filter` 是同一个路子）。

过滤器拦了三类东西：

    · 单引号、双引号
    · 注释（`--`、`#`、`/*`）
    · `union`

于是有两个"看起来很合理"的结论，而**两个都是错的**：

    一、「引号被拦掉了，注入就打不了」
       —— 错。这一题的注入点是**数字型**的，压根不需要引号。
          而真正需要写字符串字面量的时候，SQLite 有**不用引号**的写法。

    二、「UNION 被拦掉了，就读不出数据」
       —— 错。UNION 只是**一种**信道。这一题用布尔信道照样能读 ——
          而且那个字符串比较**必须**用不带引号的写法，否则过滤器会拦。

两件事合起来，就把"怎么在不能写引号的情况下拼出字符串"变成了**必答题**。
"""

import re
import sqlite3

from vuln4all import Vuln, render_template, request

DB_NAME = "stock.db"

#: admin 的密码。6 位，小写字母加数字。
SECRET = "t4kp8w"
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

# ---------------------------------------------------------------- 过滤层
#
# 一份"字符黑名单"式的过滤器。它拦的是**符号**，而写注入 payload
# 不一定需要那些符号。
RULES = [
    ("单引号",   r"'"),
    ("双引号",   r'"'),
    ("注释",     r"--|#|/\*"),
    ("union",    r"(?i)\bunion\b"),
]

COMPILED = [(name, re.compile(pattern)) for name, pattern in RULES]


def inspect(value):
    for name, pattern in COMPILED:
        if pattern.search(value):
            return name
    return None


GOAL_FILTER = "让注入生效（用一个不存在的编号，却让页面查出东西）"
GOAL_PASSWORD = "把 admin 的密码完整猜出来并提交"


class QuoteFilter(Vuln):
    info = {
        "name": "过滤掉引号之后的注入",
        "author": ["guaidao2"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "difficulty": "困难",
        "description": (
            "库存查询前面挂了一份黑名单：单引号、双引号、注释、`union`。\n"
            "于是两个「看起来很合理」的结论冒出来了 ——"
            "「没引号打不了注入」和「没 UNION 读不出数据」。两个都是错的。"
        ),
        "hint": (
            "先试一条经典 payload：`1' OR 1=1 -- `，看过滤器报哪条规则。\n"
            "然后想两件事：\n"
            "  一、这个注入点是**数字型**的还是字符型的？\n"
            "     （提示：看页面上显示的执行语句 —— 你输的 `1` 两边有引号吗？）\n"
            "  二、`union` 被拦了，那 UNION 是唯一的「读数据」方式吗？\n"
            "     （前面几道题里，还有哪种信道？）\n"
            "接下来是最关键的一问：\n"
            "  **如果不能用引号，怎么在 SQL 里写一个字符串字面量？**\n"
            "  （想想：SQL 里有没有函数，能用数字「拼」出字符串？）"
        ),
        "solution": (
            "一、先看清过滤器和注入点的形状。\n\n"
            "   打 `1' OR 1=1 -- ` 会被「单引号」拦掉。\n"
            "   但看页面上的执行语句：\n\n"
            "     SELECT id, sku, qty FROM stock WHERE sku_id = 1\n\n"
            "   **那个 1 两边没有引号** —— 这是个**数字型**注入点。\n"
            "   所以闭合引号这一步根本不需要。引号被拦掉不影响打。\n\n"
            "二、`union` 被拦了，换信道。\n\n"
            "   前面学过：只要有真假两种可观测状态，就能一位一位读数据。\n"
            "   这个接口正好有 —— 查到就显示表格，查不到就显示「没有」：\n\n"
            "     1 OR 1=1\n\n"
            "   所有行都出来了（基线：查一个不存在的编号是空表）。\n\n"
            "三、关键：**不用引号写字符串字面量**。\n\n"
            "   要判断「密码的第一位是不是某个字符」，就得把那个字符写成字符串。\n"
            "   而单引号被拦了。怎么办？\n\n"
            "   **`char()` —— 它接受一串数字，返回对应的字符串。**\n\n"
            "     char(97)              -> 'a'\n"
            "     char(97,100,109,105,110)  -> 'admin'\n\n"
            "   整个 payload 一个引号都没有：\n\n"
            "     1 OR (SELECT substr(password,1,1) FROM users\n"
            "             WHERE username=char(97,100,109,105,110))=char(116)\n\n"
            "   写脚本把 substr 的位置从 1 数到 6、把 char(N) 里的 N 换一遍，\n"
            "   6 位密码就出来了。提交到页面下面那个框里。\n\n"
            "四、提速（跟 `sqli/boolean_blind` 同一套）：\n\n"
            "   · 二分：把 `=` 换成 `>`，一位从 36 次降到 6 次\n"
            "   · `hex()`：把字符集压到 16 个\n"
            "   · 先用 `length()` 问出长度\n\n"
            "顺手记一下**不用引号的几种写法**（很重要）：\n\n"
            "  | 写法 | 要引号吗 | 在 SQLite 上能用吗 |\n"
            "  |---|---|---|\n"
            "  | `'admin'` | 要 | 被拦了 |\n"
            "  | `char(97,100,109,105,110)` | **不要** | **能用** |\n"
            "  | `X'61646d696e'` | 要（`X'...'` 里有引号） | 被拦了 |\n"
            "  | `CAST(X'61646d696e' AS TEXT)` | 要（同上） | 被拦了 |\n"
            "  | `0x61646d696e` | 不要 | **不能当字符串用** ——\n"
            "    SQLite 里它是**整数** 1633771876，不是 'admin'（这个坑很容易踩） |\n\n"
            "  所以引号被拦之后，`char()` 是这里唯一顺手的路子。\n"
            "  （MySQL 那套 cheat sheet 里，这一节叫「String Concatenation」。）\n\n"
            "这一题的教训：\n\n"
            "  · **黑名单拦的是「符号」，而 payload 的写法有很多种。**\n"
            "    拦了引号，还有 `char()`；拦了 UNION，还有布尔信道。\n"
            "  · **判断注入点是什么类型，永远是第一步。**\n"
            "    数字型不需要引号 —— 这一条能让一大半「字符黑名单」直接失效。\n"
            "  · 防御要看的是「这个位置是值还是语法」，不是「输入里有没有某几个字符」。"
        ),
        "refs": [
            "https://portswigger.net/web-security/sql-injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Bypassing_WAF/",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE stock (
                id     INTEGER PRIMARY KEY,
                sku_id INTEGER NOT NULL,
                sku    TEXT NOT NULL,
                qty    INTEGER NOT NULL
            );
            INSERT INTO stock (sku_id, sku, qty) VALUES
                (1001, 'KB-MECH-01', 12),
                (1002, 'MON-27-4K',  3),
                (1003, 'CHR-ERGO-1', 7);
            CREATE TABLE users (
                id       INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            );
            """
        )
        con.execute(
            "INSERT INTO users (username, password) VALUES (?,?)", ("admin", SECRET)
        )
        con.execute(
            "INSERT INTO users (username, password) VALUES (?,?)",
            ("carol", "carol-pw"),
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def search(sql):
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            try:
                return [dict(r) for r in con.execute(sql)]
            finally:
                con.close()

        def render(sku_id="", rows=None, raw_sql=None, blocked=None,
                   error=None, feedback=None):
            return render_template(
                "index.html",
                sku_id=sku_id,
                rows=rows or [],
                raw_sql=raw_sql,
                blocked=blocked,
                error=error,
                feedback=feedback,
                rules=[name for name, _ in RULES],
                length=len(SECRET),
                alphabet_size=len(ALPHABET),
            )

        @app.route("/")
        def index():
            return render()

        @app.route("/query", methods=["POST"])
        def query_stock():
            sku_id = request.form.get("sku_id", "")

            # ↓↓↓ 过滤层：拦符号，不拦"结构" ↓↓↓
            blocked = inspect(sku_id)
            if blocked is not None:
                return render(sku_id=sku_id, blocked=blocked,
                              error="被安全策略拦下了")

            # 注入点是**数字型**的 —— 这一行是这一题的关键
            sql = "SELECT id, sku, qty FROM stock WHERE sku_id = %s" % sku_id

            try:
                rows = search(sql)
                error = None
            except sqlite3.Error as exc:
                rows = []
                error = "%s: %s" % (type(exc).__name__, exc)

            # 判定一：用一个不存在的编号，却查出了东西 —— 注入生效了
            if rows and sku_id.strip() not in ("1001", "1002", "1003"):
                ctx.progress.mark(GOAL_FILTER)

            return render(sku_id=sku_id, rows=rows, raw_sql=sql, error=error)

        @app.route("/submit", methods=["POST"])
        def submit():
            guess = request.form.get("guess", "").strip()
            feedback = None
            if guess:
                if guess == SECRET:
                    ctx.progress.mark(GOAL_PASSWORD)
                    feedback = ("ok", "密码对了。")
                else:
                    feedback = ("bad", "不对。")
            return render(feedback=feedback)

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {
            GOAL_FILTER: ctx.progress.achieved(GOAL_FILTER),
            GOAL_PASSWORD: ctx.progress.achieved(GOAL_PASSWORD),
        }
