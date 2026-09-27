"""退款不退货 —— 业务逻辑漏洞系列之三。

业务场景是"积分商城的订单退款"。

一笔退款请求要做三件事：

  1. 检查这笔订单**允不允许**退（状态、时间窗）
  2. 算清楚该退**多少**（这个金额必须服务端算）
  3. 记录"这笔退款已经发生过了"（**幂等性**）

这一题的代码只做了第 1 件的一半，跳过了第 2 和第 3 件：

  · 退款金额从请求里来（默认值贴心地把实付填好了 —— 但默认值不是校验）
  · 没有记录"已经退过了"，所以同一个订单能退很多次

于是"退款不退货"变成"退款还能再退款"。
"""

import sqlite3
from datetime import datetime

from vuln4all import Vuln, render_template, request

DB_NAME = "shop.db"

#: 演示用的订单：已付款，实付 199.00。
ORDER_NO = "SO-2026-0001"
ORDER_GOODS = "机械键盘"
ORDER_PAID = 199.00

#: 浮点比较留一点零头。
TOLERANCE = 0.01

GOAL = "让一笔订单的退款总额超过它实付的金额"


class RefundLogic(Vuln):
    info = {
        "name": "退款不退货",
        "author": ["guaidao2"],
        "cwe": "CWE-837",
        "owasp": "A04:2021 - Insecure Design",
        "difficulty": "进阶",
        "description": (
            "退款接口做了一半的事：它检查了订单状态，"
            "但**没算退款金额**（金额从请求里来），"
            "也**没记录退过款**（所以能退很多次）。\n"
            "任何一条都足以让退款总额超过实付。"
        ),
        "hint": (
            "先正常退一次款，看余额怎么变。\n"
            "然后问三个问题（这三个问题就是这类漏洞的全部）：\n"
            "  1. **这个动作允许做几次？** 再点一次会怎么样？\n"
            "  2. **该退多少是服务端算的，还是客户端说的？**\n"
            "  3. **「已经做过」这件事，服务端记在哪？**\n"
            "一边点一边看请求 —— 里面有一个字段是「请求替你填好了默认值」的。\n"
            "**默认值不是校验。**"
        ),
        "solution": (
            "这一题有两条路，都是同一个根因（状态没被记住、金额没被算）。\n\n"
            "一、重复退款（幂等性缺失）。\n\n"
            "   curl -X POST --data-urlencode 'order={{ORDER}}' \\\n"
            "        --data-urlencode 'amount=199.00' '<退款地址>'\n\n"
            "   再发**完全一样**的请求一次。余额又加了 199。\n"
            "   退款总额 398 > 实付 199 —— 通关。\n\n"
            "   真实世界里的原话是：**「退款」这个动作必须幂等。**\n"
            "   一次请求因为超时被重发、用户点了两下、前端重试逻辑 ——\n"
            "   这些都会造成「同一个退款请求到达两次」，而只要服务端没记录，\n"
            "   就退两次钱。\n\n"
            "   （它们如果**并发**到达，那就变成竞态条件了 ——\n"
            "    去看 `race_condition/coupon_redeem`，那是另一道题的角度。）\n\n"
            "二、金额由客户端给。\n\n"
            "   curl -X POST --data-urlencode 'order={{ORDER}}' \\\n"
            "        --data-urlencode 'amount=9999.00' '<退款地址>'\n\n"
            "   一次就超过实付了。\n\n"
            "   请求里那个 `amount` 字段默认填着实付金额 —— 看着很贴心，\n"
            "   但那只是**方便用户**，不是**校验**。服务端要算的是：\n"
            "   「这笔订单还允许退多少」= 实付 - 已退。\n\n"
            "正确的设计长什么样：\n\n"
            "   def refund(order_no, reason):\n"
            "       order = load(order_no)              # 服务端自己加载\n"
            "       refunded = sum_refunds(order_no)    # 已经退了多少\n"
            "       if order.status != \"已发货\":\n"
            "           reject(\"这个状态不能退款\")\n"
            "       remaining = order.paid - refunded\n"
            "       if remaining <= 0:\n"
            "           reject(\"已经没有可退的金额了\")\n"
            "       amount = remaining                  # ← 金额服务端算\n"
            "       do_refund(order_no, amount)         # ← 记录这笔退款\n\n"
            "   三个关键点：\n"
            "     · **金额不接受客户端输入**（连读都不读）\n"
            "     · **每次算「剩余可退」而不是「该退多少」** —— 天然幂等\n"
            "     · **退款是一张流水表**，不是订单上的一个标志位\n"
            "       （这一点在 `business_logic/state_machine` 那道题里会展开）\n\n"
            "另外两个常被忘掉的检查：\n\n"
            "  · **退款要退到原路**（当初用哪张卡付的，就退到哪张卡）。\n"
            "    否则可以把自己的订单退款到别人的账户。\n"
            "  · **时间窗**（超过 30 天不能退）。这一题故意没加，\n"
            "    因为「时间」在靶场里不好演示 —— 但真实系统里这是必须的。"
        ),
        "refs": [
            "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
            "https://cwe.mitre.org/data/definitions/837.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE orders (
                order_no TEXT PRIMARY KEY,
                goods    TEXT NOT NULL,
                status   TEXT NOT NULL,
                paid     REAL NOT NULL
            );
            CREATE TABLE refunds (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                order_no TEXT NOT NULL,
                amount   REAL NOT NULL,
                created  TEXT NOT NULL
            );
            CREATE TABLE wallet (
                id      INTEGER PRIMARY KEY CHECK (id = 1),
                balance REAL NOT NULL
            );
            """
        )
        con.execute(
            "INSERT INTO orders (order_no, goods, status, paid) VALUES (?,?,?,?)",
            (ORDER_NO, ORDER_GOODS, "已发货", ORDER_PAID),
        )
        # 余额一开始扣掉了货款（模拟"买了东西"）
        con.execute("INSERT INTO wallet (id, balance) VALUES (1, ?)", (0.0,))
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def query(sql, args=()):
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            try:
                return [dict(r) for r in con.execute(sql, args)]
            finally:
                con.close()

        def do_refund(order_no, amount):
            con = sqlite3.connect(db_path)
            try:
                con.execute(
                    "INSERT INTO refunds (order_no, amount, created) VALUES (?,?,?)",
                    (order_no, amount, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                )
                con.execute("UPDATE wallet SET balance = balance + ? WHERE id = 1", (amount,))
                con.commit()
            finally:
                con.close()

        def snapshot():
            order = query("SELECT order_no, goods, status, paid FROM orders")[0]
            refunds = query(
                "SELECT amount, created FROM refunds WHERE order_no = ? ORDER BY id",
                (order["order_no"],),
            )
            total = round(sum(r["amount"] for r in refunds), 2)
            balance = query("SELECT balance FROM wallet")[0]["balance"]
            return order, refunds, total, balance

        def render(error=None, ok=None):
            order, refunds, total, balance = snapshot()
            return render_template(
                "index.html",
                order=order,
                refunds=refunds,
                refunded_total="%.2f" % total,
                remaining="%.2f" % (order["paid"] - total),
                balance="%.2f" % balance,
                paid="%.2f" % order["paid"],
                over=total > order["paid"] + TOLERANCE,
                error=error,
                ok=ok,
            )

        @app.route("/")
        def index():
            return render()

        @app.route("/refund", methods=["POST"])
        def refund():
            order_no = request.form.get("order", "").strip()
            if order_no != ORDER_NO:
                return render(error="没有这个订单")

            # ↓↓↓ 这里检查了状态 —— 这一半是对的 ↓↓↓
            status = query("SELECT status FROM orders WHERE order_no = ?", (order_no,))[0]["status"]
            if status not in ("已发货", "已完成"):
                return render(error="这个状态的订单不能退款")
            # ↑↑↑ ↑↑↑

            # ↓↓↓ 洞 1：金额从请求里来。默认值贴心，但那不是校验。 ↓↓↓
            try:
                amount = round(float(request.form.get("amount", ORDER_PAID)), 2)
            except (TypeError, ValueError):
                return render(error="退款金额不是一个数字")
            # ↑↑↑ 正确做法：amount = 实付 - 已退总额（服务端自己算） ↑↑↑

            # ↓↓↓ 洞 2：没有查"这笔订单是不是已经退过了"。 ↓↓↓
            #     也没有把结果夹到「剩余可退」以内。
            do_refund(order_no, amount)
            # ↑↑↑ 正确做法：
            #     一、先算 refunded = sum(refunds.amount)
            #     二、remaining = paid - refunded；remaining <= 0 就拒绝
            #     三、amount = remaining
            #     四、退款写一张流水表（天然幂等），而不是订单上的布尔标志 ↑↑↑

            return render(ok="退款已处理：%.2f" % amount)

        @app.route("/清空", methods=["POST"])
        def clear():
            con = sqlite3.connect(db_path)
            try:
                con.execute("DELETE FROM refunds")
                con.execute("UPDATE wallet SET balance = 0.0 WHERE id = 1")
                con.commit()
            finally:
                con.close()
            return render()

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        """直接从退款流水推：退款总额有没有超过实付。

        用「流水求和」而不是订单上的标志位来判，是因为**退款本来就是一串事件**。
        订单上的一个布尔值表达不了"退了几次、每次多少"。
        """
        try:
            con = sqlite3.connect(str(ctx.workspace / DB_NAME))
            try:
                row = con.execute(
                    "SELECT o.paid, COALESCE(SUM(r.amount), 0) AS refunded"
                    " FROM orders o LEFT JOIN refunds r ON r.order_no = o.order_no"
                    " GROUP BY o.order_no"
                ).fetchone()
            finally:
                con.close()
        except sqlite3.Error:
            return {GOAL: False}
        paid, refunded = row[0], row[1]
        return {GOAL: refunded > paid + TOLERANCE}
