"""状态机乱序 —— 业务逻辑漏洞系列之四。

业务场景是"积分商城的订单流转"。

订单有一个状态机：

    待付款 -> 已付款 -> 已发货 -> 已完成

而"退款"体现在订单上的一个**布尔字段** `refunded`。

洞就在这里：**布尔字段可以和任何状态共存。**

`/refund` 把 `refunded` 置 1，但**不动 `status`**；
`/confirm` 检查了 `status == '已发货'`，却没检查 `refunded`。

于是：

    已付款 --发货--> 已发货 --退款--> 已发货 + refunded=1
                                          |
                                      --确认收货--> 已完成 + refunded=1

**货到了，钱也退了。** 而单独看每一个接口，它的状态检查都是"对"的。

正确的做法不是"在 /confirm 里再加一句 if"。而是：
**「已退款」本身就该是状态机里的一个状态**，不是订单上的一个旁挂标志位。
"""

import sqlite3
from datetime import datetime

from vuln4all import Vuln, render_template, request

DB_NAME = "shop.db"

ORDER_NO = "SO-2026-0002"
ORDER_GOODS = "人体工学椅"
ORDER_PAID = 1888.00

#: 状态机的全部状态（顺带就是它的转换表）。
TRANSITIONS = {
    "待付款": ["已付款"],
    "已付款": ["已发货"],
    "已发货": ["已完成"],
    "已完成": [],
    "已取消": [],
}

GOAL = "让一笔订单同时处于「已退款」和「已完成」"


class StateMachine(Vuln):
    info = {
        "name": "订单状态机乱序",
        "author": ["guaidao2"],
        "cwe": "CWE-841",
        "owasp": "A04:2021 - Insecure Design",
        "difficulty": "困难",
        "description": (
            "订单有一个状态机，而「退款」被实现成了订单上的一个**布尔字段**。\n"
            "每个接口自己的状态检查看起来都对，但布尔字段可以和任何状态共存 ——"
            "于是能走成「已退款 + 已完成」：货到了，钱也退了。"
        ),
        "hint": (
            "先照着正常流程走一遍（发货、确认收货），看状态怎么变。\n"
            "然后把状态机画在纸上。**「已退款」在这个状态机里是哪个状态？**\n"
            "再单独看每个接口：它检查了哪些条件？\n"
            "关键的一问：**一个布尔字段能不能和某个状态同时成立？**\n"
            "如果能，那些「看起来都对」的检查加起来能拼出一条合法路径吗？"
        ),
        "solution": (
            "一、正常流程：\n\n"
            "   已付款 --确认发货--> 已发货 --确认收货--> 已完成\n\n"
            "   每一步接口都检查了前置状态，看着没问题。\n\n"
            "二、关键：`refunded` 是订单上的一个**布尔字段**，不是状态。\n\n"
            "   `/refund` 做的事是「把 refunded 置 1」，**它不动 status**。\n"
            "   所以退款之后订单仍然停在「已发货」：\n\n"
            "   已付款 --确认发货--> 已发货 --申请退款--> 已发货（refunded=1）\n\n"
            "三、而 `/confirm`（确认收货）检查的是 `status == '已发货'` ——\n"
            "   它**不知道 refunded 这回事**。所以：\n\n"
            "   已发货（refunded=1）--确认收货--> 已完成（refunded=1）\n\n"
            "   通关。钱退了，货也「收到」了。\n\n"
            "curl -X POST --data-urlencode 'order=<单号>' '<发货地址>'\n"
            "curl -X POST --data-urlencode 'order=<单号>' '<退款地址>'\n"
            "curl -X POST --data-urlencode 'order=<单号>' '<收货地址>'\n\n"
            "为什么这题不是为了好玩：\n\n"
            "  每个接口的检查**单独看都是对的**，加起来却拼出一条不该存在的路径。\n"
            "  这就是「状态机漏洞」区别于「缺一句 if」的地方 ——\n"
            "  后者是忘了写，前者是**模型建错了**。\n\n"
            "正确的模型（值得背下来）：\n\n"
            "  一、**把「已退款」放进状态机，而不是旁挂一个布尔字段。**\n"
            "     因为它确实是一个状态：它决定了「这个订单接下来还能做什么」。\n\n"
            "       待付款 -> 已付款 -> 已发货 -> 已完成\n"
            "                            |\n"
            "                            +-> 已退款（终态）\n\n"
            "     这样 `/confirm` 只要检查「当前状态允许转到已完成吗」，\n"
            "     就已天然把已退款排除了 —— **不需要多加任何一个 if**。\n\n"
            "  二、**转换表是数据，不是散落各处的 if。**\n\n"
            "       self.TRANSITIONS = {\n"
            "           \"已发货\": [\"已完成\", \"已退款\"],\n"
            "           \"已退款\": [],                 # 终态\n"
            "       }\n\n"
            "     然后所有接口都走同一句检查：\n\n"
            "       if target not in self.TRANSITIONS[order.status]:\n"
            "           reject()\n\n"
            "     新加一个状态的时候，你改的是**一张表**，不是十个接口。\n"
            "     这一题就是「状态和标志各管一摊」的典型后果。\n\n"
            "  三、**金额、库存这类东西也要跟着状态走。**\n"
            "     这一题里退款没回滚库存 —— 如果回滚了，\n"
            "     `已完成 + refunded` 这条路径会立刻把库存数变成负数，\n"
            "     对账的时候就会暴露。**能自动发现异常的设计，比靠人审查的设计可靠。**\n\n"
            "这一类漏洞怎么系统性地找：\n\n"
            "  · 画状态机：把所有状态和所有转换列出来，画成一张图\n"
            "  · 找「旁挂字段」：除了 status 之外，还有哪些布尔/数值字段也描述状态？\n"
            "    （refunded、paid、shipped、cancelled、locked……）\n"
            "  · 对每一对「状态 + 字段」的组合问：这个组合**应该**存在吗？\n"
            "  · 把顺序打乱走一遍：状态机的图上有几条从 A 到 B 的路？\n"
            "    如果有一条你没设计过的路，那就是洞。"
        ),
        "refs": [
            "https://cwe.mitre.org/data/definitions/841.html",
            "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
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
                refunded INTEGER NOT NULL DEFAULT 0,
                paid     REAL NOT NULL
            );
            CREATE TABLE history (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                order_no TEXT NOT NULL,
                action   TEXT NOT NULL,
                created  TEXT NOT NULL
            );
            """
        )
        con.execute(
            "INSERT INTO orders (order_no, goods, status, refunded, paid) VALUES (?,?,?,0,?)",
            (ORDER_NO, ORDER_GOODS, "已付款", ORDER_PAID),
        )
        con.execute(
            "INSERT INTO history (order_no, action, created) VALUES (?,?,?)",
            (ORDER_NO, "创建订单（已付款）", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
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

        def update(sql, args=()):
            con = sqlite3.connect(db_path)
            try:
                con.execute(sql, args)
                con.commit()
            finally:
                con.close()

        def log(action):
            update(
                "INSERT INTO history (order_no, action, created) VALUES (?,?,?)",
                (ORDER_NO, action, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )

        def snapshot():
            order = query(
                "SELECT order_no, goods, status, refunded, paid FROM orders"
            )[0]
            history = query(
                "SELECT action, created FROM history WHERE order_no = ? ORDER BY id",
                (ORDER_NO,),
            )
            return order, history

        def render(error=None, note=None):
            order, history = snapshot()
            reached = order["refunded"] == 1 and order["status"] == "已完成"
            return render_template(
                "index.html",
                order=order,
                history=history,
                paid="%.2f" % order["paid"],
                transitions=TRANSITIONS,
                reached=reached,
                error=error,
                note=note,
            )

        def guard(order):
            """返回 (错误信息, None) 或者 (None, 订单)。顺手做统一的订单号校验。"""
            order_no = request.form.get("order", "").strip()
            if order_no != order["order_no"]:
                return "没有这个订单", None
            return None, order

        def current():
            return query(
                "SELECT order_no, status, refunded FROM orders WHERE order_no = ?",
                (ORDER_NO,),
            )[0]

        @app.route("/")
        def index():
            return render()

        @app.route("/ship", methods=["POST"])
        def ship():
            order = current()
            err, order = guard(order)
            if err:
                return render(error=err)
            # 这一步的状态检查是对的
            if order["status"] != "已付款":
                return render(error="只有「已付款」的订单能发货")
            update("UPDATE orders SET status = '已发货' WHERE order_no = ?", (ORDER_NO,))
            log("确认发货 -> 已发货")
            return render(note="已发货。")

        @app.route("/refund", methods=["POST"])
        def refund():
            order = current()
            err, order = guard(order)
            if err:
                return render(error=err)
            # 这一步的状态检查也是对的（已付款和已发货都能退）
            if order["status"] not in ("已付款", "已发货"):
                return render(error="这个状态的订单不能退款")
            if order["refunded"]:
                return render(error="这笔订单已经退过款了")

            # ↓↓↓ 洞就在这里：置了 refunded，但**没有动 status** ↓↓↓
            update("UPDATE orders SET refunded = 1 WHERE order_no = ?", (ORDER_NO,))
            # ↑↑↑ 正确做法：「已退款」应该是状态机里的一个状态 ——
            #     status 转到「已退款」，而不是另挂一个布尔字段。
            #     那样后面所有转换检查都天然把它排除掉了。 ↑↑↑
            log("申请退款 -> refunded=1（status 没变）")
            return render(note="退款已处理。注意：订单状态没有变化。")

        @app.route("/confirm", methods=["POST"])
        def confirm():
            order = current()
            err, order = guard(order)
            if err:
                return render(error=err)
            # ↓↓↓ 洞在这里：只检查了 status，**完全不知道 refunded 这回事** ↓↓↓
            if order["status"] != "已发货":
                return render(error="只有「已发货」的订单能确认收货")
            # ↑↑↑ 正确做法：检查「当前状态允许转到已完成吗」——
            #     如果退款是个状态，这一句就已天然把已退款排除了 ↑↑↑
            update("UPDATE orders SET status = '已完成' WHERE order_no = ?", (ORDER_NO,))
            log("确认收货 -> 已完成")
            return render(note="已确认收货。")

        @app.route("/清空", methods=["POST"])
        def clear():
            update("UPDATE orders SET status = '已付款', refunded = 0 WHERE order_no = ?",
                   (ORDER_NO,))
            update("DELETE FROM history WHERE order_no = ? AND id > 1", (ORDER_NO,))
            return render(note="已重置到「已付款」。")

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        """直接从订单表推：有没有订单同时是「已退款」和「已完成」。

        这两个字段的组合本身就表达了「货到手了、钱也退了」——
        不需要另存进度。
        """
        try:
            con = sqlite3.connect(str(ctx.workspace / DB_NAME))
            try:
                row = con.execute(
                    "SELECT COUNT(*) FROM orders WHERE refunded = 1 AND status = '已完成'"
                ).fetchone()
            finally:
                con.close()
        except sqlite3.Error:
            return {GOAL: False}
        return {GOAL: row[0] > 0}
