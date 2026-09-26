"""下单接口的价格篡改 —— 业务逻辑漏洞。

业务场景是"积分商城下单"：前端展示单价，用户填数量，提交订单。

洞在于**服务端信了客户端给的单价**。前端把单价放在一个隐藏字段里传回来，
服务端拿它算总价 —— 于是改一下那个字段，就能用一分钱买东西。

这一类不叫"注入"、不叫"越权"，它的正式名字是**业务逻辑漏洞**：
代码没有违反任何"技术上的安全规则"，它只是**相信了不该相信的东西**。

业务逻辑漏洞的特点：
  · 没有现成的 payload 可以背
  · 扫描器基本扫不出来（它看起来就是一个正常请求）
  · 要靠"这个流程本来该是怎么走的"来推理
"""

import sqlite3
from datetime import datetime

from vuln4all import Vuln, render_template, request

DB_NAME = "shop.db"

#: 商品的**真实**单价。服务端本该用它，而不是用客户端传来的。
CATALOG = {
    "coffee": ("精品咖啡豆 250g", 128.00),
    "keyboard": ("机械键盘", 499.00),
    "chair": ("人体工学椅", 1888.00),
}

#: 判定：实付金额低于标价。低多少才算"篡改"？留一点零头防止浮点误差误判。
TOLERANCE = 0.01

GOAL = "用低于标价的价格下单成功"



class PriceTamper(Vuln):
    info = {
        "name": "下单接口的价格篡改",
        "author": ["guaidao2"],
        "cwe": "CWE-602",
        "owasp": "A04:2021 - Insecure Design",
        "difficulty": "入门",
        "description": (
            "积分商城的下单页把**单价**放在一个隐藏字段里传回服务端，"
            "服务端直接拿它算总价。\n"
            "把那个字段改小（或者把数量改成负数），就能用远低于标价的价格下单。"
        ),
        "hint": (
            "先在页面上正常下一单，然后用浏览器的开发者工具（或者 curl）"
            "看那个请求**到底发了什么**。\n"
            "重点看：请求里出现了哪些字段？其中哪些是「用户能自己决定的」、"
            "哪些是「服务端应该自己知道的」？\n"
            "一个很实用的问法：**如果我是攻击者，我能改这个值吗？"
            "改了之后服务端会发现吗？**"
        ),
        "solution": (
            "一、先正常下一单，把请求捕获下来（开发者工具的 Network 面板，"
            "或者 `curl -i` 看表单提交）。\n\n"
            "   你会看到请求里有 `price` 和 `qty` 这两个字段。\n"
            "   而 `price` 是**前端展示用的那个单价** —— 服务端直接拿它算钱。\n\n"
            "二、把单价改成 0.01：\n\n"
            "   curl -X POST \\\n"
            "        --data-urlencode 'item=chair' \\\n"
            "        --data-urlencode 'price=0.01' \\\n"
            "        --data-urlencode 'qty=1' \\\n"
            "        '<下单地址>'\n\n"
            "   订单就成立了。1888 块的椅子卖一分钱。\n\n"
            "三、同一个洞的另一种用法：数量改成负数。\n\n"
            "   --data-urlencode 'qty=-5'\n\n"
            "   如果服务端不校验数量，总价会变成负数 —— 那就是「商家倒找你钱」。\n"
            "   （这一题会把这个也判成通关，因为它同样属于「服务端信了客户端」。）\n\n"
            "这一类漏洞怎么找：\n\n"
            "  不要从「技术」入手，要从**业务流程**入手。问这几个问题：\n"
            "  · 这个流程里，**哪些数值决定了钱或者权限**？\n"
            "    单价、数量、折扣、余额、积分、运费……\n"
            "  · 这些数值是**服务端自己算出来的**，还是**客户端传上来的**？\n"
            "  · 如果把顺序打乱呢？（先发货再付款、先退款再确认收货）\n"
            "  · 如果同一个请求重复发呢？（这一条去看 `race_condition/coupon_redeem`）\n"
            "  · 边界值呢？（0、负数、极大的数、小数精度）\n\n"
            "真实世界里的同类例子：\n\n"
            "  · 隐藏字段里放价格 / 折扣 / 用户 ID / 权限等级\n"
            "  · 优惠券叠加：两个「互斥」的券同时用，或者同一个券用两次\n"
            "  · 整数溢出：数量填到让总价溢出成负数\n"
            "  · 四舍五入：拆成很多笔，每笔都利用舍入误差赚一点点\n"
            "  · 退款不退货：退款接口只看订单号，不看「货是否已退回」\n"
            "  · 免费试用：注册-删除-再注册，无限试用"
        ),
        "refs": [
            "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
            "https://cwe.mitre.org/data/definitions/602.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE orders (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                item       TEXT NOT NULL,
                item_name  TEXT NOT NULL,
                unit_price REAL NOT NULL,
                qty        INTEGER NOT NULL,
                paid       REAL NOT NULL,
                created    TEXT NOT NULL
            );
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def add_order(item, name, unit_price, qty, paid):
            con = sqlite3.connect(db_path)
            try:
                con.execute(
                    "INSERT INTO orders (item, item_name, unit_price, qty, paid, created)"
                    " VALUES (?,?,?,?,?,?)",
                    (
                        item, name, unit_price, qty, paid,
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    ),
                )
                con.commit()
            finally:
                con.close()

        def all_orders():
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            try:
                return [
                    dict(r)
                    for r in con.execute(
                        "SELECT item, item_name, unit_price, qty, paid, created"
                        " FROM orders ORDER BY id"
                    )
                ]
            finally:
                con.close()

        @app.route("/")
        def index():
            return render_template(
                "index.html",
                catalog=[
                    {"key": k, "name": v[0], "price": "%.2f" % v[1]}
                    for k, v in CATALOG.items()
                ],
                orders=all_orders(),
                error=None,
                last=None,
            )

        @app.route("/order", methods=["POST"])
        def order():
            item = request.form.get("item", "")
            if item not in CATALOG:
                return render_template(
                    "index.html",
                    catalog=[
                        {"key": k, "name": v[0], "price": "%.2f" % v[1]}
                        for k, v in CATALOG.items()
                    ],
                    orders=all_orders(), error="没有这个商品", last=None,
                )

            name, list_price = CATALOG[item]

            # ↓↓↓ 洞就在这里：单价和数量都从请求里拿，而且不校验 ↓↓↓
            try:
                unit_price = float(request.form.get("price", list_price))
            except (TypeError, ValueError):
                unit_price = list_price
            try:
                qty = int(request.form.get("qty", 1))
            except (TypeError, ValueError):
                qty = 1
            # ↑↑↑ 正确做法：单价只从 CATALOG 取；
            #     数量要校验成正整数、并且设上限 ↑↑↑

            paid = round(unit_price * qty, 2)
            add_order(item, name, list_price, qty, paid)

            # 判定：实付比标价低（含数量为负导致总价为负的情况）
            if paid < round(list_price * max(qty, 0), 2) - TOLERANCE:
                ctx.progress.mark(GOAL)
            elif qty < 0:
                ctx.progress.mark(GOAL)

            return render_template(
                "index.html",
                catalog=[
                    {"key": k, "name": v[0], "price": "%.2f" % v[1]}
                    for k, v in CATALOG.items()
                ],
                orders=all_orders(),
                error=None,
                last={
                    "name": name,
                    "list_price": "%.2f" % list_price,
                    "unit_price": "%.2f" % unit_price,
                    "qty": qty,
                    "paid": "%.2f" % paid,
                },
            )

        @app.route("/清空", methods=["POST"])
        def clear():
            con = sqlite3.connect(db_path)
            try:
                con.execute("DELETE FROM orders")
                con.commit()
            finally:
                con.close()
            return render_template(
                "index.html",
                catalog=[
                    {"key": k, "name": v[0], "price": "%.2f" % v[1]}
                    for k, v in CATALOG.items()
                ],
                orders=[], error=None, last=None,
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        """直接从订单表推：有没有哪一单的实付低于标价。

        能从业已存在的状态推出来的，就别另存一份进度。
        """
        try:
            orders = all_orders_of(ctx)
        except sqlite3.Error:
            return {GOAL: False}
        for o in orders:
            if o["qty"] < 0:
                return {GOAL: True}
            if o["paid"] < round(o["unit_price"] * max(o["qty"], 0), 2) - TOLERANCE:
                return {GOAL: True}
        return {GOAL: False}


def all_orders_of(ctx):
    con = sqlite3.connect(str(ctx.workspace / DB_NAME))
    con.row_factory = sqlite3.Row
    try:
        return [
            dict(r)
            for r in con.execute(
                "SELECT item_name, unit_price, qty, paid FROM orders"
            )
        ]
    finally:
        con.close()

