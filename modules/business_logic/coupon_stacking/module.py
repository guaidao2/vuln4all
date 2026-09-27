"""优惠券叠加 —— 业务逻辑漏洞系列之二。

业务场景是"积分商城的优惠券"。

规则白纸黑字写在页面上：**一次只能用一张券，同一张券不能用两次。**

而代码只做了一件看起来天经地义的事：把请求里出现的每一张券都减一遍。
它没有查重、没有查互斥、也没有查"这张券是不是你的"。

这一题跟 `business_logic/price_tamper` 的区别：

  · 那道题是「某个**数值**不该由客户端给」
  · 这一题是「**组合**不该由客户端决定」—— 数值没一个越界，
    但把合法的值**凑在一起**就出问题了

这是业务逻辑漏洞里更难防的一类：每个单独校验都对，缺的是「组合校验」。
"""

import sqlite3
from datetime import datetime

from vuln4all import Vuln, render_template, request

DB_NAME = "shop.db"

#: 购物车里就一件商品：单价 300.00。
GOODS_NAME = "年度会员（12 个月）"
GOODS_PRICE = 300.00

#: 优惠券表。规则是「一次只能用一张，同一张不能用两次」。
COUPONS = {
    "FULL200": ("满 200 减 50", 50.00),
    "NEW30": ("新用户立减 30", 30.00),
    "VIP20": ("会员额外减 20", 20.00),
}

#: 只用一张券能到的最低价 —— 判定基准。实付低于它就说明券被叠加了。
BEST_SINGLE = GOODS_PRICE - max(d for _, d in COUPONS.values())

#: 浮点比较留一点零头。
TOLERANCE = 0.01

GOAL = "用叠加或者重复的方式，把实付压到「只用一张券」的最低线以下"


class CouponStacking(Vuln):
    info = {
        "name": "优惠券叠加",
        "author": ["guaidao2"],
        "cwe": "CWE-840",
        "owasp": "A04:2021 - Insecure Design",
        "difficulty": "进阶",
        "description": (
            "下单时可以填优惠券，服务端把请求里出现的每一张都减一遍。\n"
            "规则说「一次只能用一张、同一张不能用两次」，但代码里"
            "既没查重也没查互斥 —— 它只管把收到的券全减掉。"
        ),
        "hint": (
            "先在页面上正常用一张券，看实付变成多少。\n"
            "然后注意表单里那个字段的**名字** —— 如果同一个字段名在请求里"
            "出现**两次**，服务端会怎么做？\n"
            "（用浏览器的开发者工具看看那个请求；或者用 curl 手写一遍。\n"
            "  关键词：`request.form.getlist(...)` 和 `request.form.get(...)`\n"
            "  的区别。）\n"
            "再想想：既然能填两张不同的券，能不能填两张**一样**的？"
        ),
        "solution": (
            "一、先正常用一张券，记下实付：\n\n"
            "     300.00 - 50.00（FULL200）= 250.00\n\n"
            "   所以「只用一张券」能到的最低价是 250.00。要通关就得比它更低。\n\n"
            "二、绕过一：两张不同的券一起用。\n\n"
            "   表单字段叫 `coupon`，而 HTTP 允许同一个名字出现多次：\n\n"
            "   curl -X POST \\\n"
            "        --data-urlencode 'coupon=FULL200' \\\n"
            "        --data-urlencode 'coupon=NEW30' \\\n"
            "        '<下单地址>'\n\n"
            "   服务端把两张都减了：300 - 50 - 30 = 220.00。\n"
            "   规则说这两张互斥，但代码里没有任何地方检查了这件事。\n\n"
            "三、绕过二更简单：把**同一张券**用两次。\n\n"
            "   curl -X POST \\\n"
            "        --data-urlencode 'coupon=FULL200' \\\n"
            "        --data-urlencode 'coupon=FULL200' \\\n"
            "        '<下单地址>'\n\n"
            "   300 - 50 - 50 = 200.00。同一张券被重复核销了两次。\n\n"
            "四、还有一条更隐蔽的：**三张全上**。\n\n"
            "   FULL200 + NEW30 + VIP20 = 300 - 100 = 200.00\n\n"
            "   如果优惠券多一点，价格能压到 0 甚至负数。\n\n"
            "为什么代码会这样：\n\n"
            "  因为 `request.form.getlist('coupon')` 返回的是一个**列表**，\n"
            "  而开发者下意识觉得「一个字段就是一个值」。\n"
            "  他把列表里的每一项都减了 —— 代码没错，**心智模型错了**。\n\n"
            "这一类漏洞怎么系统性地找（值得背下来）：\n\n"
            "  一、**单个值都合法，组合起来呢？**\n"
            "     两张互斥的券、一个折扣加一个满减、一张券加一次积分抵扣。\n"
            "  二、**同一个东西能提交几次？**\n"
            "     同一个参数名多次出现、同一个请求重复发送\n"
            "     （后者去看 `race_condition/coupon_redeem`）。\n"
            "  三、**顺序能换吗？**\n"
            "     先打折再满减，跟先满减再打折，结果不一样。\n"
            "     如果服务端按「请求里出现的顺序」算，那顺序就由客户端决定了。\n"
            "  四、**有没有上限？**\n"
            "     折扣总额能不能超过商品价格？能不能变成负数？\n"
            "  五、**「互斥」是写在文档里的，还是写在代码里的？**\n"
            "     这一题的互斥只写在页面上 —— 那就是没写。"
        ),
        "refs": [
            "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
            "https://cwe.mitre.org/data/definitions/840.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE orders (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                goods       TEXT NOT NULL,
                list_price  REAL NOT NULL,
                coupons     TEXT NOT NULL,
                discount    REAL NOT NULL,
                paid        REAL NOT NULL,
                created     TEXT NOT NULL
            );
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def add_order(coupons, discount, paid):
            con = sqlite3.connect(db_path)
            try:
                con.execute(
                    "INSERT INTO orders (goods, list_price, coupons, discount, paid, created)"
                    " VALUES (?,?,?,?,?,?)",
                    (
                        GOODS_NAME, GOODS_PRICE, ",".join(coupons) or "（无）",
                        discount, paid, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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
                        "SELECT goods, coupons, discount, paid, created"
                        " FROM orders ORDER BY id DESC"
                    )
                ]
            finally:
                con.close()

        def render(error=None, last=None):
            return render_template(
                "index.html",
                goods=GOODS_NAME,
                price="%.2f" % GOODS_PRICE,
                coupons=[{"code": k, "desc": v[0], "amount": "%.2f" % v[1]}
                         for k, v in COUPONS.items()],
                best_single="%.2f" % BEST_SINGLE,
                orders=all_orders(),
                error=error,
                last=last,
            )

        @app.route("/")
        def index():
            return render()

        @app.route("/order", methods=["POST"])
        def order():
            # ↓↓↓ 洞就在这里：把请求里出现的每一张券都减一遍 ↓↓↓
            codes = request.form.getlist("coupon")
            applied, discount, unknown = [], 0.0, []
            for code in codes:
                code = code.strip()
                if not code:
                    continue
                if code in COUPONS:
                    applied.append(code)
                    discount += COUPONS[code][1]
                else:
                    unknown.append(code)
            # ↑↑↑ 正确做法：先按业务规则收敛成一组合法的券，
            #     再算折扣，而且要把结果**夹在 [0, 原价]** 之间 ↑↑↑

            unknown_note = None
            if unknown:
                unknown_note = "不认识的券被忽略了：" + "、".join(sorted(set(unknown)))

            discount = round(discount, 2)
            paid = round(GOODS_PRICE - discount, 2)
            add_order(applied, discount, paid)

            return render(
                error=unknown_note,
                last={
                    "codes": applied,
                    "discount": "%.2f" % discount,
                    "paid": "%.2f" % paid,
                    "stacked": paid < BEST_SINGLE - TOLERANCE,
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
            return render()

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        """直接从订单表推：有没有哪一单的实付低于「只用一张券」的最低线。

        用「低于基准」而不是「用了多张券」来判，是因为重复用同一张券
        同样算叠加 —— 而那样订单里的券列表看起来只有一张。
        """
        try:
            orders = all_orders_of(ctx)
        except sqlite3.Error:
            return {GOAL: False}
        return {GOAL: any(o["paid"] < BEST_SINGLE - TOLERANCE for o in orders)}


def all_orders_of(ctx):
    con = sqlite3.connect(str(ctx.workspace / DB_NAME))
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute("SELECT paid FROM orders")]
    finally:
        con.close()
