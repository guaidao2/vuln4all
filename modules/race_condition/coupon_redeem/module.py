"""电商领券接口的竞态条件。

业务场景是"限时优惠券，每个账号只能领一次"：接口先查"领过没有"，
再标记已领、加余额。这是典型的 check-then-act，两步之间有一个窗口。

这道题还顺带演示契约里那个可选钩子：**模块在进程内存里留了状态时，
才需要自己实现 `reset(ctx)`**。常规的"清 workspace + 重跑 setup()"清不掉内存。
"""

import threading
import time

from vuln4all import Vuln, redirect, render_template, request, url_for

COUPON_AMOUNT = 100
#: 故意把窗口放大，否则本地很难稳定打中。现实里这个窗口是微秒级。
WINDOW_SECONDS = 0.05

#: 进程内存里的状态。core 的 reset 清不掉它 —— 所以下面必须实现 reset()。
_LOCK = threading.Lock()
_STATE = {"redeemed": 0, "balance": 0, "attempts": 0}


def _reset_state():
    # 持锁清零：否则一个已经过了检查、正卡在 sleep 里的请求，
    # 会在 reset 之后把 balance 加回去 —— 留下一个"重置了但数字不对"的状态。
    with _LOCK:
        _STATE.update(redeemed=0, balance=0, attempts=0)


class CouponRedeem(Vuln):
    info = {
        "name": "优惠券领取处的竞态条件",
        "author": ["guaidao2"],
        "cwe": "CWE-362",
        "owasp": "A04:2021 - Insecure Design",
        "difficulty": "困难",
        "description": (
            "「每人只能领一次」的判断是「先查、再改」两步。"
            "两个请求同时进来时，它们可以**都**在对方改之前通过检查。"
            "这不是代码写错了，是这段逻辑本身不原子。"
        ),
        "hint": (
            "先手动领一次，看看页面怎么说。然后想：这个「已经领过了」的判断，"
            "和「标记为已领」之间隔了多少时间？\n"
            "如果我在那段时间里再发一次请求，后一个请求看到的还是「没领过」吗？\n"
            "并发地打一批请求试试 —— curl 的 xargs -P、Burp 的 Turbo Intruder、"
            "或者自己写几行 threads 都行。"
        ),
        "solution": (
            "用 curl 并发打 20 次（-P 控制并发数）：\n\n"
            "  seq 20 | xargs -P20 -I{} curl -s -o /dev/null -X POST \\\n"
            "    'http://127.0.0.1:8800/v/race_condition/coupon_redeem/redeem'\n\n"
            "然后刷新页面：余额会大于 100，成功次数大于 1 —— 这题就通了。\n\n"
            "为什么能成：接口是\n"
            "    if 已领: 拒绝        ← 所有并发请求都在这里读到「没领过」\n"
            "    sleep(0.05)          ← 窗口。现实里是微秒级，这里故意放大了\n"
            "    标记已领 + 加余额\n"
            "两个请求同时通过了第一行，于是都执行了后面的加钱。\n\n"
            "Python 的写法也一样：用线程池一次发几十个请求。\n\n"
            "另一种打法（思路不同但同样有效）：\n"
            "  单个请求并发不上去就一边发一边取消，或者用 HTTP/2 的单包多请求\n"
            "  —— 目的是让多个请求在时间上尽量重叠。"
        ),
        "refs": [
            "https://portswigger.net/web-security/race-conditions",
            "https://cwe.mitre.org/data/definitions/362.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        # 首次初始化时把内存状态清零
        _reset_state()

    def reset(self, ctx):
        """core 的常规 reset 只会清 workspace 目录，清不掉 _STATE 这个内存字典。

        所以这道题必须自己实现这个钩子 —— 这正是它存在的意义。
        """
        _reset_state()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/")
        def index():
            with _LOCK:
                snapshot = dict(_STATE)
            return render_template(
                "index.html",
                amount=COUPON_AMOUNT,
                window=int(WINDOW_SECONDS * 1000),
                **snapshot,
            )

        @app.route("/redeem", methods=["POST"])
        def redeem():
            with _LOCK:
                _STATE["attempts"] += 1

            # ↓↓↓ 洞就在这里：check 和 act 之间不是原子的 ↓↓↓
            if _STATE["redeemed"]:                       # ① 检查
                return redirect(url_for("index"))
            time.sleep(WINDOW_SECONDS)                   # ② 窗口
            with _LOCK:                                  # ③ 动手
                _STATE["redeemed"] += 1
                _STATE["balance"] += COUPON_AMOUNT
            # ↑↑↑ 正确做法：把 ①②③ 放进同一把锁里，或者用数据库的原子操作：
            #     UPDATE coupons SET used=1 WHERE user=? AND used=0
            #     然后看 rowcount —— 影响行数为 0 就说明没抢到 ↑↑↑

            return redirect(url_for("index"))

        return {"": app}
