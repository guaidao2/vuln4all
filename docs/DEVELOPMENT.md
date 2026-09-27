# vuln4all 模块开发指南

一个模块 = `modules/` 下的一个目录。放进去，重启靶场，它就出现在首页清单里。
不用登记，不用改 core。

---

## 1. 快速开始

```bash
python3 main.py new sqli/login_bypass
```

生成三个文件：

```
modules/sqli/login_bypass/
├── module.py             必需，题目本体
├── templates/index.html  页面
└── writeup.md            教学文档（可选，但建议写）
```

骨架**不改一行就能跑**，`doctor` 也会通过。先让能跑的东西立起来，再往上加洞。

把里面的 TODO 填掉，然后：

```bash
python3 main.py doctor                # 体检：契约、挂载冲突、没填完的占位文本……
python3 main.py run                   # 起靶场看一眼
```

---

## 2. module.py 长什么样

```python
"""一句话说清这题在教什么。"""

from vuln4all import Vuln, render_template, request


class LoginBypass(Vuln):
    info = {
        "name": "登录处的 SQL 注入",
        "author": ["你的名字"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "difficulty": "入门",
        "description": "一句话说清漏洞在哪。",
        "hint": "给做题的人的提示：先试什么、观察什么。别直接给答案。",
        "solution": "具体怎么打通，最好给一条能直接复制的 payload。",
        "refs": ["https://portswigger.net/web-security/sql-injection"],
    }

    def setup(self, ctx):
        """首次运行和每次 reset 之后各调一次。造初始数据放这儿。"""
        (ctx.workspace / "data.db").write_bytes(b"...")

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/")
        def index():
            return render_template("index.html")

        return {"": app}
```

一个目录里**只能有一个** `Vuln` 子类。写多了 `doctor` 会报错并列出所有候选，
免得你不确定加载的是哪个。

模块目录里还可以放：

```
templates/          你的模板（会被优先查找）
requirements.txt    额外依赖，一行一个包名
```

---

## 3. `info`

| 字段 | 必需 | 类型 | 说明 |
|---|---|---|---|
| `name` | 是 | str | 题目名。显示在清单页和题目页 |
| `description` | 是 | str | 一句话说清漏洞在哪 |
| `author` | 推荐 | list[str] | 出题人。写你自己的名字或 ID |
| `cwe` | 推荐 | str | 例如 `CWE-89` |
| `owasp` | 推荐 | str | 例如 `A03:2021 - Injection` |
| `difficulty` | 推荐 | str | `入门` / `进阶` / `困难` |
| `hint` | 推荐 | str | 提示。渲染成默认折叠的折叠区 |
| `solution` | 推荐 | str | 解法。渲染成默认折叠的折叠区 |
| `refs` | 推荐 | list[str] | 参考资料链接 |
| `mounts` | 可选 | dict | 覆盖挂载路径、标记隐藏入口，见第 6 节 |

几点：

- **`hint` / `solution` 是这题的教学主体**，会渲染成题目页上的两个折叠区。
  `hint` 写"先试什么、观察什么"，别直接把答案写进去；`solution` 给一条能直接
  复制的 payload。
- **`description` / `hint` / `solution` 支持一点点标记**，因为纯文本里表达不了
  强调，而这三处正是最需要强调的地方。只认两种：

  | 写法 | 渲染成 |
  |---|---|
  | `**加粗**` | `<strong>加粗</strong>` |
  | `` `等宽` `` | `<code>等宽</code>` |

  换行原样保留，所以 `solution` 里那些缩进对齐的 payload 能保持形状。
  **不是完整的 Markdown**（没有列表、链接、表格）——故意的，说明文字不需要那些。
  其余内容一律按纯文本转义，写尖括号不会变成标签。
  一个细节：加粗那一对星号前后不能紧跟着 `/`，所以 SQL 里那种
  `UNION/**/SELECT` 不会被误当成加粗。
- **`difficulty` 只是标签**，不影响任何行为，只影响清单页上的徽标和筛选按钮。
  填别的值也能跑，`doctor` 会提醒一句。
- `author` 写你自己的名字 —— 这是别人知道"这题谁出的"的唯一途径。

---

## 4. `create_app(ctx)`

**必需。** 返回 `{挂载键: WSGI 应用}`。

```python
def create_app(self, ctx):
    app = ctx.flask(__name__)
    ...
    return {"": app}                       # 只有一个入口
    # 或者
    return {"": portal, "attacker": evil}  # 多个入口
```

硬性要求（不满足会被判成"加载失败"，但不影响其他题目）：

- 返回值是非空 `dict`
- 键是字符串
- 值可调用（Flask 应用、裸 WSGI callable 都行）
- **必须有 `""` 这个键** —— 主挂载点，清单页只会链到它

框架在路由这一层只做一件事：**按路径前缀把请求分发给你**。模块对外就是一个
独立的 WSGI 应用，`SCRIPT_NAME` 已经设好了 —— 所以你应用内部用 Flask 的
`url_for()` 生成的 URL 自带正确前缀，不用关心自己被挂在哪。

---

## 5. `ctx` 能给你什么

| 成员 | 说明 |
|---|---|
| `ctx.id` | 模块 id，例如 `sqli/login_bypass` |
| `ctx.info` | 你的 `info` |
| `ctx.workspace` | 模块私有目录。**所有持久化都放这儿** |
| `ctx.log` | 日志器，名字是 `vuln4all.<模块id>` |
| `ctx.url(键, 路径)` | 生成 URL。跨挂载点必须用它 |
| `ctx.mount_path(键)` | 某个挂载键的 URL 前缀 |
| `ctx.is_hidden(键)` | 这个挂载点是不是隐藏的 |
| `ctx.flask(import_name, mount="")` | 建一个接好 core 的 Flask 应用 |
| `ctx.progress` | 通关进度。见第 8 节 |

`ctx.flask()` 帮你做了四件事，**优先用它，不要手动 `Flask(__name__)`**：

1. 模板 loader 链：你的 `templates/` 优先，找不到再找 core 的。
   所以 `{% extends "vuln4all/base.html" %}` 直接能用。
2. 注入模板全局变量：`VULN` / `V4A_HOME` / `V4A_STATIC` / `V4A_STATUS` /
   `V4A_RESET` / `V4A_CHECK` / `V4A_DIFF_KEY` / `V4A_BANNER`。
3. **按挂载点隔离 session cookie 的名字和路径。**
4. 建好 `ctx.workspace` 目录。

---

## 6. 挂载点与 URL

### 默认规则

| 挂载键（`create_app()` 返回的键） | 最终路径 |
|---|---|
| `""` | `/v/<模块id>/` |
| 其他任意键 | `/v/<模块id>/<键>/` |

模块 id 就是它在 `modules/` 下的相对路径。`modules/sqli/login_bypass` 的 id 是
`sqli/login_bypass`，主挂载点是 `/v/sqli/login_bypass/`。

### 覆盖路径 / 隐藏入口

```python
info = {
    "mounts": {
        "attacker": {"path": "/evil-site"},                      # 换个路径
        "internal": {"path": "/internal-admin", "hidden": True},  # 不出现在清单页
    },
}
```

想伪装成"另一个站点"或者"内网服务"就用这个。改了路径就得自己保证不跟别人撞。

### 生成 URL

| 场景 | 用什么 |
|---|---|
| 自己应用内部的路由 | `url_for('函数名')`（Flask 自带） |
| 跨挂载点（去另一个入口） | `ctx.url("键名", "/路径")` |

`ctx.url()` 是给跨挂载点用的 —— 另一个入口是**另一个应用**，`url_for` 看不到它。

```python
ctx.url("", "/login")       # -> /v/sqli/login_bypass/login
ctx.url("attacker", "/")    # -> /evil-site/
```

**不要手写以 `/` 开头的路径。** 挂载路径是框架分配的，你硬编码它就等于把框架的
决定抄进了自己的代码 —— 哪天挂载点改了，链接会变成 404，而且没有任何报错。
`doctor` 会把这种写法报成警告。

指向 `/__vuln4all/...` 是允许的，那是框架自己的固定路径。

### 挂载点冲突会怎样

路径精确等于 `/` 或 `/v`、撞上 `/__vuln4all` 前缀、或者已被别的模块占用 ——
这几种情况那个挂载点会被**直接摘掉**（不是只记一条警告），`doctor` 报 ERROR。

只摘掉冲突的那一个，不牵连你的其他入口；但如果被摘掉的是主挂载点（`""`），
整个模块判加载失败。

---

## 7. 数据放哪

每个模块有一个私有目录：

```
workspace/<模块id>/
```

（模块 id 里的 `/` 会展开成目录层级，所以 `sqli/login_bypass` 的私有目录就是
`workspace/sqli/login_bypass/`。）

模块所有持久化的东西 —— sqlite、上传的文件、日志 —— 都放这里，
用 `ctx.workspace` 拿到这个路径。**不要往靶场目录的其他地方写文件。**

重置一道题时，框架做这几件事：

```
摘掉初始化标记（.initialized）
      |
      v
调用你自己的 reset(ctx)（如果实现了）
      |
      v
清空 workspace/<模块id>/
      |
      v
重新调用你的 setup(ctx)
      |
      v
写回 .initialized
```

所以：**只要 `setup()` 是可重复执行的，你就一行 reset 代码都不用写。**
页面上那个「重置这题」按钮和 `python3 main.py reset <id>` 都是走这条路。

### 什么时候必须自己写 `reset(ctx)`

**只有模块在进程内存里留了状态时才需要。** 上面那套清不掉 Python 的模块级变量：

```python
_STATE = {"balance": 0}
_LOCK = threading.Lock()

def reset(self, ctx):
    with _LOCK:
        _STATE.update(balance=0)
```

参考 `modules/race_condition/coupon_redeem/module.py`。

---

## 8. 记录通关进度：`check()` 与 `ctx.progress`

`check()` 让靶场能机器可读地判断"这道题有没有被打穿"。三个地方会用到它：

```
python3 main.py check [<id>] [--json]
GET /__vuln4all/check  和  /__vuln4all/check/<模块id>
题目页上的「进度」区块
```

**不实现也能跑** —— 那这道题就不出现在进度统计里（`supported: false`）。

### 返回值

```python
def check(self, ctx):
    return True / False                    # 是否通关
    # 或者
    return {"目标名": True/False, ...}      # 每个小目标的达成情况
```

给 dict 时，"通关" = 所有目标都达成。所以只把"必须做到"的事列进来，
纯技巧性的东西别塞进去，否则会抬高通关门槛。

### 两条硬性约束

1. **无副作用、可重复调用。** 同一个状态下调两次必须得到同样的结果。
   `doctor` 会真的连着调两次，并且比对 workspace 的文件指纹。
2. **不能依赖 request / session。** 它回答的是"服务端现在是什么状态"，
   不是"某个浏览器刚才做了什么"。

### 两种实现风格

**能从现有状态推出来的，直接推**（少一份状态，就少一处会和真实情况不一致的地方）：

```python
def check(self, ctx):
    uploads = ctx.workspace / "uploads"
    landed = [p for p in uploads.iterdir() if p.is_file()]
    return {"让危险后缀的文件落进了上传目录":
            any(p.suffix.lower() in BLOCKED_EXTENSIONS for p in landed)}
```

**需要记的，在处理请求时记一笔**：

```python
GOAL = "以 admin 身份登录，绕过了密码检查"     # 一个常量，mark 和 check 共用

# 在请求处理里
if row[1] == "admin":
    ctx.progress.mark(GOAL)

# 在 check 里
def check(self, ctx):
    return {GOAL: ctx.progress.achieved(GOAL)}
```

`ctx.progress` 的接口：

```python
ctx.progress.mark("目标名")        # 记一笔，返回 True 表示这次确实记上了
ctx.progress.achieved("目标名")    # 读，返回 bool
ctx.progress.all()                 # {"目标名": True} 的快照
```

进度落在 `workspace/<模块id>/progress.json`，**所以清空 workspace 的时候顺手
就被带走了** —— 你不需要为了进度写 `reset()`。

### 目标名怎么写

它会渲染到题目页的「进度」区块上，所以：

- 写清楚，别只写 `solved`
- **不要把 payload 字面量嵌进去**（别写 `uid=`、`{{7*7}}` 这种）。
  那些字符串会出现在页面上，干扰按内容做的测试断言。

参考实现：`modules/upload/avatar`（从状态推）、`modules/sqli/login_bypass`（记进度）。

---

## 9. 页面

模块模板继承 core 的外壳就行：

```jinja
{% extends "vuln4all/base.html" %}
{% block title %}登录{% endblock %}

{% block content %}
<h1>员工登录</h1>
<form method="post" action="{{ url_for('index') }}">
  <p><label>用户名<br><input type="text" name="username"></label></p>
  <p><label>密码<br><input type="password" name="password"></label></p>
  <p><button type="submit" class="btn">登录</button></p>
</form>
{% endblock %}
```

白拿这些东西：顶栏、题目页头（题目名、模块 id、难度、CWE、OWASP、描述）、
「重置这题」按钮、「提示」和「答案」两个折叠区（从 `info` 自动渲染）、
「进度」区块、页脚。

`base.html` 只有 `title` 和 `content` 两个 block。

### 可用的类名

这些是框架提供的样式，直接用：

| 类名 | 用途 |
|---|---|
| `btn` / `btn-ghost` | 按钮 / 次要按钮 |
| `payload` | 命令行、payload、代码块这类等宽文本块 |
| `findings` | 数据表格（`<table class="findings">`） |
| `mono` / `muted` / `small` / `err` / `ok` | 文字样式 |
| `badge` / `tag` | 小徽标 |
| `badge-cwe` / `badge-owasp` / `badge-hidden` / `badge-solved` | 带色徽标 |
| `notice` / `notice-ok` / `notice-bad` | 提示框 |
| `cards` / `card` / `card-title` / `card-meta` / `card-desc` | 卡片 |
| `refs` | 参考资料列表 |

想跟外壳风格一致就用 `style.css` 里的 CSS 变量，别写死颜色：

```css
var(--bg) var(--surface) var(--surface-2) var(--line)
var(--fg) var(--fg-2) var(--muted)
var(--accent) var(--cyan) var(--ok) var(--warn) var(--bad)
```

### 一条约定：模块模板不要用 `<details>`

「提示 / 答案」折叠区用的是 `<details>`，答案文本就在里面。为了让"页面里
有没有某个字符串"这类断言有意义，测试会在断言前把所有 `<details>` 剥掉。
你的模板如果也用 `<details>` 装关键内容，会被一起剥掉。

---

## 10. `doctor` 会挑什么毛病

```bash
python3 main.py doctor [<模块id>] [--no-smoke]
```

有 ERROR 时退出码非 0，可以直接挂 CI。

| 级别 | 检查项 |
|---|---|
| ERROR | 模块加载失败（导入报错、找不到 `Vuln` 子类、`create_app` 返回值不对） |
| ERROR | `info` 缺 `name` 或 `description` |
| ERROR | 挂载点冲突 / 抢占保留前缀 / 多挂载点忘了传 `mount=` |
| ERROR | 没有算出任何挂载点 |
| ERROR | `workspace` 不可写 |
| ERROR | 模块目录里的 `requirements.txt` 有依赖没装 |
| ERROR | 冒烟请求（`GET /`）返回 5xx 或抛异常 |
| ERROR | `check()` 抛异常，或者返回了 `bool` / `dict` 之外的东西 |
| WARN | `info` 里还留着脚手架生成的 `TODO` 占位文本 |
| WARN | 硬编码了以 `/` 开头的绝对路径 |
| WARN | `difficulty` 填了非标准值 |
| WARN | `check()` 连着调两次结果不一样，或者动了 workspace 里的东西 |
| INFO | 推荐填的 `info` 字段缺失 |
| INFO | 每个挂载点冒烟通过 |
| INFO | `check()` 当前的通关状态 |

一个模块出错不影响其他模块 —— 框架会照常起靶场，坏模块在清单页上显示成
"加载失败"并带上具体原因。

---

## 11. 常见问题

**模块没出现在清单页上**

看清单页底部的「需要注意」，或者跑 `python3 main.py doctor`。最常见的是
`module.py` 没放在正确的层级（必须是 `modules/<分类>/<名字>/module.py`）。

**提示"挂载点被摘掉了"**

撞上了保留前缀（`/__vuln4all`）、精确占用了 `/` 或 `/v`、或者跟别的模块撞了。
换一个 `info["mounts"]["..."]["path"]`。

**两个挂载点的登录状态串了**

`create_app()` 里第二个 app 忘了传 `mount=`：

```python
return {"": portal, "attacker": ctx.flask(__name__, mount="attacker")}
#                                        ^^^^^^^^^^^^^^^^
```

不传的话两个 app 共用同一个 session cookie 名字和路径，`doctor` 会报 ERROR。

**重置之后数据还在**

数据写到 `ctx.workspace` 外面去了。框架的重置只清那个目录。

**`check()` 被报"动了 workspace 里的东西"**

`check()` 里别写文件、别调 `ctx.progress.mark()`。它是只读查询 ——
记进度要在请求处理里做。

**提交时提示不能有表情符号**

仓库有一条自动检查会拦表情符号，代码、模板、文档都算。别在模块里写。

**写中文文案时字符串报语法错**

多半是把中文引号打成了 ASCII 双引号（`“...”` 打成了 `"..."`），
而外层字符串正好也是双引号，字符串就被截断了。

---

## 12. 照着现成的题写

仓库里 37 道题都是按这份契约写的，可以直接拿来对照：

```
modules/sqli/login_bypass/            字符串拼接 SQL（含 sqlite + seed）
modules/sqli/union_query/             拼 SQL 但**不回显报错**（教"数不清列数时的排查"）
modules/sqli/time_blind/              create_function 注册自定义 SQL 函数 + 只靠耗时判定
modules/sqli/keyword_filter/          模块内自带一份正则规则表当过滤器（拦截式）
modules/xss/reflect_search/           最简：一个模板 + 一个路由
modules/xss/stored_guestbook/         写库再渲染（check() 直接从库推）
modules/xss/dom_based/                服务端不输出 payload；页面自己回报命中
modules/xss/tag_filter/               删除式过滤器 + 一个独立的判定检测器
modules/csrf/password_change/         多挂载点：受害者站 + 攻击者站
modules/csrf/json_api/                多挂载点 + 不看 Content-Type 的 JSON 接口
modules/ssrf/url_preview/             多挂载点 + 隐藏入口 + 自己发 HTTP 请求
modules/ssrf/ip_format_filter/        多挂载点 + 隐藏入口 + 只做字符串匹配的地址校验
modules/upload/avatar/                往 workspace 里写文件 + check() 从状态推
modules/upload/zip_slip/              手写解压循环 + 受保护文件的内容比对
modules/idor/admin_endpoint/          session 里的角色 + 前端隐藏的入口
modules/path_traversal/encoding_filter/ 双重解码 + 应用自己写下载逻辑
modules/command_injection/space_filter/ shell=True 起子进程 + check() 读应用自己写的日志
modules/ssti/sandbox_escape/          继承 SandboxedEnvironment 并放宽（反面教材）
modules/jwt/kid_injection/            手搓 JWT + 按 kid 从目录读密钥
modules/deserialization/pickle_cookie/ 手搓 pickle 载荷 + 从磁盘状态推进度
modules/xxe/svg_preview/              自己实现 EntityResolver（反面教材）
modules/cors/credentials/             手写 CORS 头 + 双挂载点无关（单源）
modules/open_redirect/login_next/     两条件式的"站内跳转"校验（反面教材）
modules/host_header/password_reset/   "受信主机列表" + 自己记邮件箱
modules/business_logic/price_tamper/  全部数值从表单来 + check() 从订单表推
modules/info_leak/backup_files/       静态文件服务 + 故意的 dotfile 残留
modules/business_logic/price_tamper/  客户端给的数值直接信 + check() 从订单表推
modules/business_logic/coupon_stacking/ getlist() 收多个同名字段 + 用「低于基准」判定
modules/business_logic/refund_logic/  退款流水表 + check() 对流水求和
modules/business_logic/state_machine/ 状态转换表 + 一个旁挂的布尔字段当反面教材
modules/upload/tar_symlink/           tarfile.extractall() 不传 filter + 符号链接穿越
modules/race_condition/coupon_redeem/ 模块级内存状态 + 自己实现 reset()
modules/jwt/alg_none/                 手搓 JWT（不引入额外依赖）
```

每道题目录里都有一个 `writeup.md`，是给做题的人看的分题文档 ——
写清楚"这题在教什么、漏洞在哪、怎么打通、怎么修"。它是可选文件，
但留一份能省掉后来人很多时间。
