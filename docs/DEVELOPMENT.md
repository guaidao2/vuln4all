# vuln4all 开发文档

面向**要往这个靶场里加题目、改 core、或者接着往下做**的人。

如果你只是想跑起来打靶，看 [README](../README.md) 就够了。

作者：guaidao2

---

## 目录

1. [这是什么，设计取向是什么](#1-这是什么设计取向是什么)
2. [十分钟加一道题](#2-十分钟加一道题)
3. [架构总览](#3-架构总览)
4. [模块契约（API 参考）](#4-模块契约api-参考)
5. [挂载与 URL](#5-挂载与-url)
6. [状态与生命周期](#6-状态与生命周期)
7. [前端与模板](#7-前端与模板)
8. [运行配置与局域网模式](#8-运行配置与局域网模式)
9. [命令行参考](#9-命令行参考)
10. [开发流程](#10-开发流程)
11. [doctor 会检查什么](#11-doctor-会检查什么)
12. [验证脚本 verify.sh](#12-验证脚本-verifysh)
13. [部署到远端主机](#13-部署到远端主机)
14. [踩过的坑](#14-踩过的坑)
15. [设计原则与已知边界](#15-设计原则与已知边界)

---

## 1. 这是什么，设计取向是什么

vuln4all 是一个**模块化的 Web 漏洞靶场**：类似 DVWA 的定位（给新手练 Web 安全），
类似 Metasploit 的模块体系（丢一个模块进目录，不用改框架）。

三条贯穿全项目的取向，理解了这三条，后面所有设计选择都能自己推出来：

**一、加一道题 = 丢一个目录。**

没有中央注册表、没有清单文件、不改 core、不碰别人的文件。
`modules/<分类>/<名字>/module.py` 放进去，重启靶场就出现在首页。
这是整个项目的核心卖点，任何会削弱它的设计都会被拒掉。

**二、自包含比 DRY 值钱。**

允许模块之间复制粘贴代码。有人想改 SQLi 那题，不该先去理解一个共享抽象层。
只有真属于框架的东西（页面外壳、`ctx`）才放 core。

**三、契约要窄，默认要安全。**

这条跟作者是谁没关系。理由是**框架自己制造了一种隐式的跨层耦合**：

挂载路径是框架分配的（`/v/<模块id>/`，或者被 `info["mounts"]` 覆盖成任意路径），
而模块的代码在另一个地方。模块一旦把路径硬编码进去，就等于把"框架的决定"抄进了
"模块的实现"—— 将来挂载点一改，坏掉的方式是**静默**的：链接指向 404，
没有任何异常、没有任何日志。

**任何人对着任何框架都会踩这种坑。** 资深开发也一样，只是踩得少一点、找得快一点；
而这类错误的特点是"找得到但要花时间"，所以更划算的做法是让它从一开始就不可能发生：

- 默认值可预测，让"不写"就是对的
- 跨挂载点只有一个写法（`ctx.url()`），没有第二种选择要记
- 工具主动把这类耦合挑出来（`doctor` 会警告硬编码的绝对路径）

同样的思路也解释了另外几条：session 自动按挂载点隔离、挂载冲突硬拦、
`check()` 连着调两次会被验一遍。**这些都不是在防某个水平的人，是在防某一类错误。**

本项目的约定（跟技术无关，写在这里免得后来的人猜）：

- **代码、模板、文档里不出现表情符号。** `verify.sh` 第 12 步会自动检查。
- **`info["author"]` 写你自己的名字。** 这是别人知道"这题谁出的"的唯一途径。
  仓库里现有模块的作者都是各自的出题人（最早那批是 `guaidao2`）。

---

## 2. 十分钟加一道题

```bash
python3 main.py new xss/dom_based     # 生成骨架
```

生成三个文件：

```
modules/xss/dom_based/
├── module.py            # 题目本体
├── templates/index.html # 页面
└── writeup.md           # 教学文档（提示 / 解法 / 修法）
```

骨架**不改一行就能跑**，`doctor` 也会通过。先把能跑的东西放进去，再往上加洞。

接着把 `module.py` 里的 TODO 填掉：

```python
"""一句话说清这题在教什么。"""

from vuln4all import Vuln, render_template, request


class DomBased(Vuln):
    info = {
        "name": "页面标题",
        "author": ["你的名字"],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "difficulty": "入门",           # 入门 / 进阶 / 困难
        "description": "一句话说清漏洞在哪。",
        "hint": "给做题的人的提示：先试什么、观察什么。别直接给答案。",
        "solution": "具体怎么打通，最好给一条能直接复制的 payload。",
        "refs": ["https://portswigger.net/web-security/..."],
    }

    def setup(self, ctx):
        """首次运行和 reset 之后各调一次。造初始数据放这儿。"""
        (ctx.workspace / "data.txt").write_text("...", encoding="utf-8")

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/")
        def index():
            return render_template("index.html")

        return {"": app}      # 键 "" 是主挂载点
```

然后：

```bash
python3 main.py doctor        # 体检
python3 main.py run           # 起靶场看效果
bash tools/verify.sh          # 端到端验证（会起服务、逐题打一遍）
```

---

## 3. 架构总览

### 3.1 目录结构

```
vuln4all/
├── main.py                      # 主入口（python3 main.py 就是起靶场）
├── vuln4all.ini.example         # 运行配置模板
├── vuln4all/                    # core
│   ├── __init__.py              # 对模块作者公开的 API（Vuln / Flask / 常用工具）
│   ├── __main__.py              # python3 -m vuln4all
│   ├── contract.py              # Vuln 基类 + Ctx（模块契约）
│   ├── config.py                # 运行配置 + 本机 IP 探测
│   ├── registry.py              # 发现 modules/、加载、算挂载点、查冲突、reset
│   ├── loader.py                # importlib 动态导入，坏模块不拖垮全家
│   ├── host.py                  # 前缀分发，拼成一个 WSGI 应用
│   ├── ui.py                    # 清单页 / 体检页 / 重置入口 / 静态资源
│   ├── doctor.py                # 体检
│   ├── scaffold.py              # new 子命令的骨架生成
│   ├── cli.py                   # 命令行
│   ├── templates/vuln4all/      # 统一外壳（base.html 等）
│   └── static/style.css         # 设计系统
├── modules/                     # 所有题目
├── tools/
│   ├── deploy.py                # 推到远端主机（本机不跑靶场）
│   └── verify.sh                # 端到端验证
└── workspace/                   # 运行时生成，每道题的私有数据
```

### 3.2 一次请求的完整路径

```
浏览器
   |
   v
werkzeug run_simple(threaded=True)          cli.py:cmd_run
   |
   v
DispatcherMiddleware                         host.py:build
   |  按**最长前缀**匹配 mount_map()
   |  设置 SCRIPT_NAME / PATH_INFO
   |
   +--> "/"                     -> core Flask app        ui.py
   |       "/"                        首页（清单页）
   |       "/__vuln4all/status"       体检页
   |       "/__vuln4all/reset"        POST 重置入口
   |       "/__vuln4all/reset-done"   重置完成页
   |       "/__vuln4all/static/*"     样式表
   |
   +--> "/v/sqli/login_bypass"  -> 该模块自己的 WSGI app
   +--> "/evil-site"            -> csrf/password_change 的第二个 app
   +--> "/internal-admin"       -> ssrf/url_preview 的隐藏 app
```

**关键点**：core 不解析模块内部的路由。它只做前缀分发。
每个模块对外就是一个普通的 WSGI 应用，挂在自己的前缀上。

好处：

- 模块内部爱用什么框架用什么（v1 只支持 WSGI）
- 因为 `SCRIPT_NAME` 被设好了，模块内部用 Flask 的 `url_for()` 生成的 URL
  **自动带正确前缀**，模块作者不用关心自己被挂在哪
- 以后要换成子进程/容器隔离，只需把这个「应用对象」换成「反向代理到某端口」，
  接口不变

### 3.3 core 各文件职责

| 文件 | 职责 | 关键函数 |
|---|---|---|
| `contract.py` | 定义模块形状：`Vuln` 基类、`Ctx` 运行时上下文 | `Vuln.create_app` / `Ctx.flask` / `Ctx.url` |
| `loader.py` | 按路径导入 `module.py`，隔离加载失败 | `load_vuln_class` |
| `registry.py` | 扫目录、建 `ModuleEntry`、算挂载点、解冲突、调度 reset | `Registry.discover` / `Registry.reset` |
| `host.py` | 组装最终 WSGI 应用 | `build` / `describe_mounts` |
| `ui.py` | core 自己的页面 | `create_core_app` |
| `doctor.py` | 静态检查 + 冒烟请求 | `check` |
| `config.py` | host/port 配置、本机 IP 探测 | `resolve` / `reachable_urls` |
| `scaffold.py` | 生成新题骨架 | `create_module` |
| `cli.py` | 命令行 | `cmd_run` / `cmd_doctor` / ... |

---

## 4. 模块契约（API 参考）

### 4.1 `Vuln` 基类

```python
class Vuln:
    info: dict = {}                            # 见 4.2

    def create_app(self, ctx) -> dict: ...     # 必需
    def setup(self, ctx) -> None: ...          # 可选
    def reset(self, ctx) -> None: ...          # 可选
    def check(self, ctx) -> bool: ...          # 可选
```

一个模块目录下**只能有一个** `Vuln` 子类。写多了 `loader` 会报错并列出所有候选，
以免你不确定加载了哪个。

### 4.2 `info` 字段

| 字段 | 必需 | 类型 | 说明 |
|---|---|---|---|
| `name` | 是 | str | 题目名。显示在清单页和题目页 |
| `description` | 是 | str | 一句话说清漏洞在哪。显示在题目页头部和卡片上 |
| `author` | 推荐 | list[str] | 出题人。写你自己的名字（或者 ID / 主页） |
| `cwe` | 推荐 | str | 例如 `CWE-89`。卡片上会标 |
| `owasp` | 推荐 | str | 例如 `A03:2021 - Injection` |
| `difficulty` | 推荐 | str | `入门` / `进阶` / `困难`。**只是个标签** |
| `hint` | 推荐 | str | 提示。渲染成默认折叠的折叠区 |
| `solution` | 推荐 | str | 解法。渲染成默认折叠的折叠区 |
| `refs` | 推荐 | list[str] | 参考资料链接 |
| `mounts` | 可选 | dict | 覆盖挂载路径、标记隐藏入口。见第 5 节 |

**`difficulty` 不是机制。** core 不会因为难度不同改变任何行为 —— 不打折、不降级、
不放行。它只影响两处渲染（徽标上色、清单页的难度筛选）。填非标准值也能跑，
`doctor` 只会发一条 WARN。

这一条是刻意的：Metasploit 的 `info` 也是纯元数据。一旦让难度变成 core 的行为分支，
就等于给契约加了一个必须处处考虑的维度，会违反第 1 节的原则三。

### 4.3 `create_app(ctx)`

**必需。** 返回 `{挂载键: WSGI 应用}`。

```python
def create_app(self, ctx):
    app = ctx.flask(__name__)
    ...
    return {"": app}                       # 只有一个入口
    # 或者
    return {"": portal, "attacker": evil}  # 多入口
```

硬性要求：

- 返回值必须是**非空 dict**
- 键必须是 str
- 值必须可调用（Flask app / 裸 WSGI callable 都行）
- **主挂载点的键固定是空字符串 `""`**，清单页只会链到它

违反任何一条，`registry` 会把这道题标记为加载失败并给出具体原因，
但**不影响其他题目**。

### 4.4 `setup(ctx)`

可选。**首次运行**和**每次 reset 之后**各调一次，用来造初始数据。

什么时候会被调用：`workspace/<模块id>/.initialized` 这个标记文件不存在时。
所以它应该写成可重复执行的 —— 但不需要防御性地处理"数据已存在"，
因为 core 只在没标记时才调它。

```python
def setup(self, ctx):
    con = sqlite3.connect(str(ctx.workspace / "app.db"))
    con.executescript("""
        CREATE TABLE users (...);
        INSERT INTO users ...;
    """)
    con.commit()
    con.close()
```

### 4.5 `reset(ctx)`

可选，**只有模块在进程内存里留了状态时才需要写**。

core 的常规重置会做：摘掉标记 → 清空 `workspace/<模块id>/` → 重跑 `setup()`。
它清不掉 Python 模块级的全局变量。所以如果你用了模块级状态（比如竞态题用的计数器、
缓存、连接池），必须自己把它归零：

```python
_STATE = {"balance": 0}
_LOCK = threading.Lock()

def reset(self, ctx):
    with _LOCK:
        _STATE.update(balance=0)
```

参考实现：`modules/race_condition/coupon_redeem/module.py`。

### 4.6 `check(ctx)`：机器可读的通关进度

可选。**不实现就返回 `None`。**

这是靶场对外承诺的那个接口 —— 扫描器、AI agent、以及靶场自己的回归测试都靠它
判断"这道题有没有被打穿"。所以它不是"顺手做的好事"，而是有明确约束的合同。

**返回值两种形态：**

```python
def check(self, ctx):
    return True / False                     # 是否通关
    # 或者
    return {"目标名": True/False, ...}       # 每个小目标的达成情况
```

给 dict 时，**"通关" = 所有目标都达成**。所以只把"必须做到"的事列进来；
纯技巧性的东西（比如"用绝对路径那种方式穿越")不要塞进去，否则会抬高通关门槛。

**两条硬性约束：**

1. **必须无副作用，而且可重复调用。** 同一个状态下调两次必须得到同样的结果。
   `doctor` 会真的连着调两次来验证这一点。
2. **不能依赖 request / session。** 它回答的是「服务端现在是什么状态」，
   不是「某个浏览器刚才做了什么」。要记进度就用 `ctx.progress`。

**目标名的注意点：**

目标名会渲染到页面上（题目页的「进度」区块）。所以：

- 写清楚，别只写 `solved`
- **不要把 payload 字面量嵌进去**（例如别写 `uid=`、`{{7*7}}`）。
  验证脚本会按页面内容做断言，目标名里带上这些字符串会污染断言 —— 这个坑踩过一次。

**两种实现风格，按题的实际情况选：**

```python
# 风格一：直接从现有状态推（能推就别记，少一份状态少一处会不一致的地方）
def check(self, ctx):
    uploads = ctx.workspace / "uploads"
    landed = [p for p in uploads.iterdir() if p.is_file()]
    return {"让一个危险后缀的文件落进了上传目录":
            any(p.suffix.lower() in BLOCKED_EXTENSIONS for p in landed)}


# 风格二：请求处理时记一笔，check 读回来
def check(self, ctx):
    return {GOAL: ctx.progress.achieved(GOAL)}
```

参考实现：`upload/avatar`（风格一）、`sqli/login_bypass`（风格二）。

### 4.7 `ctx.progress`：通关进度

```python
ctx.progress.mark("目标名")        # 记一笔，返回 True 表示这次是新达成的
ctx.progress.achieved("目标名")    # 读
ctx.progress.all()                 # {"目标名": True} 的快照
```

它落在 `workspace/<模块id>/progress.json`。**用文件而不是内存变量是有意的：**

- `reset` 会清空整个 workspace，**进度自动归零** —— 模块不用为了进度去实现
  `reset()` 那个钩子
- 重启靶场不丢

多线程安全（内部有锁，写盘用原子替换）。

用它还是直接用现有状态？**能从状态推出来的就别存**。存一份就意味着多一处会和
真实情况不一致的地方。`upload/avatar` 就是从上传目录推的，文件被删了进度自然回退。

### 4.8 check 的对外接口

三处入口，都是同一份数据（内部都走 `Registry.check_report()`）：

**命令行**

```bash
python3 main.py check                  # 人类可读
python3 main.py check --json           # 机器可读
python3 main.py check sqli/login_bypass
```

退出码只在**有题目的 check() 出错**时非 0 —— 不是"没全通关就非 0"。
（一道题没被打通是很正常的状态，不该当成命令失败。）

**HTTP**

```bash
GET /__vuln4all/check                  # 整份报告
GET /__vuln4all/check/<模块id>         # 单道题
```

单道题返回：

```json
{
  "id": "sqli/login_bypass",
  "name": "登录处的 SQL 注入",
  "difficulty": "入门",
  "cwe": "CWE-89",
  "mount": "/v/sqli/login_bypass",
  "loaded": true,
  "supported": true,
  "solved": true,
  "objectives": { "以 admin 身份登录，绕过了密码检查": true },
  "error": null
}
```

整份报告多三个计数：`total` / `supported` / `solved` / `errored`。

**页面**

清单页顶部显示「已通关 X / Y」，每张已通关的卡片带一个"已通关"徽标；
题目页有「进度」区块（目标清单）。这三处和上面两个接口是同一份数据。

**当 benchmark 用的标准流程：**

```bash
curl -X POST http://<靶场>/__vuln4all/reset --data-urlencode 'id=*'   # 清成初始状态
# ...让被测的扫描器 / agent 去随便打...
curl -s http://<靶场>/__vuln4all/check                                # 读结果
```

`mount` 字段就是给被测方用的入口地址。

### 4.7 `Ctx` 完整 API

| 成员 | 类型 | 说明 |
|---|---|---|
| `ctx.id` | str | 模块 id，例如 `sqli/login_bypass` |
| `ctx.info` | dict | 模块的 `info` |
| `ctx.home` | Path | 靶场根目录 |
| `ctx.workspace` | Path | 模块私有目录。**所有持久化都放这儿** |
| `ctx.log` | Logger | 名字是 `vuln4all.<模块id>` |
| `ctx.mount_path(key="")` | str | 某个挂载键的 URL 前缀（不带结尾斜杠） |
| `ctx.url(key="", path="/")` | str | 生成 URL。跨挂载点必须用它 |
| `ctx.is_hidden(key)` | bool | 这个挂载点是不是隐藏的 |
| `ctx.flask(import_name, mount="")` | Flask | 建一个接好 core 的 Flask 应用 |

`ctx.flask()` 帮你做了四件事，所以**优先用它，不要手动 `Flask(__name__)`**：

1. 模板 loader 链：模块自己的 `templates/` 优先，找不到再找 core 的。
   所以 `{% extends "vuln4all/base.html" %}` 直接能用。
2. 注入 Jinja 全局变量：`VULN` / `V4A_HOME` / `V4A_STATIC` / `V4A_STATUS` /
   `V4A_RESET` / `V4A_DIFF_KEY` / `V4A_BANNER`。
3. **按挂载点隔离 session cookie 的名字和路径。** 顺带把
   `SESSION_COOKIE_SAMESITE="Lax"`、`SESSION_COOKIE_HTTPONLY=True` 也设好。
4. 建好 `ctx.workspace` 目录。

---

## 5. 挂载与 URL

### 5.1 默认挂载规则

| 挂载键 | 默认路径 |
|---|---|
| `""` | `/v/<模块id>/` |
| 其他任意键 | `/v/<模块id>/<键>/` |

模块 id 就是它在 `modules/` 下的相对路径。`modules/sqli/login_bypass` 的
id 是 `sqli/login_bypass`，主挂载点是 `/v/sqli/login_bypass/`。

### 5.2 覆盖路径 / 隐藏入口

```python
info = {
    ...
    "mounts": {
        "attacker": {"path": "/evil-site"},
        "internal": {"path": "/internal-admin", "hidden": True},
    },
}
```

- `path`：任意绝对路径。改完就得自己保证不跟别人撞（见 5.4）。
- `hidden`：不显示在清单页上。清单页只会给一个不带路径的"隐藏入口"徽标 ——
  隐藏入口的路径不该从清单页泄露出去。

### 5.3 URL 生成的正确姿势

| 场景 | 用什么 |
|---|---|
| 自己应用内部的路由 | `url_for('函数名')`（Flask 自带） |
| 跨挂载点（去另一个入口） | `ctx.url("键名", "/路径")` |

`url_for` 能正确工作，是因为 `DispatcherMiddleware` 把 `SCRIPT_NAME` 设好了。
`ctx.url()` 则是给跨挂载点用的 —— 另一个入口是**另一个应用**，`url_for` 看不到它。

```python
ctx.url("", "/login")       # -> /v/sqli/login_bypass/login
ctx.url("attacker", "/")    # -> /evil-site/
```

**不要手写以 `/` 开头的路径。** 挂载点一改，所有硬编码链接会静默烂掉。
`doctor` 会把这种写法报成 WARN（`href="/..."` / `action="/..."` / `redirect("/...")`
/ `"/v/..."`，`module.py` 和模块自己的 `*.html` 都会扫）。

放行 `/__vuln4all/...` —— 那是 core 的固定路径，模块指向它是对的。

### 5.4 挂载冲突是怎么处理的

`Registry._resolve_conflicts()` 在加载后跑一次，**不是只记一条警告，而是真的把
冲突的挂载点摘掉**。

规则：

- 路径精确等于 `/` 或 `/v`：拒绝（那是 core 和模块聚居区本身）
- 路径撞上 `/__vuln4all` 前缀或其下任何路径：拒绝
- 路径已被别的模块占了：拒绝，后到的输；谁先谁后按模块 id 排序，稳定可复现

处理方式：

- 只摘掉**冲突的那一个**挂载点，不牵连这个模块的其他入口
- 摘掉的是主挂载点（`""`）时，整个模块判加载失败
- 两种情况都会往 `entry.problems` 追加说明，`doctor` 报 ERROR

为什么要这么硬：一个模块声明 `{"path": "/__vuln4all/status"}` 就能按最长前缀
把 core 的体检页和重置入口整个盖掉，而命令行只打印一句警告照样把靶场起起来。
只记录不拦截是不够的。

---

## 6. 状态与生命周期

### 6.1 workspace 约定

每个模块有一个私有目录：

```
workspace/<模块id>/
```

模块 id 里的 `/` 会展开成目录层级。`sqli/login_bypass` 的私有目录就是
`workspace/sqli/login_bypass/`。

- 模块所有持久化的东西（sqlite、上传的文件、日志）都放这儿
- 模块之间物理隔离：路径结构天然单射，不可能撞
- `reset` 就是清空这个目录，所以**别往靶场目录的其他地方写文件**

### 6.2 初始化标记

`workspace/<模块id>/.initialized` 存在 = `setup()` 已经跑过了。
删掉它，下次启动会重跑 `setup()`。

### 6.3 reset 的三层

```
vuln4all reset <id>              # 重置一道
vuln4all reset --all             # 重置全部
页面上每道题的「重置这题」按钮    # 走 POST /__vuln4all/reset
```

内部流程（`Registry.reset`，全程持一把锁）：

```
摘掉 .initialized 标记
      |
      v
调用模块自己的 reset(ctx)（如果实现了）
      |
      v
清空 workspace/<模块id>/
      |
      v
重新调用模块的 setup(ctx)
      |
      v
写回 .initialized
```

几个刻意的设计：

- **先摘标记**：万一中途炸了，下次启动会重跑 `setup()`，而不是看到一个空目录
  却以为已经初始化过了。
- **持锁**：reset 是「删目录 → 重建」这套非原子操作。被另一个 reset 插进来，
  会留下半死的目录。
- **它不保证什么**：它**没有**和请求线程互斥。如果 reset 正在删某个模块的
  sqlite 文件，而另一条线程正好握着那个库的连接在查，那条请求会拿到一个数据库
  错误。单进程教学靶场里这可以接受（刷新一下就好）。真要挡住得在模块的数据访问
  上加锁。
- **容错**：`reset --all` 逐题容错，一道题炸了不会让剩下的都重置不了。
- **进度也一起清**：`ctx.progress` 落在 `workspace/<模块id>/progress.json`，
  所以清目录的时候顺手就被带走了。模块**不用**为了进度单独写 `reset()`。
  验证脚本里有一条专门测这个：`reset --all` 之后 `/__vuln4all/check` 必须回到 0。

### 6.4 线程模型

靶场用 `werkzeug` 的开发服务器，`threaded=True`。

**这个必须开着**：不少题目需要请求内部再发请求（SSRF 抓自己、CSRF 页面 post
到另一个挂载点），单线程会直接死锁。

代价是模块作者要注意：

- 模块级可变状态需要自己加锁（参考 `race_condition`）
- `check_same_thread` 之类的 sqlite 参数按需处理
- `race_condition/coupon_redeem` 这道题就是拿"单进程 + 多线程"当题眼的

---

## 7. 前端与模板

### 7.1 外壳

模块模板只要一句：

```jinja
{% extends "vuln4all/base.html" %}
{% block title %}页面标题{% endblock %}
{% block content %}
  ...你的页面...
{% endblock %}
```

就从 `base.html` 白拿：

- 顶栏（品牌、面包屑、导航）
- **题目页头**：题目名、模块 id、难度徽标、CWE / OWASP 徽标、描述
- **「重置这题」按钮**（自动带上正确的 id 和返回地址）
- **「提示」和「答案」两个折叠区**（从 `info["hint"]` / `info["solution"]` 自动渲染）
- 页脚的安全警告和作者署名

`base.html` 只有 `title` 和 `content` 两个 block。别指望覆盖别的。

### 7.2 公开类名 API

**下面这些类名是给模块模板用的公开 API。** 改样式随便改，改名字要连带改所有模块。

| 类名 | 用途 |
|---|---|
| `btn` | 按钮 |
| `btn-ghost` | 次要按钮（透明底） |
| `payload` | 命令行、payload、代码块这类等宽文本块 |
| `findings` | 数据表格（`<table class="findings">`） |
| `mono` | 等宽字体 |
| `muted` | 次要文字 |
| `small` | 小一号字 |
| `err` | 错误文字（红） |
| `ok` | 成功文字（绿） |
| `badge` / `tag` | 小徽标 |
| `badge-cwe` / `badge-owasp` / `badge-hidden` | 带色的徽标 |
| `badge-diff-{{ V4A_DIFF_KEY(x) }}` | 难度徽标上色 |
| `notice` / `notice-ok` / `notice-bad` | 提示框 |
| `cards` / `card` / `card-title` / `card-meta` / `card-desc` | 卡片 |
| `refs` | 参考资料列表 |

### 7.3 设计令牌

想跟外壳风格一致就用 `style.css` 里的 CSS 变量，别写死颜色：

```css
var(--bg) var(--surface) var(--surface-2) var(--surface-3)
var(--line) var(--line-strong)
var(--fg) var(--fg-2) var(--muted)
var(--accent) var(--cyan) var(--ok) var(--warn) var(--bad)
var(--r-sm) var(--r) var(--r-lg)
```

### 7.4 通关提示怎么写

每道题算完"是否通关"后，用这个统一写法：

```jinja
{% if hit %}
  <div class="notice notice-ok">你做到了 XXX —— <strong>这题通了</strong>。</div>
{% endif %}
```

`id="v4a-solved"` 这个约定**没有**被强制使用，但 `verify.sh` 的内容断言会先把
`<details>` 折叠区剥掉再匹配，所以你的通关提示文字要出现在折叠区**外面**。

### 7.5 两条硬约定

**一、模块模板不要用 `<details>`。**

`verify.sh` 的 `strip_teaching()` 会把页面里所有 `<details>...</details>` 剥掉，
因为 core 外壳的「提示 / 答案」折叠区里写着完整解法，不剥掉的话任何内容断言都会
变成"永远通过"的假阳性。

**二、`check()` 的目标名里不要嵌 payload 字面量。**

目标名会渲染进题目页的「进度」区块，而那个区块也在 `strip_teaching()` 的剥离范围内，
所以它不会污染断言 —— 但为了不让人依赖这一点，仍然不要在目标名里写 `uid=`、
`{{7*7}}` 这种字符串。它是给人看的描述。

---

## 8. 运行配置与局域网模式

### 8.1 优先级

```
命令行参数  >  vuln4all.ini  >  内置默认值
```

### 8.2 配置文件

在靶场根目录放 `vuln4all.ini`：

```ini
[vuln4all]
host = 0.0.0.0
port = 8800
allow_remote = true
reload = false
```

模板在 `vuln4all.ini.example`。`vuln4all.ini` 已加进 `.gitignore`
（各人环境不同，别提交）。

实现细节上有一点值得注意：`cli.py` 里 `--host` / `--port` / `--reload` 的
`argparse` 默认值用的是 `argparse.SUPPRESS`。这是为了区分"用户没写"和
"用户写了默认值" —— 不然配置文件里的值永远被默认值盖掉。

### 8.3 局域网模式

```bash
python3 main.py --lan
```

等价于绑 `0.0.0.0`，并且算作"我知道别人能连进来"的确认。

启动时会打印两套地址：

```
  本机   http://127.0.0.1:8800/
  局域网  http://192.168.44.149:8800/
```

`config.local_ips()` 不依赖第三方库：先用 UDP connect（不会真发包）探默认出口地址，
再补上主机名解析出来的地址。**私有网段排前面** —— 否则在开了 VPN / Tailscale 的
机器上会把一个别人根本连不上的地址当成"局域网地址"念出来。

标签有三种：`本机` / `局域网`（私有网段）/ `其他`（非私有，比如公网 IP 或 VPN 地址）。

### 8.4 安全门控

**默认只绑 `127.0.0.1`。** 想让别人连进来，三条路任选：

| 方式 | 场景 |
|---|---|
| `--lan` | 一次性 |
| `--i-know-what-im-doing` | 配合显式 `--host` |
| ini 里 `allow_remote = true` | 长期 |

门控逻辑在 `cli.py:cmd_run`：合成完配置后，如果 host 不是回环地址且
`allow_remote` 为假，就打印说明并 `return 2`。

`config.is_loopback()` 是 fail-closed 的：认不出来的写法一律当"不是回环"，
所以最坏情况是多问一次，不会漏放。它处理了 `localhost.`（尾点）、`[::1]`
（方括号）、`::ffff:127.0.0.1`（IPv4 映射的 IPv6）。

**开放到局域网时必须告知的两件事**（启动横幅里会打）：

1. 所有题目的数据是共享的，谁点了「重置」大家的进度一起清空。单进程架构就是
   互相干扰的，多人认真打请各自拿一份副本。
2. 这些漏洞是真的。别带到公网、别用真数据、别连生产网。

---

## 9. 命令行参考

`main.py` 是主入口，`python3 -m vuln4all` 等价。

```
python3 main.py [--home PATH] <子命令> [选项]
```

| 子命令 | 说明 |
|---|---|
| （不带） | 等价于 `run` |
| `run` | 启动靶场 |
| `list [--category X]` | 列出所有题目 |
| `check [<id>] [--json]` | 报告通关进度。见 4.8 |
| `reset <id>` / `reset --all` | 恢复出厂 |
| `doctor [<id>] [--no-smoke]` | 体检。有 ERROR 时退出码 1 |
| `new <分类>/<名字> [--force]` | 生成题目骨架 |

`run` 的选项：

| 选项 | 说明 |
|---|---|
| `--host HOST` | 绑定地址，默认 `127.0.0.1` |
| `--port PORT` | 端口，默认 `8800` |
| `--lan` | 开放到局域网（绑 `0.0.0.0` + 确认） |
| `--reload` / `--no-reload` | 改模块文件自动重启 |
| `--i-know-what-im-doing` | 显式指定非本机地址时的确认开关 |

全局选项 `--home` 可以写在子命令前面，例如 `python3 main.py --home /srv/v4a list`。

---

## 10. 开发流程

推荐顺序（每一步都有对应的自动化）：

```
1. python3 main.py new <分类>/<名字>     生成骨架
        |
2. 改 module.py / templates/ / writeup.md
        |
3. python3 main.py doctor               静态检查 + 冒烟请求
        |
4. python3 main.py run                  肉眼过一遍
        |
5. 把新题的端到端断言加进 tools/verify.sh 第 10 步（或新开一步）
        |
6. python3 tools/deploy.py ... --fresh  推到远端
   bash tools/verify.sh                 端到端全跑
        |
7. git commit
```

**第 5 步不能省。** 这个项目的题目是"故意有洞"的，光看代码看不出洞有没有真的生效；
必须有一条"这样打过去应该成功"的断言，以及（重要）一条"这样打过去不该成功"的
反向断言。

---

## 11. doctor 会检查什么

`python3 main.py doctor` 跑的是 `vuln4all/doctor.py` 里的 `check()`。
退出码非 0 表示有 ERROR，可以直接挂 CI。

| 级别 | 检查项 |
|---|---|
| ERROR | 模块加载失败（导入报错、找不到 `Vuln` 子类、`create_app` 返回值类型不对） |
| ERROR | `info` 缺必需字段 |
| ERROR | 挂载点冲突 / 抢占 core 保留前缀（见 5.4） |
| ERROR | 多挂载点忘了传 `ctx.flask(mount=...)` |
| ERROR | 没有算出任何挂载点 |
| ERROR | `workspace` 不可写 |
| ERROR | 模块 `requirements.txt` 里的依赖没装 |
| ERROR | 冒烟请求（`GET /`）返回 5xx 或抛异常 |
| ERROR | `check()` 抛异常，或者返回了 bool / dict 之外的东西 |
| WARN | `modules/` 下有放东西但没 `module.py` 的目录 |
| WARN | `info` 里还留脚手架生成的 `TODO` 占位文本（包括没填的作者名） |
| WARN | 硬编码绝对路径（`href="/..."` 之类） |
| WARN | `difficulty` 填了非标准值 |
| WARN | `check()` 连着调两次结果不一样（有副作用） |
| INFO | 建议补的 `info` 字段缺失 |
| INFO | 每个挂载点冒烟通过 |
| INFO | `check()` 当前的通关状态和目标计数 |

几点说明：

- **一个模块出错不影响其他模块。** core 会继续起靶场，坏模块在清单页上显示成
  "加载失败"并带上具体原因。
- 体检页 `/__vuln4all/status` 跑的是**静态检查**（`smoke=False`），不发请求，
  也不会往磁盘写探针文件。要看完整结果用 CLI。
- **加载失败和"挂载点被摘掉"是两回事。** 后者只有部分入口失效，
  详细原因看 `doctor` 输出的 ERROR 行。

---

## 12. 验证脚本 verify.sh

```bash
bash tools/verify.sh              # 默认端口 8800
PORT=9000 bash tools/verify.sh
```

它做的事：起靶场（后台）→ 用 curl 把每道题的漏洞真打一遍 → 检查重置、前端、
CLI、契约加固、运行配置、仓库卫生 → 收尾（杀掉自己起的进程）。

**只在隔离环境里跑。**

### 12.1 一条重要的历史教训：假阳性

验证脚本犯过一个很隐蔽的错误，而且**犯过两次**：

> **第一次**：题目页自带「提示 / 答案」折叠区，**答案文本就嵌在每个页面的
> HTML 里**。于是 `expect_has "命令注入拿到 uid=" "uid="` 这种断言**永远成立**
> —— 因为答案里就有 `uid=`。漏洞真的坏了，测试照样绿。
>
> **第二次**（加了 `check()` 进度区块之后）：那个区块把**目标名**渲染到页面上，
> 而我给命令注入题写的目标名是"注入的命令真的被 shell 执行了（输出里出现 uid=）"
> —— 里面就有 `uid=`。于是同一条否定断言 `expect_no ... "uid="` 被它顶掉了。

两次都是同一个病：**页面里除了模块自己的内容，还嵌着 core 注入的文字。**

修法是 `strip_teaching()`：断言前先把 core 注入的那两块剥掉。

```python
# <details>...</details>                      提示 / 答案折叠区
# <section class="progress">...</section>     进度区块（目标名在里面）
```

```bash
page() { curl -s "$@" | strip_teaching; }     # 抓页面 + 剥掉 core 注入的文字
```

**两条纪律：**

1. 写新断言时一律用 `page`，不要用裸 `curl`。
2. **目标名里不要嵌 payload 字面量**（`uid=`、`{{7*7}}` 之类）。
   它是给人看的描述，不是数据。

顺带一个更强的做法：**能用 `check()` 就用 `check()`，别去抓页面文案。**
`expect_solved` / `expect_unsolved` 问的是靶场自己算出来的状态，不碰 HTML，
从根本上不会假阳性。

### 12.2 可用的断言辅助

| 函数 | 用法 |
|---|---|
| `expect_has "说明" "要找的子串" "$body"` | 子串必须出现 |
| `expect_no "说明" "不该出现的子串" "$body"` | 子串必须不出现 |
| `expect_code "说明" "$code" "200"` | HTTP 状态码相等 |
| `expect_solved "<模块id>" "说明"` | `check()` 说这题已通关 |
| `expect_unsolved "<模块id>" "说明"` | `check()` 说这题还没通关 |

`expect_solved` / `expect_unsolved` 走 `GET /__vuln4all/check/<模块id>`。
**这是首选**，因为它验证的不只是"漏洞还能打"，还有"check() 和实际状态一致"。

失败会打印"返回体里找不到 [...]"，方便定位。

### 12.3 端口护栏

第 0 步会检查目标端口有没有被占。占了就直接 FAIL 退出，并打印占用者。

**这不是洁癖。** 真的发生过一次：旧服务占着 8800，新进程绑不上就死了，
于是 curl 一直在问"那个别人"，拿旧模板和已被删掉的数据库做断言 ——
结果 16 项全红，看着像代码坏了，实际是测错了对象。验证脚本最怕的就是这种
"安静地给了个假结论"。

同一段还会校验：应答的确实是我们刚起的 PID、页面上确实有 `vuln4all`。

### 12.4 反向断言

正向断言只能证明"打过去成功了"，不能证明"这个成功是漏洞带来的"。

举例：SSRF 那道题有两条。

```bash
# 正向：经典绕过能拿到内网后台
expect_has "SSRF 打到内网管理后台" "内部管理后台" "$body"
# 反向：过了白名单、但目标不是内网后台 —— 应该抓不到
expect_no  "过了白名单但目标不对，抓不到内网内容" "内部管理后台" "$body"
```

第二条是用来证明第一条是"真抓到了"，而不是断言写松了。

### 12.5 进程管理

脚本用 `trap cleanup EXIT` 收尾。`cleanup` 杀进程前会**核对命令行**，
只杀自己起的那个：

```bash
if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q "vuln4all"; then
  kill "$pid"
fi
```

**不要改成无差别批量杀进程。** 同一台机器上可能跑着别人的东西。

---

## 13. 部署到远端主机

本机不要跑这个靶场。开发在本地，验证在远端隔离主机。

```bash
python3 tools/deploy.py --host 192.168.44.149 --user root --password root \
    --path /root/Desktop/vuln4all --fresh
```

| 参数 | 说明 |
|---|---|
| `--host` / `--user` / `--password` / `--port` | SSH 连接信息（paramiko，走密码认证） |
| `--path` | 远端项目根目录 |
| `--fresh` | 顺便删掉远端 `workspace/`，让所有题目重新 `setup()` |
| `--run "命令"` | 同步完在远端跑一条命令 |
| `--root` | 本地要推的目录，默认项目根 |

它自动跳过 `.git` / `__pycache__` / `.venv` / `workspace` / `*.pyc`。

**目标机是 Kali，装 Python 包用 `apt`，不要用 `pip`。**

```bash
apt install python3-flask
```

Kali 的系统 Python 是托管的，pip 会污染系统环境。本项目唯一的运行依赖是 Flask
（`python3-flask` 通常已经自带）。

---

## 14. 踩过的坑

按"会不会再踩一次"排序。

### 14.1 作者样式会压过 `[hidden]`

清单页的筛选靠 `element.hidden = true` 收卡片。但 `[hidden] { display: none }`
来自**用户代理样式表**，而作者样式表里的 `.card { display: flex }` 会**无条件**
压过它 —— 跟元素特异性无关。结果搜索框只能让整个分类消失，同一分类里不匹配的
卡片照样杵着。

`style.css` 里有一句兜底的：

```css
[hidden] { display: none !important; }
```

### 14.2 模块 id 归一化会撞名

`sqli/login-bypass` 和 `sqli/login_bypass` 如果都简单地做"非字母数字换成下划线"，
会得到同一个字符串。早期版本因此让后加载的模块把先加载的从 `sys.modules` 顶掉，
而且 `reset` 会删掉对方的库，全程无声。

现在的规则：

- Python 模块名 = `v4a_mod_<可读部分>_<id 的 sha1 前 8 位>`，唯一性由哈希保证
- workspace 路径 = 按 id 分层展开，路径结构天然单射

### 14.3 `urllib` 不剥离 URL 里的 userinfo

SSRF 那道题的经典绕过是 `http://allowed@127.0.0.1/` —— `@` 前面是 userinfo，
后面才是主机。但 Python 的 `urllib.request` **不会**这么做：它把 `a@b` 整串当
主机名去解析，和 requests / curl / 浏览器都不一样。

所以那题的 `fetch()` 用 `urlsplit` + `http.client` 手动实现，还原真实语义。

教训：**校验和连接必须用同一个解析器** —— 这本身就是那题要教的东西。

### 14.4 core 注入的文字会污染测试断言

题目页里除了模块自己的内容，还嵌着 core 注入的两块文字：**「提示 / 答案」折叠区**
（答案原文）和**「进度」区块**（`check()` 的目标名）。

按页面内容做断言时，这两块会让断言变成"永远通过"的假阳性。这个坑**踩过两次**：

- 第一版：`uid=` 在答案里就有
- 加了进度区块之后：给命令注入题写的目标名里又带上了 `uid=`

修法见 12.1：`strip_teaching()` + 目标名里不嵌 payload。

### 14.5 `nohup` / systemd 下 stdout 是块缓冲

启动横幅（挂载点、可达 URL、安全警告）如果不显式 `flush`，会一直卡在缓冲区里。
进程被 kill 就全丢，用户只看到一个"起来了但什么都没说"的空白日志。

`cli.py` 在 `run_simple` 之前有 `sys.stdout.flush()`。

### 14.6 `configparser` 默认开 `%`-插值

配置里任何百分号（比如带 zone 的 IPv6 `fe80::1%eth0`）都会抛
`InterpolationSyntaxError`，然后**整个配置文件被丢掉** —— 连 host/port 一起
静默降回默认值。

`config.py` 里用的是 `ConfigParser(interpolation=None)`。

### 14.7 Python 字面量里的中文引号

写中文文案时很容易把 `"..."` 打成 `"..."`（ASCII 双引号），
在双引号字符串里就是把字符串截断了。踩过两次。

用中文引号就写中文引号，别混。

### 14.8 `os.path.join` 的绝对路径陷阱

```python
>>> os.path.join('/srv/files', '/etc/passwd')
'/etc/passwd'          # 基准目录整个没了
```

`pathlib` 的 `/` 运算符行为一样。这是 `path_traversal/file_download` 那道题的
第二个教学点。

### 14.9 换行符

开发在 Windows，跑在 Linux。仓库里的 `.gitattributes` 强制 `* text=auto eol=lf`。
不加这条的话，Windows 上 clone 出来的 shell 脚本是 CRLF，在 Linux 上跑会满屏
`\r: command not found`。

---

## 15. 设计原则与已知边界

### 15.1 三条原则（同第 1 节，展开说）

**自包含比 DRY 值钱。** 允许复制粘贴，抽象层的价值在这里被高估了。

理由是**变更的局部性**：改一道题应该只需要读那一道题的文件。抽出一个共享抽象层，
就等于在"N 道题"和"那个抽象"之间拉了一根隐式的绳子 —— 改抽象会牵动所有题，
而改一道题得先读懂抽象才敢动。这个代价跟谁在维护、维护多久都没关系：
**它跟"一次变更会波及多少地方"有关。**

具体落法：模块之间可以复制粘贴；只有真属于框架的东西（页面外壳、`ctx`）才放 core。

**契约要窄。** 现在模块只需要记住五件事：继承 `Vuln`、`info` 里填 `name` 和
`description`、实现 `create_app()`、返回 `{"": app}`、持久化放 `ctx.workspace`。
其他都有默认值或者有自动化帮你兜。**加新概念到这个列表里之前，先问一句：
能不能不进契约？** `difficulty` 就是这么处理的 —— 它只是元数据，没变成机制。

`check()` / `ctx.progress` 是唯一一次例外，而且是有代价才加的：它把"这题有没有
被打穿"变成了对外承诺的接口，换来的是靶场能自己做回归、以及能被当 benchmark 用。
加的时候守住了两条：**不实现也能跑**（返回 `None` 就是"不支持"），
**进度落在 workspace 里**（所以 `reset` 不需要模块写任何额外代码）。

**默认要安全。** 具体体现：默认只绑回环、挂载路径可预测、session 自动隔离、
挂载冲突硬拦、`doctor` 主动挑毛病、`reset` 持锁且先摘标记。

### 15.2 已知边界（诚实清单）

- **隔离性为零。** 所有模块跑在同一个 Python 进程里。一道命令注入题拿到手的是
  **整个靶场**的 shell，不是那一题的沙箱 —— 它能看到别的题的数据、能改内存里的
  状态、能改 core 的代码。这是单进程架构的必然代价，只在本地单人用。
  真需要隔离，得换子进程或容器；`create_app()` 返回的 WSGI 应用换成反向代理即可，
  接口不用改。

- **只支持 WSGI。** Flask / 裸 WSGI 都行，FastAPI 这种 ASGI 的还不支持。

- **没有跨模块链接。** `ctx.url()` 只能指向自己模块的挂载点。

- **多用户共享状态。** 多人同时打同一道题会互相干扰；一个人点重置，
  所有人的进度一起清空。

- **没有 per-session 数据隔离。** 想加的话代价不小：得给每个会话一个独立的
  workspace 与数据库，是数据层的大改。

- **`ctx.progress` 是全局的，不分会话。** 一道题被打通就是打通，谁打的都一样。
  这跟其他状态（订单、上传的文件）是一致的，但和真人多开时的直觉不一致。

- **模块加载只认 `module.py`。** 不能把入口文件改名。

- **没有配置热重载。** `--reload` 只监听模块文件和 core 的 py/html。

### 15.3 下一步可以做的

按价值排序：

1. **题目级的数据隔离。** 让每道题可以按会话开独立 workspace，以支持多人同时
   认真打。这也是 `ctx.progress` 能变成 per-session 的前提。
2. **题目内容继续扩。** 差异化价值最高的是 Python 栈独有的题 —— 已有的
   Jinja2 SSTI、Flask session 伪造、手搓 JWT 都属于这一类；PHP 靶场里做不出
   这种"真"。
3. **`check()` 的消费者。** 现在写了一个 skill 驱动的 eval 流程：
   `reset --all` → 让靶场自己跑一遍已知利用 → `check --json` 对答案。
   可以把它包成 `tools/benchmark.py`，接扫描器或者 AI agent。
4. **输出格式。** `list` / `doctor` 支持 `--json`，方便接别的工具。
