# vuln4all

**模块化 Web 漏洞靶场。丢一个模块进去，就多一道题。**

像 Metasploit 那样：你不用改 core、不用在注册表里登记、不用碰任何别人的文件。
在 `modules/<分类>/<名字>/` 放一个 `module.py`，重启靶场，它就出现在首页清单里。

作者：**guaidao2**

> ⚠️ **这是故意留洞的靶场。只在本机或隔离的虚拟机里跑。**
> 绝不要暴露到公网、生产网络，或者任何你能被别人访问到的地址。

---

## 跑起来

```bash
python3 main.py
```

就这一条。默认只绑 `127.0.0.1:8800`。

**局域网一起打（多人）：**

```bash
python3 main.py --lan            # 等价于绑 0.0.0.0，并算作"我知道别人能连进来"
```

启动后会把**本机**和**局域网**两种地址都打出来，直接把局域网那个发给人就行。

更省事的办法是写一份配置文件，以后 `python3 main.py` 就按它跑：

```bash
cp vuln4all.ini.example vuln4all.ini
# 然后改里面的 host / port / allow_remote
```

优先级：**命令行 > `vuln4all.ini` > 默认值**。

> ⚠️ 开放到局域网后有两件事必须知道：
> 1. **所有题目的数据是共享的** —— 谁点了「重置」，大家的进度一起清空。
>    单进程架构就是互相干扰的，多人同时打请各自拿一份副本。
> 2. 这些漏洞是真的。别带到公网、别用真数据、别连生产网。

然后打开 <http://127.0.0.1:8800/>：

- `/` —— 题目清单（自动生成，按分类分组，带搜索 + 分类筛选 + 难度筛选）
- `/__vuln4all/status` —— 体检页
- 每道题的页面顶部都有「重置这题」按钮，以及「提示」/「答案」两个折叠区

## 命令

`main.py` 是主入口，不带子命令就是启动靶场：

```bash
python3 main.py                        # 启动靶场（127.0.0.1:8800）
python3 main.py --lan                  # 开放到局域网
python3 main.py --port 9000            # 换端口
python3 main.py list                   # 列出所有题目
python3 main.py list --category sqli   # 只看某一类
python3 main.py reset sqli/login_bypass  # 把一道题恢复出厂
python3 main.py reset --all            # 全部恢复
python3 main.py doctor                 # 体检：模块合不合规、能不能跑
python3 main.py new xss/dom_based      # 生成一个新题目的骨架
```

装成包之后也能用 `vuln4all <子命令>`，或者 `python3 -m vuln4all <子命令>`，等价。

`python3 main.py doctor` 有错误时返回非 0 退出码，可以直接挂 CI。

## 加一道题

**一个目录、一个 `module.py`、一套模板。就这些。**

```bash
python3 main.py new sqli/login_bypass
```

生成的骨架**立刻就能跑**，然后往上加洞：

```python
"""登录处的 SQL 注入"""

from vuln4all import Vuln, render_template, request, redirect, url_for


class LoginBypass(Vuln):
    info = {
        "name": "登录处的 SQL 注入",
        "author": ["你的名字"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "description": "一句话说清漏洞在哪。",
        "hint": "给新手的提示：先试什么、观察什么。别直接给答案。",
        "solution": "具体怎么打通，最好给一条能直接复制的 payload。",
        "refs": ["https://portswigger.net/web-security/sql-injection"],
    }

    def setup(self, ctx):
        """首次初始化和 reset 之后各跑一次。造数据放这儿。"""
        (ctx.workspace / "data.db").write_bytes(b"...")

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/")
        def index():
            return render_template("index.html")

        return {"": app}      # 键 "" 是主挂载点
```

## 模块契约

### 必需

| 成员 | 说明 |
|---|---|
| `info: dict` | 必填 `name`、`description`，其余可选 |
| `create_app(ctx) -> dict` | 返回 `{挂载键: WSGI 应用}`，`""` 是主挂载点 |

### 可选

| 成员 | 什么时候需要 |
|---|---|
| `setup(ctx)` | 造初始数据。首次运行 + 每次 reset 后各调一次 |
| `reset(ctx)` | **只有模块在进程内存里留了状态才需要写** |
| `check(ctx) -> bool` | 自动判定「是否已经打通」，留给以后的自动化用 |

### `info` 里能写什么

| 键 | 说明 |
|---|---|
| `name` / `description` | **必填** |
| `author` / `cwe` / `owasp` / `refs` | 推荐填，清单页和题页面会展示 |
| `difficulty` | 推荐填，`入门` / `进阶` / `困难` —— 只是个**标签**，core 不为它做任何机制。填别的值也能跑，doctor 会提醒一句 |
| `hint` / `solution` | 推荐填，会渲染成可折叠区 —— 教学靶场的灵魂 |
| `mounts` | 覆盖挂载路径、标记隐藏入口，见下 |

## 多挂载点

一道题可以有好几个入口。SSRF 要的「内网服务」、CSRF 要的「攻击者站点」都靠这个：

```python
info = {
    ...
    "mounts": {
        # 默认是 /v/<模块id>/<键>/，像这样覆盖成任意路径：
        "attacker": {"path": "/evil-site"},
        # 或者藏起来，不显示在清单页上：
        "internal": {"path": "/internal/admin", "hidden": True},
    },
}

def create_app(self, ctx):
    portal = ctx.flask(__name__)                     # 主入口
    evil   = ctx.flask(__name__, mount="attacker")   # 第二个入口
    return {"": portal, "attacker": evil}
```

**多挂载点的模块，`ctx.flask()` 一定要传 `mount="键名"`。** 它会顺手把
session cookie 的名字和路径按挂载点隔离开 —— 不这么做的话，同一个域名下
几个挂载点的 session 会互相覆盖，而且错得很难查。**`doctor` 会检查这件事**：
`create_app()` 返回的挂载键，如果在 `ctx.flask()` 里没登记过，直接报错。

挂载点撞车也是硬拦的：路径撞上 core 的保留前缀（`/__vuln4all`、`/v`）
或者别的模块抢先占了，那个挂载点会被**摘掉**（不是只记一条警告），
`doctor` 报 ERROR。摘掉的是主挂载点的话，这道题直接判加载失败 ——
一道写错的题不该把别人的题或者 core 的体检页顶掉。

## 生成 URL

**别手写以 `/` 开头的路径。** 前缀是 core 分配的，改挂载点的时候会静默烂掉。

| 场景 | 用哪个 |
|---|---|
| 自己应用内部的路由 | `url_for('函数名')` —— Flask 自带，前缀会自动带上 |
| 跨挂载点（去另一个入口） | `ctx.url("键名", "/路径")` |

```python
ctx.url("", "/login")          # -> /v/sqli/login_bypass/login
ctx.url("attacker", "/")       # -> /evil-site/
```

`vuln4all doctor` 会把硬编码的绝对路径报成警告。

## 状态与重置

每个模块有一个**私有目录**：`ctx.workspace`，也就是 `workspace/<模块id>/`，
模块 id 里的 `/` 会展开成目录层级。比如 `sqli/login_bypass` 的私有目录就是
`workspace/sqli/login_bypass/`。模块所有持久化的东西（sqlite、上传的文件……）
都放这儿，模块之间物理隔离。

重置就三步，core 全包了：

```
摘掉初始化标记  →  清空 workspace/<模块id>/  →  重新 setup(ctx)
```

先摘标记是为了万一中途炸了，下次启动会重跑 `setup()`，而不是看到一个空目录
却以为已经初始化过了。整个过程持锁，免得并发 reset 交叉出一个半死的目录。

所以**你只要把 `setup()` 写成可重复执行的，就一行 reset 代码都不用写**。
页面上那个「重置这题」按钮和 `python3 main.py reset` 命令都是走这条路。

真遇到内存里的状态（比如竞态题用的共享计数），才需要自己实现 `reset(ctx)`，
或者直接重启进程 —— 单进程架构下这是最彻底的洗牌方式。

## 目录结构

```
vuln4all/
├── main.py                      # 主入口：python3 main.py 就是启动靶场
├── vuln4all.ini.example         # 运行配置模板（复制成 vuln4all.ini 生效）
├── vuln4all/                    # core
│   ├── contract.py              #   Vuln 基类 + Ctx（模块契约）
│   ├── config.py                #   运行配置（host/port）+ 本机 IP 探测
│   ├── registry.py              #   发现 modules/、加载、算挂载点、查冲突
│   ├── loader.py                #   importlib 动态导入，坏模块不拖垮全家
│   ├── host.py                  #   前缀分发，拼成一个 WSGI 应用
│   ├── doctor.py                #   体检
│   ├── scaffold.py              #   new 子命令的骨架生成
│   ├── ui.py                    #   清单页 / 体检页 / 重置入口
│   ├── cli.py                   #   命令行
│   ├── templates/vuln4all/      #   统一外壳 base.html 等
│   └── static/style.css         #   设计系统
├── modules/                     # ← 题目都在这儿，一个目录一道题
│   ├── sqli/login_bypass/             入门
│   ├── xss/reflect_search/            入门
│   ├── idor/order_detail/             入门
│   ├── path_traversal/file_download/  入门
│   ├── ssti/jinja2_profile/           入门（Python 独有）
│   ├── csrf/password_change/          进阶
│   ├── upload/avatar/                 进阶
│   ├── command_injection/ping_tool/   进阶
│   ├── ssrf/url_preview/              进阶（双挂载点）
│   ├── flask_session/forged_cookie/   进阶（Python 独有）
│   ├── race_condition/coupon_redeem/  困难
│   └── jwt/alg_none/                  困难
├── tools/                       # 开发/验证工具
│   ├── deploy.py                #   推到远端主机验证（本机不跑靶场）
│   └── verify.sh                #   端到端验证：起靶场 + 逐题打一遍
└── workspace/                   # 运行时生成，每道题的私有数据，随时能删
```

## 题目一览

| 难度 | 题目 | 业务场景 | 洞在哪 |
|---|---|---|---|
| 入门 | `sqli/login_bypass` | 员工登录页 | 字符串拼接 SQL，`admin' --` |
| 入门 | `xss/reflect_search` | 站内搜索 | `\|safe` 关掉了 Jinja 自动转义 |
| 入门 | `idor/order_detail` | 订单中心 | 只按订单号查，不查归属 |
| 入门 | `path_traversal/file_download` | 企业网盘 | `os.path.join` 被 `../` 和绝对路径顶穿 |
| 入门 | `ssti/jinja2_profile` | 团队协作 SaaS | 用户输入被当 Jinja2 模板渲染 |
| 进阶 | `csrf/password_change` | 个人中心 + 攻击者站 | 改密码接口不看请求来源 |
| 进阶 | `upload/avatar` | 头像上传 | 后缀黑名单大小写敏感 + 信客户端 Content-Type |
| 进阶 | `command_injection/ping_tool` | 运维诊断面板 | 用户输入拼进 shell 命令 |
| 进阶 | `ssrf/url_preview` | 聊天链接预览 | 白名单只做子串匹配，`@` 骗过校验 |
| 进阶 | `flask_session/forged_cookie` | 订阅制 SaaS 后台 | 弱密钥硬编码，session 可以自己签 |
| 困难 | `race_condition/coupon_redeem` | 限时优惠券 | check-then-act 不原子，并发领取 |
| 困难 | `jwt/alg_none` | 开放 API 平台 | 验签算法从 token 自己声明的 `alg` 里读 |

## 前端

`vuln4all/static/style.css` 是一套自带的设计系统，`base.html` 是外壳。
模块的模板 `{% extends "vuln4all/base.html" %}` 就白拿题目页头、
「提示」/「答案」折叠区和重置按钮。

模板里这几个类名是**公开 API**，样式随便改，改名要连带改所有模块：

| 类名 | 用途 |
|---|---|
| `btn` / `btn-ghost` | 按钮 |
| `payload` | 命令行、payload 这类等宽文本块 |
| `findings` | 数据表格（订单列表、体检结果都在用） |
| `mono` / `muted` / `err` / `ok` / `small` | 文字样式 |
| `badge` / `tag` | 小徽标 |

清单页的搜索框和分类筛选是原生 JS，没有依赖。

## 两条设计原则

**1. 自包含比 DRY 值钱。**
允许模块之间复制粘贴代码。有人想改 SQLi 那题，不该先去理解一个共享抽象层。
只有真属于框架的东西（`base.html`、`ctx`）才放 core。

**2. 契约要窄，默认要安全。**
模块作者多半是学安全的人，不是资深 Web 开发者。让他有写错的自由，他一定会写错，
而且错得无声无息。所以：默认挂载路径可预测、session 自动隔离、
`ctx.url()` 是唯一推荐的跨挂载点写法、`doctor` 主动挑毛病。

## 目前没做的

诚实列一下，免得踩坑：

- **隔离性为零。** 所有模块跑在同一个 Python 进程里。一道命令注入题拿到手的
  是整个靶场的 shell，不是那一题的沙箱。这是单进程架构的必然代价 ——
  只在本地单人用。真需要隔离，得换子进程或容器，`create_app()` 返回的
  WSGI 应用换成反向代理即可，接口不用改。
- **只支持 WSGI。** Flask / 裸 WSGI 都行，FastAPI 这种 ASGI 的还不支持。
- **没有跨模块链接。** `ctx.url()` 只能指向自己模块的挂载点。
- **每个模块单进程共享状态。** 多人同时打同一道题会互相干扰。
- **没有 flag / 积分系统**，故意的。这是教学靶场，不是 CTF 平台：
  「打通了」由题目页面自己告诉你，学习靠每题的 `hint` / `solution` / `writeup.md`。

## 部署到远程主机

`tools/deploy.py` 是用来把靶场推到一台远端机器上验证的（本机不要跑靶场）。
它用 paramiko 走密码 SSH，会把项目同步过去、建好目录。

```bash
python3 tools/deploy.py --host 192.168.44.149 --user root --password root \
    --path /root/Desktop/vuln4all
```

Kali 上装 Python 包**用 apt，不要用 pip**：

```bash
apt install python3-flask
```

## License

MIT · © guaidao2
