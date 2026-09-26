"""站点根目录里的残留文件 —— 信息泄露。

业务场景是"一个静态站点"，带一个按路径取文件的接口。

这个洞跟路径穿越**不是一回事**：接口老老实实把访问限制在站点根目录里，
`../` 是拦掉的。问题是**根目录里本来就不该有的东西被一起发出去了**：

  · `.env`          环境变量文件，常常直接存着口令
  · `.git/`         版本库目录，能倒推出源码
  · `*.bak` / `*.swp`  编辑器或者部署脚本留下的备份
  · `deploy.sh`     部署脚本，里面有服务器地址和路径

这类东西是**主动摆在那里的** —— 你不用绕任何校验，直接请求就行。
所以它属于"扫一遍就能发现"的漏洞，也是最容易被漏掉的一类：
开发觉得"这个文件又不对外"，但 web 服务器是为整个目录服务的。
"""

import re
import sqlite3

from vuln4all import Vuln, render_template, request, session

SITE_DIR = "site"

#: 预期的公开文件（页面上列出来的就是这些）。
PUBLIC_FILES = {
    "index.html": (
        "<!doctype html>\n<html><head><title>内部工具导航</title></head>\n"
        "<body><h1>内部工具导航</h1>\n<ul>\n  <li>工单系统</li>\n"
        "  <li>监控面板</li>\n  <li>发布流水线</li>\n</ul>\n</body></html>\n"
    ),
    "style.css": "body { font-family: system-ui, sans-serif; margin: 40px; }\n",
    "robots.txt": "User-agent: *\nDisallow: /admin/\nDisallow: /files/\n",
}

#: 不该在 web 目录里的东西（用户看不到列表，得自己猜/扫）。
LEAKED_FILES = {
    ".env": (
        "APP_ENV=production\n"
        "DB_HOST=db.internal\n"
        "DB_PASSWORD=pg-9f2c1a\n"
        "ADMIN_PASSWORD=ADMIN-LEAK-5c8e\n"
        "SESSION_SECRET=sk-live-77b2\n"
    ),
    ".git/HEAD": "ref: refs/heads/main\n",
    ".git/config": (
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
        "[remote \"origin\"]\n\turl = https://git.corp.example/portal/nav.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
    ),
    "deploy.sh.bak": (
        "#!/bin/sh\n"
        "rsync -av --delete ./ deploy@10.0.0.7:/var/www/nav/\n"
        "ssh deploy@10.0.0.7 'systemctl restart nav'\n"
    ),
    "app.py.bak": (
        "import os\n"
        "SECRET_KEY = \"sk-live-77b2\"\n"
        "DB_DSN = \"postgres://portal:pg-9f2c1a@db.internal/portal\"\n"
    ),
    "index.html.swp": "b0VIM 9.0\x00\x00\x00\x00\x00\x00\x00\x00\n",
}

#: 从泄露文件里能拿到的管理员口令。用它登录 = 通关。
ADMIN_PASSWORD = "ADMIN-LEAK-5c8e"

MAX_READ = 256 * 1024

GOAL_LEAK = "拿到了 web 目录里不该有的文件（.env / .git / 备份）"
GOAL_LOGIN = "用泄露出来的口令登录管理员"


class BackupFiles(Vuln):
    info = {
        "name": "站点根目录里的残留文件",
        "author": ["guaidao2"],
        "cwe": "CWE-538",
        "owasp": "A05:2021 - Security Misconfiguration",
        "difficulty": "入门",
        "description": (
            "这个静态站点的取文件接口把访问限制在了站点根目录里"
            "（`../` 是拦掉的），但**根目录里本来就不该有的东西**被一起发出去了：\n"
            "`.env`、`.git/`、部署脚本的备份、编辑器的临时文件。\n"
            "页面只列出「公开文件」，剩下的得你自己去找。"
        ),
        "hint": (
            "页面上列出来的只是公开文件。真正要找的东西**不会**被列出来 ——"
            "想想要在一个 web 目录里找什么：\n"
            "  · 环境变量文件叫什么？\n"
            "  · 版本库目录叫什么？里面哪个文件最先能看？\n"
            "  · 部署脚本、配置文件的备份一般叫什么后缀？\n"
            "  · 编辑器崩溃之后留下的临时文件叫什么？\n"
            "然后直接请求它们就行 —— 这个洞**不需要绕过任何校验**。"
        ),
        "solution": (
            "一、直接猜/扫常见名字，用那个取文件的接口：\n\n"
            "   curl 'http://<靶场>/v/info_leak/backup_files/files/.env'\n"
            "   curl 'http://<靶场>/v/info_leak/backup_files/files/.git/HEAD'\n"
            "   curl 'http://<靶场>/v/info_leak/backup_files/files/.git/config'\n"
            "   curl 'http://<靶场>/v/info_leak/backup_files/files/deploy.sh.bak'\n"
            "   curl 'http://<靶场>/v/info_leak/backup_files/files/app.py.bak'\n"
            "   curl 'http://<靶场>/v/info_leak/backup_files/files/index.html.swp'\n\n"
            "   `.env` 里直接就有 ADMIN_PASSWORD。\n\n"
            "二、拿到口令之后去页面上那个管理员登录框登录。\n\n"
            "这一题为什么值得单独讲：\n\n"
            "  它跟路径穿越**不是一回事**。这里没有绕任何校验 ——\n"
            "  接口老老实实把访问限制在根目录里。问题是**根目录里本来就不该有**"
            "  那些文件。所以它的成因不是「代码写错了」，「运维/部署的时候漏了」。\n\n"
            "真实环境里该怎么找（这套清单值得记住）：\n\n"
            "  版本库：      /.git/HEAD  /.git/config  /.svn/entries  /.hg/\n"
            "  环境变量：    /.env  /.env.local  /.env.production  /.env.bak\n"
            "  配置备份：    /config.php.bak  /app.py.bak  /web.config.old\n"
            "  编辑器残留：  /index.html.swp  /page.php~  /.index.html.un~\n"
            "  部署脚本：    /deploy.sh  /Makefile  /Dockerfile  /.dockerignore\n"
            "  打包产物：    /backup.zip  /site.tar.gz  /db.sql  /dump.sql\n"
            "  依赖清单：    /package.json  /requirements.txt  /composer.lock\n"
            "  编辑器/IDE：  /.vscode/  /.idea/  /.project\n"
            "  日志：        /debug.log  /error.log  /access.log\n"
            "  测试残留：    /test.php  /phpinfo.php  /.DS_Store\n\n"
            "  `.git/` 特别值得单独说：拿到 `.git/HEAD` 只说明**有版本库**，\n"
            "  但把整个 `.git/` 目录拖下来之后，可以用工具从对象库里把\n"
            "  **全部源码和历史**还原出来：\n"
            "    · git-dumper  https://github.com/arthaud/git-dumper\n"
            "    · GitHacker\n"
            "  这是最经典的一条「从信息泄露到源码泄露」的路，\n"
            "  而源码里常常有别的地方都拿不到的密钥和逻辑。\n\n"
            "  另外 `robots.txt` 也值得一看 —— 它经常主动告诉你\n"
            "  「哪些路径不该被索引」，而那正好是你要去看的地方\n"
            "  （这一题的 robots.txt 就写了 /admin/ 和 /files/）。"
        ),
        "refs": [
            "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
            "https://cwe.mitre.org/data/definitions/538.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        site = ctx.workspace / SITE_DIR
        site.mkdir(parents=True, exist_ok=True)
        for name, body in PUBLIC_FILES.items():
            (site / name).write_text(body, encoding="utf-8")
        for name, body in LEAKED_FILES.items():
            path = site / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")

        con = sqlite3.connect(str(ctx.workspace / "log.db"))
        con.executescript(
            """
            CREATE TABLE hits (
                id     INTEGER PRIMARY KEY AUTOINCREMENT,
                path   TEXT NOT NULL,
                leaked INTEGER NOT NULL
            );
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        site = (ctx.workspace / SITE_DIR).resolve()
        log_db = str(ctx.workspace / "log.db")

        def record(path, leaked):
            con = sqlite3.connect(log_db)
            try:
                con.execute(
                    "INSERT INTO hits (path, leaked) VALUES (?,?)",
                    (path, 1 if leaked else 0),
                )
                con.commit()
            finally:
                con.close()

        @app.route("/")
        def index():
            return render_template(
                "index.html",
                files=sorted(PUBLIC_FILES),
                admin=bool(session.get("admin")),
                result=None,
                blocked=None,
            )

        @app.route("/files/<path:name>")
        def serve(name):
            # 这一题特意把 `../` 拦掉，跟 path_traversal 那两道题区分开 ——
            # 这里的问题不是"能越出根目录"，是"根目录里有不该有的东西"。
            target = (site / name).resolve()
            if target != site and site not in target.parents:
                return render_template(
                    "index.html", files=sorted(PUBLIC_FILES),
                    admin=bool(session.get("admin")),
                    result=None, blocked=name,
                )
            if not target.is_file():
                record(name, False)
                return render_template(
                    "index.html", files=sorted(PUBLIC_FILES),
                    admin=bool(session.get("admin")),
                    result={"name": name, "body": "404 没有这个文件", "leaked": False},
                    blocked=None,
                )

            with open(target, "rb") as handle:
                raw = handle.read(MAX_READ)
                truncated = bool(handle.read(1))
            body = raw.decode("utf-8", "replace")
            if truncated:
                body += "\n...（文件太大，只显示了前 %d 字节）" % MAX_READ

            leaked = name in LEAKED_FILES
            record(name, leaked)
            if leaked:
                ctx.progress.mark(GOAL_LEAK)

            return render_template(
                "index.html", files=sorted(PUBLIC_FILES),
                admin=bool(session.get("admin")),
                result={"name": name, "body": body, "leaked": leaked},
                blocked=None,
            )

        @app.route("/admin/login", methods=["POST"])
        def admin_login():
            password = request.form.get("password", "")
            ok = password == ADMIN_PASSWORD
            if ok:
                session["admin"] = True
                ctx.progress.mark(GOAL_LOGIN)
            return render_template(
                "index.html",
                files=sorted(PUBLIC_FILES),
                admin=bool(session.get("admin")),
                result={"login": True, "ok": ok},
                blocked=None,
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        """一个目标从访问日志推，一个从进度记（登录状态在 session 里）。"""
        leaked = ctx.progress.achieved(GOAL_LEAK)
        try:
            con = sqlite3.connect(str(ctx.workspace / "log.db"))
            try:
                row = con.execute("SELECT 1 FROM hits WHERE leaked=1 LIMIT 1").fetchone()
            finally:
                con.close()
            leaked = leaked or row is not None
        except sqlite3.Error:
            pass
        return {
            GOAL_LEAK: leaked,
            GOAL_LOGIN: ctx.progress.achieved(GOAL_LOGIN),
        }


_ = re  # 名字匹配相关的东西在 writeup 的清单里列了
