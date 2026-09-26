# 普通用户调到了管理员接口（垂直越权）

## 这一题在教什么

**水平越权和垂直越权是两件事。**

| | 水平越权（IDOR） | 垂直越权（这一题） |
|---|---|---|
| 你怎么打 | 换一个对象的 id | 换一个功能入口 |
| 你拿到了什么 | 同级别别人的数据 | 高权限才有的功能 |
| 服务端缺什么 | 「这数据是不是你的」 | 「你这角色允不允许调这个」 |
| 对应那道题 | `idor/order_detail` | 这一题 |

两者经常同时出现，但**要找的位置不一样**：水平越权看 URL 里的对象编号，
垂直越权看**菜单里、接口列表里那些"你没权限的入口"**。

## 漏洞在哪

两处合起来才成立。

**一、前端把管理员菜单藏起来了，但 HTML 里还在。**

```html
<li class="card" style="display:none">
  <a href="/v/idor/admin_endpoint/admin/export">全员数据导出（管理员）</a>
</li>
```

`display:none` 只是不给看。右键「查看页面源代码」、或者直接 curl 一下，
入口地址就在那里。

**二、那个接口只检查了"你登录了吗"。**

```python
@app.route("/admin/export")
def admin_export():
    if not session.get("user"):
        return redirect(url_for("index"))
    # ↑ 到这里就放行了，没有下面这一句
    # if session.get("role") != "admin":
    #     abort(403)
```

## 怎么打通

**第一步：用 `bob / bob123` 登录（普通用户）。**

**第二步：找那个被藏起来的入口。**

右键 → 查看页面源代码，搜 `display:none`。你会看到：

```
/v/idor/admin_endpoint/admin/export
```

**第三步：直接访问它。**

浏览器地址栏输进去，或者：

```bash
curl -b 'session=<bob 的 cookie>' \
  'http://<靶场>/v/idor/admin_endpoint/admin/export'
```

你会拿到全员的姓名、电话、月薪。

## 现实里怎么找这类洞

**一、把前端当"线索"而不是"边界"。**

菜单、路由表、JS 里的 API 列表、被注释掉的代码、`display:none`、
`.map` 文件里残留的路由 —— 这些都在告诉你"还有哪些入口存在"。

```bash
# 从打包的 JS 里捞路径
curl -s https://target/app.js | grep -oE '"/[a-zA-Z0-9_/-]+"' | sort -u
```

**二、拿到两个不同权限的账号，做对比。**

同样一个请求，用低权限账号发一遍。如果返回的不是 403/404 而是真数据，
那就是垂直越权。

**三、注意"接口层"和"页面层"的差别。**

一个很常见的错法：页面层做了角色判断（不给你的菜单就不显示），
但接口层没做。绕过前端直接打接口就成了。

## 怎么修

**一、每个敏感接口都在服务端检查角色。** 而且要**默认拒绝**：

```python
from functools import wraps
from flask import abort, session

def require_role(role):
    def deco(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if session.get("role") != role:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return deco

@app.route("/admin/export")
@require_role("admin")
def admin_export():
    ...
```

**默认拒绝的关键是"白名单式"而不是"黑名单式"**：新加的接口默认是不可访问的，
必须显式声明谁能用。反过来（"默认都能用，个别加限制"）就是这题的成因。

**二、别把角色放在客户端能改的地方。**

这一题的角色存在 session 里（服务端签名，还好）。但如果是
`?role=admin` 或者隐藏表单字段，那就更糟 —— 那属于客户端控制权限。
（`flask_session/forged_cookie` 那道题就是这一类的极端情况。）

**三、不要用"隐藏"当权限。**

- 前端隐藏菜单：便利性，不是安全
- 接口不返回字段：也不是安全（换个接口就拿到了）
- 真正管用的是**服务端对每一个入口的判断**

**四、统一响应，别泄露结构。**

对没权限的入口，返回 403 还是 404 是个取舍：

- 403 更清楚（但告诉攻击者"这个入口存在"）
- 404 更隐蔽（但会让排查权限问题变难）

敏感系统里通常选 404，让攻击者连"这个路径存不存在"都判断不出来。

**五、把权限检查做成"过不去就报错"的测试。**

这类洞最好的防线是自动化测试：给每个敏感接口写一条"用低权限账号请求，
断言返回 403"。人工审查一定会漏，因为漏掉的是"没写的那一句"。

## 顺手想想

- 如果 `/admin/export` 检查了角色，但 `/admin/export?format=csv` 是一个
  单独的接口，忘了检查，算不算同一个洞？
- 前端隐藏入口的问题在于"藏得不够好"。如果那个链接是 JS 动态生成的，
  是不是就安全了？（提示：JS 文件本身也是能读的）
- 「角色」这种东西一旦多了（普通用户 / 组长 / 管理员 / 审计），
  硬编码 `role != "admin"` 会出什么问题？
- 如果一个接口同时有水平越权和垂直越权，你先修哪个？为什么？
