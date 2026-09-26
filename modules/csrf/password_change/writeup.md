# 改密码处的 CSRF

## 这一题在教什么

CSRF 的核心不是「伪造请求」这个技术动作，而是一个概念问题：

> 服务端凭什么相信「这个请求是用户本人想发的」？

当答案是「因为它带着 session cookie」的时候，问题就来了 —— cookie 是**浏览器自动带**
的，请求由谁发起它不管。这题就是让你亲眼看一遍。

## 这道题的结构

这一题有两个站点，都在同一个靶场进程里：

| 站点 | 挂在哪 | 是什么 |
|---|---|---|
| 受害者站 | 主入口 | 需要登录的个人中心，改密码接口只看 session |
| 攻击者站 | `/evil-site/` | 一张假的「免费抽奖」页面 |

## 攻击者站的攻击载荷

就这三行：

```html
<form action="<受害者站的改密码接口>" method="POST">
  <input type="hidden" name="new_password" value="pwned-by-csrf">
</form>
<script>document.forms[0].submit()</script>
```

页面一加载，表单就自动提交。没有点击，没有确认。

## 怎么打通

1. 打开**个人中心**，用 `bob / password123` 登录。
2. 在**保持登录**的状态下，打开攻击者站点 `/evil-site/`。
   页面会自动提交那个隐藏表单（也会弹出一个新标签页，里面直接显示改密码的结果）。
3. 回个人中心，点「退出」。
4. 用 `bob / password123` 登录 —— 登不上了。
5. 换成 `pwned-by-csrf` —— 进去了。

你一下都没碰「修改密码」那个按钮，密码却变了。

## 为什么 SameSite=Lax 没拦住

这是这一题最容易搞错的地方。Flask 这边 `SESSION_COOKIE_SAMESITE` 设的是 `Lax`，
而 `Lax` 的规则是「跨 **site** 的 POST 不带 cookie」。

问题是：攻击者站和受害者站在**同一个 host** 上，对浏览器来说属于同一个 site。
所以 `Lax` 判定这属于「同站请求」，cookie 照带不误。

真实世界里还有一条更狠的路：如果站点是 `http://`，攻击者只要在页面里
放一个 `<form action="http://victim/...">` 并且让浏览器把 SameSite 当成
「无效配置」（早期浏览器对未知值一律当作 None），保护就整个失效。

**结论：SameSite 是纵深防御的一层，不能当唯一防线。**

## 怎么修

标准做法是 **CSRF token**：服务端给表单塞一个随机且和当前 session 绑定的一次性 token，
提交时校验。

```python
# 生成（放进表单隐藏字段）
session["csrf"] = secrets.token_urlsafe(32)

# 校验（处理 POST 时）
if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "")):
    abort(403)
```

配套的三件事：

1. 改密码这种敏感操作，要求**再输一次旧密码** —— 攻击者不知道旧密码，这一步就挡住了。
2. 检查 `Origin` / `Referer` 头（作为补充，别当唯一手段）。
3. `SESSION_COOKIE_SAMESITE = "Lax"`（或者对更严格的场景用 `"Strict"`），仍要保留。

## 顺手想想

- 如果这个改密码接口改成了 `GET`，攻击者连表单都不用写，
  在页面里塞一个 `<img src="...">` 就完事了。为什么 GET 更危险？
- 如果目标站点是 `https://`、`SameSite=Lax`、并且检查了 `Referer`，
  还有没有别的 CSRF 路子？（提示：想想 `Referer` 什么时候会被浏览器省略）
