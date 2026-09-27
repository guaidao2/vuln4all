# 数据看板表名处的注入

## 这一题在教什么

**参数化只能用在「值」的位置。标识符用不了它。**

看这两个东西的区别：

```sql
SELECT * FROM orders WHERE id = ?
             ↑                  ↑
        标识符（表名）        值
    参数化管不到这里     参数化管得到这里
```

SQL 的 `?` 占位符只能用在**值**的位置：数字、字符串、日期。
表名、列名、`ORDER BY` 的目标 —— 这些是**语法结构**，不能当参数传。

所以：

> **「我用了参数化」不等于「我没有注入」。**
> 只要有一个标识符来自用户输入，参数化就漏了一个口子。

而开发者给这个口子加的防护是"一份表名黑名单，比较方式是整串相等" ——
这就留下了两条路。

## 漏洞在哪

`module.py`：

```python
if table.lower() in BLOCKED_TABLES:          # 黑名单，整串比较
    return render(blocked=table)

sql = "SELECT * FROM %s" % table
```

## 怎么打通

### 第一步：确认这个位置能拼东西

```
table=orders     正常
table=users      被黑名单拦下
table=nosuch     报错：no such table: nosuch
```

（页面上会显示拼出来的 SQL，直接看更清楚。）

### 第二步：绕过一 —— 加 schema 限定

```
table=main.users
```

黑名单比的是"整串等于 `users`"，而 `main.users` 不等于它 → 放行。
但 SQLite 完全认这个写法：`main` 就是主库的名字。

```sql
SELECT * FROM main.users        -- 合法
```

顺便：`SELECT * FROM pragma_database_list` 能列出有哪些库。

### 第三步：绕过二 —— 换成子查询

```
table=(SELECT * FROM users)
```

拼出来是：

```sql
SELECT * FROM (SELECT * FROM users)
```

还是不等于 `users` → 放行，结果一模一样。

### 第四步：大小写那条为什么没成

```
table=USERS
```

**被挡住了** —— 因为这份黑名单做了 `.lower()`。

**但要知道它为什么没成**：SQLite 的标识符是**大小写不敏感**的
（`USERS` 能匹配到 `users`），所以如果黑名单没做大小写归一，这条路就通。
「黑名单做了归一」和「黑名单没做」是完全不同的两件事 ——
审计的时候要看的就是这一句。

### 第五步：先枚举再动手（更真实的打法）

```
table=sqlite_master                不在黑名单里 → 拿到全部表名
table=pragma_table_info('users')   → 拿到 users 的全部列名
```

`sqlite_master` 和 `pragma_*` **都不在那份黑名单里**：黑名单只列了几个
"敏感表名"，没列"元数据表"。而元数据恰恰是攻击者的起点。

## 这一题的教训

**一、标识符那里必须用白名单。**

```python
PUBLIC_TABLES = ("orders", "products", "shipments")

table = request.form.get("table", "orders").strip()
if table not in PUBLIC_TABLES:
    abort(403)
```

或者更好的做法：让客户端传**选项序号**，后端映射成真实表名 ——
这样表结构完全不暴露。

**二、黑名单在标识符这一层几乎必然失败。**

同一个表有很多种写法：

| 写法 | 例子 |
|---|---|
| schema 限定 | `main.users` |
| 加引号 | `"users"` |
| 方括号 | `[users]` |
| 大小写变体 | `USERS` |
| 子查询 | `(SELECT * FROM users)` |
| 换个入口 | `pragma_table_info('users')`、`sqlite_master` |

**枚举"不该允许的"是不可能的；枚举"允许的"是可能的。**

**三、元数据要显式处理。**

`sqlite_master` 是 SQLite 的"表目录"。MySQL 对应的是 `information_schema`。
这些**天然存在、天然可读**的东西，在很多项目里根本没人想到要禁 ——
因为开发者的注意力在"业务表"上。

**四、"参数化"这句话要说完整。**

| 位置 | 用什么 |
|---|---|
| 值（数字 / 字符串 / 日期） | **参数化** `?` |
| 标识符（表名 / 列名 / 排序目标） | **白名单** |
| `LIKE` 的 `%` | 参数化，但要把 `%` 拼在**传进去的参数**里，不是拼在 SQL 里 |

说"我用了参数化所以安全"，必须回答一个问题：**所有进入 SQL 结构的东西，
来源是什么？**

## 顺手想想

- 如果黑名单改成"`table` 里出现 `users` 就拦"（子串匹配），
  上面哪几条绕过还能用？哪几条不能？
- `SELECT * FROM pragma_table_info('users')` 能读到列名。
  那 `pragma_table_list` 呢？还有哪些 `pragma_*` 能当表来查？
  （提示：SQLite 3.16+ 把一部分 pragma 做成了表值函数）
- 如果这个看板还允许传**列名**（`SELECT <列> FROM <表>`），
  列名那里跟表名有什么不一样？
- 为什么说"白名单是唯一可行方向"这句话，在标识符这一层成立，
  而在"值"那一层参数化更好？
