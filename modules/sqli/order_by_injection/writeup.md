# 商品排序处的注入

## 这一题在教什么

**`ORDER BY` 这个位置很特别，而它照样能把数据泄露出去。**

三个特点：

| 特点 | 说明 |
|---|---|
| **UNION 用不了** | UNION 要求前后列数一致，而这里的列由原查询定 —— 你没有地方"接"一张新表 |
| **参数化管不到** | `ORDER BY ?` 在 SQL 里是无效的。排序目标是**标识符**，不是**值** |
| **但它能读数据** | 因为**排序结果本身就是输出** |

第三条是这一题的核心：

> 服务端不告诉你某个值是多少，但告诉你"**谁比谁大**"。
> 而行序是那些值的一个函数 —— 于是你就知道了一些东西。

这跟盲注是同一件事：**信道不一定是"值本身"，也可以是"值的某个函数"。**

## 漏洞在哪

`module.py`：

```python
hit = next((w for w in BLOCKED if w in sort), None)   # 黑名单，子串匹配
if hit is not None:
    return render(blocked=hit)

sql = "SELECT %s FROM products ORDER BY %s" % (", ".join(COLUMNS), sort)
```

开发者的思路是"我只能拼字符串，所以做一份黑名单"。这个思路在标识符这一层
**几乎必然失败**（下面有两条绕过）。

## 怎么打通

### 第一步：确认这个位置存在，并看清列数

```
sort=name             正常
sort=price            正常
sort=internal_grade   被黑名单拦下
sort=9                报错：
  9th ORDER BY term out of range - should be between 1 and 4
```

最后那句报错**直接告诉你表里有 4 列**。这是很常见的一类泄露：
**报错信息本身就是一张地图。**

### 第二步：绕过一 —— 用列号，不用列名

```
sort=4
```

`ORDER BY 4` 就是"按第 4 列排"，而第 4 列正好是 `internal_grade`。

**黑名单只拦名字，拦不到位置。**

### 第三步：绕过二 —— 大小写

```
sort=INTERNAL_GRADE
```

SQLite 的标识符**大小写不敏感**（`INTERNAL_GRADE` 能匹配到 `internal_grade`），
而那份黑名单是区分大小写的。

两条绕过都成立，随便挑一条。走通之后页面的行序就是按内部评级排的。

### 第四步：如果目标是读一个**标量**

这个位置也能做布尔盲注：

```
sort=CASE WHEN substr((SELECT password FROM users WHERE username='admin'),1,1)='S'
          THEN price ELSE name END
```

- 条件为真 → 按 `price` 排
- 条件为假 → 按 `name` 排

**页面的行序会变**，于是你就有了一个布尔信道，一位一位把密码问出来。

（这一条在 `sqli/boolean_blind` 那道题里会展开。）

## 为什么"排个序"就等于泄露了数据

服务端从来没有把 `internal_grade` 的值写进响应。
但它把**行序**写进了响应 —— 而行序是那些值的一个函数。

| 行数 | 你能推出来的东西 |
|---|---|
| 3 行 | 完整排名（谁最高、谁中间、谁最低） |
| 5 行 | 完整排名 |
| 30 行 | 排名 + 二分（"它的值在 50 和 80 之间吗？"） |

这就是为什么"只返回对象 ID 和名称"这类**看起来安全**的接口仍然可能泄露数据：
**它返回的顺序、行数、耗时、页面大小，全都是信道。**

## 怎么修

**一、白名单，不是黑名单。**

```python
PUBLIC_SORTS = ("name", "price")

sort = request.form.get("sort", "name").strip()
if sort not in PUBLIC_SORTS:          # 精确匹配
    sort = "name"
```

黑名单在这一层为什么必然失败：

| 你的黑名单拦的 | 攻击者换成 |
|---|---|
| 列名 `internal_grade` | 列号 `4` |
| 小写列名 | 大小写变体 `INTERNAL_GRADE` |
| 单个标识符 | 表达式 `CASE WHEN ... END`、`(SELECT ...)` |
| 带引号的写法 | `main.users`（schema 限定）、`"users"`、`[users]` |

**枚举"不该允许的写法"是不可能的；枚举"允许的写法"是可能的。**
这就是白名单和黑名单在这一层的区别。

**二、如果选项是有限几个，就别让客户端传来传去。**

更好的设计：前端传 `sort=1` / `sort=2` 这样的**枚举序号**，
后端映射成列名。

```python
SORTS = {"1": "name", "2": "price"}
sort = SORTS.get(request.form.get("sort"), "name")
```

这样客户端传的永远是一个"选项编号"，**表结构完全不暴露给它**。

**三、报错信息不要回显。**

这一题故意把 SQLite 的报错显示出来了 —— 好让你看见列数是怎么泄露的。
真实环境里那是一条免费情报：`should be between 1 and 4` 直接告诉你有 4 列。

## 顺手想想

- 如果黑名单改成"不许出现 `grade` 这个子串"，`sort=4` 和 `sort=INTERNAL_GRADE`
  还能用吗？那还有别的写法吗？
- 如果接口返回的是**排序后的 ID 列表但顺序被打乱**（比如总是按 id 升序输出），
  这个洞还在吗？
- 除了行序，还有哪些"看起来无害"的东西能当信道？
  （提示：行数、响应时间、HTTP 状态码、页面大小、分页的总页数）
- 如果这个列表接口还支持 `LIMIT`，`LIMIT` 后面的注入跟 `ORDER BY` 有什么不一样？
  （提示：SQLite 允许 `LIMIT (SELECT ...)`，MySQL 不允许）
