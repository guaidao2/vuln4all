# 批量上传头像包时的 Zip Slip

## 这一题在教什么

**压缩包里的成员名，是"路径"还是"名字"？**

开发写解压逻辑的时候，很容易把它当"名字"用（`upload_dir / name`），
但 zip 格式里的 `filename` 字段**可以包含路径**，而且可以包含 `../`。
命令行 `zip` 工具会帮你规范化掉，但你手搓的压缩包不会。

于是：一个成员名叫 `../运营公告/公告.txt` 的文件，被写到了上传目录**外面**。

这就是 Zip Slip。真实环境里它的后果通常是直接 getshell —— 覆盖一个
能被执行的配置、模板、cron 文件、或者 `~/.ssh/authorized_keys`。

## 漏洞在哪

`module.py` 的 `_handle_upload()`：

```python
if name.lower().endswith(BLOCKED_EXT):     # 这一行没问题
    blocked.append(name)
    continue

target = upload_dir / name                 # ← 洞在这里
```

开发的心思全花在"别让人传可执行文件"上了，**旁边这一行没做任何处理**。

一个值得记住的对照：

```python
# 标准库这条路是安全的（Python 3.6+ 会把 .. 和绝对路径清掉）
archive.extractall(upload_dir)

# 而几乎所有 Zip Slip 都出现在"不用标准库、自己写循环"的地方 ——
# 因为开发想加点自己的过滤、改名、限大小逻辑
```

**你想加的那点过滤，恰恰是让你自己失去保护的原因。**

## 怎么打通

**第一步：手搓一个恶意 zip。**

命令行 `zip` 会规范化成员名，所以用 Python：

```python
import zipfile

z = zipfile.ZipFile("evil.zip", "w")
z.writestr(zipfile.ZipInfo("../运营公告/公告.txt"), "这里已经被我改了")
z.close()
```

成员名是 `../运营公告/公告.txt` —— 往上走一级就出了「上传的头像」。

**第二步：传上去。**

页面会告诉你"落到上传目录外面的成员"是哪几个。

**第三步：回首页看那条运营公告。**

它已经被换掉了。那个文件在上传目录的**上一级**，正常上传永远碰不到它。

## 还能往哪写

```
../运营公告/公告.txt                往上走一级
../../../../tmp/anything            写到系统临时目录
../../../../root/.ssh/authorized_keys    写到就是登录
/etc/cron.d/backdoor                绝对路径（有些解压实现不过滤这个）
```

Windows 上还有另一套：`..\..\`, `C:\...`, 以及 `foo.txt:ads` 这类 NTFS 备用数据流。

**判断危害大小只看两件事：**

1. 进程以什么身份在跑（root 还是普通用户）
2. 有没有能被覆盖成"可执行/被解析"的目标

## 怎么修

**一、把成员名收敛成纯文件名。**

```python
import os

def safe_member_name(name: str) -> str:
    return os.path.basename(name.replace("\\", "/"))

target = upload_dir / safe_member_name(info.filename)
```

这一题里已经写好了 `safe_member_name()`，只是故意没用它。

**二、或者用标准库，别自己循环。**

```python
archive.extractall(upload_dir)      # Python 3.6+ 已经会处理 ..
```

**但要确认你的语言/版本**：不同语言的实现行为不一样，有些老版本没修。

**三、最稳的：先规范化，再校验结果还在目标目录里。**

```python
target = (upload_dir / name).resolve()
if upload_dir.resolve() not in target.parents:
    raise PermissionError("越界了")
```

注意 `resolve()` 要在**写入之前**做，而且校验对象是解析后的**绝对**路径 ——
字符串比较 `/uploads` 这种写法会被 `/uploads-evil` 骗过去。

**四、上传目录本身不要有"上一级"。**

如果上传目录挂在独立的挂载点、或者干脆在容器里，`../` 就走不到任何有价值的地方。
这是纵深防御，不能替代前三条。

**五、防 zip 炸弹。**

这一题加了包大小和总解压量上限。真实环境里还要防：

- **压缩比炸弹**：42.zip 这种，几 KB 解出几 PB
- **大量小文件**：一个 zip 里塞几十万个小文件，把 inode 耗尽
- **嵌套压缩包**：解压出来的还是压缩包

## 顺手想想

- 如果代码里写的是 `if ".." not in name`，怎么绕？（提示：`....//`、
  以及"删掉一次 `..` 之后剩下的拼起来正好又是 `..`"）
- 如果成员名是绝对路径 `/etc/cron.d/x`，`os.path.join(upload_dir, name)` 会得到什么？
  （想不起来的话，去看 `path_traversal/file_download` 那道题）
- 解压时把文件重命名成 uuid 是不是就安全了？
  （提示：`../` 还在，只是结尾的名字变了 —— 想清楚它到底挡掉了什么）
- 为什么"命令行 zip 工具不会帮你做这件事"反而更容易让人踩坑？
