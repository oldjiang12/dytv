#!/usr/bin/env bash
# DYTV macOS 助手：setup | run | doctor | service | logs | token
# 兼容 macOS 自带的 bash 3.2：不用关联数组、mapfile、${var,,}
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
SERVER="$ROOT/server"
VENV="$SERVER/.venv"
VPY="$VENV/bin/python"
REQ="$SERVER/requirements.txt"
STAMP="$VENV/.dytv-ok"
ENV_FILE="$ROOT/.env"
ENV_EXAMPLE="$ROOT/.env.example"
LABEL="${DYTV_LABEL:-io.github.dytv.server}"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
TEMPLATE="$ROOT/scripts/launchd/dytv.plist.template"
LOG_DIR="$HOME/Library/Logs/DYTV"
LOG_FILE="$LOG_DIR/dytv.log"
UIDN="$(id -u)"

if [ -t 1 ]; then R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
else R=; G=; Y=; B=; N=; fi
info() { printf '%s==>%s %s\n' "$G" "$N" "$1"; }
warn() { printf '%s[warn]%s %s\n' "$Y" "$N" "$1" >&2; }
die()  { local c="${2:-1}"; printf '%s[error]%s %s\n' "$R" "$N" "$1" >&2; exit "$c"; }

[ "$(uname -s)" = "Darwin" ] || die "mac.sh 只支持 macOS；Linux 或 NAS 请用 Docker（见 README）"

# ---------- 环境 ----------
load_env() {   # 解析而不执行；已存在的环境变量优先
  [ -f "$ENV_FILE" ] || return 0
  local line key val isset
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in *=*) ;; *) continue ;; esac
    key="${line%%=*}"; val="${line#*=}"
    key="${key#export }"
    key="$(printf '%s' "$key" | tr -d '[:space:]')"
    case "$key" in ''|[0-9]*|*[!A-Za-z0-9_]*) warn ".env 忽略非法行：$line"; continue ;; esac
    case "$val" in \"*\") val="${val#\"}"; val="${val%\"}" ;; \'*\') val="${val#\'}"; val="${val%\'}" ;; esac
    isset="${!key+x}"
    if [ -z "$isset" ]; then export "$key=$val"; fi
  done < "$ENV_FILE"
  return 0
}

py_ok() { "$1" -c 'import sys; sys.exit(0 if sys.version_info[:2]==(3,12) else 1)' >/dev/null 2>&1; }
find_python() {
  local c
  for c in "${PYTHON:-}" python3.12 /opt/homebrew/bin/python3.12 /usr/local/bin/python3.12 "$HOME/.pyenv/shims/python3.12"; do
    [ -n "$c" ] || continue
    if command -v "$c" >/dev/null 2>&1 && py_ok "$c"; then command -v "$c"; return 0; fi
  done
  return 1
}
venv_ok()  { [ -x "$VPY" ] && py_ok "$VPY"; }
req_hash() { shasum -a 256 "$REQ" | awk '{print $1}'; }
stamp_ok() { [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$(req_hash)" ]; }
port_pid() { lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null | head -n1 || true; }
user_data_dir() { printf '%s' "${USER_DATA_DIR:-$SERVER/user_data}"; }

lan_ip() {   # 默认路由走 Clash TUN（utun）时，那个 IP 是 198.18.x，不能给 Apple TV 用
  local ifc ip=""
  ifc="$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}' || true)"
  case "$ifc" in utun*|ppp*|ipsec*|"") ifc="" ;; esac
  if [ -n "$ifc" ]; then ip="$(ipconfig getifaddr "$ifc" 2>/dev/null || true)"; fi
  if [ -z "$ip" ]; then ip="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"; fi
  printf '%s' "$ip"; return 0
}
local_host() {
  local n; n="$(scutil --get LocalHostName 2>/dev/null || true)"
  if [ -n "$n" ]; then printf '%s.local' "$n"; fi
  return 0
}

check_profile_lock() {   # Chromium 的 SingletonLock 是指向 "主机名-pid" 的软链
  local lock pid=""
  lock="$(user_data_dir)/SingletonLock"
  [ -L "$lock" ] || return 0
  pid="$(readlink "$lock" 2>/dev/null | sed 's/.*-//')" || true
  case "$pid" in ''|*[!0-9]*) return 0 ;; esac
  if kill -0 "$pid" 2>/dev/null; then
    die "user_data 正被 PID $pid 的 Chromium 占用。两个实例共用同一份 profile 会损坏登录态" 78
  fi
  return 0
}

gen_token() { "$VPY" -c 'import secrets; print(secrets.token_urlsafe(24))'; }
write_token() {   # $1=源文件 $2=token，结果原子写回 .env
  local tmp; tmp="$(mktemp "$ROOT/.env.XXXXXX")"
  awk -v t="$2" 'BEGIN{d=0} /^ADMIN_TOKEN=/{print "ADMIN_TOKEN=" t; d=1; next} {print} END{if(!d) print "ADMIN_TOKEN=" t}' "$1" > "$tmp"
  chmod 600 "$tmp"; mv "$tmp" "$ENV_FILE"
}
ensure_env_file() {
  if [ -f "$ENV_FILE" ]; then info ".env 已存在，保持不动"; return 0; fi
  [ -f "$ENV_EXAMPLE" ] || die "缺少 .env.example"
  write_token "$ENV_EXAMPLE" "$(gen_token)"
  info "已生成 .env（含随机 ADMIN_TOKEN，权限 600）"
}

smoke_chromium() {
  "$VPY" - <<'PY'
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(headless=True)
    pg = b.new_page(); pg.goto("about:blank")
    print("chromium ok:", b.version)
    b.close()
PY
}

# ---------- 子命令 ----------
cmd_setup() {
  local py
  py="$(find_python)" || die "未找到 Python 3.12。请执行 brew install python@3.12，或者 PYTHON=/path/to/python3.12 ./scripts/mac.sh setup"
  info "Python：$py"
  case "$VENV" in */server/.venv) ;; *) die "VENV 路径异常：$VENV" ;; esac
  if [ -d "$VENV" ] && ! venv_ok; then warn "venv 已失效（多半是 brew 升级了 Python），正在重建"; rm -rf "$VENV"; fi
  if [ ! -d "$VENV" ]; then info "创建 venv"; "$py" -m venv "$VENV"; fi
  ensure_env_file
  load_env                                  # 让 PIP_INDEX_URL 和 PLAYWRIGHT_DOWNLOAD_HOST 生效
  info "安装依赖（版本已固定）"
  "$VPY" -m pip install --disable-pip-version-check -q -r "$REQ"
  info "安装 Playwright 自带的 Chromium（首次约 150MB；下载慢可在 .env 设置 PLAYWRIGHT_DOWNLOAD_HOST）"
  "$VPY" -m playwright install chromium     # 不加 --with-deps，那个参数只适用于 Linux
  smoke_chromium || die "Chromium 冒烟测试失败，见上方报错；可以运行 ./scripts/mac.sh doctor"
  req_hash > "$STAMP"
  info "安装完成。下一步：${B}./scripts/mac.sh run${N}"
}

banner() {
  local port="$1" ip lh
  ip="$(lan_ip)"; lh="$(local_host)"
  echo "------------------------------------------------------------"
  echo " DYTV 已启动，端口 $port"
  [ -n "$ip" ] && echo " Apple TV 填写：  $ip:$port"
  [ -n "$lh" ] && echo "            或：  $lh:$port   （IP 变了也能用）"
  echo " 网页播放器：     http://${ip:-127.0.0.1}:$port/"
  if [ -n "${ADMIN_TOKEN:-}" ]; then
    if [ "${DYTV_SERVICE:-0}" = "1" ]; then echo " 登录页：         http://127.0.0.1:$port/login?token=<见 .env>"
    else echo " 登录页：         http://127.0.0.1:$port/login?token=$ADMIN_TOKEN"; fi
  else
    echo " 登录页：         http://127.0.0.1:$port/login   （⚠️ 未设 ADMIN_TOKEN，局域网内任何设备都能访问）"
  fi
  echo " user_data：      $(user_data_dir)"
  echo " 首次启动时 macOS 可能会弹出防火墙授权，请点「允许」"
  echo "------------------------------------------------------------"
}

cmd_run() {
  venv_ok  || die "venv 不可用，请先运行 ./scripts/mac.sh setup" 78
  stamp_ok || die "setup 没有完成，或 requirements.txt 有变化，请重新运行 ./scripts/mac.sh setup" 78
  load_env
  local host="${BIND_HOST:-0.0.0.0}" port="${BIND_PORT:-8055}" pid access="--no-access-log"
  case "$port" in ''|*[!0-9]*) die "BIND_PORT 不合法：$port" 78 ;; esac
  pid="$(port_pid "$port")"
  if [ -n "$pid" ]; then
    die "端口 $port 已被 PID ${pid}（$(ps -p "$pid" -o comm= 2>/dev/null || true)）占用。可以换端口：BIND_PORT=8056 ./scripts/mac.sh run" 78
  fi
  check_profile_lock
  if [ "${DYTV_ACCESS_LOG:-0}" = "1" ]; then access="--access-log"; fi
  export BIND_PORT="$port" PYTHONUNBUFFERED=1
  banner "$port"
  cd "$SERVER"
  exec "$VPY" -m uvicorn main:app --host "$host" --port "$port" "$access"
}

cmd_doctor() {
  local bad=0 v port pid ip code
  chk() { if [ "$1" = ok ]; then printf '  %s✓%s %s\n' "$G" "$N" "$2"; else printf '  %s✗%s %s\n' "$R" "$N" "$2"; bad=$((bad+1)); fi; }
  note() { printf '  %s!%s %s\n' "$Y" "$N" "$1"; }
  load_env
  echo "${B}DYTV doctor${N}"
  echo "  macOS $(sw_vers -productVersion)，架构 $(uname -m)"
  case "$ROOT" in "$HOME/Desktop"*|"$HOME/Documents"*|"$HOME/Downloads"*)
    note "仓库在 Desktop、Documents 或 Downloads 下，launchd 常驻会被隐私保护（TCC）拦截，建议移到 ~/dev/dytv" ;; esac
  if v="$(find_python)"; then chk ok "Python 3.12：$v"; else chk bad "未找到 Python 3.12（brew install python@3.12）"; fi
  if venv_ok; then chk ok "venv 可用"; else chk bad "venv 不可用，需要运行 setup"; fi
  if stamp_ok; then chk ok "依赖与 requirements.txt 一致"; else chk bad "依赖未安装或已过期，需要运行 setup"; fi
  if venv_ok; then
    if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = "1" ] && \
       [ "$("$VPY" -c 'import platform;print(platform.machine())')" != "arm64" ]; then
      note "Apple Silicon 上用的是 x86 版 Python（Rosetta），能跑但慢。建议改用 /opt/homebrew 下的 python3.12"
    fi
    if v="$(cd "$SERVER" && "$VPY" -c 'import main; print(main.USER_DATA_DIR)' 2>&1 | tail -n1)"; then
      chk ok "main.py 可以导入（Playwright 版本断言通过），user_data=$v"
    else chk bad "导入 main.py 失败：$v"; fi
    if smoke_chromium >/dev/null 2>&1; then chk ok "headless Chromium 能启动"; else chk bad "Chromium 无法启动（重新运行 setup，或检查 PLAYWRIGHT_DOWNLOAD_HOST）"; fi
    v="$("$VPY" -c 'import socket,ipaddress,os;ip=socket.gethostbyname("www.douyin.com");print(ip, ipaddress.ip_address(ip) in ipaddress.ip_network(os.environ.get("FAKE_IP_RANGE","198.18.0.0/16"),strict=False))' 2>/dev/null || echo "fail False")"
    case "$v" in
      fail*) chk bad "无法解析 www.douyin.com" ;;
      *True) if [ "${ALLOW_FAKE_IP:-0}" = "1" ]; then chk ok "检测到 fake-ip，并已设置 ALLOW_FAKE_IP=1（${v}）"
             else chk bad "检测到 fake-ip（${v% *}）但没有设置 ALLOW_FAKE_IP=1，/proxy 会全部被拒"; fi ;;
      *) chk ok "DNS 正常（${v% *}）" ;;
    esac
  fi
  code="$(curl -s -o /dev/null -m 6 -w '%{http_code}' https://www.douyin.com/ || true)"
  case "$code" in 2*|3*) chk ok "能访问 douyin.com（HTTP ${code}）" ;; *) chk bad "访问 douyin.com 失败（HTTP ${code:-超时}）" ;; esac
  if [ "${ALLOW_FAKE_IP:-0}" = "1" ]; then
    code="$(curl -s -o /dev/null -m 6 -w '%{http_code}' "${DOH_URL:-https://223.5.5.5/resolve}?name=www.douyin.com&type=A" || true)"
    case "$code" in 200) chk ok "DoH 可用" ;; *) chk bad "DoH 不可用（HTTP ${code:-超时}），fake-ip 场景下 /proxy 会被拒" ;; esac
  fi
  port="${BIND_PORT:-8055}"; pid="$(port_pid "$port")"
  if [ -n "$pid" ]; then
    code="$(curl -s -o /dev/null -m 3 -w '%{http_code}' "http://127.0.0.1:$port/healthz" || true)"
    note "端口 $port 已被 PID $pid 占用，/healthz 返回 HTTP ${code:-超时}"
  else note "端口 $port 空闲"; fi
  if [ -n "${ADMIN_TOKEN:-}" ]; then chk ok "已设置 ADMIN_TOKEN"; else note "没有设置 ADMIN_TOKEN，/login 对局域网开放"; fi
  ip="$(lan_ip)"; note "局域网地址：${ip:-未检测到}，以及 $(local_host)"
  if launchctl print "gui/$UIDN/$LABEL" >/dev/null 2>&1; then note "常驻服务已加载（${LABEL}）"; else note "常驻服务未安装"; fi
  note "睡眠设置：$(pmset -g 2>/dev/null | awk '$1=="sleep"{print $2}' || true)（0 表示不睡眠）"
  [ "$bad" -eq 0 ] && info "全部通过" || die "$bad 项未通过"
}

xml_safe() { case "$1" in *'&'*|*'<'*|*'>'*|*'|'*) return 1 ;; esac; return 0; }
svc_loaded() { launchctl print "gui/$UIDN/$LABEL" >/dev/null 2>&1; }
svc_status() {
  if svc_loaded; then
    launchctl print "gui/$UIDN/$LABEL" | awk '/^\t(state|pid|runs|last exit code) = /' | head -n 4
  else echo "  服务未安装或未加载"; fi
  load_env
  echo "  healthz：HTTP $(curl -s -o /dev/null -m 3 -w '%{http_code}' "http://127.0.0.1:${BIND_PORT:-8055}/healthz" || true)"
}
svc_install() {
  { venv_ok && stamp_ok; } || die "请先运行 ./scripts/mac.sh setup"
  case "$ROOT" in "$HOME/Desktop"*|"$HOME/Documents"*|"$HOME/Downloads"*)
    die "仓库在 Desktop、Documents 或 Downloads 下，launchd 会被隐私保护（TCC）拦截。请移到 ~/dev/dytv 之类的目录" ;; esac
  case "$LABEL" in *[!A-Za-z0-9._-]*) die "DYTV_LABEL 含非法字符" ;; esac
  xml_safe "$ROOT" || die "仓库路径里有 & < > | 字符，无法安全生成 plist，请换目录"
  [ -f "$TEMPLATE" ] || die "缺少模板 $TEMPLATE"
  if svc_loaded; then info "先卸载旧实例"; launchctl bootout "gui/$UIDN/$LABEL" || true; sleep 2; fi
  load_env
  local port="${BIND_PORT:-8055}" pid
  pid="$(port_pid "$port")"
  [ -z "$pid" ] || die "端口 $port 已被 PID $pid 占用，装上后服务会反复重启失败。请先停掉它，或在 .env 里改 BIND_PORT"
  mkdir -p "$(dirname "$PLIST")" "$LOG_DIR"
  sed -e "s|__LABEL__|$LABEL|g" -e "s|__ROOT__|$ROOT|g" -e "s|__LOG_FILE__|$LOG_FILE|g" "$TEMPLATE" > "$PLIST.tmp"
  plutil -lint "$PLIST.tmp" >/dev/null || { rm -f "$PLIST.tmp"; die "生成的 plist 校验失败"; }
  mv "$PLIST.tmp" "$PLIST"
  launchctl bootstrap "gui/$UIDN" "$PLIST" || die "bootstrap 失败，请执行 ./scripts/mac.sh logs 查看原因"
  launchctl enable "gui/$UIDN/$LABEL" || true
  info "已安装：$PLIST"; sleep 4; svc_status
}
svc_uninstall() {
  if svc_loaded; then launchctl bootout "gui/$UIDN/$LABEL" || true; fi
  rm -f "$PLIST"; info "已卸载（user_data、.env 和日志都保留）"
}
svc_restart() { svc_loaded || die "服务未安装"; launchctl kickstart -k "gui/$UIDN/$LABEL"; sleep 4; svc_status; }

cmd_logs()  { mkdir -p "$LOG_DIR"; touch "$LOG_FILE"; tail -n 200 -F "$LOG_FILE"; }
cmd_token() {
  venv_ok || die "请先运行 setup"; [ -f "$ENV_FILE" ] || die "没有 .env，请先运行 setup"
  write_token "$ENV_FILE" "$(gen_token)"
  info "新 token 已写入 .env。重启后生效：./scripts/mac.sh service restart，或重新执行 run"
}

usage() { cat <<EOF
用法：./scripts/mac.sh <命令>
  setup                       创建 venv、安装依赖和 Chromium、生成 .env（可重复执行）
  run                         前台启动（Ctrl-C 停止）
  doctor                      环境自检
  service install|uninstall|restart|status
                              开机常驻（launchd，Label：${LABEL}）
  logs                        查看常驻日志
  token                       重新生成 ADMIN_TOKEN
EOF
}

case "${1:-help}" in
  setup)  cmd_setup ;;
  run)    cmd_run ;;
  doctor) cmd_doctor ;;
  service)
    case "${2:-status}" in
      install) svc_install ;; uninstall) svc_uninstall ;;
      restart) svc_restart ;; status) svc_status ;;
      *) usage; exit 2 ;;
    esac ;;
  logs)   cmd_logs ;;
  token)  cmd_token ;;
  help|-h|--help) usage ;;
  *) usage; exit 2 ;;
esac
