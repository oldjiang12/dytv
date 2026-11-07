#!/bin/zsh
# DYTV：tvOS 免费开发证书自动续签。
# 描述文件大约 7 天过期。只重签不会重置窗口，必须先删掉缓存的 profile，
# 再让已登录的 Xcode 图形界面重新签发并装回 Apple TV。
# 命令行 xcodebuild 经常报 No Accounts，所以不用它续签（免费账号实测）。
# 装机失败后缓存 profile 可能已经是新的，状态文件记录「设备上那一份」的到期时间，
# 不一致时只补装，避免第二天误判成「还早，不用管」而让电视上的旧签名过期。
#
# 个性化配置（工程路径/设备 UDID/profile key 等）写在同目录 renew.env（被 gitignore
# 忽略），参考 renew.env.example。FORCE=1 可忽略剩余时间立刻重签。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="$HERE/renew.env"
if [ -f "$CONF" ]; then . "$CONF"; fi

die() { echo "[renew] $*" >&2; exit 64; }
[ -n "${DYTV_PROJ:-}" ]        || die "缺少 DYTV_PROJ，请配置 ${CONF}（参考 renew.env.example）"
[ -n "${DYTV_DEVICE:-}" ]      || die "缺少 DYTV_DEVICE（Apple TV UDID，xcrun devicectl list devices 查看），请配置 ${CONF}"
[ -n "${DYTV_PROFILE_KEY:-}" ] || die "缺少 DYTV_PROFILE_KEY（profile 名包含的标识片段），请配置 ${CONF}"

PROJ="$DYTV_PROJ"
SCHEME="${DYTV_SCHEME:-DouyinTV}"
DEVICE_ID="$DYTV_DEVICE"
DEVICE_NAME="${DYTV_DEVICE_NAME:-appletv}"
PROFILE_KEY="$DYTV_PROFILE_KEY"
LOG="${DYTV_LOG:-$HOME/Library/Logs/dytv-renew.log}"
PROFILE_DIR="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
STATE_DIR="${DYTV_STATE_DIR:-$HOME/Library/Application Support/dytv-renew}"
STATE_FILE="$STATE_DIR/$SCHEME.installed"
LOCK="/tmp/dytv-renew.lock"
THRESHOLD_H="${DYTV_THRESHOLD_H:-72}"
OK_H="${DYTV_OK_H:-164}"
# 可选：与其他自动续签任务互斥的锁目录（如 /tmp/xxx-renew.lock）
WAIT_LOCK="${DYTV_WAIT_LOCK:-}"

log()    { echo "[$(date '+%F %T')] $*" >> "$LOG"; }
notify() { osascript -e "display notification \"${1}\" with title \"DYTV 续签\"" >/dev/null 2>&1 || true; }

exp_of_profile() {
  security cms -D -i "$1" 2>/dev/null | grep -A1 '<key>ExpirationDate</key>' \
    | grep -o '<date>[^<]*</date>' | sed -e 's/<date>//' -e 's|</date>||' || true
}

profile_name() {
  security cms -D -i "$1" 2>/dev/null | awk -F'<string>|</string>' '/<key>Name<\/key>/{getline; print $2; exit}'
}

# 打印剩余小时数，以及对应的到期串。没有匹配 profile 时两行都空。
profile_best() {
  local f name exp epoch rem best_rem="" best_exp=""
  for f in "$PROFILE_DIR"/*.mobileprovision(N); do
    name=$(profile_name "$f")
    [[ "$name" == *"$PROFILE_KEY"* ]] || continue
    exp=$(exp_of_profile "$f")
    epoch=$(date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$exp" +%s 2>/dev/null) || continue
    rem=$(( (epoch - $(date +%s)) / 3600 ))
    if [[ -z "$best_rem" || "$rem" -gt "$best_rem" ]]; then
      best_rem=$rem
      best_exp=$exp
    fi
  done
  echo "$best_rem"
  echo "$best_exp"
}

embedded_exp() { exp_of_profile "$1/embedded.mobileprovision"; }

newest_app() {
  local cand m mtime=0 best=""
  for cand in "$HOME"/Library/Developer/Xcode/DerivedData/${SCHEME}-*/Build/Products/Debug-appletvos/${SCHEME}.app(N) \
              /tmp/dytv-dd/Build/Products/Debug-appletvos/${SCHEME}.app; do
    [[ -f "$cand/$SCHEME" && -f "$cand/Info.plist" ]] || continue
    m=$(stat -f %m "$cand/$SCHEME")
    if (( m > mtime )); then
      mtime=$m
      best=$cand
    fi
  done
  echo "$best"
}

mkdir -p "$(dirname "$LOG")" "$STATE_DIR"
mkdir "$LOCK" 2>/dev/null || { log "another instance running, exit"; exit 0; }
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT

# 与其他自动续签任务错开，避免同时抢 Xcode
if [[ -n "$WAIT_LOCK" ]]; then
  for _ in $(seq 1 120); do
    [[ -d "$WAIT_LOCK" ]] || break
    log "waiting for ${WAIT_LOCK} to be released"
    sleep 20
  done
fi

best=$(profile_best)
rem=$(echo "$best" | sed -n '1p')
exp=$(echo "$best" | sed -n '2p')
installed_exp=$(cat "$STATE_FILE" 2>/dev/null || true)

RETRY_INSTALL=""
if [[ -z "${FORCE:-}" && -n "$rem" && "$rem" -ge "$THRESHOLD_H" ]]; then
  if [[ -n "$installed_exp" && "$exp" == "$installed_exp" ]]; then
    log "rem=${rem}h >= ${THRESHOLD_H}h and installed profile current -> skip"
    exit 0
  fi
  RETRY_INSTALL=1
  log "rem=${rem}h but device copy is stale (cached=${exp:-?} installed=${installed_exp:-none}) -> install-only"
else
  log "device=${DEVICE_NAME} rem=${rem:-unknown}h -> renew start"
fi
[[ -n "$rem" && "$rem" -lt 24 ]] && notify "证书剩余 ${rem} 小时，正在自动续签"

visible=""
for _ in 1 2 3; do
  out=$(xcrun devicectl list devices 2>/dev/null || true)
  if [[ "$out" == *"$DEVICE_ID"* ]]; then visible=1; break; fi
  sleep 5
done
if [[ -z "$visible" ]]; then
  log "ABORT: device ${DEVICE_ID} not visible"
  notify "Apple TV 不在线，这次没能续签"
  exit 1
fi

APP=""
if [[ -n "$RETRY_INSTALL" ]]; then
  for cand in "$HOME"/Library/Developer/Xcode/DerivedData/${SCHEME}-*/Build/Products/Debug-appletvos/${SCHEME}.app(N) \
              /tmp/dytv-dd/Build/Products/Debug-appletvos/${SCHEME}.app; do
    [[ -f "$cand/$SCHEME" ]] || continue
    if [[ "$(embedded_exp "$cand")" == "$exp" ]]; then
      APP=$cand
      break
    fi
  done
  if [[ -n "$APP" ]]; then
    log "install-retry product: $APP"
  else
    log "install-retry: no product matches current profile -> full renew"
    RETRY_INSTALL=""
  fi
fi

if [[ -z "$RETRY_INSTALL" ]]; then
  for f in "$PROFILE_DIR"/*.mobileprovision(N); do
    name=$(profile_name "$f")
    if [[ "$name" == *"$PROFILE_KEY"* ]]; then
      rm -f "$f"
      log "removed cached profile: ${name}"
    fi
  done

  open "$PROJ"
  sleep 15
  BUILD_MARK=$(date +%s)
  if ! osascript >/dev/null 2>"$STATE_DIR/osascript.err" <<AS
tell application "Xcode"
  set ws to missing value
  repeat with doc in workspace documents
    try
      if (path of doc as text) contains "${SCHEME}" then
        set ws to doc
        exit repeat
      end if
    end try
  end repeat
  if ws is missing value then error "${SCHEME} workspace not open"
  set active scheme of ws to (first scheme of ws whose name is "${SCHEME}")
  set dest to missing value
  set names to ""
  repeat with d in run destinations of ws
    set n to name of d
    set names to names & n & " | "
    if n is "${DEVICE_NAME}" then set dest to d
  end repeat
  if dest is missing value then error "no destination named ${DEVICE_NAME}. have: " & names
  set active run destination of ws to dest
  build ws
end tell
AS
  then
    log "FAIL: cannot drive Xcode GUI build ($(tr '\n' ' ' < "$STATE_DIR/osascript.err"))"
    notify "续签失败：无法驱动 Xcode 构建"
    exit 1
  fi
  log "xcode gui build dispatched"

  ok=""
  for _ in $(seq 1 120); do
    sleep 10
    best=$(profile_best)
    r=$(echo "$best" | sed -n '1p')
    if [[ -n "$r" && "$r" -ge "$OK_H" ]]; then ok=1; break; fi
  done
  if [[ -z "$ok" ]]; then
    log "FAIL: new profile not observed"
    notify "续签失败：没有签发出新描述文件"
    exit 1
  fi
  exp=$(echo "$best" | sed -n '2p')
  log "new profile observed, rem=$(echo "$best" | sed -n '1p')h exp=${exp}"

  ok=""
  for _ in $(seq 1 60); do
    cand=$(newest_app)
    if [[ -n "$cand" ]]; then
      mtime=$(stat -f %m "$cand/$SCHEME")
      if (( mtime >= BUILD_MARK )) && [[ "$(embedded_exp "$cand")" == "$exp" ]]; then
        APP=$cand
        ok=1
        break
      fi
    fi
    sleep 10
  done
  if [[ -z "$ok" ]]; then
    log "FAIL: product not ready after new profile"
    notify "续签失败：新包还没编出来"
    exit 1
  fi
  log "product ready: $APP"
fi

xcrun devicectl device install app --device "$DEVICE_ID" "$APP" >> "$LOG" 2>&1 \
  || { log "FAIL: devicectl install"; notify "续签失败：装到 Apple TV 失败"; exit 1; }

echo "$(embedded_exp "$APP")" > "$STATE_FILE"
log "RENEWED OK rem=$(echo "$(profile_best)" | sed -n '1p')h installed (profile expires $(embedded_exp "$APP"))"
notify "续签成功，已装回 Apple TV"
