#!/bin/bash
# privacy-scan.sh — 提交前隐私扫描。用法：privacy-scan.sh [--staged]
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
[ -n "${ROOT}" ] || ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
if [ "${1:-}" = "--staged" ]; then
  FILES="$(git diff --cached --name-only --diff-filter=ACMR | grep -v '^scripts/privacy-scan\.sh$' || true)"
else
  FILES="$(find . -type f -not -path './.git/*' -not -path './.venv/*' -not -path './server/.venv/*' \
           -not -path './server/user_data/*' -not -path './build/*' -not -path './apple-tv/build/*' \
           -not -path './.mimosa/*' -not -path './.video_agent/*' -not -path '*__pycache__*' \
           -not -name '.env' -not -name 'renew.env' -not -name 'privacy-patterns.local' \
           -not -name '*.local.xcconfig' -not -name 'privacy-scan.sh' | sed 's|^\./||')"
fi
[ -z "${FILES}" ] && exit 0
FAIL=0
GEN="$(mktemp)"; PER="$(mktemp)"; trap 'rm -f "${GEN}" "${PER}"' EXIT

# A. 禁止入库的文件
FORBID='(^|/)(\.env|renew\.env|[^/]*\.local\.xcconfig|[^/]*\.local\.env|privacy-patterns\.local|[^/]*\.mobileprovision|[^/]*\.p12|[^/]*\.xcuserstate|\.DS_Store|[^/]*\.log)$|(^|/)(user_data|\.venv|xcuserdata|DerivedData|__pycache__)/'
if echo "${FILES}" | grep -E "${FORBID}"; then echo "❌ 上面这些文件不能入库"; FAIL=1; fi

# B. 通用规则（内网 IP 段用"末尾不跟 /"排除 CIDR 写法）
cat > "${GEN}" <<'EOF'
/Users/[A-Za-z0-9._-]+
/home/[a-z][a-z0-9_-]+/
/volume[0-9]+/
(^|[^0-9.])(10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}([^0-9/]|$)
[0-9A-F]{8}-[0-9A-F]{16}
DEVELOPMENT_TEAM[[:space:]]*=[[:space:]]*[A-Z0-9]{10}
(sessionid|sessionid_ss|sid_tt|sid_guard|uid_tt|ttwid|odin_tt|passport_csrf_token|msToken|s_v_web_id)["']?[[:space:]]*[=:][[:space:]]*["']?[A-Za-z0-9%_.-]{12,}
ADMIN_TOKEN[[:space:]]*=[[:space:]]*[^[:space:]#]{8,}
[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}
qfhome|douyintv
EOF
# B 类命中若带「privacy-scan-allow」内联标记则视为已人工审定的豁免
echo "${FILES}" | tr '\n' '\0' | xargs -0 grep -nIE -f "${GEN}" -- 2>/dev/null \
  | grep -v 'privacy-scan-allow' && { echo "❌ 命中通用规则（逐条人工确认）"; FAIL=1; }

# C. 本机个人特征（自动生成，不入库）
{ whoami; scutil --get LocalHostName 2>/dev/null; scutil --get ComputerName 2>/dev/null; git config --global user.email
  [ -f scripts/privacy-patterns.local ] && grep -v '^#' scripts/privacy-patterns.local
} 2>/dev/null | awk 'length>=3' > "${PER}"
if [ -s "${PER}" ]; then
  echo "${FILES}" | tr '\n' '\0' | xargs -0 grep -nIiF -f "${PER}" -- 2>/dev/null && { echo "❌ 命中本机个人特征"; FAIL=1; }
fi

# D. bash 陷阱：变量后紧跟非 ASCII 字符（bash 3.2 会把它并进变量名）
echo "${FILES}" | grep -E '\.sh$' | tr '\n' '\0' | LC_ALL=C xargs -0 grep -nE '\$[A-Za-z_][A-Za-z0-9_]*[^ -~]' -- 2>/dev/null \
  && { echo "❌ 变量后紧跟非 ASCII 字符，请改成 \${var}"; FAIL=1; }

[ "${FAIL}" = 0 ] && echo "✅ privacy-scan 通过"
exit "${FAIL}"
