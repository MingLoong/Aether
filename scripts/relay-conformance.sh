#!/usr/bin/env bash
# relay-conformance.sh — relay（自定义透传）供应商端到端验收脚本
#
# 断言四件事：
#   1. 真实请求经 AE 打到 relay 后返回 200
#   2. 回执头没有泄漏给客户端
#   3. （给了 PSQL_URL 时）usage_http_audits 记录 provider_headers_source = upstream_echo
#   4. 回执头表里没有夹带 x-aether-* 控制头
#
# 用法：
#   AETHER_API_KEY=sk-aether-xxx \
#   RELAY_MODEL=hy3 \
#   PSQL_URL='postgresql://aether:${AETHER_DB_PASSWORD}@127.0.0.1:5432/aether' \
#     bash scripts/relay-conformance.sh
#
# 环境变量：
#   AETHER_BASE_URL   AE 网关地址，默认 http://127.0.0.1:8084
#   AETHER_API_KEY    必填，AE 客户端 key
#   RELAY_MODEL       打到 relay 的模型名，默认 hy3
#   PSQL_URL          可选，给了才做落库断言
#   EXPECT_SOURCE     期望的来源标记，默认 upstream_echo
#   WAIT_SECONDS      等待异步落库的秒数，默认 15
#
# 退出码：0 全部通过；1 有断言失败；2 用法/依赖问题。

set -uo pipefail

BASE="${AETHER_BASE_URL:-http://127.0.0.1:8084}"
: "${AETHER_API_KEY:?必须设置 AETHER_API_KEY}"
MODEL="${RELAY_MODEL:-hy3}"
EXPECT_SOURCE="${EXPECT_SOURCE:-upstream_echo}"
WAIT_SECONDS="${WAIT_SECONDS:-15}"

for bin in curl python3; do
  command -v "$bin" >/dev/null 2>&1 || { echo "缺少依赖：$bin" >&2; exit 2; }
done
if [ -n "${PSQL_URL:-}" ] && ! command -v psql >/dev/null 2>&1; then
  echo "设置了 PSQL_URL 但找不到 psql" >&2
  exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FAILED=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILED=1; }

NONCE="conformance-$(date +%s)-$$"
BODY=$(python3 - "$MODEL" "$NONCE" <<'PY'
import json, sys
model, nonce = sys.argv[1], sys.argv[2]
print(json.dumps({
    "model": model,
    "messages": [{"role": "user", "content": f"Reply with exactly: {nonce}"}],
    "stream": False,
}))
PY
)

echo "== relay conformance =="
echo "   base=$BASE model=$MODEL nonce=$NONCE"

STATUS=$(curl -sS --max-time 180 -D "$TMP/headers" -o "$TMP/body" \
  -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $AETHER_API_KEY" \
  -X POST "$BASE/v1/chat/completions" --data "$BODY" || echo "000")

# 1) HTTP 200
if [ "$STATUS" = "200" ]; then
  pass "chat completions 返回 200"
else
  fail "chat completions 返回 $STATUS（期望 200）"
  head -c 400 "$TMP/body" 2>/dev/null; echo
fi

# 2) 回执头不得泄漏给客户端
if grep -qi '^x-aether-provider-request-headers:' "$TMP/headers"; then
  fail "回执头泄漏到了客户端响应"
else
  pass "客户端响应不含回执头"
fi

# 3) 落库断言
TRACE_ID=$(grep -i '^x-trace-id:' "$TMP/headers" | head -1 | sed 's/^[^:]*:[[:space:]]*//; s/\r$//')
if [ -z "$TRACE_ID" ]; then
  fail "响应缺少 x-trace-id，无法关联审计记录"
elif [ -z "${PSQL_URL:-}" ]; then
  echo "  SKIP 未提供 PSQL_URL，跳过落库断言（request_id=$TRACE_ID）"
else
  ROW=""
  for _ in $(seq 1 "$WAIT_SECONDS"); do
    ROW=$(psql "$PSQL_URL" -Atc \
      "SELECT provider_headers_source || '|' || (provider_request_headers IS NOT NULL)::text
         FROM usage_http_audits WHERE request_id = '$TRACE_ID'" 2>/dev/null)
    [ -n "$ROW" ] && break
    sleep 1
  done

  SOURCE="${ROW%%|*}"
  HAS_HEADERS="${ROW##*|}"

  if [ "$SOURCE" = "$EXPECT_SOURCE" ]; then
    pass "provider_headers_source = $SOURCE"
  else
    fail "provider_headers_source = '${SOURCE:-<空>}'（期望 $EXPECT_SOURCE；request_id=$TRACE_ID）"
    echo "        排查：抓包看请求是否带 x-aether-echo、响应是否带回执头（见 spec D.3 / D.4）"
  fi

  if [ "$HAS_HEADERS" = "true" ]; then
    pass "provider_request_headers 已落库"
  else
    fail "provider_request_headers 为空"
  fi

  # 4) 回执头表里不得夹带控制头
  LEAK=$(psql "$PSQL_URL" -Atc \
    "SELECT count(*) FROM usage_http_audits
       WHERE request_id = '$TRACE_ID'
         AND provider_request_headers::text ~ '(x-aether-echo|x-aether-trace-id)'" 2>/dev/null)
  if [ "${LEAK:-0}" = "0" ]; then
    pass "回执头表未夹带 x-aether-* 控制头"
  else
    fail "回执头表夹带了 x-aether-* 控制头（relay 未在转发前剥离）"
  fi
fi

echo
if [ "$FAILED" -eq 0 ]; then
  echo "结论：PASS"
  exit 0
fi
echo "结论：FAIL"
exit 1
