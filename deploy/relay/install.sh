#!/usr/bin/env bash
# Aether Gateway（relay-only）离线安装脚本
#
# 用法：
#   sudo ./install.sh                 # 安装到 /opt/aether
#   sudo PREFIX=/srv/aether ./install.sh
#   sudo ./install.sh --no-start      # 只安装不启动
#
# 安装内容：
#   /opt/aether/releases/<版本>/     二进制 + 前端
#   /opt/aether/current -> 上面的目录
#   /etc/aether/aether-gateway.env   配置文件（已存在则保留）
#   /etc/systemd/system/aether-gateway.service
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VERSION=$(cat "${HERE}/VERSION")
PREFIX="${PREFIX:-/opt/aether}"
CONFIG_DIR="${CONFIG_DIR:-/etc/aether}"
CONFIG_FILE="${CONFIG_DIR}/aether-gateway.env"
SERVICE_NAME="aether-gateway"
SERVICE_USER="${SERVICE_USER:-aether}"
SERVICE_GROUP="${SERVICE_GROUP:-aether}"
START=1

for arg in "$@"; do
  case "$arg" in
    --no-start) START=0 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "未知参数：$arg" >&2; exit 2 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "请用 root 运行：sudo $0" >&2
  exit 1
fi

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }

say "安装 Aether Gateway ${VERSION} 到 ${PREFIX}"

# 1. 服务账号
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  say "创建系统用户 ${SERVICE_USER}"
  useradd --system --home-dir "${PREFIX}" --shell /usr/sbin/nologin "${SERVICE_USER}"
fi
if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
  groupadd --system "${SERVICE_GROUP}"
fi
usermod -g "${SERVICE_GROUP}" "${SERVICE_USER}"

# 2. 目录与文件
RELEASE_DIR="${PREFIX}/releases/${VERSION}"
say "展开到 ${RELEASE_DIR}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${RELEASE_DIR}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${PREFIX}/logs"
rm -rf "${RELEASE_DIR}/bin" "${RELEASE_DIR}/frontend"
cp -a "${HERE}/bin" "${RELEASE_DIR}/bin"
cp -a "${HERE}/frontend" "${RELEASE_DIR}/frontend"
cp -a "${HERE}/VERSION" "${RELEASE_DIR}/VERSION"
chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${RELEASE_DIR}"
chmod 0755 "${RELEASE_DIR}/bin/aether-gateway"

say "切换 ${PREFIX}/current -> ${RELEASE_DIR}"
ln -sfn "${RELEASE_DIR}" "${PREFIX}/current"

# 3. 配置
install -d -m 0750 "${CONFIG_DIR}"
if [[ -f "${CONFIG_FILE}" ]]; then
  say "保留已有配置 ${CONFIG_FILE}"
else
  say "生成配置 ${CONFIG_FILE}"
  install -m 0640 "${HERE}/config/aether-gateway.env.example" "${CONFIG_FILE}"
  gen_secret() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 43; }
  jwt=$(gen_secret)
  enc=$(gen_secret)
  admin_pw=$(gen_secret | head -c 18)
  sed -i \
    -e "s|^JWT_SECRET_KEY=.*|JWT_SECRET_KEY=${jwt}|" \
    -e "s|^ENCRYPTION_KEY=.*|ENCRYPTION_KEY=${enc}|" \
    -e "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=${admin_pw}|" \
    "${CONFIG_FILE}"
  warn "已自动生成 JWT_SECRET_KEY / ENCRYPTION_KEY / 初始管理员密码"
  warn "管理员密码：${admin_pw}（请记录后自行修改）"
  warn "请检查 AETHER_DATABASE_URL 是否指向可用的 PostgreSQL"
fi

# 4. systemd
say "安装 systemd 单元 ${SERVICE_NAME}.service"
install -m 0644 "${HERE}/systemd/aether-gateway.service" "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" >/dev/null

if [[ "${START}" -eq 1 ]]; then
  say "启动服务"
  systemctl restart "${SERVICE_NAME}"
  port=$(grep -E '^APP_PORT=' "${CONFIG_FILE}" | tail -1 | cut -d= -f2)
  port=${port:-8084}
  for i in $(seq 1 30); do
    sleep 2
    code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/_gateway/health" || true)
    if [[ "${code}" == "200" ]]; then
      say "健康检查通过（第 ${i} 次，端口 ${port}）"
      break
    fi
    if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
      warn "服务已退出，查看日志：journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
      exit 1
    fi
    if [[ "${i}" -eq 30 ]]; then
      warn "健康检查超时，服务仍在运行，请查看：journalctl -u ${SERVICE_NAME} -f"
    fi
  done
  systemctl is-active "${SERVICE_NAME}" >/dev/null && say "安装完成"
else
  say "已安装，未启动。启动：systemctl start ${SERVICE_NAME}"
fi

echo
echo "版本    ${VERSION}"
echo "目录    ${PREFIX}/current"
echo "配置    ${CONFIG_FILE}"
echo "端口    $(grep -E '^APP_PORT=' "${CONFIG_FILE}" | tail -1 | cut -d= -f2)"
echo "日志    journalctl -u ${SERVICE_NAME} -f"
