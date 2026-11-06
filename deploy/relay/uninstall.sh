#!/usr/bin/env bash
# Aether Gateway（relay-only）卸载脚本
#
#   sudo ./uninstall.sh              # 停止并删除服务与程序，保留配置和数据库
#   sudo ./uninstall.sh --purge      # 连同 /opt/aether 与 /etc/aether 一起删除
set -euo pipefail

PREFIX="${PREFIX:-/opt/aether}"
CONFIG_DIR="${CONFIG_DIR:-/etc/aether}"
SERVICE_NAME="aether-gateway"
PURGE=0

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "未知参数：$arg" >&2; exit 2 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "请用 root 运行：sudo $0" >&2
  exit 1
fi

echo "==> 停止并禁用 ${SERVICE_NAME}"
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload

echo "==> 删除程序目录 ${PREFIX}"
rm -rf "${PREFIX}"

if [[ "${PURGE}" -eq 1 ]]; then
  echo "==> 删除配置 ${CONFIG_DIR}"
  rm -rf "${CONFIG_DIR}"
  echo "注意：数据库未删除，如需清理请手动 DROP DATABASE。"
else
  echo "配置保留在 ${CONFIG_DIR}（加 --purge 可一并删除）"
fi

echo "==> 卸载完成"
