# Aether Gateway（relay-only）离线安装包

内置二进制、前端静态资源、systemd 单元与安装脚本，无需联网即可安装。

## 内容

```
VERSION                              版本号
SHA256SUMS                           各文件校验和
bin/aether-gateway                   Linux x86_64 可执行文件（glibc ≥ 2.35）
frontend/                            前端静态资源
config/aether-gateway.env.example    配置模板
systemd/aether-gateway.service       systemd 单元
install.sh / uninstall.sh            安装 / 卸载脚本
```

## 安装

```bash
tar -xzf aether-gateway-<版本>-linux-amd64.tar.gz
cd aether-gateway-<版本>-linux-amd64      # 或解压到的目录
sudo ./install.sh
```

默认安装到 `/opt/aether`，配置写在 `/etc/aether/aether-gateway.env`，服务名 `aether-gateway`。

可选参数：

```bash
sudo PREFIX=/srv/aether ./install.sh     # 换安装目录
sudo ./install.sh --no-start             # 只安装不启动
```

首次安装会自动生成 `JWT_SECRET_KEY`、`ENCRYPTION_KEY` 和初始管理员密码并打印出来。
**安装前请先确认配置里的 `AETHER_DATABASE_URL` 指向可用的 PostgreSQL。**

## 升级

解压新版本后重复执行 `install.sh` 即可：程序装进新的 `releases/<版本>/` 目录，
`current` 软链接切过去，已有配置保留不动。

## 卸载

```bash
sudo ./uninstall.sh            # 删服务与程序，保留 /etc/aether
sudo ./uninstall.sh --purge    # 连配置一起删（数据库不受影响）
```

## 校验

```bash
sha256sum -c SHA256SUMS
```

## 运行状态

```bash
systemctl status aether-gateway
journalctl -u aether-gateway -f
curl -s localhost:8084/_gateway/health
```
