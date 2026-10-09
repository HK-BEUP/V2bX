# HK-BEUP 旧队列增强版

新节点采用 LegacyAccounting，经现有 UniProxy / Redis / Horizon / traffic:update 入账。
包含稳定报告编号、磁盘持久化待确认报告、200/202 回执核对、重启重试及退出前尾流确认。
启动遇到明确的 traffic_settling 短暂锁冲突时重试；不会把所有 409 错误视为可重试。
TransferAccounting 代码保留，但新装向导不会开启新的计量 epoch。

## 一键新装

在 Linux/systemd 或 Alpine/OpenRC 的 root 终端运行（需要 bash、Python 3、wget 或 curl）：

```bash
wget -N https://raw.githubusercontent.com/HK-BEUP/V2bX-script/master/install.sh && bash install.sh
```

自动选择 x86_64 / aarch64 包、验证 SHA256SUMS，填写 HTTPS 面板域名、API Key（不回显）和 NodeID。
确认后保存私有配置、启动、验证 TCP 监听并设置开机自启。面板节点须为 VLESS + TCP + REALITY + Vision，
且支持本版旧队列回执协议。节点日志默认关闭；成功启动之后还需在面板确认自然流量入账。

## 已有节点

已有配置、证书、计量方式及 journal 位置保持原样；不会自动将普通旧上报或 TransferAccounting 切换模式。
同一二进制重复安装会提示并跳过，不停止服务；不同二进制需明确确认。运行中升级会先备份，等待原进程正常退出后切换。保留原先的运行/停止状态；失败保留现场及待确认流量。
备份在 /usr/local/.backups/V2bX/。不要删除 /var/lib/beup-legacy/、任何配置指定的 journal 或历史备份。

退出会等待最后流量入账，可能跨一个分钟结算周期；这不是安装卡住。新服务关闭 systemd 强制退出超时，
各计量节点本身有有界的尾流确认流程。已有 systemd 服务需要确保退出超时覆盖全部计量节点；OpenRC 标准服务会先备份再补齐无强杀退出和日志关闭，自定义服务及 conf.d 覆盖需单独核对。
恢复旧二进制前必须确认兼容当前配置和 journal；不要用更老公开包覆盖本版保护。

## 手动重新配置

`v2bx` 菜单 15（或 `v2bx generate` / `v2bx init`）支持对已有 VLESS/Xray 节点重新配置。
面板、节点编号和同面板唯一密钥可回车保留；API Key 不回显。显示保留/新增/移除数量后，输入 `YES` 才应用。
运行中的实例会先备份、等待正常退出，再切换配置和启动，失败尝试回退；原先停止的实例保持停止。
同面板同编号节点和全局设置保留，新节点身份使用新装默认配置；不删除 DNS/路由文件、证书、程序或 journal。
备份在 `/etc/.backups/V2bX/reconfigure-*/`，包含原配置、SHA-256 和状态记录。并发修改或无法确认正常退出时保留现场，不强行覆盖或启动。
Include、自定义服务以及 TransferAccounting 节点身份迁移须另行核对。

首次安装仍使用初始化保护，不会覆盖已有节点；未变化/取消也不会重启。
已有服务器需更新完整发行包中的配套脚本；同二进制重复安装会跳过，不能用于单独刷新脚本。
本机进程和监听通过后，还需客户端连接和面板流量入账验收。

## 可复现构建

运行时源来自已部署的 legacy startup-busy-fix revision2；第三方 Xray 审计源码随仓库保留。
使用 Go 1.26.5、GOEXPERIMENT=jsonv2、CGO_ENABLED=0、xray 标签。release/package.py 生成两种架构包及 SHA256SUMS。
release/install/ 是与发行包绑定的安装器源快照；发布时须与 V2bX-script 对应文件校验相同。
发布新版安装包不会自动更新现有节点或执行客户套餐迁移。
