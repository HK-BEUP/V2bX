# HK-BEUP Xray 试点验收版

版本 `v25.12.2-beup-observe-rc.1`。保留试点版本号，发布与已验收候选相同的安装包，不重新编译或替换核心。

## 适用范围

- Linux systemd，amd64 / arm64；面向 VLESS + TCP + REALITY + Vision 节点。
- 不是全协议、多核心通用升级。OpenRC、其他架构、其他核心、Include 或符号链接配置、自定义启动命令会被保守拒绝。
- 新装需要 root、Python 3（含 SSL 标准库）、有效 CA 证书及 GitHub HTTPS 连通性。

## 安装与升级

```bash
wget -N https://raw.githubusercontent.com/HK-BEUP/V2bX-script/master/install.sh && bash install.sh
```

旧节点自动备份并保留原配置，无需重填。运行中的服务升级会短暂中断；原来停止的服务仍保持停止。建议逐台维护并验收，不同时升级全部节点。

全新节点安装后不自动启动空配置：执行 `v2bx init` 填写面板信息与 NodeID，核对后执行 `v2bx start`；需要开机自启时执行 `v2bx enable`。REALITY/Vision 参数仍由面板下发。

安装器先校验 HTTPS 下载及 SHA256SUMS，验证包成员、架构、版本后才切换；活动服务需恢复原监听并通过稳定检查。失败时尝试回退，备份位于 `/usr/local/.backups/V2bX/`。回退前核对后续人工改动，勿直接覆盖新配置。

## 验证与边界

双架构包完整性、安装器回归、普通 VLESS/采集 race、真实 REALITY/Vision 正常构建测试已通过；日本单机保配置升级及用户客户端验收通过。另有原生 amd64/arm64 一次性 GitHub-hosted systemd 新装、停止状态、升级与故障回退验收。

完整 Vision race/checkptr 仍受固定上游 unsafe 实现限制，不能声称该项通过。隔离 systemd 监听测试不等于全部业务协议场景验收。

采集默认关闭；本次不自动注册节点、不上传账户行为、不启用自动封禁或更改既有带宽保护规则。攻击防护仍需独立完成归因、配送与执行能力验收。

构建源码：`19a661b52103c5c47438330a2a753d1b35be2b58`。安装脚本：`b74ad979a2199e2a733dbfb14cd2881a11d13c40`。
