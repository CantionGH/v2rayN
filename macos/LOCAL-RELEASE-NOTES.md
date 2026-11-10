# macOS 本机信任 TUN 自用测试版

**仅供本人测试，不是 Apple Developer ID 签名或 Apple 公证的正式发行版。**

- 无需 Apple 开发者会员，不配置 sudo 免密，也不保存管理员密码。
- 使用 ad-hoc 签名的 NativeAOT GUI、独立 launchd helper、审计令牌及本机 root 信任清单固定代码哈希。
- 首次安装和每次升级都需要通过 macOS 安装器授权；此授权会安装一个 root 服务。
- 安装器无 Apple 签名。下载前核对来源和 SHA-256、审阅源代码；校验和本身不证明发布者身份。
- GUI 为加载无 Team ID 的 Avalonia/Skia 库，具有本地专用的 library-validation 例外；这不等同于严格 Developer ID 版的安全保证。
- 不关闭 Gatekeeper、SIP 或系统安全策略。不接受该信任模型时，请勿安装。

Apple Silicon 下载 `arm64`，Intel 下载 `x64`。解压 ZIP 后，先阅读 `README-local-tun.md`，再安装其中的 PKG。

安装完成后，以普通用户打开：

```text
/Library/Application Support/v2rayN-LocalTun/v2rayN.app
```

不要移动或修改该应用。更换代码或内核后，需要重新安装 PKG 并授权。TUN 不执行用户数据目录里自动更新的内核。

CI 包含安装、已批准客户端 IPC 正向检查、未批准客户端拒绝检查；不创建 TUN 或改动测试机路由。实际联网、DNS/路由恢复、睡眠唤醒及强杀清理仍需要在自己的 Mac 上验收。

卸载 root 服务可运行 ZIP 中的 `Uninstall Local TUN.command`；它通过系统认证停止服务并撤销信任，不删除用户配置。
