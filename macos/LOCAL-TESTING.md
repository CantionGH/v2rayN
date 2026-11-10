# 无 Developer ID 的 macOS TUN 自用测试版

这是与 Developer ID 分发路径分离的**本机安装信任**实现。无需付费 Apple
开发者账户、第三方签名证书、Apple 公证或 GitHub Secrets。它不是面向不特定
用户的正式安全发行版，仍需要真实 Mac 的联网和清理测试。

## 安装与使用

1. Apple Silicon 选择 `arm64`，Intel 选择 `x64`。下载自己构建或自己信任的
   GitHub Release ZIP，核对同次发布的 `.sha256`。校验和只能发现字节变化，
   **不能单独证明发布者身份**；首次安装实际是在信任整个 PKG 的代码。
2. 解压并阅读说明，退出旧的 v2rayN。双击 ZIP 内的 `.pkg`，在 macOS 原生
   安装器中进行一次管理员授权。不要把管理员密码输入 v2rayN。
3. 安装器会添加一个 root LaunchDaemon，并固定本次安装的应用、helper、
   内核和资源哈希。没有使用 sudoers 免密规则，不保存管理员密码。
4. 以**普通用户**打开：

   ```text
   /Library/Application Support/v2rayN-LocalTun/v2rayN.app
   ```

   可以将此应用保留在 Dock，但不能把它移动到普通用户可写目录。
5. 开启 TUN。之后切换节点、关闭 TUN 等操作经受限 XPC 通信执行，无需反复
   提交管理员密码。GUI 断连时，helper 停止该连接自己的内核。

这个 PKG 没有 Apple 签名或公证，系统可能拦截打开。只有确认代码和来源可信
时，才按当前 macOS 的“隐私与安全性”指引对这个具体安装包/应用批准打开。
**不要关闭 Gatekeeper、SIP 或全局安全策略。** 如果系统仍然拒绝启动，停止
测试并提供错误信息；不应通过给所有程序开白名单来解决。

首次本地源码构建不等于下载已公证软件，其信任模型由你主动接受。

## 更新、撤销与卸载

- 修改、重新签名或替换任何被批准的文件都会改变哈希。升级应用或 TUN 内核
  必须重新安装 PKG，并再次通过系统授权；不能通过 GUI 的普通内核更新来
  偷偷改变 root 实际执行的代码。
- 安装新版本前先退出应用。安装器先停止旧服务并撤销旧清单，然后安装并批准
  新代码。失败的更新不会退回“接受任意客户端/内核”的模式。
- 用 ZIP 中的 **`Uninstall Local TUN.command`** 撤销权限。它只通过系统认证
  执行固定的、已安装在 root 保护目录的卸载脚本。它停止服务并删除服务定义
  和信任清单，保留用户配置、日志与应用本体。
- 也可以在终端由自己执行以下固定命令，密码交给系统 sudo，而不是应用：

  ```sh
  sudo /bin/bash -p '/Library/Application Support/v2rayN-LocalTun/v2rayN.app/Contents/Resources/LocalTun/uninstall.sh'
  ```

不需要删除普通用户的配置目录。需要删除 root 保护的应用本体时，在撤销服务
之后另行使用管理员文件管理操作。

## 安全边界

- `V2RAYN_TUN_LOCAL_TRUST` 是明确的**构建时开关**，不是配置选项、环境变量
  或签名校验失败后的自动降级。默认的 Developer ID 构建仍然要求 Apple
  信任链和 Team ID；原分支没有被改成接受任意 ad-hoc 客户端。
- 本机安装目录固定为 `/Library/Application Support/v2rayN-LocalTun`，与
  Developer ID 版分开。服务名为 `2dust.v2rayN.LocalTunHelper`。
- 系统安装器将所有文件放入 root 保护目录。安装器随后从**实际安装的字节**
  生成 `trust.plist`，而不是接受普通用户提供的哈希清单。清单只能由 root
  更新；每次更新都需要新的管理员授权。
- 清单记录所有文件的 SHA-256，以及固定角色可执行文件的代码目录哈希
  （CDHash）。应用、helper、内核的路径也固定。缺失清单、改变哈希、增加文件、
  符号链接、非 root 所有者、可写权限或可写 ACL 都会拒绝。
- 每个 XPC 请求/回复仍使用消息**审计令牌**验证运行代码，并要求身份、
  CDHash、实际安装路径和硬化运行时匹配。不能用伪造 PID、同名程序或另一个
  目录里的程序副本取得权限。客户端还要求服务确实以 root 运行。
- 没有为 XPC 增加 enrollment、任意命令、环境变量、可执行路径或任意 PID
  操作。已有配置限制、私有快照、控制 API 随机令牌及断连清理保持不变。

### 与 Developer ID 版不同的取舍

无 Team ID 的 ad-hoc Avalonia/Skia 动态库不能在严格的 library validation
下加载。因此**仅本地 GUI**具有 `disable-library-validation` entitlement；
helper、信任工具和内核没有这个例外。仍禁止 `allow-jit`、调试权限、未签名
可执行内存及 DYLD 环境变量覆盖，且仅支持 NativeAOT。

整个安装包的库文件也被 root 权限和 SHA-256 清单保护，但这不是内核级严格
库验证的等价替代。不要添加用户可写插件、原生库搜索路径或自行放宽运行时
entitlements。首次授权依赖你审阅/信任源码和下载渠道，没有 Apple 的发布者
身份担保。内核仍以 root 运行，配置策略不是针对内核漏洞的沙箱。

## 从源码构建

在自己的 Mac 上安装 Xcode 命令行工具和 .NET 10。以下以 Apple Silicon
为例；Intel 将 `osx-arm64` 改为 `osx-x64`，并使用对应架构的 core bundle。

```sh
dotnet publish v2rayN/v2rayN.Desktop/v2rayN.Desktop.csproj \
  -c Release -r osx-arm64 -p:SelfContained=true -p:IsAot=true \
  -o artifacts/local-publish
touch artifacts/local-publish/v2rayN.NativeAOT
bash macos/build-tun-helper.sh osx-arm64 artifacts/local-native local
bash macos/assemble-app.sh artifacts/local-publish \
  /path/to/extracted/v2rayN-macos-arm64 artifacts/local-native \
  artifacts/v2rayN.app 7.25.6
bash macos/package-local-tun.sh artifacts/v2rayN.app 7.25.6 \
  artifacts/v2rayN-macos-arm64-local-tun.pkg
```

只使用已审阅的 core bundle。CI 固定了 core-bin Git 提交，不能随意换成另一个
来源而不重新审查。`codesign --sign -` 是本地 ad-hoc 签名，不需要任何账户。

## 测试与发布

```sh
bash macos/test-tun-helper.sh artifacts/local-policy-tests local
dotnet test --project v2rayN/ServiceLib.Tests -c Release -p:PublishAot=false -- --maximum-parallel-tests 1
```

安装后可以做一个**不启动内核、不创建 TUN、不改路由**的认证 IPC 检查：

```sh
'/Library/Application Support/v2rayN-LocalTun/v2rayN.app/Contents/MacOS/v2rayN' --macos-tun-self-test
```

`macos-local-tun-release.yml` 在本分支推送后构建 ARM64/Intel 包，并在临时
GitHub runner 上测试安装、批准客户端的 IPC、未批准客户端拒绝及普通用户不能
enroll。只有全部通过，且推送 `local-tun-*` 标签，才发布明确标为自用实验版的
GitHub Pre-release。没有 Apple 签名、公证或密钥上传步骤。

这些 CI 检查不能替代以下真实 Mac 验收：三个内核实际联网、路由/DNS 恢复、
快速切换节点、退出和强杀 GUI/helper、睡眠唤醒、重启、升级失败与卸载。CI
没有通过或尚在排队时，不能把包描述为已验证可用。
