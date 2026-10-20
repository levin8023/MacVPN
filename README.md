# MacVPN

轻量的 macOS 菜单栏 VPN 客户端，通过本机 strongSwan 管理 Cisco IPSec（IKEv1 PSK + XAuth）连接。
提供连接状态、多线路并发、按线路断开、自动重连和路由检查。

当前为 **0.1.0 预览版**，支持 Apple Silicon。它适用于已有的兼容 VPN 网关，不包含 VPN 服务端。

## 安装

### 1. 准备环境

- Apple Silicon Mac；App 的最低系统版本为 macOS 13，但 Homebrew 和 strongSwan 的当前支持范围可能更高。
  新安装环境建议使用 macOS 15 或更高版本，并以 [Homebrew 安装要求](https://docs.brew.sh/Installation)为准。
- 安装 Apple 命令行工具：

  ```sh
  xcode-select --install
  ```

- 从 [Homebrew 官网](https://brew.sh/)安装 Homebrew，然后安装 strongSwan：

  ```sh
  /opt/homebrew/bin/brew install strongswan
  /usr/bin/python3 --version
  /opt/homebrew/bin/swanctl --version
  ```

App 使用 `/usr/bin/python3`（需要 Python 3.9+），以及 Apple Silicon Homebrew 路径下的
`swanctl` 和 `charon`。无需启动 `brew services` 中的 strongSwan 服务，App 会管理独立实例。
已在 strongSwan 6.0.7 上进行本地验证；其他版本需自行验证兼容性。
参考 [strongSwan macOS 文档](https://docs.strongswan.org/docs/latest/os/macos.html)。

### 2. 安装 App

从仓库的 **Releases** 下载 `MacVPN-<版本>-macos-arm64.zip`，解压并把 `MacVPN.app`
拖到“应用程序”。Git 源码仓库不包含 App 二进制。

下载页同时提供 `SHA256SUMS`，可在安装包所在目录验证：

```sh
shasum -a 256 -c SHA256SUMS
```

当前安装包使用本地签名，尚未进行 Apple Developer ID 签名和公证。
若 macOS 阻止打开，请先确认来源和校验值，再按照
[Apple 官方说明](https://support.apple.com/guide/mac-help/open-an-app-by-overriding-security-settings-mh40617/mac)
在“系统设置 → 隐私与安全性”中允许打开。无需关闭系统安全保护。

### 3. 准备自己的配置

从发布包复制 `config.example.json`：

```sh
mkdir -p "$HOME/Library/Application Support/MacVPN"
cp -n config.example.json "$HOME/Library/Application Support/MacVPN/config.local.json"
chmod 600 "$HOME/Library/Application Support/MacVPN/config.local.json"
```

编辑 `config.local.json`，把示例服务器替换成实际地址，并填写管理员提供的认证信息。
示例地址属于文档专用地址，不能用于实际连接；示例中的空认证字段必须填写。

```json
{
  "schema_version": 1,
  "default_profile": "office-primary",
  "profiles": {
    "office-primary": {
      "label": "Primary VPN",
      "server": "192.0.2.10",
      "group": "YOUR_GROUP",
      "username": "YOUR_USERNAME",
      "password": "YOUR_PASSWORD",
      "shared_secret": "YOUR_PSK",
      "direct_gateway": false
    }
  }
}
```

| 字段 | 含义 |
| --- | --- |
| `profiles` 的键 | 线路标识，仅支持英文字母、数字、下划线和连字符 |
| `label` | 界面显示名称 |
| `server` | VPN 网关地址；使用 `direct_gateway` 时必须是 IPv4 地址 |
| `group` | Cisco IPSec 群组名称 |
| `username` / `password` | XAuth 登录账号、密码 |
| `shared_secret` | IPSec 共享密钥（PSK），与登录密码不同 |
| `direct_gateway` | 可选，默认 `false`；让该 VPN 网关通过物理默认网关直连，避免被其他 TUN 代理接管 |
| `aliases` / `service` | 可选，兼容旧线路名称的 CLI 别名 |

可删除不需要的线路，或按同样结构添加线路，并相应修改 `default_profile`。
认证信息只从选择的 JSON 读取，不读取 AppleScript 文件或钥匙串。
JSON 明文保存凭据，应仅允许自己的账号访问，不得随源码、日志或安装包共享。

### 4. 开始连接

1. 启动 App，从菜单栏图标打开面板。
2. 选择自己的 `config.local.json`，点击“启用后台”并完成系统管理员授权。
3. 点击各线路的“连接”。多条线路可同时连接；断开按钮只影响该线路。
4. 按需打开各线路的“自动重连”。主动断开后不会自动重新连接。

左键菜单栏图标打开或隐藏面板；右键菜单提供打开和退出；面板支持关闭按钮、Esc 和 ⌘W。
退出界面不会停止后台已有连接；需要停止全部连接时，使用界面菜单中的停止后台操作。
登录启动选项只负责启动界面；重启电脑后，需再次授权启用后台。

修改配置后需停止并重新启用后台以加载新内容。后台升级也可能短暂断开并恢复已请求的连接。

## 自动重连与网络问题

后台约每 3 秒检查状态。首次连接失败、隧道被删除或 DPD 判定对端失联后，会按线路自动重试，
失败重试间隔从 15 秒逐步增加到最多 300 秒。IKEv1 DPD 的失联判断可能需要约 120 秒，
所以重连并非在物理掉网瞬间发生。明确认证失败会暂停重试，需更正配置后重新连接。

重连前会清除该线路残留的 IKE 会话，包括只有 IKE、尚未安装 CHILD_SA 的半连接，
避免重复使用已经卡住的会话。清理失败时推迟重试，不会重启其他线路来强制恢复。

显示“已连接”代表 IKE 与 IPsec CHILD_SA 均已建立，不保证目标应用服务正常。
App 会校验内网路由的隧道接口；无法确认或发现多个 VPN 网段重叠时，会显示路由异常。
多个 VPN 使用相同网段时不提供自动策略路由隔离。

如果另一个代理 App 使用 TUN 模式，导致连接初期卡顿、握手反复超时或频繁掉线，
可仅为受影响线路设置 `"direct_gateway": true`，再重启后台。
该选项只维护目标 VPN 网关的 `/32` 物理出口路由，不会关闭其他代理或修改默认路由；
不适用于必须经过代理才能访问的 VPN 网关。断开线路会清理本程序创建的路由。

## 命令行

克隆源码后，在项目根目录运行。默认读取根目录下未被 Git 跟踪的 `config.local.json`；
也可用 `--config` 指定外部文件。

```sh
./strongvpn profiles
./strongvpn check --profile office-primary
./strongvpn connect --profile office-primary
./strongvpn connect --profile partner
./strongvpn status --json
./strongvpn disconnect --profile office-primary
./strongvpn shutdown
```

`connect` 把连接交给后台管理，终端关闭后继续运行；`run --profile office-primary`
会保持前台状态输出，Ctrl+C 只断开所选线路。管理隧道的命令通过 `sudo` 获得权限，
`profiles`、`check`、`status` 无需管理员权限。不要同时运行其他手工启动的 charon 实例。

## 开发与构建

```sh
./scripts/test.sh
./build-app.sh
open build/MacVPN.app
./scripts/package-release.sh
```

构建需要 macOS、Apple 命令行工具和 Swift 编译器；构建与离线测试不需要真实凭据或安装 strongSwan。
VPN 实机测试需要另行安装 strongSwan 并使用自己的配置。离线测试覆盖并发、故障重试、
旧会话清理、鉴权暂停、进程恢复、本地控制接口权限和路由所有权。

```text
Sources/                 Swift 菜单栏界面
backend/                 Python 控制层与 strongSwan 后台
scripts/                 构建、测试、发布打包
tests/                  离线回归测试
.github/workflows/       CI 与标签发布工作流
config.example.json      不含真实认证信息的模板
build/                   本地 App，忽略提交
dist/                    Release 安装包及校验文件，忽略提交
```

发布前修改 `VERSION` 和 `CHANGELOG.md`，推送对应的 `v<版本>` 标签。
GitHub Actions 会运行测试、构建 App，并上传预发布版本和 SHA-256 校验文件。
Release 只包含 App、说明文档、模板和许可证；strongSwan 由使用者独立安装。

## 隐私与安全

运行文件存放在 `/private/var/run/macvpn-<uid>/`。认证配置与 strongSwan 控制套接字受权限保护；
日志会遮盖已知账号、密码与共享密钥，但仍可能包含网关、内网地址和路径，应在分享前进一步脱敏。
本地 RPC 限制为当前用户与 root，且只接受指定管理操作。

这是适配旧式 IKEv1 网关的客户端，包含网关兼容性所需的旧算法；不应据此部署新的 VPN 安全方案。
提交问题请遵循 [安全说明](SECURITY.md) 和 [贡献指南](CONTRIBUTING.md)。

## License

本项目源码采用 [MIT License](LICENSE)。独立安装的 strongSwan 遵循其自身的开源许可证，
本项目的发布包不捆绑 strongSwan 二进制或源代码。
