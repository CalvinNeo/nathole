# 通过打洞通路转发 NAS WebDAV

这一版会保留打洞成功的原 UDP socket，用可靠传输层承载双向认证的 TLS，再把多个 TCP 连接转发到 NAS 上指定的服务。

```text
电脑 WebDAV 客户端
    -> 127.0.0.1:18080（本地 TCP）
    -> TLS 加密、双向证书认证 / 可靠 UDP / 原打洞 socket
    -> NAS 转发进程
    -> 127.0.0.1:5005（示例 WebDAV HTTP 端口）
```

公网 VPS 只做配对和公网地址探测，不转发文件。原来的 `server` 无须更新，Python / Rust 协调器均使用原有协议。隧道两端需要本次的 Python 程序。

运行要求：Python 3.8+，包含标准库 `ssl`，无 pip 依赖。**OpenSSL 命令只在电脑生成证书时使用，NAS 不需要安装 Rust 或 OpenSSL 命令行程序。** Python 自带的 ssl 模块本身仍需可用。

## 1. 更新两端的程序

电脑项目目录已更新。NAS 上把以下三个文件放在同一个 `python` 目录，覆盖旧的 `nat4_demo.py`：

```text
python/nat4_demo.py
python/nat4_rudp.py
python/nat4_tunnel.py
```

下面命令均从项目根目录执行。Windows Git Bash 使用已经激活的 Conda base 中的 `python`；NAS 使用 `python3`。确认 NAS 的 TLS 支持：

```bash
python3 -c 'import ssl; print(ssl.OPENSSL_VERSION)'
```

## 2. 确认 NAS 的 WebDAV 端口

**本说明暂用 `127.0.0.1:5005`，这只是示例，不能保证是你的 NAS 的默认值。** 请以 NAS 的 WebDAV 设置页为准。NAS 上可以先检查：

```bash
curl -I --max-time 5 http://127.0.0.1:5005/
```

出现 HTTP 状态码（如 200、401、403、405）说明该端口有 HTTP 服务响应；认证可能需要 WebDAV 用户名和密码。`Connection refused` 表示此地址端口没有监听，需要检查服务是否开启、监听地址和端口。若只绑定 NAS 的局域网 IP，就把下文 `--target` 改成那个 IP。

若实际使用 HTTPS WebDAV，例如端口 5006，可以把 `--target` 改为 `127.0.0.1:5006`，访问端也使用 `https://`。隧道透明转发 TLS 字节，不改写 NAS 证书；客户端仍需使用 NAS 证书匹配的主机名。HTTP WebDAV 则在电脑与 NAS 的公网段由外层隧道 TLS 保护。

## 3. 在 Windows 生成一套配对凭据（只做一次）

在当前 Git Bash 的项目根目录执行：

```bash
source /c/ProgramData/Anaconda3/etc/profile.d/conda.sh
conda activate base
python python/nat4_tunnel.py keygen --out tunnel-keys
```

命令会自动查找电脑已有的 OpenSSL，包括 Anaconda 和 Git for Windows 的安装路径。如果找不到，可用 `--openssl /c/ProgramData/Anaconda3/Library/bin/openssl.exe` 指定。程序通过 Python 调用 OpenSSL，不需要手工输入证书参数。

生成以下目录：

```text
tunnel-keys/
  nas/        NAS 的证书、私钥、CA 和 UDP 认证密钥
  client/     电脑的证书、私钥、CA 和 UDP 认证密钥
  authority/  私有 CA 与签发材料，保留在电脑，无须部署
```

把**这一套凭据中的 `tunnel-keys/nas` 整个目录**复制到 NAS 项目里的 `tunnel-keys/nas`；电脑保留 `tunnel-keys/client`。不要在 NAS 上另生成一套，否则证书和密钥不匹配。凭据目录已加入项目 `.gitignore`，不要上传到公共仓库。

`keygen` 拒绝覆盖已有目录。证书有效期为 365 天，更新时生成到新目录并同时替换两端凭据。下载的源码包不包含任何真实私钥或通用共享密钥。

## 4. 公网服务器保持原协调服务运行

你已使用的协调地址是 `47.100.82.242:40000`。如果原服务仍在运行，无须再启动第二个。

需要重启时，在 VPS 上执行原命令：

```bash
python3 -u python/nat4_demo.py server --bind 0.0.0.0:40000 --rounds 12 --round-ms 5000
```

若 VPS 把脚本直接放在当前目录，就去掉 `python/`。VPS 继续放行 TCP 40000 和 UDP 40000–40002；WebDAV 的端口不用开放到 VPS。

## 5. NAS 启动服务端转发

```bash
python3 -u python/nat4_tunnel.py serve --server 47.100.82.242:40000 --room webdav-1 --id alice --keys tunnel-keys/nas --target 127.0.0.1:5005 2>&1 | tee nas-tunnel.log
```

`--target` 是 **NAS 本地能连接的 WebDAV 地址**。该地址由 NAS 进程启动参数固定，远端不能请求转发任意其他地址。

## 6. Windows 启动本地入口

在 NAS 启动后的 55 秒内，电脑 Git Bash 执行：

```bash
python -u python/nat4_tunnel.py connect --server 47.100.82.242:40000 --room webdav-1 --id bob --keys tunnel-keys/client --listen 127.0.0.1:18080 2>&1 | tee pc-tunnel.log
```

双方看到 `DIRECT_OK` 后，还会做密钥认证和 TLS 握手。等电脑出现：

```text
[tunnel] TUNNEL_READY listen=127.0.0.1:18080 mutual_TLS=true
```

此时才可以使用 WebDAV。两个进程必须保持运行；关闭终端或 Ctrl+C 会关闭隧道。旧 `peer` 模式仍只验证打洞并退出，不会启动端口转发。

## 7. 访问 WebDAV

在电脑的 WebDAV 客户端填写：

```text
地址：http://127.0.0.1:18080/
用户名：原 NAS WebDAV 用户名
密码：原 NAS WebDAV 密码
```

若服务有路径前缀（如 `/webdav/`），在本地地址后保留相同路径。隧道不改写 HTTP 请求头、跳转地址或 WebDAV 路径；服务端若配置了强制跳转到特定域名，应使用对应域名访问并让其连接本地入口。

可以先在电脑用 curl 查询目录；`-u` 仅填用户名，curl 会提示输入密码：

```bash
curl -i --max-time 20 -u YOUR_WEBDAV_USERNAME -X PROPFIND -H 'Depth: 1' http://127.0.0.1:18080/
```

用户名需要替换。通常成功查询目录会得到 `207 Multi-Status`；`401` 表示需要检查 NAS 的账号密码或权限。浏览器的普通 GET 是否显示目录，取决于 NAS WebDAV 服务，不能单独据此判断隧道是否工作。

如果转发的是 HTTPS 5006，为保留 NAS 证书的主机名校验，可以用支持指定连接目标的客户端。例如域名为 `nas.example.com` 时：

```bash
curl --connect-to nas.example.com:5006:127.0.0.1:18080 -u YOUR_WEBDAV_USERNAME -X PROPFIND -H 'Depth: 1' https://nas.example.com:5006/
```

替换为实际 NAS 域名及 WebDAV 端口；若使用私有 CA，配置客户端信任该 CA。这里内层 NAS HTTPS 证书与隧道自己的配对证书是两套独立的证书。

## 参数、行为与边界

- 默认每方向 TLS 数据发送上限为 `512 KiB/s`，可在两端设置 `--rate-kib 1024` 等值。实际速度还受 RTT、丢包、拥塞窗口和 Python 运行速度影响，不能将这个参数当成速度保证。
- 支持最多 16 个并发 TCP 连接，每个连接有 64 KiB 接收额度；队列有界，慢接收端会向 TCP 施加背压。
- UDP 数据带序号、选择确认、超时重传、基本拥塞退让及速率控制，报文约 1.1 KiB。应用数据由标准库 TLS 加密并双向验证证书，未自行实现加密算法。
- 默认空闲 5 秒发认证保活，30 秒未收到认证报文则断开。当前不自动重新打洞或恢复中断的 TCP 连接；网络变化后重新启动双方，文件续传由 WebDAV 客户端负责。
- 当前是实验性转发实现，尚未做长期公网运行和高吞吐压力验证；未实现 QUIC，也没有跨 TCP 连接的独立丢包恢复。一个 UDP 数据缺口会暂时影响共享可靠字节流上的其他连接。
- 本地监听只允许回环地址。NAS WebDAV 的原账号密码和访问权限继续生效，程序不记录请求内容或密码。
- 已有 `--strategy predict/fanout`、`--fanout`、`--pps`、端口范围和探测端点参数仍可用于建连；`--pps` 只控制打洞阶段，文件传输阶段使用 `--rate-kib`。

## 常见日志

| 日志 | 含义 / 处理 |
|---|---|
| `waiting for the second peer` | 启动另一端，核对同一 room 和不同 id |
| `NO_DIRECT_PATH` | 打洞尚未成功，TLS 和转发不会启动 |
| `peer authentication timed out` | 核对同一次 keygen 的 nas/client 目录及两端角色，也可能是 UDP 路径中断 |
| `CERTIFICATE_VERIFY_FAILED` | 核对两端配套凭据、机器时间和证书有效期 |
| `TARGET_CONNECT_FAILED ...:5005` | 隧道已收到连接请求，但 NAS 无法连接目标服务；确认 WebDAV 地址端口 |
| `direct UDP path lost` | 保活超时，重新启动两端建立新通路 |
| `Address already in use` / 10048 | 电脑端口被占用，可改 `--listen 127.0.0.1:18081` |

## 实现与验证

`nat4_demo.py` 增加成功回调并保留原 socket；原 server / peer / lab 仍可独立运行。`nat4_rudp.py` 实现有限窗口的可靠 UDP 字节通路，`nat4_tunnel.py` 实现凭据生成、TLS 和 TCP 多路复用。

运行完整测试（需要电脑可用的 OpenSSL，生成的测试凭据位于临时目录）：

```bash
python -B -m unittest discover -s python -v
```

测试覆盖原有打洞场景、Rust 互通，以及实际三进程打洞后的 1 MiB 上传下载校验、WebDAV PUT/GET/PROPFIND、并发连接、丢包/乱序/重复包、流量背压、TCP 半关闭、严格 NAT 空闲保活、错误密钥、错误证书、缺失客户端证书、目标拒绝连接和对端消失。

设计参考：[Python SSL](https://docs.python.org/3/library/ssl.html)、[asyncio 已连接 socket 的 TLS 接入](https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.connect_accepted_socket)、[RFC 8085 UDP 使用建议](https://www.rfc-editor.org/rfc/rfc8085.html)。
