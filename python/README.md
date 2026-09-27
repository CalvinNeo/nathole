# NAT4 UDP 打洞实验：Python / NAS 版

**新增 WebDAV / TCP 持续转发：** 部署见 [TUNNEL.md](TUNNEL.md)。使用 `nat4_tunnel.py serve/connect`，支持保活、可靠传输、双向 TLS 和并发 TCP 连接；需要本目录中的三个程序文件。下文仍介绍可独立运行的单文件打洞实验。

**运行只需要 `nat4_demo.py` 一个文件和 Python 3.8+，全部使用标准库。** 不需要 Rust、pip、虚拟环境或第三方包。服务器、客户端、本机 NAT 模拟器都在这个文件里。

本版本与项目里的 Rust 版使用相同的控制和 UDP 协议，可混用服务器和客户端。它验证 UDP 通路及数据回包，不提供持续隧道或文件传输。

## 在 NAS 上先验证

把 `nat4_demo.py` 复制到 NAS 的任意工作目录，通过 SSH 进入该目录：

```bash
python3 --version
python3 -u nat4_demo.py lab --case all --seed 7
```

这里的 `-u` 让日志立即输出。`lab` 只使用本机回环网络，不需要公网服务器、root 权限、路由器配置或防火墙端口转发。

| 实验 | 预期 | 含义 |
|---|---|---|
| `predict` | `PASS ... direct=True` | 两侧端口递增的严格 NAT 可以预测并连通 |
| `random-small` | `PASS ... direct=True` | 两侧在已知 32 端口池随机分配，每侧 24 个 socket 可以命中 |
| `random-full` | `PASS ... direct=False` | 全范围随机分配，当前种子及两轮预算内未连通 |
| `predict-on-random` | `PASS ... direct=False` | 猜下一端口在当前随机场景下未连通 |

`PASS` 表示**符合该实验的预期**。真正打通必须在双方看到 `VERIFIED ... round_trips=3` 和 `DIRECT_OK`；单独看到 ACK、协调器消息或 `PASS` 都不够。

默认 Python 实验每轮 700 ms，比 Rust 的 450 ms 更宽裕。如果 NAS 较慢，可增大时间：

```bash
python3 -u nat4_demo.py lab --case all --seed 7 --round-ms 2000
python3 -u nat4_demo.py lab --case predict --seed 7 --trace true
```

调整轮次时长会同步调整模拟 NAT 的有效期及轮间等待，让旧映射先过期。随机场景的结果也可能受端口占用和系统负载影响；不符合预期会输出 `UNEXPECTED` 并返回非零退出码。

## 三台机器实际打洞

需要一台有公网 IPv4 的服务器，以及位于两个待测 NAT 后面的客户端（NAS 可以是其中一端）。三台机器都可以直接运行同一个 Python 文件，也可混用已有 Rust 可执行文件。

在公网服务器上启动协调服务：

```bash
python3 -u nat4_demo.py server --bind 0.0.0.0:40000 --rounds 12 --round-ms 5000
```

服务器主机防火墙及云安全组需允许 **TCP 40000、UDP 40000–40002**。固定端口 `P` 对应 TCP `P` 和 UDP `P`、`P+1`、`P+2`。服务器只交换候选地址、轮次和结果，并回答地址探测，不中继客户端的数据。

以下 `203.0.113.10` 是文档示例地址，必须改成服务器真实公网 IPv4。两个客户端在 55 秒内启动，使用相同 `room`、不同 `id`。

NAS / 客户端 A：

```bash
python3 -u nat4_demo.py peer --server 203.0.113.10:40000 --room nas-test-1 --id alice --strategy predict
```

另一网络的客户端 B：

```bash
python3 -u nat4_demo.py peer --server 203.0.113.10:40000 --room nas-test-1 --id bob --strategy predict
```

B 也可以使用 Rust 版：

```bash
./nat4-demo peer --server 203.0.113.10:40000 --room nas-test-1 --id bob --strategy predict
```

Windows 上用 `nat4-demo.exe`。两个客户端都需要能向服务器发 TCP/UDP、向对端发 UDP，并允许相应回包。如果部署在 NAS 的容器中，容器网络可能再增加一层 NAT；第一次建议直接在 NAS 主机的 Python 中运行。

端口没有规律时，可让双方改用多 socket 尝试（第二端把 id 改成 bob）：

```bash
python3 -u nat4_demo.py peer --server 203.0.113.10:40000 --room nas-test-2 --id alice --strategy fanout --fanout 32 --pps 200
```

`--pps` 是所有 socket 合计的主动 PUNCH/PING 目标发送频率；ACK/PONG 回复另计。调度器使用小批次补偿系统定时精度，不无限补发积压。增大 fanout 需要更长轮次或更高发送频率，给每个 socket 留出至少三次数据往返的时间。

仅当你另有依据知道 NAT 的端口池时，才使用 `--port-min` 和 `--port-max` 缩小范围。默认 `1024–65535`。`--seed` 可复现客户端的端口猜测；省略则随机选种子，不读取或控制真实 NAT 的分配器。

默认三个探测端点位于同一公网 IP、不同端口；不能据此完整识别仅依赖目标 IP 的映射。`--probes IP:PORT,IP:PORT,IP:PORT` 可指定运行本 demo 的三个探测端点，支持跨公网 IP。这里使用自定义 WHO/SEEN 协议，不能直接填写标准 STUN 服务。程序当前要求 IPv4 字面地址，不解析域名。

## 实验边界与成功证据

用户态 NAT 模型同时实现目标地址、端口相关映射（APDM）和严格地址、端口相关过滤（APDF）。改变内部 socket 或目标 IP/端口就会产生新映射；每条映射只放行来自精确目标 `IP:port` 的回包，并受有效期、容量限制。

客户端不读取 NAT 映射表；每端分别猜测自己的接收端口，通过协调器交换后发送。`random-small` 明确把 32 个端口的范围告诉了客户端，不能把它的成功率套用到全范围随机的运营商 NAT。全范围随机场景中的失败，也只是给定预算未命中，不是理论上不可能。

数据验证检查 session、room、轮次、对端 id、本 socket 的随机 nonce、请求序号、来源地址、原始 payload。重复 PONG 不重复计数，多个 socket 的回包不累加成同一条成功通路。双方各自至少收到三个有效的不同请求回包，才报告 `DIRECT_OK`。协调器单独发送 `DONE OK` 不能让客户端凭空报告成功。

实验结束会关闭 socket。room/session/nonce 只用于匹配实验报文；协议没有加密或密码学身份认证。用户态模型没有模拟真实路由、运营商背景流量、多层 NAT、拥塞或 IP 池变化。

退出码：客户端 `0` 为数据验证成功，`2` 为预算耗尽，运行错误 `1`；`lab` 的 `0` 表示全部符合预期，`2` 表示有结果不同。命令行用法错误由 argparse 返回 `2`，Ctrl+C 返回 `130`。

## 测试与文件

在本目录（同时包含主程序和测试文件）运行：

```bash
python3 -B -m unittest -v test_nat4_demo
```

或者在项目根目录运行 `python3 -B -m unittest discover -s python -v`。测试全部使用回环网络，无需外网或 root。若只有主程序单文件，可直接用前面的 `lab` 命令验证。

测试覆盖 NAT 映射键、精确过滤、过期、容量耗尽、重复及错误回包、协调器假成功、协调器不转发业务数据、四种 NAT 场景、三个独立 Python 进程。另有五项与 Rust 的互通测试；默认查找项目 `target/release/nat4-demo`（Windows 为 `.exe`），也可用环境变量 `NAT4_RUST_EXE` 指定。没有 Rust 可执行文件时只跳过互通测试，Python 本身不依赖它。

本次已在 **Windows + Python 3.8.8** 验证 17 项测试全部通过，包括五项 Rust 互通测试。尚未在你的实际 NAS 或两处真实运营商 NAT4 网络上测试。

| 文件 | 用途 |
|---|---|
| `nat4_demo.py` | 单文件程序，部署仅需此文件 |
| `test_nat4_demo.py` | 标准库 unittest 测试及 Rust 互通测试 |
| `README.md` | NAS 与公网部署说明 |

代码使用项目的 MIT 许可证，从零实现，未继承 frp。
