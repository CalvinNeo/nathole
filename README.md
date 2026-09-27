# NAT4 UDP 打洞实验（Rust）

从零实现，纯 Rust 标准库，无第三方 crate。本机验证环境是 Windows；服务器和客户端使用可移植的标准网络接口。

它验证的是：两个具有**目标相关映射（APDM）和地址、端口相关过滤（APDF）**的 NAT 后面的客户端，能否建立 UDP 数据通路。这个组合对应这里讨论的严格对称型 NAT4。

这是可执行的实验，不是“所有 NAT4 都能穿透”的实现。默认实验同时包含成功和失败场景。

## 一条命令验证

Windows PowerShell，已安装 Rust 1.75 或更新版本：

```powershell
cd C:\DiskF\nat4-hole-punch-demo
cargo run --offline --release -- lab --case all --seed 7
```

构建后可直接运行，无须 Rust 运行时：

```powershell
.\target\release\nat4-demo.exe lab --case all --seed 7
```

查看每一条 NAT 映射：

```powershell
.\target\release\nat4-demo.exe lab --case predict --trace true
```

默认 seed=7 的预期结果：

| case | 两端 NAT | 策略 | 预期结果 |
|---|---|---|---|
| `predict` | 严格过滤，公网端口递增 | 预测下一端口 | 双向数据验证成功 |
| `random-small` | 严格过滤，在 32 个端口中随机分配 | 每端 24 个新 socket；已知端口池 | 双向数据验证成功 |
| `random-full` | 严格过滤，在 1024–65535 中随机分配 | 每端 24 个新 socket，尝试 2 轮 | 在给定预算内未成功 |
| `predict-on-random` | 严格过滤，全范围随机分配 | 猜测下一端口，尝试 2 轮 | 在给定预算内未成功 |

`PASS` 表示**结果符合这个实验的预期**，不一定表示连接成功。真正连通会输出双方的 `VERIFIED` 和 `DIRECT_OK`；失败会输出 `NO_DIRECT_PATH`。

`random-small` 明确向客户端提供小端口池的范围。这是受控的可行性演示，不能把它的结果当作运营商随机 NAT4 的成功率。更换 seed、端口占用情况或系统负载，可能改变结果；`UNEXPECTED` 会以非零退出码报告。

## 验证没有绕过 NAT 或偷用数据中继

实验使用真实的 localhost UDP socket 传递报文；两端分别通过用户态 NAT 网关。客户端算法与真实联网模式相同，只有底层收发适配器不同。

- 映射键包含本地 `IP:port` 和远端 `IP:port`。换远端 IP 或端口就建立新映射。
- 每条公网映射只允许来自该远端精确 `IP:port` 的报文进入。来自其他 IP 或端口的报文计入 `filtered`。
- 同一映射复用公网端口；映射有有效期和端口容量限制，不会自动把随机映射转换为 cone NAT。
- 客户端只知道探测结果和自己配置的端口搜索范围，读不到 NAT 分配表，也不知道 NAT 的随机种子。
- TCP 协调服务只交换配对信息、候选地址、轮次和结果；UDP 探测服务只回答 `WHO` 地址查询。
- 数据由两个客户端发送 `PUNCH → ACK → PING → PONG`。`PONG` 必须匹配本次会话、轮次、对端 id、本 socket 的 nonce、请求序号、来源地址和原始 payload。
- 双方各自收到至少 **3 个不同请求的数据回包**，协调器才确认 `DONE OK`。客户端也不会仅凭协调器的成功消息就报告连通。

用户态网关不是内核 network namespace、实体路由器或运营商 CGNAT。这里没有模拟 TCP NAT、真实路由、防火墙、IP 池变化、背景用户、丢包和拥塞；因此实验结果只证明所实现模型下的行为。

## 两种算法

### predict：保持 socket，预测一个目标

1. 同一个 UDP socket 依次访问三个不同探测端点，获取公网映射。
2. 若两次端口差相同且绝对值不超过 64，假设下一次仍按这个步长分配；映射不变时复用观察值。
3. 对无明显规律的结果，仅作 `最后端口 + 1` 的有限尝试，日志明确标成 `irregular-next-port-guess`。
4. 经协调器交换各自预测的下一公网端口。
5. 继续使用原 socket，只向对端的这个候选目标发送和重传。避免向大量不同目标发包，自己打乱顺序分配。
6. 失败后下一轮重新建 socket、重新探测。

这适用于能够预测的端口分配器，不保证背景流量、端口冲突或多层 NAT 下预测仍成立。

### fanout：猜测接收端口，多 socket 尝试

1. 探测公网 IP。每端在指定范围内猜测一个自己未来的公网接收端口，排除自己已知的探测映射端口。
2. 经协调器交换两个猜测值。**这不是请求 NAT 映射指定端口**。
3. 每端创建 `fanout` 个全新 UDP socket，全部向对端猜测的同一个公网端口发包。
4. 如果 A 的某个 socket 恰好映射为 A 猜的端口，B 也有 socket 恰好映射为 B 猜的端口，就形成严格过滤允许的相互匹配通路。
5. 选中收到真实数据回包的 socket；其他 socket 不构成成功证据。

理想化地，双方各自从 N 个可用端口中均匀取得 m 个不同映射，两个独立猜测同时命中的概率约为 `(m/N)^2`。它不是只需猜中一侧端口的生日碰撞模型。因此，小池实验可以很容易成功，全范围双随机 NAT 的这套朴素方案效率很低。这个近似不是实网成功率。

## 三台机器实测

需要一台有公网 IPv4 的协调服务器，以及两台位于不同待测 NAT 后面的客户端。源码可在各机器执行 `cargo build --release --offline`；不同操作系统需要分别构建。部署时复制 `target/release/` 下的可执行文件即可。

服务端，例如 Linux VPS：

```bash
./target/release/nat4-demo server --bind 0.0.0.0:40000 --rounds 12 --round-ms 1500
```

允许服务端 TCP 40000 和 UDP 40000、40001、40002 通过主机防火墙及云安全组。协调器不应再位于未配置映射的 NAT 后面。

客户端 A、B 在 55 秒内启动，使用相同 room 和不同 id。以下 `203.0.113.10` 是文档示例地址，必须替换成协调器真实公网 IPv4。

```powershell
# A
.\nat4-demo.exe peer --server 203.0.113.10:40000 --room experiment1 --id alice --strategy predict

# B（另一台机器）
.\nat4-demo.exe peer --server 203.0.113.10:40000 --room experiment1 --id bob --strategy predict
```

若端口探测无规律，可在双方尝试：

```powershell
.\nat4-demo.exe peer --server 203.0.113.10:40000 --room experiment2 --id alice --strategy fanout --fanout 32 --pps 200
# 另一端同样启动，将 --id 改为 bob。
```

`--pps` 是每端主动探测和 PING 的总发送速率上限，分摊到所有 socket；ACK/PONG 回复不计入。增大 fanout 时，需要给协调器设置更长 `--round-ms` 或提高这个速率，以留出至少三次数据往返的时间。增加参数只扩大尝试预算，不保证随机 NAT 下成功。

如果你通过独立测量已知公网分配端口池，可以显式指定 `--port-min`、`--port-max`。不要仅根据两三个端口样本就假定运营商只使用某个小池。

默认三个 UDP 探测端点位于同一服务器 IP、不同端口，能观察目的端口相关映射，**不能完整识别仅依赖目的 IP 的映射行为**。可在其他公网 IP 上另外运行探测服务，用 `--probes IP:PORT,IP:PORT,IP:PORT` 指定三个不同探测端点。它们仍使用本 demo 的 WHO/SEEN 协议，不是标准 STUN 服务。

程序退出码：`peer` 为 0 表示已验证，2 表示预算耗尽，1 表示配置、网络或协议错误。`lab` 为 0 表示所有所选实验符合预期，2 表示出现不同结果。

实验结束后 socket 会关闭；此版本只验证通路与 payload 回包，不提供持久隧道、TCP 转发、文件传输或加密通信。room/session/nonce 用于区分实验和请求，不构成密码学认证；协调通道也是明文 TCP。

## 完整检查

```powershell
cargo fmt --all -- --check
cargo test --offline
cargo clippy --offline --all-targets -- -D warnings
cargo build --offline --release
.\target\release\nat4-demo.exe lab --case all --seed 7
```

也可执行 `powershell -ExecutionPolicy Bypass -File .\scripts\verify.ps1`，逐项检查并把实验日志保存到 `logs/lab-seed7.txt`。

测试覆盖映射的目的 IP/端口依赖、内部 socket 隔离、严格来源过滤、过期映射、协调器不转发数据、协调器假成功消息、原生 UDP 收发、三个独立进程的命令行运行，以及四种双 NAT 场景。

## 源码入口

| 文件 | 职责 |
|---|---|
| `src/main.rs` | 命令行、参数与退出码 |
| `src/peer.rs` | 探测、预测、fanout、双向 payload 验证 |
| `src/server.rs` | TCP 配对、轮次协调、UDP 地址探测 |
| `src/nat.rs` | 有有效期和严格过滤的用户态 NAT 模拟器 |
| `src/wire.rs` | UDP 适配器、实验协议、控制消息 |
| `src/lab.rs` | 可重复实验及预期结果 |
| `tests/validation.rs` | 网络行为和结果真实性验证 |

设计参考：[RFC 4787 的映射与过滤行为](https://www.rfc-editor.org/rfc/rfc4787.html)、[RFC 5128 §3.5 端口预测](https://www.rfc-editor.org/rfc/rfc5128.html#section-3.5)。代码为本项目独立实现，未继承 frp。
