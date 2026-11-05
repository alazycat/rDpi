# rDpi 性能基线

> 建立时间：2026-11-05，commit `c33db6b`（F12-F27 误报面审计轮之后）；miss 路径两项于 F28/F29 后经同机 A/B 重测（本地改动，2026-11-05）。
> 基准代码：[benches/bench_detect.rs](file:///d:/rust_code/rDpi/benches/bench_detect.rs)（criterion 0.5）。

## 基线数据

实测环境：Windows（本机开发机），`cargo bench --features quic`（release 构建），criterion 默认 100 样本。**基线数据强依赖机器与负载环境，横向比较只在本机同环境内有意义；跨 criterion 调用的噪声可达 ±7%，重大结论必须同机紧凑 A/B。**

| 基准项 | 路径含义 | 中位耗时 | 折算吞吐 |
|---|---|---|---|
| `detect_dns` | 单包冷路径（含 Detector 创建），UDP DNS 命中 | 791.89 ns | ~1.26M pkt/s |
| `detect_http` | 单包冷路径，TCP HTTP 命中 | 1.0205 µs | ~0.98M pkt/s |
| `detect_tls_clienthello` | 单包冷路径，TCP TLS ClientHello + SNI/JA4 解析 | 2.3501 µs | ~0.43M pkt/s |
| `detect_steady_state_mixed_100` | 稳态：单实例 100 包（HTTP+DNS 两条已定型流，回显+规则跳过路径） | 41.263 µs/100 包 = 0.413 µs/包 | ~2.42M pkt/s |
| `detect_unknown_tcp_miss_100` | 稳态 miss：单实例 100 包 256B 伪随机 TCP（首字节恒 0x42；F29 门后重测 167.06 µs，门 OFF 同机 190.56 µs，**-12.3%**） | 167.06 µs/100 包 = 1.671 µs/包 | ~0.60M pkt/s |
| `detect_unknown_tcp_miss_varied_100` | 稳态 miss 平均场景（F29 新增）：100 包首字节互异 | 175.39 µs/100 包 = 1.754 µs/包 | ~0.57M pkt/s |
| `detector_new` | Detector 创建（含流表/规则初始化） | 57.984 ns | — |
| `detect_quic_header_only` | QUIC long header 判定 + 解密失败兜底（quic feature） | 5.2425 µs | ~0.19M pkt/s |
| `detect_quic_initial_decrypt` | QUIC Initial 全解密 + ClientHello + JA4（quic feature） | 23.318 µs | ~0.043M pkt/s |
| `detect_quic_initial_decrypt_steady_100` | QUIC 稳态：单实例 100 包（第 1 包解密定型，其余 99 包回显） | 57.393 µs/100 包 = 0.574 µs/包 | ~1.74M pkt/s |

## 方法论与结论

1. **冷路径 vs 稳态**：`detect_dns/http/tls` 与既有基准风格一致，在 iter 内新建 Detector——数字包含 `detector_new`（~58ns，占比 <5%），可视为单包上限。稳态两项（steady/miss）单实例连续喂包，摊销流表创建，代表长流场景的真实每包成本。
2. **已定型流回显极廉价**：稳态混合（命中+回显混合）0.413 µs/包，约为冷路径 DNS 的 1/2——识别后流不再遍历 Registry（F7 回显直接携带元数据）。
3. **miss 是最坏路径但可控**：全 Registry 遍历 + 20 包后 Giveup 接管。**注意结构**：`detect_unknown_tcp_miss_100` 的 100 包中仅前 ~19 包走 DPI 扫描（giveup=20 后 GuessEngine 接管，[lib.rs:352](file:///d:/rust_code/rDpi/src/lib.rs#L352)），门预筛收益集中在扫描段（折算每扫描包省 ~1.24µs，约 -55%）。同机 A/B（门 OFF 190.56 → ON 167.06 µs）为结论依据（F29，risks.md）。
4. **首字节门预筛（F29）**：36/49 detector 声明门，Registry 注册期预计算 skip 位图、detect 循环内一次位测试跳过；13 个首字节任意的 detector（dns/mongodb/pop3 等）不受影响。`detect_unknown_tcp_miss_varied_100`（首字节均匀铺开）反映真实流量平均收益（1.754 µs/包）——部分首字节落在 quic/rtp/tls/http 等重解析器区间，成本高于 0x42 点，属预期。
5. **TLS 元数据解析约 2.3µs**：包含 ClientHello/JA4 解析；QUIC 全解密路径 23.3µs 是唯一显著开销项（AES-GCM + HKDF，F28 后已从 25.6µs 降 9%，见 risks.md R13/F28）。
6. **QUIC 稳态回显极廉价**：0.574 µs/包（第 1 包全解密 23µs 摊入，其余 99 包走回显路径）；流协议只写一次语义保证解密同样只做一次。

## 如何对比新改动

```bash
cargo bench --features quic        # criterion 自动与 target/criterion 上次基线对比
cargo bench --features quic -- detect_tls   # 只跑匹配过滤的基准
```

- criterion 会在输出中给出 `Performance has changed` / `Performance has improved/regressed` 判定（噪声阈值默认 ±5%）。
- **改动了 detect 路径的热循环后必须跑基准**；显式回退/提升应在改动说明中引用具体基准项数字。
- 若确认接受性能变化，可更新本表数字并注明 commit；`cargo bench --features quic -- --save-baseline <tag>` 可保存命名基线供 `--baseline <tag>` 对比。

## 已知性能注意

- QUIC GHASH 已升级 Shoup 4-bit 查表（150 倍，risks.md R13）；逐位实现仅存留为测试 oracle。
- QUIC Initial 解密已做密钥缓存 + 候选解密分层（F28，risks.md）：冷解密 25.6→23.3µs；`detect_quic_header_only` 4.12→5.24µs 是**合成最坏情形**（pn_len<4 且永久解密失败的包需付候选 0 miss 后的预计算成本）——真实流第 1 包即定型走回显，不会重复触发，已接受。
- websocket detect 路径已去 `to_lowercase()` 堆分配（F27）；审计后全部尾部 detector 判定为零分配（F12-F27）。
