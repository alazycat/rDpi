#!/usr/bin/env python3
"""生成 P0 差分测试的首批 pcap 语料（自生成，无第三方抓包版权问题）。

用法：python -I tests/parity/gen_corpus.py
输出：tests/parity/corpus/*.pcap

语料保持确定性（固定时间戳、固定序列号），golden 输出可复现。
扩展方式：新增 build_* 函数并加入 CORPUS 列表。
"""

import struct
from pathlib import Path

ETH_IPV4 = bytes.fromhex("00112233445566778899aabb0800")
BASE_TS = 1_700_000_000_000_000  # 微秒


def ipv4(src, dst, proto, payload, ttl=64, ident=1):
    total = 20 + len(payload)
    header = (
        bytes([0x45, 0x00])
        + struct.pack(">H", total)
        + struct.pack(">H", ident)
        + struct.pack(">H", 0)
        + bytes([ttl, proto])
        + b"\x00\x00"
        + bytes(src)
        + bytes(dst)
    )
    return header + payload


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, seq, ack, flags, payload=b"", ttl=64):
    header = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 0xFFFF, 0, 0)
    return header + payload


def frame(src, dst, proto, l4_payload, ttl=64):
    return ETH_IPV4 + ipv4(src, dst, proto, l4_payload, ttl=ttl)


def dns_query_payload(name="example.com"):
    payload = bytes([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    for label in name.split("."):
        payload += bytes([len(label)]) + label.encode()
    return payload + b"\x00\x00\x01\x00\x01"


def tls_client_hello(sni="example.com"):
    if sni is None:
        sni_ext = b""
    else:
        name = sni.encode()
        list_len = len(name) + 3
        ext_len = len(name) + 5
        sni_ext = (
            bytes([0x00, 0x00])
            + struct.pack(">H", ext_len)
            + struct.pack(">H", list_len)
            + bytes([0x00])
            + struct.pack(">H", len(name))
            + name
        )
    versions_ext = bytes([0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04])
    extensions = struct.pack(">H", len(sni_ext) + len(versions_ext)) + sni_ext + versions_ext

    body = (
        bytes([0x03, 0x03])
        + bytes([0x11] * 32)
        + bytes([0x00])
        + struct.pack(">H", 2)
        + bytes([0x13, 0x01])
        + bytes([0x01, 0x00])
        + extensions
    )
    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16, 0x03, 0x01]) + struct.pack(">H", len(handshake)) + handshake


def build_dns_udp(name="example.com"):
    client, server = [192, 168, 1, 1], [10, 0, 0, 1]
    return [
        (
            BASE_TS,
            frame(
                client,
                server,
                17,
                udp(12345, 53, dns_query_payload(name)),
            ),
        )
    ]


def build_http(host="example.com", method="GET", path="/", body=b""):
    client, server = [192, 168, 1, 1], [10, 0, 0, 1]
    request = (
        method.encode()
        + b" "
        + path.encode()
        + b" HTTP/1.1\r\nHost: "
        + host.encode()
        + b"\r\nUser-Agent: parity-test\r\n"
    )
    if body:
        request += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    request += b"\r\n" + body
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    cseq, sseq = 1000, 5000
    return [
        (BASE_TS + 0, frame(client, server, 6, tcp(50000, 80, cseq, 0, 0x02))),
        (BASE_TS + 10_000, frame(server, client, 6, tcp(80, 50000, sseq, cseq + 1, 0x12))),
        (BASE_TS + 20_000, frame(client, server, 6, tcp(50000, 80, cseq + 1, sseq + 1, 0x10))),
        (
            BASE_TS + 30_000,
            frame(client, server, 6, tcp(50000, 80, cseq + 1, sseq + 1, 0x18, request)),
        ),
        (
            BASE_TS + 40_000,
            frame(
                server,
                client,
                6,
                tcp(80, 50000, sseq + 1, cseq + 1 + len(request), 0x18, response),
            ),
        ),
    ]


def build_tls_client_hello(sni="example.com"):
    client, server = [192, 168, 1, 1], [10, 0, 0, 1]
    hello = tls_client_hello(sni)
    cseq, sseq = 2000, 6000
    return [
        (BASE_TS + 0, frame(client, server, 6, tcp(50001, 443, cseq, 0, 0x02))),
        (BASE_TS + 10_000, frame(server, client, 6, tcp(443, 50001, sseq, cseq + 1, 0x12))),
        (BASE_TS + 20_000, frame(client, server, 6, tcp(50001, 443, cseq + 1, sseq + 1, 0x10))),
        (
            BASE_TS + 30_000,
            frame(client, server, 6, tcp(50001, 443, cseq + 1, sseq + 1, 0x18, hello)),
        ),
    ]


def mixed(*builders):
    packets = []
    for builder in builders:
        packets.extend(builder())
    return sorted(packets, key=lambda packet: packet[0])


CORPUS = {
    # DNS
    "dns_udp": lambda: build_dns_udp("example.com"),
    "dns_youtube": lambda: build_dns_udp("youtube.com"),
    "dns_github": lambda: build_dns_udp("github.com"),
    "dns_facebook": lambda: build_dns_udp("facebook.com"),
    # HTTP
    "http_get": lambda: build_http("example.com"),
    "http_youtube": lambda: build_http("youtube.com"),
    "http_github": lambda: build_http("github.com"),
    "http_facebook": lambda: build_http("facebook.com"),
    "http_post": lambda: build_http("example.com", method="POST", path="/login", body=b"user=a"),
    "http_post_youtube": lambda: build_http(
        "youtube.com", method="POST", path="/upload", body=b"data"
    ),
    # TLS
    "tls_client_hello": lambda: build_tls_client_hello("example.com"),
    "tls_youtube": lambda: build_tls_client_hello("www.youtube.com"),
    "tls_github": lambda: build_tls_client_hello("github.com"),
    "tls_facebook": lambda: build_tls_client_hello("facebook.com"),
    "tls_googleapis": lambda: build_tls_client_hello("www.googleapis.com"),
    "tls_no_sni": lambda: build_tls_client_hello(None),
    # 多流混合（验证 flow 集合匹配与双向去重）
    "mixed_web": lambda: mixed(
        lambda: build_dns_udp("example.com"),
        lambda: build_http("example.com"),
        lambda: build_tls_client_hello("example.com"),
    ),
    "mixed_apps": lambda: mixed(
        lambda: build_dns_udp("youtube.com"),
        lambda: build_http("youtube.com"),
        lambda: build_tls_client_hello("www.youtube.com"),
    ),
    "mixed_enterprise": lambda: mixed(
        lambda: build_http("github.com"),
        lambda: build_tls_client_hello("github.com"),
        lambda: build_dns_udp("facebook.com"),
    ),
    "mixed_post": lambda: mixed(
        lambda: build_http("example.com", method="POST", path="/login", body=b"user=a"),
        lambda: build_tls_client_hello(None),
    ),
}


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts_us, data in packets:
            sec, usec = divmod(ts_us, 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)


def main():
    out_dir = Path(__file__).resolve().parent / "corpus"
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, builder in CORPUS.items():
        path = out_dir / f"{name}.pcap"
        write_pcap(path, builder())
        print(f"wrote {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
