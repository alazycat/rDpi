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


def tcp_session(
    client, server, cport, sport, exchanges, base=0, cseq=1000, sseq=5000
):
    """构造带三次握手的 TCP 会话。

    exchanges: [(direction, payload), ...]，direction 为 "c" 或 "s"。
    """
    packets = [
        (
            BASE_TS + base + 0,
            frame(client, server, 6, tcp(cport, sport, cseq, 0, 0x02)),
        ),
        (
            BASE_TS + base + 10_000,
            frame(server, client, 6, tcp(sport, cport, sseq, cseq + 1, 0x12)),
        ),
        (
            BASE_TS + base + 20_000,
            frame(client, server, 6, tcp(cport, sport, cseq + 1, sseq + 1, 0x10)),
        ),
    ]
    ts = 30_000
    cnext, snext = cseq + 1, sseq + 1
    for direction, payload in exchanges:
        if direction == "c":
            packets.append(
                (
                    BASE_TS + base + ts,
                    frame(
                        client,
                        server,
                        6,
                        tcp(cport, sport, cnext, snext, 0x18, payload),
                    ),
                )
            )
            cnext += len(payload)
        else:
            packets.append(
                (
                    BASE_TS + base + ts,
                    frame(
                        server,
                        client,
                        6,
                        tcp(sport, cport, snext, cnext, 0x18, payload),
                    ),
                )
            )
            snext += len(payload)
        ts += 10_000
    return packets


def udp_pair(client, server, cport, sport, request, response, base=0):
    return [
        (BASE_TS + base + 0, frame(client, server, 17, udp(cport, sport, request))),
        (
            BASE_TS + base + 10_000,
            frame(server, client, 17, udp(sport, cport, response)),
        ),
    ]


def dns_query_payload(name="example.com"):
    payload = bytes([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    for label in name.split("."):
        payload += bytes([len(label)]) + label.encode()
    return payload + b"\x00\x00\x01\x00\x01"


def tls_client_hello(sni="example.com", alpn=None, version=(0x03, 0x01)):
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
    if alpn is None:
        alpn_ext = b""
    else:
        proto = alpn.encode()
        proto_list = bytes([len(proto)]) + proto
        alpn_ext = (
            bytes([0x00, 0x10])
            + struct.pack(">H", len(proto_list) + 2)
            + struct.pack(">H", len(proto_list))
            + proto_list
        )
    extensions = (
        struct.pack(">H", len(sni_ext) + len(versions_ext) + len(alpn_ext))
        + sni_ext
        + versions_ext
        + alpn_ext
    )

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
    return (
        bytes([0x16])
        + bytes(version)
        + struct.pack(">H", len(handshake))
        + handshake
    )


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


# --- F44 子分类语料：HTTP CONNECT/Proxy、DoH/DoT、FTP 传输命令 ---


def build_http_connect():
    return tcp_session(
        CLIENT, SERVER, 50012, 3128, [("c", b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")]
    )


def build_http_proxy():
    return tcp_session(
        CLIENT,
        SERVER,
        50013,
        8080,
        [("c", b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")],
    )


def build_doh_resolver():
    """DoH：TLS ClientHello SNI 命中已知 DoH 解析器域名（443）"""
    client, server = [192, 168, 1, 1], [10, 0, 0, 1]
    hello = tls_client_hello("dns.google", alpn="h2")
    cseq, sseq = 3000, 7000
    return [
        (BASE_TS + 0, frame(client, server, 6, tcp(50014, 443, cseq, 0, 0x02))),
        (BASE_TS + 10_000, frame(server, client, 6, tcp(443, 50014, sseq, cseq + 1, 0x12))),
        (BASE_TS + 20_000, frame(client, server, 6, tcp(50014, 443, cseq + 1, sseq + 1, 0x10))),
        (
            BASE_TS + 30_000,
            frame(client, server, 6, tcp(50014, 443, cseq + 1, sseq + 1, 0x18, hello)),
        ),
    ]


def build_dot_alpn():
    """DoT：TLS ClientHello ALPN=dot（853）"""
    client, server = [192, 168, 1, 1], [10, 0, 0, 1]
    hello = tls_client_hello("dns.example.com", alpn="dot")
    cseq, sseq = 4000, 8000
    return [
        (BASE_TS + 0, frame(client, server, 6, tcp(50015, 853, cseq, 0, 0x02))),
        (BASE_TS + 10_000, frame(server, client, 6, tcp(853, 50015, sseq, cseq + 1, 0x12))),
        (BASE_TS + 20_000, frame(client, server, 6, tcp(50015, 853, cseq + 1, sseq + 1, 0x10))),
        (
            BASE_TS + 30_000,
            frame(client, server, 6, tcp(50015, 853, cseq + 1, sseq + 1, 0x18, hello)),
        ),
    ]


def build_dot_port():
    """DoT：无 ALPN/SNI 信号，TCP 853 端口回退（DpiPartial）"""
    client, server = [192, 168, 1, 1], [10, 0, 0, 1]
    hello = tls_client_hello(None)
    cseq, sseq = 5000, 9000
    return [
        (BASE_TS + 0, frame(client, server, 6, tcp(50016, 853, cseq, 0, 0x02))),
        (BASE_TS + 10_000, frame(server, client, 6, tcp(853, 50016, sseq, cseq + 1, 0x12))),
        (BASE_TS + 20_000, frame(client, server, 6, tcp(50016, 853, cseq + 1, sseq + 1, 0x10))),
        (
            BASE_TS + 30_000,
            frame(client, server, 6, tcp(50016, 853, cseq + 1, sseq + 1, 0x18, hello)),
        ),
    ]


def build_ftp_transfer():
    """FTP 传输命令：RETR/STOR 提取文件名（有状态会话 F44）"""
    return tcp_session(
        CLIENT,
        SERVER,
        50017,
        21,
        [
            ("s", b"220 (vsFTPd 3.0.5)\r\n"),
            ("c", b"USER ftpuser\r\n"),
            ("s", b"331 Please specify the password.\r\n"),
            ("c", b"RETR report.pdf\r\n"),
            ("s", b"150 Opening data connection.\r\n"),
        ],
    )


# --- 企业协议（P0 差分扩展）---

CLIENT, SERVER = [192, 168, 1, 1], [10, 0, 0, 1]


def build_ssh():
    return tcp_session(
        CLIENT,
        SERVER,
        50000,
        22,
        [
            ("s", b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"),
            ("c", b"SSH-2.0-OpenSSH_9.6p1\r\n"),
        ],
    )


def build_smtp():
    return tcp_session(
        CLIENT,
        SERVER,
        50001,
        25,
        [
            ("s", b"220 mail.example.com ESMTP Postfix\r\n"),
            ("c", b"EHLO client.example.com\r\n"),
            (
                "s",
                b"250-mail.example.com\r\n250-PIPELINING\r\n"
                b"250-SIZE 10240000\r\n250 HELP\r\n",
            ),
        ],
    )


def build_ftp():
    return tcp_session(
        CLIENT,
        SERVER,
        50002,
        21,
        [
            ("s", b"220 (vsFTPd 3.0.5)\r\n"),
            ("c", b"USER anonymous\r\n"),
            ("s", b"331 Please specify the password.\r\n"),
            ("c", b"PASS anonymous@example.com\r\n"),
            ("s", b"230 Login successful.\r\n"),
        ],
    )


def mysql_greeting():
    version = b"8.0.36\x00"
    conn_id = struct.pack("<I", 11)
    auth1 = bytes(range(1, 9))
    cap1 = struct.pack("<H", 0xFFFF)
    charset = b"\x21"
    status = struct.pack("<H", 0x0002)
    cap2 = struct.pack("<H", 0x81FF)
    reserved = b"\x00" * 10
    auth2 = bytes(range(0x10, 0x1D))
    plugin = b"caching_sha2_password\x00"
    return (
        b"\x0a"
        + version
        + conn_id
        + auth1
        + b"\x00"
        + cap1
        + charset
        + status
        + cap2
        + b"\x15"
        + reserved
        + auth2
        + plugin
    )


def build_mysql():
    greeting = mysql_greeting()
    packet = len(greeting).to_bytes(3, "little") + b"\x00" + greeting
    return tcp_session(CLIENT, SERVER, 50003, 3306, [("s", packet)])


def build_postgresql():
    params = (
        b"user\x00postgres\x00database\x00postgres\x00"
        b"application_name\x00psql\x00\x00"
    )
    body = struct.pack(">I", 196608) + params
    message = struct.pack(">I", len(body) + 4) + body
    return tcp_session(CLIENT, SERVER, 50004, 5432, [("c", message)])


def build_redis():
    return tcp_session(
        CLIENT,
        SERVER,
        50005,
        6379,
        [("c", b"*1\r\n$4\r\nPING\r\n"), ("s", b"+PONG\r\n")],
    )


def dhcp_message(opcode, yiaddr, option, server_id=None):
    packet = bytearray(236)
    packet[0] = opcode
    packet[1] = 1  # Ethernet
    packet[2] = 6
    packet[4:8] = struct.pack(">I", 0x12345678)
    packet[16:20] = bytes(yiaddr)
    packet[28:34] = bytes.fromhex("001122334455")
    packet[236:240] = bytes.fromhex("63825363")
    packet += bytes([53, 1, option, 255])
    if server_id:
        packet += bytes([54, 4]) + bytes(server_id) + bytes([255])
    return bytes(packet)


def build_dhcp():
    return udp_pair(
        [0, 0, 0, 0],
        [255, 255, 255, 255],
        68,
        67,
        dhcp_message(1, [0, 0, 0, 0], 1),
        dhcp_message(2, [192, 168, 1, 100], 2, [192, 168, 1, 1]),
    )


def build_ntp():
    request = bytearray(48)
    request[0] = 0x23  # LI=0, VN=4, mode=3 (client)
    request[40:48] = struct.pack(">Q", 0xE000000000000000)
    response = bytearray(48)
    response[0] = 0x24  # mode=4 (server)
    response[1] = 1
    response[40:48] = struct.pack(">Q", 0xE000000100000000)
    return udp_pair(CLIENT, SERVER, 50006, 123, bytes(request), bytes(response))


def build_snmp():
    request = bytes.fromhex(
        "302602010104067075626c6963a019020401020304020100020100"
        "300b300906052b060102010500"
    )
    response = bytes.fromhex(
        "302902010104067075626c6963a21c020401020304020100020100"
        "300e300c06082b060102010105000400"
    )
    return udp_pair(CLIENT, SERVER, 50007, 161, request, response)


def build_modbus():
    request = bytes.fromhex("000100000006010300000001")
    response = bytes.fromhex("000100000005010302002a")
    return tcp_session(
        CLIENT, SERVER, 50008, 502, [("c", request), ("s", response)]
    )


def build_mqtt():
    connect = bytes.fromhex("101000044d5154540402003c000474657374")
    connack = bytes.fromhex("20020000")
    return tcp_session(
        CLIENT, SERVER, 50009, 1883, [("c", connect), ("s", connack)]
    )


def build_sip():
    invite = (
        b"INVITE sip:bob@example.com SIP/2.0\r\n"
        b"Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776\r\n"
        b"Max-Forwards: 70\r\n"
        b"From: Alice <sip:alice@example.com>;tag=1928301774\r\n"
        b"To: Bob <sip:bob@example.com>\r\n"
        b"Call-ID: 1234567890@example.com\r\n"
        b"CSeq: 1 INVITE\r\n"
        b"Contact: <sip:alice@192.168.1.1:5060>\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    trying = (
        b"SIP/2.0 100 Trying\r\n"
        b"Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776\r\n"
        b"From: Alice <sip:alice@example.com>;tag=1928301774\r\n"
        b"To: Bob <sip:bob@example.com>\r\n"
        b"Call-ID: 1234567890@example.com\r\n"
        b"CSeq: 1 INVITE\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    return udp_pair(CLIENT, SERVER, 50010, 5060, invite, trying)


def build_dns_tcp():
    query = dns_query_payload("example.com")
    message = len(query).to_bytes(2, "big") + query
    return tcp_session(CLIENT, SERVER, 50011, 53, [("c", message)])


def nbns_encode_name(name, suffix):
    """First-level NetBIOS 编码（RFC 1002）：每字节拆两个半字节 + 'A' 偏移。"""
    padded = bytearray(name.encode("ascii")[:15])
    padded += b" " * (15 - len(padded))
    padded.append(suffix)
    return bytes(
        byte for nibble in padded for byte in (0x41 + (nibble >> 4), 0x41 + (nibble & 0x0F))
    )


def build_nbns():
    name = nbns_encode_name("SMB-PC", 0x20)
    question = (
        b"\x20" + name       # question name（len=32）
        + b"\x00"            # root domain
        + b"\x00\x20\x00\x01"  # type=NB class=IN
    )
    request = (
        b"\x9e\x8b"          # transaction id
        + b"\x00\x00"        # flags（query）
        + b"\x00\x01"        # qdcount
        + b"\x00\x00\x00\x00\x00\x00"  # ancount/nscount/arcount
        + question
    )
    response = (
        b"\x9e\x8b"          # transaction id
        + b"\x84\x00"        # flags（response，authoritative）
        + b"\x00\x00"        # qdcount
        + b"\x00\x01"        # ancount
        + b"\x00\x00\x00\x00"  # nscount/arcount
        + question
        + b"\x00\x00\x0e\x10"  # ttl
        + b"\x00\x06"          # rdlength
        + b"\x00\x00"          # NB flags（B node）
        + b"\xc0\xa8\x01\x64"  # 192.168.1.100
    )
    return udp_pair(CLIENT, SERVER, 50012, 137, request, response)


def nbds_payload(dgm_id):
    return (
        b"\x11"                # type = direct group datagram
        + b"\x01"              # flags
        + dgm_id               # dgm id
        + bytes(CLIENT)        # source ip（须与 IP 头 saddr 一致，nDPI 校验）
        + b"\x00\x8a"          # source port 138
        + (16 + 16 + 13).to_bytes(2, "big")  # dgm length（data 部分）
        + b"\x00\x01"          # packet offset
        + b"SMB-PC".ljust(16, b" ")     # source name（16 字节，空格补齐）
        + b"SMB-GROUP".ljust(16, b" ")  # target name（16 字节）
        + b"hello netbios"    # datagram 数据
    )


def build_nbds():
    return udp_pair(
        CLIENT, SERVER, 50012, 138,
        nbds_payload(b"\x8d\x8e"),
        nbds_payload(b"\x8d\x8f"),
    )


def nbss_name_field(name):
    """RFC 1002 会话请求名字段：长度字节(0x20) + 32 字符编码 + 终止字节，共 34 字节。"""
    return b"\x20" + nbns_encode_name(name, 0x20) + b"\x00"


def build_nbss():
    """NBSS 会话请求：nDPI 要求 payload_len == 72 且长度字段 == 68。"""
    body = nbss_name_field("SMB-SRV") + nbss_name_field("SMB-PC")
    payload = b"\x81\x00" + (len(body)).to_bytes(2, "big") + body
    return tcp_session(CLIENT, SERVER, 50012, 139, [("c", payload)])


def smb_nbss(smb_body):
    length = len(smb_body)
    return b"\x00" + length.to_bytes(3, "big") + smb_body


def smb1_header(command, flags=0x18, status=0):
    """32 字节 SMB1 头：\xFFSMB + cmd + status(4LE) + flags + flags2(2) + 其余补零。"""
    header = (
        b"\xffSMB"
        + bytes([command])
        + status.to_bytes(4, "little")
        + bytes([flags])
        + b"\x53\x4d"      # flags2（UNICODE|LONG_NAMES）
    )
    return header + b"\x00" * (32 - len(header))


def smb2_header(command, status=0):
    return (
        b"\xfeSMB"
        + (64).to_bytes(2, "little")     # structure size
        + (1).to_bytes(2, "little")      # credit charge
        + status.to_bytes(4, "little")
        + command.to_bytes(2, "little")
        + b"\x00" * 4                    # credit / flags
        + b"\x00" * 4                    # next command
        + b"\x00" * 8                    # message id
        + b"\x00" * 4                    # pid
        + b"\x00" * 4                    # tree id
        + b"\x00" * 8                    # session id
        + b"\x00" * 16                   # signature
    )


def build_smb1_session_setup():
    """SMBv1 SessionSetup AndX（跳过 Negotiate 0x72 后的首个识别命令）。

    nDPI smb.c 要求载荷 > 36 字节（32+4+4）才进入判定，否则 dissector 被
    排除；Negotiate 补足到 52 字节以避免排除。
    """
    negotiate = smb_nbss(smb1_header(0x72) + b"\x00" * 16)
    setup = smb_nbss(smb1_header(0x73) + b"\x0c\x00" + b"\x00" * 16)
    return tcp_session(CLIENT, SERVER, 50013, 445, [
        ("c", negotiate),
        ("c", setup),
    ])


def build_smb23_session_setup():
    """SMB2 SessionSetup（跳过 SMB2 Negotiate 0x0000 后的首个识别命令）。"""
    negotiate = smb_nbss(smb2_header(0x0000))
    setup = smb_nbss(smb2_header(0x0001) + b"\x19\x00" + b"\x00" * 16)
    return tcp_session(CLIENT, SERVER, 50013, 445, [
        ("c", negotiate),
        ("c", setup),
    ])


def build_smb_echo():
    """SMB2 Echo（无需跳过，直接识别）。"""
    echo = smb_nbss(smb2_header(0x000E))
    return tcp_session(CLIENT, SERVER, 50013, 445, [("c", echo)])


def split_tcp_payloads(packets):
    """把每个带载荷的 TCP 报文从中间拆成两段，用于验证跨段重组。"""
    out = []
    for ts, frame in packets:
        pieces = _split_tcp_frame(frame)
        if pieces is None:
            out.append((ts, frame))
        else:
            out.append((ts, pieces[0]))
            out.append((ts + 1000, pieces[1]))
    return out


def _split_tcp_frame(frame):
    if len(frame) < 54 or frame[12:14] != b"\x08\x00":
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[23] != 6:
        return None
    total_len = struct.unpack(">H", frame[16:18])[0]
    tcp_off = 14 + ihl
    payload = frame[tcp_off + 20 : 14 + total_len]
    if len(payload) < 2:
        return None
    flags = frame[tcp_off + 13]
    if flags & 0x02 or flags & 0x07:  # SYN/FIN/RST 不拆
        return None

    seq = struct.unpack(">I", frame[tcp_off + 4 : tcp_off + 8])[0]
    first_len = len(payload) // 2

    def rebuild(new_seq, new_payload):
        tcp = bytearray(frame[tcp_off : tcp_off + 20])
        tcp[4:8] = struct.pack(">I", new_seq)
        ip = bytearray(frame[14:tcp_off])
        ip[2:4] = struct.pack(">H", ihl + 20 + len(new_payload))
        return frame[:14] + bytes(ip) + bytes(tcp) + new_payload

    return [
        rebuild(seq, payload[:first_len]),
        rebuild(seq + first_len, payload[first_len:]),
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
    # F44 子分类：HTTP CONNECT/Proxy、DoH/DoT、FTP 传输命令
    "http_connect": build_http_connect,
    "http_proxy": build_http_proxy,
    "doh_resolver": build_doh_resolver,
    "dot_alpn": build_dot_alpn,
    "dot_port": build_dot_port,
    "ftp_transfer": build_ftp_transfer,
    # 企业协议（B 组首批）：SSH / 邮件 / 文件传输 / 数据库 / 基础设施 / 工业 / IoT / VoIP
    "ssh_banner": build_ssh,
    "smtp_session": build_smtp,
    "ftp_control": build_ftp,
    "mysql_handshake": build_mysql,
    "postgresql_startup": build_postgresql,
    "redis_ping": build_redis,
    "dhcp_discover": build_dhcp,
    "ntp_request": build_ntp,
    "snmp_get": build_snmp,
    "modbus_read": build_modbus,
    "mqtt_connect": build_mqtt,
    "sip_invite": build_sip,
    "dns_tcp": build_dns_tcp,
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
    "mixed_enterprise_protocols": lambda: mixed(
        build_ssh, build_mysql, build_redis, build_dns_tcp
    ),
    "mixed_infra": lambda: mixed(build_dhcp, build_ntp, build_snmp, build_sip),
    # 跨 TCP 段重组（每个带载荷报文从中间拆成两段）
    "ssh_banner_split": lambda: split_tcp_payloads(build_ssh()),
    "smtp_session_split": lambda: split_tcp_payloads(build_smtp()),
    "ftp_control_split": lambda: split_tcp_payloads(build_ftp()),
    "mysql_handshake_split": lambda: split_tcp_payloads(build_mysql()),
    "postgresql_startup_split": lambda: split_tcp_payloads(build_postgresql()),
    "redis_ping_split": lambda: split_tcp_payloads(build_redis()),
    "modbus_read_split": lambda: split_tcp_payloads(build_modbus()),
    "mqtt_connect_split": lambda: split_tcp_payloads(build_mqtt()),
    "dns_tcp_split": lambda: split_tcp_payloads(build_dns_tcp()),
    # F45：NetBIOS（NBNS/NBDS/NBSS）+ SMBv1/v2（Negotiate 跳过 + SessionSetup 识别）
    "nbns_registration": build_nbns,
    "nbds_datagram": build_nbds,
    "nbss_session_request": build_nbss,
    "smb1_session_setup": build_smb1_session_setup,
    "smb23_session_setup": build_smb23_session_setup,
    "smb_echo": build_smb_echo,
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
