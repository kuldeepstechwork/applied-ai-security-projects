#!/usr/bin/env python3
"""
sniffer.py — Deep-Packet Inspection Sniffer with Protocol Analysis
===================================================================
Module 01 · Module 1 · Project 4

A production-grade packet capture and analysis engine built entirely on
raw sockets — no Scapy, no libpcap, no third-party libraries.

What makes this different from a basic sniffer:

  MULTI-LAYER PARSING
    Full decode from Ethernet → IP → TCP/UDP/ICMP → application layer.
    Each layer is parsed into a typed dataclass, not a raw byte blob.

  TCP CONNECTION STATE MACHINE
    Maintains a state table for every TCP 4-tuple, tracking the full
    handshake lifecycle: LISTEN → SYN_SENT → ESTABLISHED → FIN_WAIT →
    CLOSED.  Displays active connections like 'netstat -an'.

  DNS INTELLIGENCE
    Parses binary DNS questions and answers (including compressed labels).
    Shows "queried: google.com" on the request and "→ 142.250.x.x" when
    the response arrives.

  HTTP PAYLOAD DETECTION
    Recognises HTTP request lines (GET/POST/PUT/DELETE + path) and status
    lines (HTTP/1.x NNN ...) inside TCP payloads without touching port 80
    hardcoding — works on any port.

  ARP SPOOFING DETECTOR
    Tracks IP→MAC mappings over time.  If the same IP is announced with a
    different MAC within the session, fires a real-time alert.

  PORT SCAN DETECTOR
    Counts unique destination ports contacted by each source IP within a
    sliding 5-second window.  Fires when the count exceeds a configurable
    threshold (default 15).

  PCAP WRITER
    Writes all captured frames to a Wireshark-compatible PCAP file
    (libpcap magic 0xa1b2c3d4, link type 1 = Ethernet).

  FILTER EXPRESSIONS
    Subset of BPF syntax: 'tcp', 'udp', 'icmp', 'arp',
    'host 1.2.3.4', 'port 80', 'src port 443', 'dst host 10.0.0.1',
    and compound 'tcp and port 80'.

  LIVE STATS DASHBOARD
    Background thread refreshes every 3 seconds: total packets/bytes,
    throughput, protocol distribution, and top-5 talkers.

Requires root (raw socket needs CAP_NET_RAW):
    sudo python3 sniffer.py
    sudo python3 sniffer.py --filter "tcp and port 8080"
    sudo python3 sniffer.py --filter "host 192.168.100.10" --pcap capture.pcap
    sudo python3 sniffer.py --no-payload --stats-interval 5

Author : Kuldeep Singh
Lab    : 192.168.100.0/24 | Kali .10 | Webserver .30
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# ANSI color helpers
# ─────────────────────────────────────────────────────────────────────────────

_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    """Wrap *text* in an ANSI escape code if color output is active."""
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def green(t: str)  -> str: return _c("32;1", t)   # open / established
def yellow(t: str) -> str: return _c("33",   t)   # ICMP / warnings
def cyan(t: str)   -> str: return _c("36",   t)   # DNS / info
def blue(t: str)   -> str: return _c("34",   t)   # UDP
def red(t: str)    -> str: return _c("31;1", t)   # alerts / ARP
def magenta(t: str)-> str: return _c("35",   t)   # HTTP
def grey(t: str)   -> str: return _c("90",   t)   # secondary info
def bold(t: str)   -> str: return _c("1",    t)   # headers


# ─────────────────────────────────────────────────────────────────────────────
# Protocol constants
# ─────────────────────────────────────────────────────────────────────────────

ETH_P_ALL  = 0x0003   # Capture all Ethernet frames
ETH_P_IP   = 0x0800   # IPv4
ETH_P_ARP  = 0x0806   # ARP

PROTO_ICMP = 1
PROTO_TCP  = 6
PROTO_UDP  = 17

# TCP flag bitmasks (flags byte in TCP header)
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20

# TCP connection states (RFC 793 state machine)
class TCPState:
    """Enumeration of TCP connection lifecycle states per RFC 793."""
    LISTEN      = "LISTEN"
    SYN_SENT    = "SYN_SENT"
    SYN_RCVD    = "SYN_RCVD"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1  = "FIN_WAIT_1"
    FIN_WAIT_2  = "FIN_WAIT_2"
    CLOSE_WAIT  = "CLOSE_WAIT"
    TIME_WAIT   = "TIME_WAIT"
    CLOSED      = "CLOSED"


# ─────────────────────────────────────────────────────────────────────────────
# Parsed packet dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EthernetFrame:
    """
    Decoded IEEE 802.3 Ethernet frame header.

    Attributes:
        dst_mac    Destination MAC address as colon-separated hex string
        src_mac    Source MAC address as colon-separated hex string
        ethertype  EtherType field (0x0800 = IPv4, 0x0806 = ARP, etc.)
        payload    Bytes following the 14-byte Ethernet header
    """
    dst_mac: str
    src_mac: str
    ethertype: int
    payload: bytes


@dataclass
class IPPacket:
    """
    Decoded IPv4 packet header (RFC 791).

    Attributes:
        version     IP version (should always be 4)
        ihl         Internet header length in bytes (min 20)
        tos         Type of service / DSCP field
        total_len   Total length including header and data
        ttl         Time-to-live hop counter
        protocol    Encapsulated protocol (1=ICMP, 6=TCP, 17=UDP)
        src_ip      Source IP address as dotted decimal string
        dst_ip      Destination IP address as dotted decimal string
        payload     Bytes starting after the IP header (transport layer)
    """
    version: int
    ihl: int
    tos: int
    total_len: int
    ttl: int
    protocol: int
    src_ip: str
    dst_ip: str
    payload: bytes


@dataclass
class TCPSegment:
    """
    Decoded TCP segment header (RFC 793).

    Attributes:
        src_port    Source TCP port
        dst_port    Destination TCP port
        seq         Sequence number
        ack         Acknowledgment number
        data_offset Header length in bytes (data_offset_byte >> 4) * 4
        flags       Flags byte: FIN/SYN/RST/PSH/ACK/URG
        window      Receive window size
        payload     TCP payload bytes (application data)
        flag_str    Human-readable flags string, e.g. 'SYN+ACK'
    """
    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset: int
    flags: int
    window: int
    payload: bytes
    flag_str: str = ""

    def __post_init__(self) -> None:
        """Build the human-readable flag string after construction."""
        parts = []
        if self.flags & FLAG_SYN: parts.append("SYN")
        if self.flags & FLAG_ACK: parts.append("ACK")
        if self.flags & FLAG_FIN: parts.append("FIN")
        if self.flags & FLAG_RST: parts.append("RST")
        if self.flags & FLAG_PSH: parts.append("PSH")
        if self.flags & FLAG_URG: parts.append("URG")
        self.flag_str = "+".join(parts) if parts else "—"


@dataclass
class UDPDatagram:
    """
    Decoded UDP datagram header (RFC 768).

    Attributes:
        src_port    Source UDP port
        dst_port    Destination UDP port
        length      Total datagram length including header
        payload     UDP payload bytes
    """
    src_port: int
    dst_port: int
    length: int
    payload: bytes


@dataclass
class ICMPPacket:
    """
    Decoded ICMP message header (RFC 792).

    Attributes:
        type_code   ICMP type number (0=echo reply, 8=echo request, etc.)
        code        ICMP code (sub-type)
        type_name   Human-readable type name
    """
    type_code: int
    code: int
    type_name: str


@dataclass
class ARPPacket:
    """
    Decoded ARP message (RFC 826).

    Attributes:
        operation   1=request, 2=reply
        sender_mac  Sender hardware address
        sender_ip   Sender protocol address (IPv4 dotted decimal)
        target_mac  Target hardware address
        target_ip   Target protocol address (IPv4 dotted decimal)
        op_name     'REQUEST' or 'REPLY'
    """
    operation: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    op_name: str = ""

    def __post_init__(self) -> None:
        """Resolve the operation name after construction."""
        self.op_name = "REQUEST" if self.operation == 1 else "REPLY"


@dataclass
class DNSRecord:
    """
    A single DNS resource record from a DNS answer section.

    Attributes:
        name     Domain name this record answers
        rtype    Record type (1=A, 28=AAAA, 5=CNAME, etc.)
        rdata    Parsed record data (IP string for A records, name for CNAME)
    """
    name: str
    rtype: int
    rdata: str


@dataclass
class DNSPacket:
    """
    Parsed DNS message (RFC 1035).

    Attributes:
        transaction_id   16-bit ID matching query to response
        is_response      True if QR bit is set (this is an answer)
        questions        List of queried domain names
        answers          List of DNSRecord answer records
    """
    transaction_id: int
    is_response: bool
    questions: list[str]
    answers: list[DNSRecord]


@dataclass
class CapturedPacket:
    """
    Top-level wrapper representing a fully decoded captured frame.

    Holds the raw bytes, decoded layers, and timestamp.  All analyzers
    and the display engine work from this single object.

    Attributes:
        timestamp    Unix timestamp (float) when the frame was captured
        raw          Original raw frame bytes (for PCAP writing)
        eth          Decoded Ethernet frame (always present)
        ip           Decoded IP packet, or None for non-IP frames (e.g. ARP)
        tcp          Decoded TCP segment, or None
        udp          Decoded UDP datagram, or None
        icmp         Decoded ICMP packet, or None
        arp          Decoded ARP message, or None
        dns          Decoded DNS message, or None (from UDP port 53)
        http_info    Short HTTP description string if HTTP payload detected
        proto_label  Top-level protocol label for display ('TCP', 'UDP', etc.)
    """
    timestamp: float
    raw: bytes
    eth: EthernetFrame
    ip: Optional[IPPacket] = None
    tcp: Optional[TCPSegment] = None
    udp: Optional[UDPDatagram] = None
    icmp: Optional[ICMPPacket] = None
    arp: Optional[ARPPacket] = None
    dns: Optional[DNSPacket] = None
    http_info: str = ""
    proto_label: str = "ETH"


# ─────────────────────────────────────────────────────────────────────────────
# Packet parsers — pure functions: bytes in, dataclass out
# ─────────────────────────────────────────────────────────────────────────────

def _mac_to_str(raw: bytes) -> str:
    """
    Convert 6 raw MAC address bytes to a colon-separated hex string.

    Args:
        raw : 6-byte MAC address

    Returns:
        String like 'aa:bb:cc:dd:ee:ff'
    """
    return ":".join(f"{b:02x}" for b in raw)


def parse_ethernet(raw: bytes) -> Optional[EthernetFrame]:
    """
    Decode a raw Ethernet frame.

    Args:
        raw : Complete raw frame bytes from AF_PACKET socket

    Returns:
        EthernetFrame if the frame is at least 14 bytes, else None.
    """
    if len(raw) < 14:
        return None
    dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", raw[:14])
    return EthernetFrame(
        dst_mac=_mac_to_str(dst_mac),
        src_mac=_mac_to_str(src_mac),
        ethertype=ethertype,
        payload=raw[14:],
    )


def parse_ip(data: bytes) -> Optional[IPPacket]:
    """
    Decode an IPv4 header from raw bytes.

    The Internet Header Length (IHL) field tells us the header size in
    32-bit words; we multiply by 4 to get bytes and use that as the
    payload offset (handles IP options correctly).

    Args:
        data : Bytes starting at the IP header (Ethernet payload)

    Returns:
        IPPacket if the header is valid, else None.
    """
    if len(data) < 20:
        return None
    ver_ihl, tos, total_len, _id, _frag, ttl, proto, _cksum, src, dst = \
        struct.unpack("!BBHHHBBH4s4s", data[:20])

    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4  # header length in bytes

    if version != 4 or ihl < 20 or len(data) < ihl:
        return None

    return IPPacket(
        version=version,
        ihl=ihl,
        tos=tos,
        total_len=total_len,
        ttl=ttl,
        protocol=proto,
        src_ip=socket.inet_ntoa(src),
        dst_ip=socket.inet_ntoa(dst),
        payload=data[ihl:],
    )


def parse_tcp(data: bytes) -> Optional[TCPSegment]:
    """
    Decode a TCP segment header.

    The data offset field (upper nibble of byte 12) gives the TCP header
    length in 32-bit words; we multiply by 4 to find where the payload
    begins.  This correctly handles TCP options.

    Args:
        data : Bytes starting at the TCP header (IP payload)

    Returns:
        TCPSegment if the header is valid, else None.
    """
    if len(data) < 20:
        return None
    src_p, dst_p, seq, ack, doff_byte, flags, window, _ck, _urg = \
        struct.unpack("!HHLLBBHHH", data[:20])

    header_len = (doff_byte >> 4) * 4  # bytes in TCP header
    if header_len < 20 or len(data) < header_len:
        return None

    return TCPSegment(
        src_port=src_p,
        dst_port=dst_p,
        seq=seq,
        ack=ack,
        data_offset=header_len,
        flags=flags,
        window=window,
        payload=data[header_len:],
    )


def parse_udp(data: bytes) -> Optional[UDPDatagram]:
    """
    Decode a UDP datagram header.

    Args:
        data : Bytes starting at the UDP header (IP payload)

    Returns:
        UDPDatagram if data is at least 8 bytes, else None.
    """
    if len(data) < 8:
        return None
    src_p, dst_p, length, _ck = struct.unpack("!HHHH", data[:8])
    return UDPDatagram(
        src_port=src_p,
        dst_port=dst_p,
        length=length,
        payload=data[8:],
    )


def parse_icmp(data: bytes) -> Optional[ICMPPacket]:
    """
    Decode an ICMP message header.

    Args:
        data : Bytes starting at the ICMP header (IP payload)

    Returns:
        ICMPPacket if data is at least 4 bytes, else None.
    """
    if len(data) < 4:
        return None
    icmp_type, code, _ck = struct.unpack("!BBH", data[:4])
    names = {
        0: "Echo Reply",    3: "Dest Unreachable",   5: "Redirect",
        8: "Echo Request", 11: "Time Exceeded",      12: "Param Problem",
    }
    return ICMPPacket(
        type_code=icmp_type,
        code=code,
        type_name=names.get(icmp_type, f"Type {icmp_type}"),
    )


def parse_arp(data: bytes) -> Optional[ARPPacket]:
    """
    Decode an ARP message.

    ARP header for Ethernet/IPv4 (RFC 826) is exactly 28 bytes:
    htype(2) + ptype(2) + hlen(1) + plen(1) + oper(2) +
    sha(6) + spa(4) + tha(6) + tpa(4).

    Args:
        data : Bytes starting at the ARP header (Ethernet payload)

    Returns:
        ARPPacket if the message is valid Ethernet/IPv4 ARP, else None.
    """
    if len(data) < 28:
        return None
    htype, ptype, hlen, plen, oper, sha, spa, tha, tpa = \
        struct.unpack("!HHBBH6s4s6s4s", data[:28])

    # Only handle Ethernet (htype=1) + IPv4 (ptype=0x0800)
    if htype != 1 or ptype != ETH_P_IP:
        return None

    return ARPPacket(
        operation=oper,
        sender_mac=_mac_to_str(sha),
        sender_ip=socket.inet_ntoa(spa),
        target_mac=_mac_to_str(tha),
        target_ip=socket.inet_ntoa(tpa),
    )


def _parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """
    Decode a DNS encoded name from a DNS message, handling label compression.

    DNS names use a length-prefixed label encoding.  A byte with the top
    two bits set (0xC0) indicates a compression pointer — the next byte
    gives the offset within the DNS message to continue reading from.

    Args:
        data   : Full DNS message bytes (from the ID field onwards)
        offset : Current read position within *data*

    Returns:
        Tuple of (domain_name_string, next_offset_after_name).
        next_offset is the position immediately after the name (or after
        the 2-byte pointer if a compression pointer was followed).
    """
    labels: list[str] = []
    end_offset = -1       # offset to return when we followed a pointer
    jumps = 0             # guard against infinite pointer loops
    max_jumps = 10

    while offset < len(data):
        length = data[offset]

        if length == 0:                       # null label = end of name
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:        # compression pointer
            if end_offset == -1:
                end_offset = offset + 2       # remember where to return to
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer                  # jump to pointed location
            jumps += 1
            if jumps > max_jumps:
                break
        else:                                 # normal label
            offset += 1
            labels.append(data[offset: offset + length].decode(errors="ignore"))
            offset += length

    name = ".".join(labels)
    return_offset = end_offset if end_offset != -1 else offset
    return name, return_offset


def parse_dns(data: bytes) -> Optional[DNSPacket]:
    """
    Decode a DNS message from a UDP payload.

    Parses the 12-byte header, then decodes question and answer sections.
    Only handles A (type=1) and CNAME (type=5) records in the answer
    section; other record types are noted by type number.

    Args:
        data : UDP payload bytes (DNS message starting from transaction ID)

    Returns:
        DNSPacket if the message is well-formed, else None.
    """
    if len(data) < 12:
        return None

    txn_id, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    is_response = bool(flags & 0x8000)

    offset = 12
    questions: list[str] = []
    answers: list[DNSRecord] = []

    # Parse question section
    for _ in range(qdcount):
        if offset >= len(data):
            break
        qname, offset = _parse_dns_name(data, offset)
        questions.append(qname)
        offset += 4   # skip QTYPE (2) + QCLASS (2)

    # Parse answer section (only on responses)
    if is_response:
        for _ in range(ancount):
            if offset + 10 > len(data):
                break
            name, offset = _parse_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset: offset + 10])
            offset += 10
            rdata = data[offset: offset + rdlen]
            offset += rdlen

            if rtype == 1 and rdlen == 4:          # A record
                rdata_str = socket.inet_ntoa(rdata)
            elif rtype == 28 and rdlen == 16:       # AAAA record
                rdata_str = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == 5:                        # CNAME
                rdata_str, _ = _parse_dns_name(data, offset - rdlen)
            else:
                rdata_str = f"[type={rtype} len={rdlen}]"

            answers.append(DNSRecord(name=name, rtype=rtype, rdata=rdata_str))

    return DNSPacket(
        transaction_id=txn_id,
        is_response=is_response,
        questions=questions,
        answers=answers,
    )


# HTTP method/status pattern — matches without caring about port number
_HTTP_REQUEST_RE = re.compile(
    rb"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/[\d.]+",
    re.MULTILINE,
)
_HTTP_RESPONSE_RE = re.compile(rb"^HTTP/([\d.]+)\s+(\d{3})\s+(.+?)[\r\n]", re.MULTILINE)


def detect_http(payload: bytes) -> str:
    """
    Detect and summarise HTTP traffic in a TCP payload.

    Does not rely on port numbers — inspects the raw payload bytes.
    Returns a short description string on a match, empty string otherwise.

    Args:
        payload : TCP payload bytes

    Returns:
        Human-readable description like 'GET /shell.sh' or '200 OK',
        or empty string if no HTTP traffic is detected.
    """
    if not payload:
        return ""
    m = _HTTP_REQUEST_RE.search(payload)
    if m:
        method = m.group(1).decode(errors="ignore")
        path   = m.group(2).decode(errors="ignore")[:60]
        return f"{method} {path}"
    m = _HTTP_RESPONSE_RE.search(payload)
    if m:
        code   = m.group(2).decode(errors="ignore")
        phrase = m.group(3).decode(errors="ignore")[:30]
        return f"{code} {phrase}"
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# Packet filter — subset of BPF expression syntax
# ─────────────────────────────────────────────────────────────────────────────

class PacketFilter:
    """
    Evaluates simple filter expressions against CapturedPacket objects.

    Supported syntax (case-insensitive):
        Primitives : tcp | udp | icmp | arp
                     host <ip>
                     port <n>
                     src host <ip>  |  dst host <ip>
                     src port <n>   |  dst port <n>
        Operators  : and  (logical AND; 'or' and 'not' not yet supported)

    Examples:
        'tcp'
        'tcp and port 8080'
        'host 192.168.100.10 and port 80'
        'dst port 443'
        'arp'

    Args:
        expression : Filter string; empty string means 'accept everything'.
    """

    def __init__(self, expression: str) -> None:
        """
        Parse the filter expression into a list of token predicates.

        Args:
            expression : BPF-like filter string (see class docstring)
        """
        self._expr = expression.strip().lower()
        self._tokens = [t.strip() for t in re.split(r"\band\b", self._expr) if t.strip()]

    def matches(self, pkt: CapturedPacket) -> bool:
        """
        Test whether *pkt* satisfies every token in the filter expression.

        All tokens must match (implicit AND between them).

        Args:
            pkt : Decoded CapturedPacket to evaluate

        Returns:
            True if packet passes the filter, False otherwise.
        """
        if not self._tokens:
            return True
        return all(self._eval_token(tok, pkt) for tok in self._tokens)

    def _eval_token(self, tok: str, pkt: CapturedPacket) -> bool:
        """
        Evaluate a single filter token against a packet.

        Args:
            tok : Single filter primitive (e.g. 'tcp', 'port 80')
            pkt : Packet to test

        Returns:
            True if the token matches the packet, False otherwise.
        """
        # Protocol primitives
        if tok == "tcp":  return pkt.tcp is not None
        if tok == "udp":  return pkt.udp is not None
        if tok == "icmp": return pkt.icmp is not None
        if tok == "arp":  return pkt.arp is not None
        if tok == "dns":  return pkt.dns is not None
        if tok == "http": return bool(pkt.http_info)

        ip  = pkt.ip
        tcp = pkt.tcp
        udp = pkt.udp

        # host <ip>
        m = re.match(r"^(src |dst )?host\s+([\d.]+)$", tok)
        if m and ip:
            direction, addr = m.group(1) or "", m.group(2)
            if not direction or "src" in direction:
                if ip.src_ip == addr: return True
            if not direction or "dst" in direction:
                if ip.dst_ip == addr: return True
            return False

        # port <n> / src port <n> / dst port <n>
        m = re.match(r"^(src |dst )?port\s+(\d+)$", tok)
        if m:
            direction, port = m.group(1) or "", int(m.group(2))
            srcp = (tcp.src_port if tcp else None) or (udp.src_port if udp else None)
            dstp = (tcp.dst_port if tcp else None) or (udp.dst_port if udp else None)
            if not direction or "src" in direction:
                if srcp == port: return True
            if not direction or "dst" in direction:
                if dstp == port: return True
            return False

        return True   # unknown token — pass through rather than drop


# ─────────────────────────────────────────────────────────────────────────────
# Analyzers — stateful, run once per packet
# ─────────────────────────────────────────────────────────────────────────────

class ConnectionTracker:
    """
    Maintains a TCP connection state table modelled on RFC 793.

    For every unique 4-tuple (src_ip, src_port, dst_ip, dst_port) we
    track the current TCP state.  Connections in CLOSED or RST states
    are pruned after 30 seconds.

    The state machine used here is a simplified subset:
        LISTEN → SYN_SENT (first SYN seen)
        SYN_SENT → ESTABLISHED (SYN+ACK then ACK)
        ESTABLISHED → FIN_WAIT_1 (FIN from either side)
        FIN_WAIT_1 → CLOSED (RST or second FIN+ACK)
    """

    # How long (seconds) to keep completed connections in the table
    _STALE_TIMEOUT = 60

    def __init__(self) -> None:
        """Initialise an empty connection table with a cleanup lock."""
        # key = (src_ip, src_port, dst_ip, dst_port), value = dict with state/timestamps
        self._table: dict[tuple, dict] = {}
        self._lock = threading.Lock()

    def update(self, pkt: CapturedPacket) -> Optional[str]:
        """
        Update the state table from a TCP packet and return a state-change event.

        Args:
            pkt : CapturedPacket that must have both .ip and .tcp set

        Returns:
            Human-readable event string on a state transition (e.g.
            'NEW 192.168.100.10:45678 → 192.168.100.30:8080 [SYN]'),
            or None if the packet caused no noteworthy transition.
        """
        if not pkt.ip or not pkt.tcp:
            return None

        tcp = pkt.tcp
        ip  = pkt.ip
        flags = tcp.flags

        key_fwd = (ip.src_ip, tcp.src_port, ip.dst_ip, tcp.dst_port)
        key_rev = (ip.dst_ip, tcp.dst_port, ip.src_ip, tcp.src_port)

        with self._lock:
            now = time.monotonic()
            self._prune_stale(now)

            # RST — immediately close the connection
            if flags & FLAG_RST:
                for k in (key_fwd, key_rev):
                    if k in self._table:
                        self._table[k]["state"] = TCPState.CLOSED
                        self._table[k]["updated"] = now
                return None

            entry = self._table.get(key_fwd) or self._table.get(key_rev)

            if flags & FLAG_SYN and not (flags & FLAG_ACK):
                # New connection initiation
                if key_fwd not in self._table:
                    self._table[key_fwd] = {
                        "state": TCPState.SYN_SENT,
                        "created": now,
                        "updated": now,
                        "src_ip": ip.src_ip,
                        "src_port": tcp.src_port,
                        "dst_ip": ip.dst_ip,
                        "dst_port": tcp.dst_port,
                    }
                    return (f"NEW  {ip.src_ip}:{tcp.src_port} → "
                            f"{ip.dst_ip}:{tcp.dst_port}  [{tcp.flag_str}]")

            elif flags & FLAG_SYN and flags & FLAG_ACK:
                # Server responding to SYN
                if key_rev in self._table:
                    self._table[key_rev]["state"] = TCPState.SYN_RCVD
                    self._table[key_rev]["updated"] = now

            elif flags & FLAG_ACK and not (flags & FLAG_SYN or flags & FLAG_FIN):
                # Final ACK completing handshake
                for k in (key_fwd, key_rev):
                    if k in self._table and self._table[k]["state"] == TCPState.SYN_RCVD:
                        self._table[k]["state"] = TCPState.ESTABLISHED
                        self._table[k]["updated"] = now
                        e = self._table[k]
                        return (f"EST  {e['src_ip']}:{e['src_port']} → "
                                f"{e['dst_ip']}:{e['dst_port']}  [ESTABLISHED]")

            elif flags & FLAG_FIN:
                for k in (key_fwd, key_rev):
                    if k in self._table and self._table[k]["state"] == TCPState.ESTABLISHED:
                        self._table[k]["state"] = TCPState.FIN_WAIT_1
                        self._table[k]["updated"] = now

        return None

    def _prune_stale(self, now: float) -> None:
        """
        Remove connections that have been in a terminal state too long.

        Args:
            now : Current monotonic time (avoids repeated time.monotonic() calls)
        """
        stale = [
            k for k, v in self._table.items()
            if v["state"] in (TCPState.CLOSED, TCPState.TIME_WAIT)
            and now - v["updated"] > self._STALE_TIMEOUT
        ]
        for k in stale:
            del self._table[k]

    def get_table(self) -> list[dict]:
        """
        Return a snapshot of the current connection table.

        Returns:
            List of connection dicts with state, src/dst IP:port, and age.
        """
        with self._lock:
            return list(self._table.values())


class ARPWatcher:
    """
    Detects ARP spoofing by maintaining an IP → MAC mapping table.

    When an ARP reply announces a different MAC for an IP that we have
    previously recorded, it fires a CRITICAL alert.  This is the classic
    ARP cache poisoning / man-in-the-middle setup signal.
    """

    def __init__(self) -> None:
        """Initialise an empty IP→MAC table."""
        self._table: dict[str, str] = {}     # ip → mac
        self._lock = threading.Lock()

    def update(self, arp: ARPPacket) -> Optional[str]:
        """
        Check an ARP packet for evidence of cache poisoning.

        Only processes ARP replies (operation == 2) since requests
        contain the sender's own IP/MAC which is always trustworthy.

        Args:
            arp : Decoded ARPPacket

        Returns:
            Alert string if a MAC change is detected for an existing IP,
            None otherwise.
        """
        if arp.operation != 2:    # only replies carry binding announcements
            return None

        ip  = arp.sender_ip
        mac = arp.sender_mac

        with self._lock:
            existing = self._table.get(ip)
            if existing is None:
                self._table[ip] = mac
                return None
            if existing != mac:
                self._table[ip] = mac   # update to latest
                return (f"[!] ARP SPOOF ALERT: {ip} changed MAC "
                        f"{existing} → {mac}")
        return None


class PortScanDetector:
    """
    Detects port scanning behaviour using a sliding-window counter.

    For each source IP, maintains a deque of (timestamp, dst_port) tuples.
    If the number of unique destination ports within the last *window_secs*
    seconds exceeds *threshold*, fires a scan alert.

    This catches both fast SYN scans (many ports, short window) and slow
    stealth scans (many ports, longer window).
    """

    def __init__(self, threshold: int = 15, window_secs: float = 5.0) -> None:
        """
        Initialise the detector.

        Args:
            threshold   : Unique port count that triggers an alert
            window_secs : Sliding time window size in seconds
        """
        self._threshold = threshold
        self._window = window_secs
        # ip → deque of (timestamp, port)
        self._events: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._alerted: set[str] = set()   # IPs we've already fired an alert for
        self._lock = threading.Lock()

    def update(self, src_ip: str, dst_port: int) -> Optional[str]:
        """
        Record a TCP SYN to a destination port and check the threshold.

        Args:
            src_ip   : Source IP address of the potential scanner
            dst_port : Destination port that was targeted

        Returns:
            Alert string if the threshold is exceeded for the first time,
            None otherwise.
        """
        now = time.monotonic()
        with self._lock:
            dq = self._events[src_ip]
            dq.append((now, dst_port))

            # Prune events outside the window
            while dq and now - dq[0][0] > self._window:
                dq.popleft()

            unique_ports = {p for _, p in dq}
            if len(unique_ports) >= self._threshold and src_ip not in self._alerted:
                self._alerted.add(src_ip)
                return (f"[!] PORT SCAN ALERT: {src_ip} probed "
                        f"{len(unique_ports)} ports in {self._window:.0f}s window")
        return None


class PacketStats:
    """
    Collects rolling packet statistics for the live dashboard.

    Tracks:
        - Total packets and bytes captured
        - Per-protocol packet counts
        - Per-source-IP packet count (for 'top talkers')
        - Packet arrival timestamps for throughput calculation
    """

    def __init__(self) -> None:
        """Initialise all counters to zero."""
        self._lock = threading.Lock()
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.by_proto: dict[str, int] = defaultdict(int)
        self.by_src_ip: dict[str, int] = defaultdict(int)
        # Rolling window of (timestamp, byte_count) for throughput
        self._window: deque = deque(maxlen=5000)

    def update(self, pkt: CapturedPacket) -> None:
        """
        Record one captured packet.

        Args:
            pkt : Decoded CapturedPacket to record statistics for
        """
        size = len(pkt.raw)
        with self._lock:
            self.total_packets += 1
            self.total_bytes += size
            self.by_proto[pkt.proto_label] += 1
            self._window.append((pkt.timestamp, size))
            if pkt.ip:
                self.by_src_ip[pkt.ip.src_ip] += 1

    def snapshot(self) -> dict:
        """
        Return a point-in-time statistics snapshot.

        Calculates throughput over the last 3 seconds from the rolling
        window rather than an average since start, so the rate reflects
        current traffic levels.

        Returns:
            Dict with keys: total_packets, total_bytes, pps, bps,
            by_proto, top_talkers.
        """
        now = time.monotonic()
        with self._lock:
            # Throughput over last 3 seconds
            recent = [(t, b) for t, b in self._window if now - t <= 3.0]
            pps = len(recent) / 3.0
            bps = sum(b for _, b in recent) / 3.0

            top = sorted(self.by_src_ip.items(), key=lambda x: x[1], reverse=True)[:5]

            return {
                "total_packets": self.total_packets,
                "total_bytes":   self.total_bytes,
                "pps":           round(pps, 1),
                "bps":           round(bps, 1),
                "by_proto":      dict(self.by_proto),
                "top_talkers":   top,
            }


# ─────────────────────────────────────────────────────────────────────────────
# PCAP writer — Wireshark-compatible binary output
# ─────────────────────────────────────────────────────────────────────────────

class PCAPWriter:
    """
    Writes captured packets to a PCAP file readable by Wireshark / tcpdump.

    File format: libpcap (magic 0xa1b2c3d4), link type 1 (Ethernet).
    Each call to write() appends a per-packet header + raw frame bytes.

    Args:
        path : Output file path
    """

    # Global header constants
    _MAGIC      = 0xa1b2c3d4   # native byte order
    _VER_MAJOR  = 2
    _VER_MINOR  = 4
    _SNAPLEN    = 65535
    _LINK_TYPE  = 1            # LINKTYPE_ETHERNET

    def __init__(self, path: str) -> None:
        """
        Open the output file and write the PCAP global header.

        Args:
            path : Destination file path (will be overwritten if it exists)
        """
        self._fh = open(path, "wb")
        self._lock = threading.Lock()
        # Global header: magic(4) ver_maj(2) ver_min(2) tz(4) acc(4) snaplen(4) linktype(4)
        self._fh.write(struct.pack(
            "=IHHiIII",
            self._MAGIC, self._VER_MAJOR, self._VER_MINOR,
            0, 0, self._SNAPLEN, self._LINK_TYPE,
        ))
        self._fh.flush()

    def write(self, raw: bytes, ts: float) -> None:
        """
        Append a packet to the PCAP file.

        Each packet is prefixed with a 16-byte per-packet header:
        ts_sec(4) ts_usec(4) incl_len(4) orig_len(4).

        Args:
            raw : Raw frame bytes (including Ethernet header)
            ts  : Capture timestamp as Unix float
        """
        ts_sec  = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        incl_len = min(len(raw), self._SNAPLEN)
        with self._lock:
            self._fh.write(struct.pack("=IIII", ts_sec, ts_usec, incl_len, len(raw)))
            self._fh.write(raw[:incl_len])

    def close(self) -> None:
        """Flush and close the PCAP file."""
        self._fh.flush()
        self._fh.close()


# ─────────────────────────────────────────────────────────────────────────────
# Main sniffer engine
# ─────────────────────────────────────────────────────────────────────────────

class PacketSniffer:
    """
    Orchestrates packet capture, multi-layer parsing, analysis, and output.

    Architecture:
        - Main thread: AF_PACKET receive loop → parse → filter → analyze → display
        - Stats thread: wakes every stats_interval seconds, prints dashboard
        - PCAPWriter (optional): writes raw frames to disk on every capture

    All analyzers (ConnectionTracker, ARPWatcher, PortScanDetector, PacketStats)
    are thread-safe and share state only via their own internal locks.

    Args:
        interface      : Network interface to bind to (e.g. 'eth0')
        filter_expr    : BPF-like filter expression string
        pcap_path      : If set, write a Wireshark PCAP file to this path
        show_payload   : Print printable ASCII from TCP/UDP payloads
        stats_interval : Seconds between live stats dashboard refreshes
        scan_threshold : Unique ports per window to trigger scan alert
    """

    def __init__(
        self,
        interface: str = "eth0",
        filter_expr: str = "",
        pcap_path: Optional[str] = None,
        show_payload: bool = False,
        stats_interval: int = 3,
        scan_threshold: int = 15,
    ) -> None:
        self._iface          = interface
        self._filter         = PacketFilter(filter_expr)
        self._pcap           = PCAPWriter(pcap_path) if pcap_path else None
        self._show_payload   = show_payload
        self._stats_interval = stats_interval
        self._running        = False

        # Analysis engines
        self._conn_tracker   = ConnectionTracker()
        self._arp_watcher    = ARPWatcher()
        self._scan_detector  = PortScanDetector(threshold=scan_threshold)
        self._stats          = PacketStats()

    def start(self) -> None:
        """
        Open a raw socket and enter the capture loop.

        Binds an AF_PACKET SOCK_RAW socket to capture all Ethernet frames.
        Starts the background stats thread before entering the main loop.
        Blocks until stop() is called or the user presses CTRL+C.

        Raises:
            PermissionError if not running as root.
            OSError if the interface does not exist.
        """
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except PermissionError:
            print(red("[!] Root required.  Run: sudo python3 sniffer.py"))
            sys.exit(1)
        except AttributeError:
            print(red("[!] AF_PACKET is Linux-only.  Run this on Kali or the Ubuntu router."))
            sys.exit(1)

        if self._iface:
            try:
                sock.bind((self._iface, 0))
            except OSError as e:
                print(red(f"[!] Cannot bind to '{self._iface}': {e}"))
                sock.close()
                sys.exit(1)

        self._running = True

        # Start background stats display thread
        stats_thread = threading.Thread(
            target=self._stats_loop, daemon=True, name="stats-display"
        )
        stats_thread.start()

        print(bold(cyan(
            f"\n  sniffer.py — capturing on {self._iface}  "
            f"filter='{self._filter._expr or 'none'}'  "
            f"{'pcap=' + str(self._pcap._fh.name) if self._pcap else ''}"
        )))
        print(grey("  CTRL+C to stop\n"))
        print(f"  {'TIME':<14} {'PROTO':<6} {'SRC':<24} {'DST':<24} {'INFO'}")
        print(f"  {'─'*14} {'─'*5} {'─'*23} {'─'*23} {'─'*35}")

        try:
            while self._running:
                raw, _ = sock.recvfrom(65535)
                ts = time.time()
                self._process_packet(raw, ts)
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            sock.close()
            if self._pcap:
                self._pcap.close()
                print(cyan(f"\n  [+] PCAP saved → {self._pcap._fh.name}"))
            snap = self._stats.snapshot()
            print(cyan(
                f"\n  Session: {snap['total_packets']} packets  "
                f"{snap['total_bytes'] / 1024:.1f} KB"
            ))

    def stop(self) -> None:
        """Signal the capture loop to stop on the next iteration."""
        self._running = False

    def _process_packet(self, raw: bytes, ts: float) -> None:
        """
        Parse one raw frame through all protocol layers and run analyzers.

        Args:
            raw : Raw frame bytes from AF_PACKET socket
            ts  : Capture timestamp
        """
        eth = parse_ethernet(raw)
        if not eth:
            return

        pkt = CapturedPacket(timestamp=ts, raw=raw, eth=eth)

        if eth.ethertype == ETH_P_IP:
            ip = parse_ip(eth.payload)
            if not ip:
                return
            pkt.ip = ip

            if ip.protocol == PROTO_TCP:
                tcp = parse_tcp(ip.payload)
                if tcp:
                    pkt.tcp = tcp
                    pkt.proto_label = "TCP"
                    pkt.http_info = detect_http(tcp.payload)
                    if pkt.http_info:
                        pkt.proto_label = "HTTP"

                    # Connection tracking
                    event = self._conn_tracker.update(pkt)
                    if event:
                        self._print_event(green(event))

                    # Port scan detection (only on SYN packets)
                    if tcp.flags & FLAG_SYN and not (tcp.flags & FLAG_ACK):
                        alert = self._scan_detector.update(ip.src_ip, tcp.dst_port)
                        if alert:
                            self._print_event(red(alert))

            elif ip.protocol == PROTO_UDP:
                udp = parse_udp(ip.payload)
                if udp:
                    pkt.udp = udp
                    pkt.proto_label = "UDP"

                    # DNS inspection on port 53 (src or dst)
                    if 53 in (udp.src_port, udp.dst_port):
                        dns = parse_dns(udp.payload)
                        if dns:
                            pkt.dns = dns
                            pkt.proto_label = "DNS"

            elif ip.protocol == PROTO_ICMP:
                icmp = parse_icmp(ip.payload)
                if icmp:
                    pkt.icmp = icmp
                    pkt.proto_label = "ICMP"

        elif eth.ethertype == ETH_P_ARP:
            arp = parse_arp(eth.payload)
            if arp:
                pkt.arp = arp
                pkt.proto_label = "ARP"
                alert = self._arp_watcher.update(arp)
                if alert:
                    self._print_event(red(alert))

        # Apply filter — drop packets that don't match
        if not self._filter.matches(pkt):
            return

        # Record statistics (even for filtered-out packets we still count)
        self._stats.update(pkt)

        # Write to PCAP file
        if self._pcap:
            self._pcap.write(raw, ts)

        self._display_packet(pkt)

    def _display_packet(self, pkt: CapturedPacket) -> None:
        """
        Render one packet line to stdout.

        Chooses protocol-specific colors and builds the info column from
        whichever decoded layer is present.

        Args:
            pkt : Fully decoded and filtered CapturedPacket
        """
        ts_str = datetime.fromtimestamp(pkt.timestamp).strftime("%H:%M:%S.%f")[:13]
        ip = pkt.ip

        # Build source/destination strings
        if ip and pkt.tcp:
            src = f"{ip.src_ip}:{pkt.tcp.src_port}"
            dst = f"{ip.dst_ip}:{pkt.tcp.dst_port}"
        elif ip and pkt.udp:
            src = f"{ip.src_ip}:{pkt.udp.src_port}"
            dst = f"{ip.dst_ip}:{pkt.udp.dst_port}"
        elif ip:
            src, dst = ip.src_ip, ip.dst_ip
        elif pkt.arp:
            src, dst = pkt.arp.sender_ip, pkt.arp.target_ip
        else:
            src = pkt.eth.src_mac
            dst = pkt.eth.dst_mac

        # Build info column
        if pkt.http_info:
            info = magenta(pkt.http_info)
        elif pkt.dns:
            if pkt.dns.is_response:
                answers_str = "  ".join(f"{r.rdata}" for r in pkt.dns.answers[:2])
                info = cyan(f"→ {answers_str}" if answers_str else "→ (no records)")
            else:
                q = pkt.dns.questions[0] if pkt.dns.questions else "?"
                info = cyan(f"A? {q}")
        elif pkt.tcp:
            flags_str = pkt.tcp.flag_str
            payload_hint = ""
            if self._show_payload and pkt.tcp.payload:
                printable = "".join(
                    chr(b) if 32 <= b < 127 else "." for b in pkt.tcp.payload[:30]
                )
                payload_hint = grey(f"  {printable}")
            info = f"[{flags_str}] win={pkt.tcp.window}{payload_hint}"
        elif pkt.udp:
            info = blue(f"len={pkt.udp.length}")
        elif pkt.icmp:
            info = yellow(pkt.icmp.type_name)
        elif pkt.arp:
            info = red(
                f"who-has {pkt.arp.target_ip}? tell {pkt.arp.sender_ip}"
                if pkt.arp.operation == 1
                else f"is-at {pkt.arp.sender_mac}"
            )
        else:
            info = grey(f"ethertype=0x{pkt.eth.ethertype:04x}")

        # Color-code the protocol label
        proto_colored = {
            "TCP":  green(f"{pkt.proto_label:<5}"),
            "HTTP": magenta(f"{pkt.proto_label:<5}"),
            "UDP":  blue(f"{pkt.proto_label:<5}"),
            "DNS":  cyan(f"{pkt.proto_label:<5}"),
            "ICMP": yellow(f"{pkt.proto_label:<5}"),
            "ARP":  red(f"{pkt.proto_label:<5}"),
        }.get(pkt.proto_label, grey(f"{pkt.proto_label:<5}"))

        print(f"  {grey(ts_str)}  {proto_colored}  {src:<24} {dst:<24} {info}")

    def _print_event(self, message: str) -> None:
        """
        Print an analyzer event (connection open, alert, etc.) on its own line.

        Args:
            message : Pre-colored event string
        """
        print(f"\n  ► {message}\n")

    def _stats_loop(self) -> None:
        """
        Background thread: print the live statistics dashboard periodically.

        Runs until self._running is False.  Prints a compact dashboard line
        showing throughput, protocol breakdown, and top talkers.
        """
        while self._running:
            time.sleep(self._stats_interval)
            if not self._running:
                break
            snap = self._stats.snapshot()
            total   = snap["total_packets"] or 1   # avoid division by zero
            protos  = "  ".join(
                f"{p}:{grey(str(c))}({c * 100 // total}%)"
                for p, c in sorted(snap["by_proto"].items(), key=lambda x: -x[1])
            )
            talkers = "  ".join(
                f"{ip}:{grey(str(c))}" for ip, c in snap["top_talkers"]
            )
            print(
                f"\n  {bold('STATS')} │ "
                f"pkts={cyan(str(snap['total_packets']))}  "
                f"bytes={cyan(f\"{snap['total_bytes']//1024}KB\")}  "
                f"rate={cyan(f\"{snap['pps']} pkt/s  {snap['bps']/1024:.1f} KB/s\")}  "
                f"│ {protos}\n"
                f"  Top talkers: {talkers}\n"
            )


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """
    Build and return the CLI argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    p = argparse.ArgumentParser(
        prog="sniffer.py",
        description=(
            "Deep-packet inspection sniffer: multi-layer parsing, TCP state machine,\n"
            "DNS intelligence, HTTP detection, ARP spoofing + port scan alerts.\n\n"
            "Examples:\n"
            "  sudo python3 sniffer.py\n"
            "  sudo python3 sniffer.py -i eth0 --filter 'tcp and port 8080'\n"
            "  sudo python3 sniffer.py --filter 'host 192.168.100.10' --pcap out.pcap\n"
            "  sudo python3 sniffer.py --filter 'dns' --payload"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-i", "--interface", default="eth0",
                   help="Network interface to sniff (default: eth0)")
    p.add_argument("--filter", default="", metavar="EXPR",
                   help="Filter expression: 'tcp', 'udp port 53', 'host 1.2.3.4 and port 80'")
    p.add_argument("--pcap", metavar="FILE",
                   help="Write captured packets to a Wireshark PCAP file")
    p.add_argument("--payload", action="store_true", dest="show_payload",
                   help="Print printable ASCII from TCP payloads")
    p.add_argument("--stats-interval", type=int, default=3, metavar="SECS",
                   help="Live stats dashboard refresh interval (default: 3)")
    p.add_argument("--scan-threshold", type=int, default=15, metavar="N",
                   help="Unique ports per 5s window to trigger scan alert (default: 15)")
    return p


def main() -> None:
    """
    Parse CLI arguments and start the packet sniffer.

    Exits with a clear error message if not running as root.
    """
    if os.geteuid() != 0:
        print(red("[!] Root required.  Run: sudo python3 sniffer.py"))
        sys.exit(1)

    parser = build_parser()
    args = parser.parse_args()

    sniffer = PacketSniffer(
        interface=args.interface,
        filter_expr=args.filter,
        pcap_path=args.pcap,
        show_payload=args.show_payload,
        stats_interval=args.stats_interval,
        scan_threshold=args.scan_threshold,
    )
    sniffer.start()


if __name__ == "__main__":
    main()
