#!/usr/bin/env python3
"""Cross-platform ISP / NAT TCP idle-timeout diagnostic tool (Linux, Windows, macOS).

Diagnoses silent NAT / CGNAT TCP session eviction (violation of RFC 5382 REQ-5, which
requires established TCP mappings to survive at least 2 hours 4 minutes of inactivity).

Method rules:
  1. Pin AF_INET (IPv4): IPv6 is routed rather than NAT-translated, so a dual-stack probe
     that resolves over IPv6 will measure the healthy path and miss the IPv4 NAT fault.
  2. Disable OS TCP keepalive on probe sockets so the host OS does not mask the fault.
  3. Test against an endpoint that holds idle connections (RFC 3501 requires IMAP servers
     to tolerate >= 30 minutes of inactivity) using an unauthenticated NOOP after greeting.
  4. Classify how each connection behaves after idling:
       - ECHO:   reply received after the idle window -> mapping survived.
       - SILENT: post-idle probe went unanswered with no RST and no FIN -> NAT mapping evicted.
       - RST:    connection actively reset by a middlebox or peer.
       - SERVER: far end sent FIN during the idle window -> server policy, discarded.
  5. Run a concurrent control connection poked every 20s AND open a fresh connection at
     the end to prove the line and server were healthy throughout the test window.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import platform
import re
import select
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from typing import Dict, List, Optional, Tuple

DEFAULT_HOST = "imap.gmx.com"
DEFAULT_PORT = 143
DEFAULT_IDLES = [30, 45, 60, 75, 90, 120]
QUICK_IDLE = 90
DEFAULT_POKE_TIMEOUT = 40
CONTROL_INTERVAL = 20
RFC_5382_MIN_SECONDS = 7440  # 2 hours 4 minutes

CANDIDATE_ENDPOINTS: List[Tuple[str, int]] = [
    ("imap.gmx.com", 143),
    ("imap.web.de", 143),
    ("smtp.gmx.com", 25),
]

CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


def now_str() -> str:
    return time.strftime("%H:%M:%S")


def get_local_ip(family: int, target: str) -> Optional[str]:
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect((target, 80))
            return s.getsockname()[0]
    except OSError:
        return None


def fetch_public_ipv4() -> Optional[str]:
    urls = [
        "https://api4.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://v4.ident.me",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "nat-idle-diag/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                text = resp.read().decode("utf-8", errors="replace").strip()
                ipaddress.IPv4Address(text)
                return text
        except Exception:
            continue
    return None


def analyze_wan_ip(wan_ip_str: Optional[str], public_ipv4: Optional[str]) -> Dict[str, str]:
    info: Dict[str, str] = {}
    if not wan_ip_str:
        return info
    try:
        wan_ip = ipaddress.IPv4Address(wan_ip_str.strip())
    except ValueError:
        info["status"] = "INVALID"
        info["detail"] = f"'{wan_ip_str}' is not a valid IPv4 address."
        return info

    info["wan_ip"] = str(wan_ip)
    if wan_ip in CGNAT_NET:
        info["status"] = "CGNAT_RFC6598"
        info["detail"] = (
            f"Router WAN IP ({wan_ip}) is inside 100.64.0.0/10 (RFC 6598 Carrier-Grade NAT). "
            f"Your ISP is applying CGNAT upstream of your router."
        )
    elif wan_ip.is_private:
        info["status"] = "DOUBLE_NAT_RFC1918"
        info["detail"] = (
            f"Router WAN IP ({wan_ip}) is in RFC 1918 private space. "
            f"There is another NAT layer upstream of this router (double NAT or ISP private WAN)."
        )
    elif public_ipv4 and str(wan_ip) != public_ipv4:
        info["status"] = "NAT_MISMATCH"
        info["detail"] = (
            f"Router WAN IP ({wan_ip}) differs from external public IP ({public_ipv4}). "
            f"Your traffic crosses an upstream carrier NAT."
        )
    elif public_ipv4 and str(wan_ip) == public_ipv4:
        info["status"] = "PUBLIC_MATCH"
        info["detail"] = (
            f"Router WAN IP ({wan_ip}) matches external public IP ({public_ipv4}). "
            f"No CGNAT detected on the line; only your local router performs NAT."
        )
    else:
        info["status"] = "PUBLIC_UNVERIFIED"
        info["detail"] = f"Router WAN IP ({wan_ip}) is a public address outside 100.64.0.0/10."
    return info


def read_os_tcp_counters() -> Dict[str, int]:
    system = platform.system()
    counters: Dict[str, int] = {}

    if system == "Linux":
        for path in ("/proc/net/netstat", "/proc/net/snmp"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lines = [line.strip().split() for line in f if line.strip()]
                for i in range(0, len(lines) - 1, 2):
                    if lines[i][0] == lines[i + 1][0] and len(lines[i]) == len(lines[i + 1]):
                        prefix = lines[i][0].rstrip(":")
                        for k, v in zip(lines[i][1:], lines[i + 1][1:]):
                            if k in ("TCPTimeouts", "TCPAbortOnTimeout", "TCPSynRetrans", "RetransSegs"):
                                try:
                                    counters[f"{prefix}.{k}"] = int(v)
                                except ValueError:
                                    pass
            except OSError:
                pass
    elif system == "Windows":
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "$s = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()"
                    ".GetTcpIPv4Statistics(); "
                    "Write-Output \"RetransSegs=$($s.SegmentsRetransmitted)\"; "
                    "Write-Output \"ResetConns=$($s.ResetConnections)\"; "
                    "Write-Output \"ErrorsRcvd=$($s.ErrorsReceived)\""
                ),
            ]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=8)
            for line in out.splitlines():
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    counters[f"Tcp4.{k}"] = int(v)
        except Exception:
            pass
    return counters


def print_counter_snapshot(label: str, counters: Dict[str, int], before: Optional[Dict[str, int]] = None) -> None:
    if not counters:
        print(f"{label}: (not available on {platform.system()})")
        return
    print(f"{label}:")
    for k, v in counters.items():
        if before is not None and k in before:
            delta = v - before[k]
            sign = f"+{delta}" if delta > 0 else str(delta)
            print(f"  {k:<28} {v:<10} (delta: {sign})")
        else:
            print(f"  {k:<28} {v}")


def open_ipv4_probe_socket(host: str, port: int, timeout: float = 20.0) -> Tuple[socket.socket, str]:
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"No IPv4 (A) record found for {host}")
    sockaddr = infos[0][4]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 0)
    except OSError:
        pass
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.connect(sockaddr)
    greeting = s.recv(512)
    if not greeting:
        s.close()
        raise OSError("Connected, but server sent empty greeting (EOF)")
    return s, sockaddr[0]


def drain_or_detect_fin(s: socket.socket) -> bool:
    """Drain any unsolicited server output and return True if the peer closed (FIN/EOF)."""
    while True:
        readable, _, _ = select.select([s], [], [], 0)
        if not readable:
            return False
        try:
            data = s.recv(512)
        except OSError:
            return True
        if not data:
            return True


def run_bracket_probes(
    host: str,
    port: int,
    idles: List[int],
    poke_timeout: int,
) -> Dict[str, str]:
    verdicts: Dict[str, str] = {}
    lock = threading.Lock()

    def record(tag: str, verdict: str, detail: str) -> None:
        with lock:
            verdicts[tag] = verdict
            print(f"  [{now_str()}] {tag:<11} {verdict:<8} {detail}", flush=True)

    def probe_idle(idle_sec: int) -> None:
        tag = f"idle-{idle_sec}s"
        s: Optional[socket.socket] = None
        try:
            s, _ = open_ipv4_probe_socket(host, port)
            time.sleep(idle_sec)
            if drain_or_detect_fin(s):
                record(tag, "SERVER", f"Server sent FIN during {idle_sec}s idle window (discarded)")
                return
            t0 = time.time()
            s.sendall(b"a1 NOOP\r\n")
            s.settimeout(poke_timeout)
            reply = s.recv(512)
            elapsed = time.time() - t0
            if reply:
                record(tag, "ECHO", f"Replied in {elapsed:.1f}s after {idle_sec}s idle")
            else:
                record(tag, "SERVER", f"EOF after poke ({elapsed:.1f}s)")
        except socket.timeout:
            record(
                tag,
                "SILENT",
                f"No reply for {poke_timeout}s after {idle_sec}s idle, no RST/FIN -> mapping evicted",
            )
        except ConnectionResetError:
            record(tag, "RST", f"Connection actively reset (RST) after {idle_sec}s idle")
        except Exception as exc:
            record(tag, "ERROR", f"{type(exc).__name__}: {exc}")
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    def probe_control() -> None:
        s: Optional[socket.socket] = None
        total_window = max(idles) + CONTROL_INTERVAL
        try:
            s, _ = open_ipv4_probe_socket(host, port)
            tick = 0
            end_time = time.time() + total_window
            while time.time() < end_time:
                time.sleep(CONTROL_INTERVAL)
                tick += 1
                s.sendall(f"c{tick} NOOP\r\n".encode("ascii"))
                s.settimeout(30)
                if not s.recv(512):
                    record("control", "SERVER", f"Server closed control connection at tick {tick}")
                    return
            record(
                "control",
                "ECHO",
                f"Survived {total_window}s with traffic every {CONTROL_INTERVAL}s (never idle >{CONTROL_INTERVAL}s)",
            )
        except socket.timeout:
            record("control", "SILENT", f"Died despite traffic every {CONTROL_INTERVAL}s (general line loss)")
        except ConnectionResetError:
            record("control", "RST", "Control connection reset (RST)")
        except Exception as exc:
            record("control", "ERROR", f"{type(exc).__name__}: {exc}")
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    threads = [threading.Thread(target=probe_idle, args=(i,), daemon=True) for i in idles]
    threads.append(threading.Thread(target=probe_control, daemon=True))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Open a brand-new connection immediately after the idle tests complete
    t0 = time.time()
    try:
        s_fresh, _ = open_ipv4_probe_socket(host, port, timeout=15)
        s_fresh.close()
        record("fresh", "ECHO", f"Brand-new connection opened and greeted in {time.time() - t0:.1f}s")
    except Exception as exc:
        record("fresh", "ERROR", f"Fresh connection failed: {type(exc).__name__}: {exc}")

    return verdicts


def print_diagnosis(
    idles: List[int],
    verdicts: Dict[str, str],
    wan_info: Dict[str, str],
    public_ipv4: Optional[str],
    local_ipv6: Optional[str],
) -> int:
    survived = [i for i in idles if verdicts.get(f"idle-{i}s") == "ECHO"]
    evicted = [i for i in idles if verdicts.get(f"idle-{i}s") == "SILENT"]
    reset = [i for i in idles if verdicts.get(f"idle-{i}s") == "RST"]
    server_closed = [i for i in idles if verdicts.get(f"idle-{i}s") == "SERVER"]
    ctrl = verdicts.get("control", "?")
    fresh = verdicts.get("fresh", "?")

    print("\n" + "=" * 76)
    print("DIAGNOSIS SUMMARY")
    print("=" * 76)
    print(f"  Survived (ECHO):        {survived if survived else 'none'}")
    print(f"  Silent Drop (SILENT):   {evicted if evicted else 'none'}")
    if reset:
        print(f"  Active Reset (RST):     {reset}")
    if server_closed:
        print(f"  Server FIN (discarded): {server_closed}")
    print(f"  Active Control (20s):   {ctrl}")
    print(f"  Fresh Connection Now:   {fresh}")
    print("-" * 76)

    if wan_info:
        print(f"  Addressing Check:       {wan_info['detail']}")
        print("-" * 76)

    if evicted and ctrl == "ECHO" and fresh == "ECHO":
        min_ev = min(evicted)
        max_ok = max([i for i in survived if i < min_ev], default=None)
        if max_ok is not None:
            threshold_desc = f"between {max_ok}s and {min_ev}s"
            approx_factor = RFC_5382_MIN_SECONDS // min_ev
        else:
            threshold_desc = f"at or below {min_ev}s"
            approx_factor = RFC_5382_MIN_SECONDS // max(min_ev, 1)

        print("VERDICT: [FAULT CONFIRMED] SILENT NAT TCP IDLE EVICTION DETECTED")
        print()
        print(f"  1. Measured Idle Threshold: {threshold_desc} of inactivity.")
        print(
            f"     RFC 5382 REQ-5 requires NAT timers for established TCP sessions to be at least\n"
            f"     2 hours 4 minutes ({RFC_5382_MIN_SECONDS}s). Your path drops mappings ~{approx_factor}x below the standard."
        )
        print()
        print(
            "  2. Why This Is Definitely Idle Eviction (and Not Line Loss or Server Downtime):\n"
            f"     - The control connection to the same server survived by sending traffic every {CONTROL_INTERVAL}s.\n"
            "     - A brand-new connection opened immediately afterwards succeeded right away.\n"
            "     - The idle connection received no FIN and no RST — its NAT translation entry was\n"
            "       silently deleted, forcing your OS to retransmit into a black hole (~15 minutes)."
        )
        print()
        print(
            "  3. Determining Whether It Is ISP CGNAT or Your Home Router (ONT):\n"
            f"     - Your external public IPv4 is: {public_ipv4 or 'unknown'}\n"
            "     - Log into your router status page (typically http://192.168.1.1/) and check the\n"
            "       WAN IPv4 address:\n"
            "         * If the WAN IP is in 100.64.0.0/10 (RFC 6598) or differs from your external\n"
            "           public IP, you are behind ISP CGNAT. Bridge mode or replacing your router\n"
            "           will NOT fix CGNAT; ask your ISP to remove CGNAT (assign a public IPv4) or\n"
            "           fix their CGNAT TCP established idle timer per RFC 5382 REQ-5.\n"
            "         * If the WAN IP equals your external public IP, only your router's own NAT is\n"
            "           in the path (reconfigure its NAT TCP timeout, update firmware, or use bridge mode)."
        )
        if local_ipv6:
            print()
            print(
                f"  4. IPv6 Note (Local IPv6 detected: {local_ipv6}):\n"
                "     IPv6 is routed rather than NAT-translated, so IPv6 connections escape this fault\n"
                "     while IPv4 connections stall. This makes failures look random across applications."
            )
        print("=" * 76)
        return 2

    if reset and ctrl == "ECHO":
        min_rst = min(reset)
        max_ok = max([i for i in survived if i < min_rst], default=None)
        threshold_desc = f"between {max_ok}s and {min_rst}s" if max_ok else f"at or below {min_rst}s"
        print("VERDICT: [FAULT CONFIRMED] ACTIVE TCP RESET (RST) ON IDLE CONNECTIONS")
        print()
        print(
            f"  A middlebox or firewall on your path actively resets idle TCP connections {threshold_desc}.\n"
            f"  RFC 5382 REQ-5 requires established TCP sessions to survive >= {RFC_5382_MIN_SECONDS}s (2h 04m)."
        )
        print("=" * 76)
        return 2

    if survived and not evicted and not reset and ctrl == "ECHO":
        max_ok = max(survived)
        print(f"VERDICT: [HEALTHY] NO NAT IDLE EVICTION DETECTED UP TO {max_ok}s")
        print()
        print(
            f"  All tested idle durations up to {max_ok}s survived without silent drops, and the\n"
            "  control connection remained healthy."
        )
        if max_ok < RFC_5382_MIN_SECONDS:
            print(
                f"\n  Note: RFC 5382 REQ-5 demands >= {RFC_5382_MIN_SECONDS}s (2h 04m). This run proves your network\n"
                f"  does not suffer from short {max_ok}s eviction, not full 2h 04m RFC compliance.\n"
                "  To test longer windows, re-run with e.g. --idles 60,300,600,1800"
            )
        print("=" * 76)
        return 0

    print("VERDICT: [INCONCLUSIVE] COULD NOT ISOLATE IDLE EVICTION")
    print()
    if ctrl != "ECHO":
        print(
            f"  - The active control connection (poked every {CONTROL_INTERVAL}s) did not survive ({ctrl}).\n"
            "    This points to general connectivity loss, firewall blocking, or server instability\n"
            "    rather than an idle-only timeout."
        )
    if server_closed and not evicted:
        print(
            f"  - The test server closed connections early with FIN ({server_closed}).\n"
            "    Run with --find-endpoint to select an endpoint that holds idle connections longer."
        )
    print("=" * 76)
    return 1


def run_find_endpoint(hold_seconds: int) -> int:
    print(
        f"[{now_str()}] Probing {len(CANDIDATE_ENDPOINTS)} IPv4 endpoints to see which hold idle TCP >= {hold_seconds}s...\n",
        flush=True,
    )
    usable: List[Tuple[str, int]] = []
    lock = threading.Lock()

    def hold_worker(host: str, port: int) -> None:
        tag = f"{host}:{port}"
        s: Optional[socket.socket] = None
        try:
            s, _ = open_ipv4_probe_socket(host, port, timeout=15)
            t0 = time.time()
            while time.time() - t0 < hold_seconds:
                remaining = max(0.0, hold_seconds - (time.time() - t0))
                readable, _, _ = select.select([s], [], [], min(5.0, remaining))
                if readable:
                    data = s.recv(512)
                    if not data:
                        elapsed = time.time() - t0
                        with lock:
                            print(f"  {tag:<28} CLOSED (FIN) at {elapsed:5.1f}s", flush=True)
                        return
            s.sendall(b"a1 NOOP\r\n")
            s.settimeout(15)
            if not s.recv(512):
                with lock:
                    print(f"  {tag:<28} CLOSED (EOF after poke)", flush=True)
                return
            with lock:
                usable.append((host, port))
                print(f"  {tag:<28} HELD past {hold_seconds}s  [USABLE]", flush=True)
        except Exception as exc:
            with lock:
                print(f"  {tag:<28} ERROR ({type(exc).__name__}: {exc})", flush=True)
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    threads = [threading.Thread(target=hold_worker, args=c, daemon=True) for c in CANDIDATE_ENDPOINTS]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print("\n" + "=" * 76)
    if usable:
        best_h, best_p = usable[0]
        print(f"RECOMMENDATION: {len(usable)} endpoint(s) held past {hold_seconds}s.")
        print(f"  Use: python3 nat_idle_diag.py --host {best_h} --port {best_p}")
        print("=" * 76)
        return 0
    print(
        f"WARNING: None of the candidate endpoints held past {hold_seconds}s.\n"
        "  If all connections timed out or reset around the same mark, your network NAT\n"
        "  may be evicting or resetting idle connections before that threshold."
    )
    print("=" * 76)
    return 1


def sample_linux_backoff_sockets() -> List[Tuple[str, str, str, int, str, str, int, str]]:
    """Return list of (state, local, peer, backoff, lastrcv, lastsnd, unacked, retrans) from `ss -tnimo`."""
    results: List[Tuple[str, str, str, int, str, str, int, str]] = []
    if not shutil.which("ss"):
        return results
    try:
        out = subprocess.check_output(["ss", "-tnimo"], stderr=subprocess.DEVNULL, text=True, timeout=5)
    except Exception:
        return results

    state = ""
    local = ""
    peer = ""
    for line in out.splitlines():
        stripped = line.strip()
        m_hdr = re.match(r"^(ESTAB|FIN-WAIT-1|FIN-WAIT-2|CLOSE-WAIT|LAST-ACK|SYN-SENT)\s+\d+\s+\d+\s+(\S+)\s+(\S+)", stripped)
        if m_hdr:
            state, local, peer = m_hdr.group(1), m_hdr.group(2), m_hdr.group(3)
            continue
        if state and any(k in stripped for k in ("backoff:", "lastrcv:", "unacked:", "retrans:")):
            bo_m = re.search(r"backoff:(\d+)", stripped)
            lr_m = re.search(r"lastrcv:(\d+)", stripped)
            ls_m = re.search(r"lastsnd:(\d+)", stripped)
            un_m = re.search(r"unacked:(\d+)", stripped)
            rt_m = re.search(r"retrans:(\d+/\d+)", stripped)
            bo = int(bo_m.group(1)) if bo_m else 0
            lr = lr_m.group(1) if lr_m else "?"
            ls = ls_m.group(1) if ls_m else "?"
            un = int(un_m.group(1)) if un_m else 0
            rt = rt_m.group(1) if rt_m else "0/0"
            results.append((state, local, peer, bo, lr, ls, un, rt))
            state = ""
    return results


def run_passive_sampler(samples: int, interval: int, out_dir: Optional[str]) -> int:
    total_sec = samples * interval
    print(
        f"[{now_str()}] Passive workload sampler started: {samples} samples every {interval}s (~{total_sec}s total).",
        flush=True,
    )
    print("  Observing existing machine traffic only (no synthetic connections opened).\n", flush=True)

    counters_start = read_os_tcp_counters()
    ipv4_stuck_peers = set()
    ipv6_stuck_peers = set()
    total_backoff_obs_v4 = 0
    total_backoff_obs_v6 = 0

    counters_file = None
    sockets_file = None
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        counters_file = open(os.path.join(out_dir, "nat-counters.tsv"), "w", encoding="utf-8")
        sockets_file = open(os.path.join(out_dir, "nat-sockets.tsv"), "w", encoding="utf-8")

    try:
        for idx in range(1, samples + 1):
            ts = int(time.time())
            cur_counters = read_os_tcp_counters()
            if counters_file:
                for k, v in cur_counters.items():
                    counters_file.write(f"{ts}\t{k}\t{v}\n")
                counters_file.flush()

            sock_rows = sample_linux_backoff_sockets()
            for state, local, peer, bo, lr, ls, un, rt in sock_rows:
                if sockets_file:
                    sockets_file.write(f"{ts}\t{state}\t{local}\t{peer}\t{bo}\t{lr}\t{ls}\t{un}\t{rt}\n")
                if state == "ESTAB" and (bo >= 1 or un > 0):
                    is_v6 = local.startswith("[") or peer.startswith("[") or local.count(":") > 1
                    if is_v6:
                        total_backoff_obs_v6 += 1
                        ipv6_stuck_peers.add(peer)
                    else:
                        total_backoff_obs_v4 += 1
                        ipv4_stuck_peers.add(peer)
            if sockets_file:
                sockets_file.flush()

            print(
                f"  [{now_str()}] Sample {idx}/{samples}: "
                f"v4 backoff flows={len(ipv4_stuck_peers)} (obs={total_backoff_obs_v4}), "
                f"v6 backoff flows={len(ipv6_stuck_peers)} (obs={total_backoff_obs_v6})",
                flush=True,
            )
            if idx < samples:
                time.sleep(interval)
    finally:
        if counters_file:
            counters_file.close()
        if sockets_file:
            sockets_file.close()

    counters_end = read_os_tcp_counters()
    print("\n" + "=" * 76)
    print("PASSIVE SAMPLER DIAGNOSIS")
    print("=" * 76)
    print_counter_snapshot("OS TCP Counters (End vs Start)", counters_end, counters_start)
    print("-" * 76)
    print(f"  Distinct IPv4 flows seen in retransmission backoff: {len(ipv4_stuck_peers)} ({total_backoff_obs_v4} observations)")
    print(f"  Distinct IPv6 flows seen in retransmission backoff: {len(ipv6_stuck_peers)} ({total_backoff_obs_v6} observations)")
    abort_delta = counters_end.get("TcpExt.TCPAbortOnTimeout", 0) - counters_start.get("TcpExt.TCPAbortOnTimeout", 0)
    timeout_delta = counters_end.get("TcpExt.TCPTimeouts", 0) - counters_start.get("TcpExt.TCPTimeouts", 0)

    if (len(ipv4_stuck_peers) >= 3 and len(ipv4_stuck_peers) > len(ipv6_stuck_peers) * 2) or abort_delta > 0 or timeout_delta >= 5:
        print(
            "\nVERDICT: [SUSPICIOUS] Elevated IPv4 TCP timeouts / retransmission backoff observed.\n"
            "  Run `python3 nat_idle_diag.py` (active bracket) to measure the exact NAT idle threshold."
        )
        print("=" * 76)
        return 2

    print("\nVERDICT: No abnormal silent TCP eviction pattern observed during passive window.")
    print("=" * 76)
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Diagnose ISP CGNAT / router NAT silent TCP idle-timeout eviction (RFC 5382 REQ-5)."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--quick",
        action="store_true",
        help=f"Quick ~2-minute live check ({QUICK_IDLE}s idle vs {CONTROL_INTERVAL}s busy control + fresh connection).",
    )
    mode.add_argument(
        "--bracket",
        action="store_true",
        help="Full parallel idle-threshold bracket (default mode).",
    )
    mode.add_argument(
        "--find-endpoint",
        action="store_true",
        help="Test candidate IPv4 servers to find one that holds idle TCP connections.",
    )
    mode.add_argument(
        "--passive",
        action="store_true",
        help="Passively sample OS TCP timeout counters and socket retransmission backoff.",
    )

    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Target host for TCP idle probes (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Target port (default: {DEFAULT_PORT})")
    parser.add_argument(
        "--idles",
        default=",".join(str(x) for x in DEFAULT_IDLES),
        help=f"Comma-separated idle durations in seconds for bracket mode (default: {','.join(str(x) for x in DEFAULT_IDLES)})",
    )
    parser.add_argument(
        "--poke-timeout",
        type=int,
        default=DEFAULT_POKE_TIMEOUT,
        help=f"Seconds to wait for post-idle reply before declaring SILENT (default: {DEFAULT_POKE_TIMEOUT})",
    )
    parser.add_argument(
        "--wan-ip",
        default=None,
        help="Optional: your router's WAN IPv4 address (from its status page) to automatically check for CGNAT (100.64.0.0/10).",
    )
    parser.add_argument(
        "--hold-seconds",
        type=int,
        default=240,
        help="Seconds to test candidate endpoints in --find-endpoint mode (default: 240)",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=15,
        help="Number of samples in --passive mode (default: 15)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=20,
        help="Seconds between samples in --passive mode (default: 20)",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Optional directory to write nat-counters.tsv and nat-sockets.tsv in --passive mode.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    print("=" * 76)
    print(f"NAT / ISP TCP IDLE-TIMEOUT DIAGNOSTIC ({platform.system()} {platform.release()})")
    print(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 76)

    if args.find_endpoint:
        return run_find_endpoint(args.hold_seconds)

    if args.passive:
        return run_passive_sampler(args.samples, args.interval, args.out_dir)

    if args.quick:
        idles = [QUICK_IDLE]
    else:
        try:
            idles = sorted({int(x.strip()) for x in args.idles.split(",") if x.strip()})
            if not idles or any(i <= 0 for i in idles):
                raise ValueError
        except ValueError:
            print(f"Error: invalid --idles value '{args.idles}'. Expected positive integers, e.g. 30,45,60,75,90,120", file=sys.stderr)
            return 1

    # Step 1: Addressing & CGNAT pre-check
    local_ipv4 = get_local_ip(socket.AF_INET, "1.1.1.1")
    local_ipv6 = get_local_ip(socket.AF_INET6, "2606:4700:4700::1111")
    public_ipv4 = fetch_public_ipv4()
    wan_info = analyze_wan_ip(args.wan_ip, public_ipv4)

    print("\n[1/4] Addressing & Path Context:")
    print(f"  Local IPv4 address:     {local_ipv4 or 'not detected'}")
    print(f"  External Public IPv4:   {public_ipv4 or 'could not query'}")
    print(f"  Routed IPv6 available:  {'yes (' + local_ipv6 + ')' if local_ipv6 else 'no'}")
    if wan_info:
        print(f"  Router WAN IP check:    {wan_info['detail']}")
    else:
        print(
            "  Router WAN IP check:    Tip: pass --wan-ip <ROUTER_WAN_IP> (from http://192.168.1.1/)\n"
            "                          to check whether your ISP places you behind CGNAT (100.64.0.0/10)."
        )

    # Step 2: OS TCP Counters before
    counters_before = read_os_tcp_counters()
    print()
    print_counter_snapshot("[2/4] OS TCP Counters (Before Test)", counters_before)

    # Step 3: Active Idle Probes + Control
    est_seconds = max(idles) + max(args.poke_timeout, CONTROL_INTERVAL) + 5
    print(
        f"\n[3/4] Running IPv4 TCP Idle Probes against {args.host}:{args.port}\n"
        f"      Idle windows: {idles}s + active control (every {CONTROL_INTERVAL}s)\n"
        f"      Estimated wait: ~{est_seconds} seconds (~{est_seconds / 60:.1f} minutes)...\n",
        flush=True,
    )
    verdicts = run_bracket_probes(args.host, args.port, idles, args.poke_timeout)

    # Step 4: OS TCP Counters after
    counters_after = read_os_tcp_counters()
    print()
    print_counter_snapshot("[4/4] OS TCP Counters (After Test)", counters_after, counters_before)

    return print_diagnosis(
        idles=idles,
        verdicts=verdicts,
        wan_info=wan_info,
        public_ipv4=public_ipv4,
        local_ipv6=local_ipv6,
    )


if __name__ == "__main__":
    sys.exit(main())
