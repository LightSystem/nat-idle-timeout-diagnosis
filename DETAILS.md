# Detailed Guide: Silent NAT / CGNAT TCP Idle Eviction

This document covers the technical background, router CGNAT verification, sample outputs, ISP escalation guide, temporary workarounds, and methodology behind [`nat-idle-timeout-diagnosis`](README.md).

---

## 1. How Silent NAT Eviction Works

Under **[RFC 5382 REQ-5](https://datatracker.ietf.org/doc/html/rfc5382#section-5)**, any NAT device must keep address translation mappings for established TCP connections alive for **at least 2 hours and 4 minutes (7,440 seconds)** of inactivity.

When an ISP's Carrier-Grade NAT (CGNAT) or a home router is misconfigured with an aggressive TCP idle timer (for example, **60–75 seconds** — ~100× below the RFC minimum):

1. **Silent Eviction:** After ~65 seconds without traffic on an established IPv4 TCP connection, the NAT device silently deletes the state-table entry. Neither endpoint receives a `FIN` or `RST`.
2. **The ~15-Minute Hang:** Because neither side was notified, your OS still considers the socket `ESTABLISHED`. The next time the application sends data, packets drop into a black hole. Your OS kernel enters exponential TCP retransmission backoff (`tcp_retries2` on Linux, `TcpMaxDataRetransmissions` on Windows) for **~15 minutes** before finally timing out.
3. **Instant Recovery on Retry:** Opening a **brand-new** connection at the exact same moment succeeds in milliseconds, because a new `SYN` creates a fresh NAT mapping.
4. **Why Speed Tests & Web Browsing Look Fine:** Speed tests and video streams push continuous traffic and never sit idle for 60+ seconds. A clean speed test is **not** evidence that your connection is healthy.

### Typical Symptoms

- **SSH sessions** freeze after ~1 minute of not typing, while opening a new SSH tab works immediately.
- **Developer & AI tools** (Claude Code, IDE remote tasks, database clients, `./gradlew` tasks waiting on a worker or remote call) stall for 5–15 minutes and succeed immediately when re-run.
- **VPN tunnels** stop passing traffic after ~1 minute of silence while the VPN client UI still displays "Connected".
- **Random-looking failures on dual-stack networks:** **IPv6** is routed end-to-end (no NAT), so IPv6 connections survive while **IPv4** connections hang. Whether an app hangs depends on which address family it happened to connect over.

---

## 2. How to Check If You Are Behind ISP CGNAT (Router WAN IP Check)

Looking up your IP on a "What is my IP" website shows a normal, routable public IPv4 address **even when you are behind CGNAT**, because CGNAT shares a routable public IP across many customers. The real check is comparing the **WAN IPv4 address inside your router** against the **external public IPv4 address** seen from the internet.

1. Log into your home router / ONT web interface (usually `http://192.168.1.1/` or `http://192.168.1.254/`).
2. Open the **Status / Diagnostics / WAN (Internet)** page and copy the **WAN IPv4 address** assigned to the router.
   - *Example (Huawei / Vodafone ONT):* **Diagnóstico e Suporte** → **Estado** → **Informação de estado da WAN** → **Endereço IPv4**.
3. Pass that WAN IP via `--wan-ip <WAN_IP>` (or `-WanIp <WAN_IP>` in PowerShell), or compare it using the table below:

| Router WAN IPv4                                         | External Public IPv4 (`api4.ipify.org`) | What It Means                                                                                       |
|---------------------------------------------------------|-----------------------------------------|-----------------------------------------------------------------------------------------------------|
| Inside `100.64.0.0/10` (`100.64.x.x`–`100.127.x.x`)     | Any public IPv4 (`WAN != Public`)       | **ISP CGNAT confirmed (RFC 6598).** Your traffic traverses two NAT layers: your router + ISP CGNAT. |
| Inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`  | Any public IPv4 (`WAN != Public`)       | **Double NAT.** Another router/modem or private ISP network sits upstream of this router.           |
| Public IPv4, but `WAN != Public`                        | Different public IPv4                   | **Upstream carrier NAT confirmed.**                                                                 |
| Matches external public IP (`WAN == Public`)            | Same public IPv4 (`WAN == Public`)      | **No CGNAT.** Only your home router/ONT performs NAT on the path.                                   |

---

## 3. Example Diagnostic Outputs

### Fault Confirmed (Before ISP Fix)

```text
[3/4] Running IPv4 TCP Idle Probes against imap.gmx.com:143
      Idle windows: [30, 45, 60, 75, 90, 120]s + active control (every 20s)

  [12:10:30] idle-30s    ECHO     Replied in 0.0s after 30s idle
  [12:10:45] idle-45s    ECHO     Replied in 0.0s after 45s idle
  [12:11:00] idle-60s    ECHO     Replied in 0.0s after 60s idle
  [12:11:55] idle-75s    SILENT   No reply for 40s after 75s idle, no RST/FIN -> mapping evicted
  [12:12:10] idle-90s    SILENT   No reply for 40s after 90s idle, no RST/FIN -> mapping evicted
  [12:12:20] control     ECHO     Survived 140s with traffic every 20s (never idle >20s)
  [12:12:40] idle-120s   SILENT   No reply for 40s after 120s idle, no RST/FIN -> mapping evicted
  [12:12:40] fresh       ECHO     Brand-new connection opened and greeted in 0.1s

============================================================================
DIAGNOSIS SUMMARY
============================================================================
  Survived (ECHO):        [30, 45, 60]
  Silent Drop (SILENT):   [75, 90, 120]
  Active Control (20s):   ECHO
  Fresh Connection Now:   ECHO
----------------------------------------------------------------------------
VERDICT: [FAULT CONFIRMED] SILENT NAT TCP IDLE EVICTION DETECTED

  1. Measured Idle Threshold: between 60s and 75s of inactivity.
     RFC 5382 REQ-5 requires NAT timers for established TCP sessions to be at least
     2 hours 4 minutes (7440s). Your path drops mappings ~99x below the standard.
```

### Healthy Line (After ISP Removed CGNAT)

```text
============================================================================
DIAGNOSIS SUMMARY
============================================================================
  Survived (ECHO):        [30, 45, 60, 75, 90, 120]
  Silent Drop (SILENT):   none
  Active Control (20s):   ECHO
  Fresh Connection Now:   ECHO
----------------------------------------------------------------------------
VERDICT: [HEALTHY] NO NAT IDLE EVICTION DETECTED UP TO 120s
```

---

## 4. What to Do If the Fault Is Confirmed

### What to Request from Your ISP

When opening a ticket with your ISP's technical support (escalate to Level 2 / network engineering if needed):

1. **Clarify that speed tests do not test this:** Physical line quality and continuous transfers work; the fault is **silent eviction of established idle TCP sessions** after `X` seconds.
2. **Cite the standard:** **[RFC 5382, Section 5, Requirement REQ-5](https://datatracker.ietf.org/doc/html/rfc5382#section-5)** mandates that the NAT idle timeout for established TCP sessions must not be less than **2 hours and 4 minutes (7,440 seconds)**.
3. **Attach the diagnostic output:** Show the exact idle bracket (`30/45/60s` surviving vs. `75/90/120s` silently dropped while the 20s control connection and fresh connection succeed). If available, also note that router optical levels and WAN error/discard counters are clean and that the exact same threshold persists immediately after a router reboot (proving a fixed timer configuration rather than fiber degradation or a full NAT table).
4. **Request the appropriate fix:**
   - **Behind CGNAT (`WAN` in `100.64.0.0/10` or `WAN != Public`):** Request removal from CGNAT (assignment of a public IPv4 address) or correction of the carrier CGNAT established-TCP timeout to ≥ 2h 04m. Bridge mode or replacing your home router will **not** bypass ISP CGNAT.
   - **Not behind CGNAT (`WAN == Public`):** The short timer is in your local router/ONT. Check router settings for a configurable TCP NAT timeout, request a firmware/TR-069 update from the ISP, or put the ISP ONT into **bridge mode** with your own router.

### Local Workarounds (While Waiting for the ISP Fix)

Configure keepalives **shorter than the measured eviction threshold** (for a 60–75s threshold, **30 seconds** is a safe interval):

- **SSH (`~/.ssh/config` on Linux, macOS, and Windows):**
  ```sshconfig
  Host *
      ServerAliveInterval 30
      ServerAliveCountMax 4
  ```
- **Linux OS-wide TCP Keepalive (for applications that enable `SO_KEEPALIVE`):**
  ```sh
  sudo sysctl -w net.ipv4.tcp_keepalive_time=30
  sudo sysctl -w net.ipv4.tcp_keepalive_intvl=15
  ```
- **Windows OS-wide TCP Keepalive (PowerShell as Administrator; requires reboot):**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value 30000 -Type DWord
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveInterval" -Value 15000 -Type DWord
  ```
- **JVM / Gradle (`~/.gradle/gradle.properties`):**
  If your network has working IPv6, prefer the routed IPv6 path to avoid IPv4 NAT entirely:
  ```properties
  systemProp.java.net.preferIPv6Addresses=true
  ```

> **Note:** `tcp_keepalive_time` / `KeepAliveTime` only helps applications that explicitly enable `SO_KEEPALIVE` on their sockets. `nat_idle_diag.py` and `diagnose.ps1` explicitly disable `SO_KEEPALIVE` on test sockets so local workarounds do not mask the fault during testing. Once your ISP resolves the fault, remove temporary local keepalive workarounds so future regressions are immediately visible rather than silently masked.

---

## 5. Methodology & Traps Avoided

1. **Pinning IPv4 (`AF_INET`):**
   Modern operating systems prefer IPv6 when a hostname has both `AAAA` and `A` DNS records. Because IPv6 is routed without NAT/CGNAT, a dual-stack test connects over IPv6, survives every idle window, and falsely reports that the network is healthy while IPv4 applications hang. All probes in this tool strictly pin `AF_INET`.
2. **Filtering out server-side idle closes (`FIN`):**
   Many HTTP/HTTPS servers close idle TCP connections after 5–60 seconds by sending a `FIN`. By default, this tool probes `imap.gmx.com:143` because [RFC 3501](https://datatracker.ietf.org/doc/html/rfc3501#section-5.4) requires IMAP servers to hold idle connections for at least 30 minutes, and an unauthenticated `NOOP` safely tests liveness after the greeting. Before sending the post-idle probe, the tool drains any untagged server output and checks for `FIN` (`EOF`), discarding server-initiated closes as `SERVER`.

---

## 6. Real-World Case Study: Vodafone Fiber CGNAT (Resolved)

This toolkit was created to diagnose a residential fiber fault where established TCP connections died silently after **60–75 seconds** of inactivity:

- **Observed failure:**
  - Idle `30s`, `45s`, `60s` → survived (`ECHO`).
  - Idle `75s`, `90s`, `120s` → died silently (`SILENT`), causing applications to hang for ~15 minutes while `TcpExt.TCPAbortOnTimeout` climbed at **33–43 aborts/hour**.
  - Over 1 hour of passive sampling (`--passive`), **46 distinct IPv4 flows** entered retransmission backoff across **20 destination networks**, compared to **1 IPv6 flow**.
  - Optical power levels and ONT WAN error counters were completely clean, the exact same 60–75s cutoff persisted immediately after an ONT reboot, and the fault reproduced identically on a second machine over Wi-Fi.
  - The ISP-supplied ONT (`Huawei OptiXstar HG8247B7-8N`, firmware `V5R024C00S114`) had an ISP-locked web UI that exposed no NAT timer or session settings.
- **Root cause & resolution:**
  - The ONT WAN IPv4 was inside `100.64.0.0/10` (RFC 6598 CGNAT space, `WAN != Public`).
  - Vodafone removed CGNAT from the line and assigned a direct public IPv4 (`WAN == Public`).
  - Immediately after CGNAT removal — with the same home ONT still performing local NAT — all idle brackets (`30s` through `120s`) survived with `0.0s` reply time and `0` TCP timeouts.
