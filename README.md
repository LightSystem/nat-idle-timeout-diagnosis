# nat-idle-timeout-diagnosis

Cross-platform diagnostic tool (**Linux**, **macOS**, **Windows**) to detect **silent TCP idle-timeout eviction** caused by ISP CGNAT or router NAT violating [RFC 5382 REQ-5](https://datatracker.ietf.org/doc/html/rfc5382#section-5) (≥ 2h 04m minimum idle timer).

Use this when **idle SSH sessions, VPNs, or developer/AI tools freeze after ~1 minute** of inactivity while brand-new connections and speed tests work normally. No third-party packages required.

## Quickstart

### Linux / macOS

```sh
./diagnose.sh
```

### Windows (Command Prompt or PowerShell — no Python required)

```cmd
diagnose.cmd
```

```powershell
powershell -ExecutionPolicy Bypass -File .\diagnose.ps1
```

### Common Runs

```sh
# Fast ~2-minute check (single 90s idle probe vs. 20s active control)
./diagnose.sh --quick
diagnose.cmd --quick

# Include your router's WAN IPv4 (from http://192.168.1.1/) to check for ISP CGNAT (100.64.0.0/10)
./diagnose.sh --wan-ip 100.64.1.25
diagnose.cmd --wan-ip 100.64.1.25
```

## Reading the Result

The tool opens parallel **IPv4-pinned** TCP connections (`SO_KEEPALIVE` disabled) across multiple idle windows (`30, 45, 60, 75, 90, 120`s) alongside a **20s active control connection**, then opens a **fresh connection** at the end:

| Outcome  | Meaning                                                                                   |
|----------|-------------------------------------------------------------------------------------------|
| `ECHO`   | Reply received after the idle window — NAT mapping survived.                              |
| `SILENT` | No reply, no `FIN`, no `RST` after idling — **NAT silently evicted the connection**.      |
| `RST`    | Connection actively reset after idling by a middlebox or firewall.                        |
| `SERVER` | Remote server closed early with `FIN` (ignored; run `--find-endpoint` if needed).         |

**Exit codes:** `0` = Healthy, `2` = Fault confirmed (`SILENT` or `RST`), `1` = Inconclusive / Error.

## CLI Options

All flags work with `./diagnose.sh`, `python3 nat_idle_diag.py`, `diagnose.cmd`, and `.\diagnose.ps1`:

| Option                    | Description                                                                        |
|---------------------------|------------------------------------------------------------------------------------|
| *(default)*               | Full parallel bracket (`30,45,60,75,90,120`s idle + 20s control, ~2.5 min)         |
| `--quick`                 | Single `90`s idle probe + 20s control (~2 min, ideal during an ISP support call)   |
| `--wan-ip <IP>`           | Compare router WAN IPv4 against external public IPv4 to detect CGNAT / double NAT  |
| `--idles 60,180,300,600`  | Test custom comma-separated idle durations in seconds                              |
| `--host <H> --port <P>`   | Override target probe server (default: `imap.gmx.com:143`)                         |
| `--find-endpoint`         | Probe candidate IPv4 servers to find one that holds idle connections ≥ 240s        |
| `--passive`               | Passively sample OS TCP timeout/retransmission counters on existing machine traffic |

## If a Fault Is Confirmed

- **Router WAN IP is in `100.64.0.0/10` or differs from your external public IP:** You are behind **ISP CGNAT**. Bridge mode or replacing your router will not fix it — ask your ISP to remove CGNAT (assign a public IPv4) or fix their CGNAT established-TCP timer per RFC 5382 REQ-5.
- **Router WAN IP matches your external public IP:** Only your local router/ONT performs NAT. Adjust its TCP NAT timeout, update firmware, or use bridge mode.

See **[DETAILS.md](DETAILS.md)** for how silent NAT eviction works, how to check your router's WAN IP, full sample outputs, local keepalive workarounds (SSH, Linux, Windows, JVM), and the Vodafone CGNAT case study.

## License

[MIT](LICENSE)
