# PCAP Investigation: "The Lucky Turkey" (malware-traffic-analysis.net, 2026-11-10)

All indicators are defanged (`[.]`, `hxxp`). The PCAP itself is **not** included in this repo.

## Evidence
| Item | Value |
|---|---|
| File | `2026-11-10-traffic-analysis-exercise.pcap` (31 MB, 30,182 packets) |
| SHA256 | `b52bd2a4ec9d747266206e10df01283197cc3e8ace8af20f1c1e5fb8f0b61533` |
| Capture window (UTC) | 2026-11-10 18:19:52 → 20:24:53 |

## Victim (matches the official answer key)
| Field | Value |
|---|---|
| Start of NetSupport RAT traffic | 2026-11-10 18:22:07 UTC |
| IP address | 10.11.10.147 |
| MAC address | 00:12:f0:e5:17:43 (Intel) |
| Host name | DESKTOP-5OMVI3L |
| User account | edward.winslow |

## Timeline (UTC)
| Time | Event |
|---|---|
| 18:20:14 | edward.winslow logs on (Kerberos AS-REQ to DC 10.11.10.10) |
| ~18:21:50 | PowerShell fetches `hxxp://vericheckusgo[.]com/` → obfuscated PowerShell stage 1 (served as text/html) |
| 18:21:50–18:21:59 | Stage 1 downloads embedded Python 3.12.7 from python.org (legitimate site misused) |
| 18:21:59 | Python fetches `hxxp://96.62.224[.]200/5555.mp4`: valid MP4 hiding an XOR + gzip payload in a `uuid` box |
| 18:22:07 | NetSupport RAT C2: `POST hxxp://93.152.209[.]36/fakeurl.htm` (plain HTTP on TCP 443, `CMD=POLL`) |
| 18:22:08 → | Beaconing every ~60 seconds |

## Stage 1 behaviour (static analysis; Base64 decoded as text, nothing executed)
- Exits if the computer name contains `CLEAN` (sandbox evasion)
- Hides its console window
- Exits if `C:\ProgramData\.ch_d5855b208b12` exists (infection marker)
- Writes `%TEMP%\ch_w_*.py`, installs Python into `%LOCALAPPDATA%\.v16c936eb5ae\py-embed\312\`, runs the Python stage hidden
- The Python stage extracts and decrypts the payload from the MP4, writes `%TEMP%\chk_*.py`, runs it, and deletes itself

## IOCs
| Type | Indicator | Context |
|---|---|---|
| Domain | vericheckusgo[.]com | Stage-1 PowerShell script |
| IP | 96.62.224[.]200 | Stage-1 + payload server |
| URL | hxxp://96.62.224[.]200/5555.mp4 | Payload hidden in MP4 |
| IP:port | 93.152.209[.]36:443 | NetSupport RAT C2 |
| URL | hxxp://93.152.209[.]36/fakeurl.htm | C2 check-in |
| User-Agent | NetSupport Manager/1.3 | C2 traffic |
| User-Agent | WindowsPowerShell/5.1 | Stage-1 download |
| File/path | C:\ProgramData\.ch_d5855b208b12 | Infection marker |
| File/path | %LOCALAPPDATA%\.v16c936eb5ae\ | Hidden Python runtime |
| File/path | %TEMP%\ch_w_*.py, %TEMP%\chk_*.py | Python stages |

## Wireshark filters used
```
ip.addr == 93.152.209.36
nbns && ip.src == 10.11.10.147
kerberos.CNameString && !(kerberos.CNameString contains "$")
(http.request || tls.handshake.type == 1) && frame.number < 24672
```

## MITRE ATT&CK
T1059.001 PowerShell · T1059.006 Python · T1027 Obfuscated Files · T1027.003 Steganography · T1105 Ingress Tool Transfer · T1564.003 Hidden Window · T1497 Sandbox Evasion · T1219 Remote Access Software · T1071.001 Web Protocols
