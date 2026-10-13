# Memory Forensics Investigations

Volatile-memory investigations from [CyberDefenders](https://cyberdefenders.org/), each documented as a SOC-style report: how a RAM capture is analyzed with Volatility to surface malicious processes, persistence, defense evasion, and IOCs, mapped to MITRE ATT&CK. The focus is the analytical process, not just the answers.

**Core skills:** memory acquisition analysis, process-tree reconstruction, command-line recovery, persistence and defense-evasion detection, MITRE ATT&CK mapping.

**Tools:** Volatility 3 (windows.pslist, psscan, pstree, cmdline, getsids, and related plugins).

## Investigations

| Lab | Focus | Key tools | ATT&CK | Status |
|---|---|---|---|---|
| [Volatility Traces](volatility-traces/) | PowerShell malware, Defender-exclusion evasion | Volatility 3 | T1564 | **Done** |
| [RedLine](redline/) | Infostealer, process injection, C2 + VPN bypass | Volatility 3, strings | T1055, T1071.001 | **Done** |

Mark each **Done** and link the write-up as you complete it.

## How this repo is organized

```
memory-forensics/
  README.md                  <- this index
  volatility-traces/
    README.md                <- the write-up
    images/                  <- redacted screenshots
  ...
```

One folder per lab, each with its own write-up and an `images/` folder for evidence screenshots.

## Notes on responsible disclosure

- Write-ups are for **retired** labs, in line with CyberDefenders' terms.
- Screenshots are **redacted** of any personal account identifiers (terminal chrome, browser chrome, usernames).

---
Built by **Prosper Emerole** · [github.com/Emerole7](https://github.com/Emerole7) · Part of my blue-team investigation portfolio.
