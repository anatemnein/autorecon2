# autorecon2

Goroutine-based OSCP recon tool — drop-in replacement for AutoRecon.

Runs rustscan → nmap service detection → per-service enumeration in parallel goroutines.  
**OSCP safe** — no automated vulnerability scanners (nuclei/odat removed).

---

## How it works

```
Phase 1  →  rustscan (fast TCP discovery, falls back to nmap -p-)
Phase 2  →  nmap -sV -sC on discovered ports only
Phase 3  →  goroutine per open service (all run in parallel)
           + sudo nmap -sU (UDP top-20, if root)
```

## Install

```bash
git clone https://github.com/anatemnein/autorecon2
cd autorecon2
go build -o autorecon2 .
cp autorecon2 ~/.local/bin/
```

**Requirements** (install what you have, tool is skipped if missing):

| Tool | Purpose |
|------|---------|
| `rustscan` | Fast port discovery |
| `nmap` | Service detection + NSE scripts |
| `httpx` | HTTP probing |
| `feroxbuster` | Directory bruteforce |
| `nikto` | Web vulnerability scanner |
| `gowitness` | Web screenshots |
| `sslscan` | TLS/SSL analysis |
| `whatweb` | Web technology fingerprinting |
| `smbmap` | SMB share enumeration |
| `smbclient` | SMB share access |
| `nbtscan` | NetBIOS scan |
| `enum4linux` | SMB/RPC enumeration |
| `nxc` / `netexec` | SMB/WinRM/MSSQL testing |
| `rpcclient` | RPC enumeration |
| `smtp-user-enum` | SMTP user enumeration |
| `snmpwalk` | SNMP enumeration |
| `onesixtyone` | SNMP community string brute |
| `showmount` | NFS share listing |
| `kerbrute` | Kerberos user enumeration |
| `redis-cli` / `valkey-cli` | Redis enumeration |
| `evil-winrm` | WinRM shell |

---

## Usage

```bash
# Single target
autorecon2 10.10.10.5

# Multiple targets
autorecon2 10.10.10.5 10.10.10.6 10.10.10.7

# Custom output directory
autorecon2 -o /tmp/recon 10.10.10.5

# Verbose (stream all tool output)
autorecon2 -v 10.10.10.5

# UDP scan (requires root)
sudo autorecon2 10.10.10.5
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-o` | `recon` | Output directory |
| `-v` | `false` | Verbose — stream all tool output to stdout |

---

## Output structure

```
recon/
└── 10.10.10.5/
    ├── disc.txt              # Phase 1: port discovery
    ├── detail.txt            # Phase 2: nmap -sV -sC
    ├── udp.gnmap             # UDP scan results
    ├── http_80/
    │   ├── httpx.txt
    │   ├── feroxbuster.txt
    │   ├── nikto.txt
    │   ├── whatweb.txt
    │   ├── sslscan.txt
    │   └── robots.txt
    ├── smb/
    │   ├── nmap_smb.txt
    │   ├── smbmap.txt
    │   ├── enum4linux.txt
    │   └── nxc_smb.txt
    ├── snmp/
    │   ├── snmpwalk_public.txt
    │   └── snmpwalk_extend_public.txt
    ├── kerberos/
    │   └── kerbrute.txt
    └── report.md             # Quick wins checklist
```

---

## report.md

After each scan, `autorecon2` generates a `report.md` with a quick wins checklist:

```markdown
## Quick Wins
- [ ] Anonymous FTP login
- [ ] SMB null session
- [ ] SNMP default community strings
- [ ] HTTP: check /robots.txt, /admin, /backup
- [ ] WinRM / evil-winrm access
...
```

---

## vs AutoRecon

| | autorecon2 | AutoRecon |
|---|---|---|
| Language | Go | Python |
| Parallelism | goroutines (true parallel) | asyncio + semaphore |
| Port discovery | rustscan → nmap (2-phase) | nmap only |
| Speed | ~5–8 min | ~20–30 min |
| HTTP probing | httpx | curl/nmap |
| Screenshots | gowitness | none |
| AD tooling | nxc, kerbrute | netexec |
| OSCP compliant | yes (no nuclei/odat) | yes |
| Binary | single static binary | Python + 78 plugins |
