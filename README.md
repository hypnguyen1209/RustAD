# RustAD v2.0.0

All-in-one Active Directory security assessment tool — collector, analyzer, and Kerberos toolkit in a single static binary.

**28,000+ lines of Rust** | **73 security checks** | **14 Kerberos modules** | **18 credential scanning rules** | **137 tests** | **~6MB static binary**

## What It Does

1. **Collects** AD data via LDAP/SMB → BloodHound CE v6 JSON
2. **Analyzes** 73 attack surface checks (ACLs, ADCS, delegation, roasting, coercion, hygiene)
3. **Scans** SYSVOL and descriptions for credentials/secrets (Snaffler-equivalent)
4. **Attacks** with built-in Kerberos toolkit (roasting, ticket forgery, S4U delegation, spray)
5. **Exports** reports in JSON, CSV, or Markdown

## Quick Start

```bash
# Collect + full analysis + JSON report
rustad -d CORP.LOCAL -u user@corp.local -p 'Pass' -f DC01.CORP.LOCAL -z --analyze --export json

# Pass-the-Hash
rustad -d CORP.LOCAL -u admin -H aad3b435b51404eeaad3b435b51404ee -f DC01 -z --analyze

# Certificate auth
rustad -d CORP.LOCAL --pfx admin.pfx -f DC01 -z --analyze

# Kerberos (Linux ccache / Windows SSPI)
KRB5CCNAME=/tmp/krb5cc_user rustad -d CORP.LOCAL -k -f DC01.CORP.LOCAL -z --analyze

# DC-only (no workstation contact)
rustad -d CORP.LOCAL -u user -p pass -c DCOnly -z --analyze

# Paths from compromised accounts
rustad -d CORP.LOCAL -u user -p pass -z --analyze --owned "svc_sql@corp.local,helpdesk@corp.local"

# Session loop (every 2 min for 3 hours)
rustad -d CORP.LOCAL -u user -p pass -c Session --loop --loopduration 10800 -z

# Domain-joined Windows (auto-detect, no args)
rustad_noargs.exe
```

## CLI Reference

```
rustad [OPTIONS] --domain <domain>
```

### Authentication

| Flag | Description |
|---|---|
| `-d, --domain <domain>` | Target domain (required) |
| `-u, --ldapusername <user>` | Username (e.g., `user@domain.local`) |
| `-p, --ldappassword <pass>` | Password |
| `-H, --hashes <hash>` | NT hash for Pass-the-Hash (`NTHASH` or `LM:NT`) |
| `-k, --kerberos` | Kerberos from ccache / Windows SSPI |
| `--pfx <path>` | PFX certificate (Pass-the-Certificate) |
| `--pfx-pass <pass>` | PFX password |
| `--crt <path>` / `--key <path>` | PEM cert + key pair |

### Connection

| Flag | Description |
|---|---|
| `-f, --ldapfqdn <fqdn>` | DC FQDN (e.g., `DC01.CORP.LOCAL`) |
| `-i, --ldapip <ip>` | DC IP address |
| `-P, --ldapport <port>` | LDAP port (389 / 636) |
| `--ldaps` | Force LDAPS |
| `-n, --name-server <ip>` | Alternative DNS |
| `--dns-tcp` | TCP for DNS |

### Collection

| Flag | Description |
|---|---|
| `-c, --collectionmethod <m>` | Method (see below) |
| `--ldap-filter <filter>` | Custom LDAP filter |
| `--fqdn-resolver` | Resolve FQDNs to IPs |

#### 17 Collection Methods

| Method | LDAP | SMB | GPO | Use Case |
|---|---|---|---|---|
| **All** | Yes | Yes | Yes | Full collection (default) |
| **Default** | Yes | No | Yes | No workstation sessions |
| **DCOnly** | Yes | No | Yes | DC data only |
| **Session** | Yes | Yes | No | User session enumeration |
| **RegistryOnly** | Yes | WINREG | No | Registry sessions only |
| **LdapOnly** | Yes | No | No | LDAP only |
| **Group** | Groups | No | No | Group memberships |
| **ACL** | ACLs | No | No | Access control |
| **ObjectProps** | Props | No | No | Object properties |
| **SPNTargets** | SPNs | No | No | SPN targets |
| **Trusts** | Trusts | No | No | Domain trusts |
| **Container** | OUs | No | No | OU hierarchy |
| **GPOLocalGroup** | GPOs | No | Yes | GPO local groups |
| **ComputerOnly** | PCs | No | No | Computers |
| **RDP** | Yes | RDP | No | RDP users |
| **DCOM** | Yes | DCOM | No | DCOM users |
| **PSRemote** | Yes | PS | No | PS Remote users |

### Output

| Flag | Description |
|---|---|
| `-o, --output <dir>` | Output directory (default: `./`) |
| `-z, --zip` | ZIP archive |
| `--outputprefix <prefix>` | Filename prefix |

### Session Loop

| Flag | Description |
|---|---|
| `--loop` | Enable loop |
| `--loopduration <sec>` | Duration (default: 7200) |
| `--loopinterval <sec>` | Interval (default: 120) |

### Analysis

| Flag | Description |
|---|---|
| `--analyze` | Run 73 security checks |
| `--owned <list>` | Compromised principals (comma-separated) |
| `--export <fmt>` | Export: `json`, `csv`, `md` |

### Operational

| Flag | Description |
|---|---|
| `--delay <ms>` | Request delay |
| `--jitter <ms>` | Random jitter |
| `--opsec` | OPSEC mode |
| `--exclude-dc` | Skip DCs in sessions |

### Caching

| Flag | Description |
|---|---|
| `--cache` | Disk cache for large domains |
| `--cache-buffer <n>` | Buffer size (default: 1000) |
| `--resume` | Resume from cache |

---

## 73 Analysis Checks

All checks run on collected data with `--analyze`. No additional network traffic.

### Attack Paths & Escalation

| # | Check | Sev | Description |
|---|---|---|---|
| 1 | Paths to Domain Admins | 8 | BFS pathfinding with stepping stones |
| 2 | Paths to DNS Admins | 8 | DLL injection → DC compromise |
| 3 | Paths to Operator Groups | 7 | Account/Server/Backup/Print Operators |
| 4 | Owned Principal Paths | 9 | From compromised accounts to HV targets |
| 5 | Cross-domain Paths | 6 | Foreign users/groups with cross-domain membership |
| 6 | Deep Group Nesting | 6 | MemberOf chains >3 hops to admin groups |
| 7 | Indirect Admin Members | 6 | Nested membership reaching DA/EA |
| 8 | Stepping Stones | 8 | Multi-hop bridge nodes on attack paths |
| 9 | Compromise Dossier | — | Per-principal rights enumeration |

### Credential Attacks

| # | Check | Sev | Description |
|---|---|---|---|
| 10 | Kerberoastable Accounts | 5-9 | Users with SPNs (prioritizes privileged) |
| 11 | AS-REP Roastable | 5-9 | No pre-authentication required |
| 12 | Privileged Roastable | 9 | Admin users vulnerable to roasting |
| 13 | Cleartext Passwords | 8 | userPassword/unixPassword/sfuPassword in LDAP |
| 14 | Password in Description | 6 | Regex detection (redacted output) |
| 15 | Password Never Expires | 4 | UAC PasswordNeverExpires |
| 16 | Password Not Required | 8 | UAC PasswordNotRequired |
| 17 | Password Age Audit | 5-8 | Passwords >365 days old |
| 18 | Old KRBTGT Password | 8 | KRBTGT key >180 days (golden ticket risk) |
| 19 | GPP Passwords | 8 | cpassword in SYSVOL (MS14-025) |
| 20 | Credential Exposure | 9 | Combined privileged kerberoastable + AS-REP |
| 21 | Snaffler Scan | varies | 18 regex patterns on descriptions + SYSVOL files |

### ADCS (Active Directory Certificate Services)

| # | Check | Sev | Description |
|---|---|---|---|
| 22 | ESC1 | 10 | Enrollee supplies subject + client auth + low-priv |
| 23 | ESC2 | 10 | SubCA/Any Purpose enrollable by low-priv |
| 24 | ESC3 | 9 | Enrollment agent template accessible |
| 25 | ESC4 | 10 | Template writable by low-priv |
| 26 | ESC6 | 10 | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA |
| 27 | ESC7 | 9 | ManageCA/ManageCertificates by non-default |
| 28 | ESC8 | 9 | HTTP web enrollment (NTLM relay) |
| 29 | ESC13 | 10 | No security extension + client auth |

### Delegation

| # | Check | Sev | Description |
|---|---|---|---|
| 30 | Unconstrained Delegation | 8 | Non-DC computers |
| 31 | Constrained Delegation | 7 | TrustedToAuth + AllowedToDelegate |
| 32 | RBCD Abuse | 9 | AllowedToAct edges |
| 33 | RBCD Configurable | 9 | Who can set msDS-AllowedToActOnBehalfOfOtherIdentity |
| 34 | Delegation Overview | 7-9 | Combined delegation analysis |

### Permissions & ACLs

| # | Check | Sev | Description |
|---|---|---|---|
| 35 | DCSync Rights | 10 | GetChanges + GetChangesAll unexpected |
| 36 | Dangerous Permissions | 9 | Non-default ACLs on HV objects |
| 37 | Shadow Credentials | 8 | msDS-KeyCredentialLink writable |
| 38 | Shadow via WriteOwner | 8 | WriteOwner → self-grant write |
| 39 | AdminSDHolder Abuse | 9 | Custom ACEs propagate to all protected objects |
| 40 | GPO Abuse | 7 | Writable GPOs linked to sensitive OUs |
| 41 | DC Ownership Audit | 9 | DCs owned by non-DA principals |
| 42 | Default Domain Policy | 8 | Default policies writable by non-admins |

### NTLM Coercion & Relay

| # | Check | Sev | Description |
|---|---|---|---|
| 43 | NTLM Coercion Paths | 8-9 | PrinterBug + PetitPotam + DFSCoerce → relay chains |
| 44 | Print Spooler | 7 | Spooler SPN (coercion target) |
| 45 | NTLM Relay Targets | 8-9 | DCs + unconstrained + ESC8 CAs |
| 46 | SMB Signing | 7 | Non-DC computers as relay targets |
| 47 | LDAP Signing | 6 | Enforcement status |
| 48 | Computer Admin of Computers | 7 | Machine-to-machine admin chains |

### Infrastructure

| # | Check | Sev | Description |
|---|---|---|---|
| 49 | Exchange Permissions | 9 | WriteDacl on Domain |
| 50 | Exchange Servers | 7 | Exchange infrastructure detection |
| 51 | SCCM Detection | 7 | SCCM/MECM infrastructure |
| 52 | ADIDNS Abuse | 8 | Writable DNS zones |
| 53 | DPAPI Exposure | 9 | Backup key access |
| 54 | Obsolete OS | 6 | 2003/2008/XP/Vista/Win7 |

### Trust & Cross-Domain

| # | Check | Sev | Description |
|---|---|---|---|
| 55 | Domain Trusts | 6-7 | Direction, type, SID filtering |
| 56 | Foreign Users | 6 | Cross-domain group membership |
| 57 | Foreign Groups | 6 | Groups with foreign members |

### Account Hygiene & Compliance

| # | Check | Sev | Description |
|---|---|---|---|
| 58 | Stale Users | 4 | Inactive >90 days |
| 59 | Stale Computers | 4 | Inactive >90 days |
| 60 | Orphan Accounts | 5 | No description, no logon, no groups |
| 61 | Account Expiration | 4 | Privileged without expiration |
| 62 | Service Account Hygiene | 5-7 | SPNs + pwd_never_expires + admin |
| 63 | Machine Account Quota | 7 | Authenticated users can create computers |
| 64 | Pre-Windows 2000 Access | 7 | Broad membership exposure |
| 65 | LAPS Deployment | 6-8 | Coverage + non-default readers |
| 66 | gMSA Exposure | 8 | Non-default password readers |
| 67 | FGPP Detection | 5 | Fine-Grained Password Policies |
| 68 | Protected Users Audit | 6-7 | Admins missing from Protected Users |
| 69 | Guest Accounts | 7 | Enabled guest accounts |
| 70 | Locked Accounts | 5 | Currently locked (brute force indicator) |
| 71 | Unexpected PrimaryGroupID | 7 | Hidden group membership |
| 72 | Recently Created Objects | 4 | Users/groups created in last 30 days |
| 73 | Tier-0 Session Violations | 9 | DA/EA sessions on non-DC hosts |
| + | Empty Groups | 3 | Abandoned group configurations |
| + | RODC Detection | 3 | Read-Only Domain Controllers |
| + | AD Recycle Bin Status | 4 | Tombstone / recycle bin |
| + | Domain Recon Summary | 3 | Informational overview |
| + | Privileged Users Summary | 5 | AdminCount exposure |
| + | GPO Local Groups | 7 | GPOs modifying local membership |
| + | Local Admin Targets | 7 | Non-default local admin access |

---

## Snaffler Engine

Built-in credential/secret scanner runs on SYSVOL files during collection and on User/Computer description fields during analysis. All secrets **redacted** in output.

### 18 Content Detection Patterns

| Category | Patterns |
|---|---|
| Credentials | Passwords, API keys, client secrets, OAuth tokens, generic secrets |
| Cloud | AWS access keys (AKIA...), S3 URIs |
| Crypto | Private key headers (RSA/DSA/EC/PGP/OPENSSH) |
| Database | Connection strings (MSSQL/MySQL/PostgreSQL/JDBC), SQL CREATE USER |
| AD-Specific | GPP cpassword, unattend.xml passwords, RDP passwords |
| Scripts | PowerShell credentials, CMD net user/psexec, ViewState keys |
| Infrastructure | Network config, SNMP community strings, Slack tokens |

### File Classification

| Severity | Examples |
|---|---|
| **Black** | .ppk, .kdbx, id_rsa, NTDS.DIT, SAM, SECURITY |
| **Red** | .pfx, .pem, passwords.txt, .git-credentials, web.config |
| **Yellow** | .bak, .keytab, unattend.xml |
| **Green** | .bash_history, ConsoleHost_History.txt |

---

## Kerberos Toolkit

14 pure Rust modules. Raw ASN.1 DER encoding — no external dependencies.

| Module | Description |
|---|---|
| **asktgt** | Request TGT (password/hash). PA-ENC-TIMESTAMP pre-auth, RC4-HMAC |
| **asktgs** | Request service ticket. AP-REQ with encrypted Authenticator |
| **roast** | Kerberoast (hashcat `$krb5tgs$`) + AS-REP roast (`$krb5asrep$`) |
| **preauthscan** | User enumeration + AS-REP target discovery |
| **forge/golden** | Forge TGT with custom PAC (krbtgt key, via ms-pac-forge) |
| **forge/silver** | Forge service ticket with custom PAC |
| **forge/diamond** | Request real TGT → decrypt PAC → modify → re-sign |
| **s4u** | S4U2Self + S4U2Proxy + Bronze Bit (CVE-2020-17049) |
| **brute** | Password spray (two-step: enumerate → validate, delay/jitter) |
| **changepw** | Kerberos password change (kpasswd, port 464) |
| **ticket** | KRB-CRED/kirbi import/export |
| **describe** | Ticket parser (flags, etype, times, SPN) |
| **tgssub** | SPN substitution in existing ticket |
| **crypto** | Key derivation: RC4 (NT hash), AES128, AES256, DES |

---

## Building

### Requirements

- Rust 1.85+ (edition 2021)
- MinGW GCC (Windows GNU targets)

### Commands

```bash
make windows_x64          # Static Windows x64 (~6MB)
make windows_x86          # Static Windows x86
make windows_noargs       # Domain-joined auto-detect
make windows_all          # All Windows builds
make linux_musl           # Fully static Linux
make linux_x86_64         # Linux x86_64
make linux_aarch64        # Linux ARM64
make macos                # macOS cross
make release              # Current platform
```

### Features

| Flag | Description |
|---|---|
| `default` | TLS + GSSAPI + NTLM |
| `nogssapi` | TLS + NTLM (cross-compilation) |
| `noargs` | Windows auto-detect domain |

---

## Architecture

```
src/
├── analyze/              # 73 security checks + graph engine + report export
│   ├── graph.rs          # petgraph DiGraph from typed AD objects
│   ├── checks.rs         # All security checks (2,100+ lines)
│   └── report.rs         # Console + JSON/CSV/Markdown export
├── kerberos/             # 14 attack modules
│   ├── asktgt.rs         # AS-REQ + PA-ENC-TIMESTAMP
│   ├── asktgs.rs         # TGS-REQ + AP-REQ
│   ├── roast.rs          # Kerberoast + AS-REP + preauthscan
│   ├── forge.rs          # Golden/Silver/Diamond ticket
│   ├── s4u.rs            # S4U2Self/Proxy + Bronze Bit
│   ├── brute.rs          # Password spray
│   ├── changepw.rs       # kpasswd (port 464)
│   └── ...               # ticket, describe, tgssub, crypto
├── snaffler/             # Credential scanner
│   ├── rules.rs          # 18 regex + extension/filename classification
│   └── scanner.rs        # File scanner + redaction
├── objects/              # 16 typed AD structs (serde)
├── transport/            # LDAP, SMB2, Kerberos, TLS cert
├── modules/              # Sessions, GPO/SYSVOL, ADCS ESC8
├── storage/              # Disk cache (bincode)
├── json/                 # BH CE v6 streaming JSON + ZIP64
└── api.rs                # Collection orchestration
```

### Data Flow

```
Auth (password/hash/kerberos/cert)
  → LDAP collect (paged, all naming contexts)
  → Rayon parallel parse (16 typed structs)
  → Post-parse checker (SID resolve, defaults)
  → Modules:
      ├── Sessions (SRVSVC/WKSSVC/WINREG over SMB2)
      ├── ADCS ESC8 probe (HTTP/HTTPS)
      └── SYSVOL (GptTmpl.inf + Groups.xml + Snaffler scan)
  → Analysis (--analyze):
      ├── Build petgraph (nodes + edges)
      ├── 73 security checks
      ├── Snaffler description scan
      └── Export (JSON/CSV/Markdown)
  → Output (BH CE v6 JSON/ZIP)
```

---

## Integrated Techniques

| Source | What | License |
|---|---|---|
| [RustHound-CE](https://github.com/g0h4n/RustHound-CE) | Object model, BH CE v6, transport, sessions, GPO | MIT |
| [BloodBash](https://github.com/DotNetRussell/BloodBash) | Graph analysis, pathfinding, ACL checks | MIT |
| [Rubeus](https://github.com/GhostPack/Rubeus) | Kerberos toolkit techniques | BSD-3 |
| [PrivescCheck](https://github.com/itm4n/PrivescCheck) | SMB/LDAP signing, relay, GPP detection | MIT |
| [PowerView.py](https://github.com/aniqfakhrul/powerview.py) | Foreign users, gMSA, RBCD, coercion | MIT |
| [ADAudit](https://github.com/azauditor/ADAudit) | Password age, FGPP, service hygiene | — |
| [phillips321/adaudit](https://github.com/phillips321/adaudit) | Protected Users, DC owners, RODC, recycle bin | GPL-3 |
| [AD_Miner](https://github.com/AD-Security/AD_Miner) | KRBTGT age, obsolete OS, tier-0 violations | GPL-3 |
| [Snaffler](https://github.com/SnaffCon/Snaffler) | Credential regex rules, file classification | MIT |

---

## Tests

137 tests across 4 suites:

```bash
cargo test    # 113 lib + 13 analyze + 11 crypto = 137 tests
```

## License

MIT
