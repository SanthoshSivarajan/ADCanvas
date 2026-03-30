# ADCanvas

### Paint the Full Picture of Your Active Directory

**Author:** Santhosh Sivarajan, Microsoft MVP
**GitHub:** [https://github.com/SanthoshSivarajan/ADCanvas](https://github.com/SanthoshSivarajan/ADCanvas)

---

## Overview

ADCanvas is a single PowerShell script that enumerates your entire Active Directory forest -- every domain, every domain controller, every object class -- and generates a **self-contained HTML report**. No external dependencies, no internet connection required, no agents to install.

Run one script. Open one HTML file. See everything.

## Quick Start

```powershell
.\ADCanvas.ps1
```

Open the generated `ADCanvas_<timestamp>.html` in any browser.

## What ADCanvas Collects

### Forest-Level

| Category | Details |
|---|---|
| **Forest Configuration** | Name, root domain, forest functional level (friendly name), global catalogs, UPN/SPN suffixes |
| **Schema** | Schema version mapped to Windows Server version (2000 through Server 2025), tombstone lifetime, garbage collection period |
| **SYSVOL Replication** | FRS vs DFSR detection |
| **FSMO Roles** | Schema Master, Domain Naming Master (forest-wide); PDC, RID, Infrastructure (per-domain) |
| **Sites & Subnets** | All AD sites, subnets with locations, site links with cost and replication frequency |
| **Replication** | Forest-wide partner metadata, per-DC replication failures, connection objects |
| **DNS Zones** | All zones with type, DS-integration status, replication scope (auto-targets a DC running DNS) |
| **DNS Forwarders** | Configured forwarders on the DNS server |
| **Trust Relationships** | All domain and forest trusts from every domain -- direction, type, transitivity, selective auth, SID filtering |
| **Entra Connect / AAD Connect** | Detects MSOL_ and Sync_ service accounts, extracts server name |
| **AD Certificate Services** | Detects Enterprise CAs registered in AD (pKIEnrollmentService objects) |
| **LAPS** | Detects Windows LAPS (built-in) and Legacy Microsoft LAPS via schema attributes |
| **dMSA Support** | Detects Delegated Managed Service Account schema support (Server 2025+) |
| **AD Recycle Bin** | Enabled or disabled status |
| **BitLocker Keys** | Whether BitLocker recovery keys are stored in AD |
| **Optional Features** | Recycle Bin, PAM, and other optional AD features |

### Per-Domain (collected separately for each domain in the forest)

| Category | Details |
|---|---|
| **Domain Configuration** | DNS name, NetBIOS, functional level (friendly name), parent/child domains, per-domain FSMO holders |
| **Domain Controllers** | Name, Domain, IP, Type (RWDC/RODC), OS, OS Build Version, Site, Global Catalog status, FSMO roles, Enabled status |
| **User Accounts** | Total, enabled, disabled, locked out, password expired, password never expires, never logged on, inactive 90+ days |
| **Computer Accounts** | Total, enabled, disabled, servers vs workstations, OS distribution |
| **Groups** | Total, security/distribution, global/domain local/universal scope, empty groups |
| **Privileged Groups** | Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account/Server/Backup/Print Operators with member names |
| **Service Accounts** | sMSA (Standalone), gMSA (Group), dMSA (Delegated) with status, creation date, password interval |
| **Group Policy Objects** | All GPOs with status (enabled/disabled/partial), creation and modification dates |
| **Organizational Units** | Full OU list with accidental deletion protection status |
| **Password Policies** | Default domain password policy (length, history, complexity, lockout) |
| **Fine-Grained Password Policies** | All FGPPs with precedence, length, age, complexity, lockout settings |

### Visual Components (11+ Charts + 5 SVG Diagrams)

**Charts:**
- User Accounts (donut) -- forest-wide status breakdown
- Computer Accounts (donut) -- forest-wide status breakdown
- DC Type Distribution (donut) -- RWDC vs RODC
- DCs by Site (bar)
- Groups (bar) -- security/distribution/scope breakdown
- GPO Status (bar) -- enabled/disabled/partial
- OS Distribution (donut)
- Users by Domain (bar) -- cross-domain comparison
- Computers by Domain (bar)
- DCs by Domain (bar)
- Privileged Group Members (bar) -- top 15 across all domains

**SVG Diagrams:**
- FSMO Role Distribution -- which DCs hold which roles
- DC Topology by Site -- DCs grouped by site with OS build, domain, GC/RODC badges
- Site Topology -- sites connected by replication links with cost/frequency
- Trust Relationships -- visual arrows showing direction and type
- OU Hierarchy -- indented tree grouped by domain with deletion-protection indicators

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7+
- **RSAT Active Directory Module** (`ActiveDirectory`) -- required
- **Group Policy Module** (`GroupPolicy`) -- optional, for GPO data
- **DNS Server Module** (`DnsServer`) -- optional, for DNS zone data
- Domain-joined machine with read access to AD
- For multi-domain forests: read permissions across all domains (Enterprise Admin or equivalent)

## Usage

```powershell
# Run from any domain-joined machine with RSAT installed
.\ADCanvas.ps1
```

Output:
```
ADCanvas_2026-03-30_143022.html
```

Open in any browser. No web server needed -- fully self-contained HTML with inline CSS, JS, and SVG.

## Error Handling

ADCanvas is designed to be resilient:

- If individual child domains are unreachable (firewall, permissions), remaining domains are still enumerated
- If DNS, GPO, ADCS, or service account modules fail, those sections show as empty -- the report still generates
- DNS zone collection auto-targets Domain Controllers (PDC Emulator first, then falls through all DCs)
- Fine-Grained Password Policy collection has a fallback method using direct LDAP object queries
- Console output clearly shows which components were collected and which were skipped

## Report Features

- **Dark navy/slate theme** with sidebar navigation
- **Per-domain sections** -- each domain gets its own complete section
- **Forest-wide summary** -- aggregated totals across all domains
- **Domain Summary table** -- all domains with functional levels, DC counts, object counts
- **All DCs table** -- every DC in the forest in one table
- **Responsive design** -- works on desktop, tablet, and mobile
- **Print-friendly** -- automatic light theme when printing
- **Zero external dependencies** -- all CSS, JS, and SVG are inline

## Domain Functional Level Support

ADCanvas maps both string and numeric functional levels to friendly names:

| Value | Display |
|---|---|
| Windows2016Domain / 7-9 | Windows Server 2016 |
| 10 | Windows Server 2025 |
| Windows2012R2Domain / 6 | Windows Server 2012 R2 |
| Windows2012Domain / 5 | Windows Server 2012 |
| Windows2008R2Domain / 4 | Windows Server 2008 R2 |
| Windows2008Domain / 3 | Windows Server 2008 |

## Schema Version Support

| Schema Version | Windows Server |
|---|---|
| 91 | Windows Server 2025 |
| 90 | Windows Server 2025 |
| 88 | Windows Server 2019/2022 |
| 87 | Windows Server 2016 |
| 69 | Windows Server 2012 R2 |
| 56 | Windows Server 2012 |

## License

MIT -- Free to use, modify, and distribute.

## Contributing

Pull requests welcome. Please open an issue first to discuss major changes.

---

*Developed by Santhosh Sivarajan, Microsoft MVP -- santhosh@sivarajan.com*
