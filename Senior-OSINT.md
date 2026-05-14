# Senior OSINT

External attack-surface discovery, asset mapping, passive recon, and evidence-driven enumeration for authorized security assessments.

## Table of Contents

- [Project Setup](#project-setup)
- [Rules of Engagement](#rules-of-engagement)
- [Recon Workflow](#recon-workflow)
- [Phase 1 — Triage](#phase-1--triage)
- [Phase 2 — Domain and Asset Expansion](#phase-2--domain-and-asset-expansion)
- [Phase 3 — Exposure Validation](#phase-3--exposure-validation)
- [Phase 4 — CVE and Weakness Mapping](#phase-4--cve-and-weakness-mapping)
- [Phase 5 — Reporting Inputs](#phase-5--reporting-inputs)
- [Tooling Reference](#tooling-reference)
- [Resource Pack](#resource-pack)

---

## Project Setup

OSINT is only useful when it is organized. Create a workspace that separates raw captures, normalized findings, and reporting artifacts.

### Recommended Directory Layout

```text
osint-workspace/
├── 00_scope/
│   ├── authorization.txt
│   ├── targets.txt
│   └── exclusions.txt
├── 01_raw/
│   ├── screenshots/
│   ├── html/
│   ├── logs/
│   └── exports/
├── 02_normalized/
│   ├── assets.csv
│   ├── domains.csv
│   ├── ip_ranges.csv
│   └── findings.json
├── 03_evidence/
│   ├── notes.md
│   ├── captures/
│   └── timestamps.txt
└── 04_report/
    ├── draft.md
    └── final.md
```

### Working Principles

1. Keep raw output untouched.
2. Normalize only after validation.
3. Timestamp every important observation.
4. Track confidence, not just presence.
5. Separate passive intelligence from active verification.

### Scope Variables

```bash
TARGET_ORG="example.com"
TARGET_ROOT_DOMAIN="example.com"
TARGET_ASN="AS12345"
TARGET_NETBLOCKS="203.0.113.0/24"
```

### Safety Note

Only run active checks on systems you are explicitly allowed to test. Passive reconnaissance can still create risk if you exceed terms of service or collect personal data without a legitimate purpose.

---

## Rules of Engagement

Before any recon begins, define what is allowed.

### Minimum Rules

- Written authorization is required.
- State whether the work is passive only, active only, or mixed.
- List excluded IPs, hosts, brands, and environments.
- Define throttling limits.
- Confirm whether login pages, production assets, and third-party services are in scope.
- Agree on evidence handling and data retention.

### Evidence Quality Targets

| Item | Minimum standard |
|------|------------------|
| Host discovery | Hostname, source, timestamp, confidence |
| Service exposure | Port, protocol, banner, screenshot |
| Credential leak | Location, snippet, hash of artifact, secrecy risk |
| CVE linkage | Product, version, validation source |
| Reporting | Reproducible, concise, bounded to scope |

---

## Recon Workflow

A strong OSINT workflow moves from broad to narrow without jumping to conclusions.

### Flow

1. Seed the target with root domains, company names, ASN, brands, and product names.
2. Expand through passive DNS, certificates, archive data, public code, and search engines.
3. Cluster assets by business unit or technology stack.
4. Validate exposure with minimal-impact checks.
5. Map results to risk categories and candidate weaknesses.

### What to Capture

- Domains and subdomains
- IPs and ASN ownership
- TLS certificate subjects and SANs
- Visible technologies and versions
- Public code mentions
- Open storage, panels, or staging assets
- Leaked credentials or secrets references
- URLs that reveal administrative or sensitive functionality

### Simple Triage Formula

```text
Priority = (Exposure + Sensitivity + Reachability + Novelty) - (Noise + Duplication)
```

Use this to rank findings for follow-up rather than treating every result equally.

---

## Phase 1 — Triage

Start with the fastest tools and the broadest signals.

### Nmap Triage Pattern

Nmap is for active validation, not blind flooding. Use it to confirm what passive recon suggests.

```bash
nmap -Pn -sV -sC -O -T3 --top-ports 200 --reason target.example
```

Use a narrower profile when the target is sensitive:

```bash
nmap -Pn -sV --version-light -T2 -p 80,443,8080,8443 target.example
```

### Triage Checklist

- Is the host actually alive?
- Is the banner real or a proxy artifact?
- Is the asset public, staging, or internal-looking?
- Is the service internet-facing or hidden behind a CDN?
- Does the response indicate a managed provider rather than the target itself?

### Good Triage Notes

```text
2026-05-08 10:14 BRT | api-staging.example.com
- TCP/443 open
- TLS CN mentions staging
- Response page contains debug footer
- Likely non-prod environment
- Confidence: medium
```

---

## Phase 2 — Domain and Asset Expansion

The goal here is breadth. Use multiple sources and keep a record of how each asset was found.

### Subdomain Discovery Stack

Use a mix of passive and active sources, but keep the output deduplicated.

#### Typical pipeline

```bash
subfinder -d example.com -silent -all -recursive > raw_subfinder.txt
amass enum -passive -d example.com -o raw_amass.txt
```

Then normalize:

```bash
cat raw_subfinder.txt raw_amass.txt | sort -u > subdomains.txt
```

### Strong Signals to Prioritize

- `dev`, `stage`, `staging`, `preprod`
- `api`, `admin`, `portal`, `auth`
- `backup`, `old`, `legacy`, `internal`
- `grafana`, `kibana`, `jenkins`, `git`, `registry`

### Search-Engine Discovery

Google dorks should be written as targeted, narrowly scoped queries. Use them to find:

- exposed directory listings
- indexed login pages
- PDF manuals and vendor docs
- public code references
- cached pages or fragments
- leaked file names or error pages

#### Example query classes

```text
site:example.com intitle:"index of"
site:example.com filetype:pdf confidential
site:example.com "password reset"
site:example.com "swagger"
site:example.com "admin login"
```

### Shodan Discovery

Shodan helps map internet-facing services and metadata. Use filters to narrow the scope.

#### Example query classes

```text
ssl.cert.subject.cn:"example.com"
hostname:example.com
org:"Example Corp"
port:22 country:BR
http.title:"admin"
```

### Validation Notes

A result is not a finding until it is validated. Many indexed pages, old banners, and stale DNS records will point to dead infrastructure. Keep a dead/live note on every asset.

---

## Phase 3 — Exposure Validation

This phase confirms whether discovered assets are reachable and whether the exposure matters.

### Validation Categories

| Category | What to confirm |
|----------|------------------|
| HTTP exposure | Title, headers, status, auth gate |
| Service exposure | Version, banner, patch age, ownership |
| File exposure | Is it public, indexed, or auth-protected? |
| Secrets exposure | Is it real, revoked, scoped, or historical? |
| Admin exposure | Is the panel public and branded? |

### Secrets Discovery

Use secret scanning carefully and only where permitted.

#### Common sources

- public Git repositories
- CI/CD logs
- paste mirrors
- issue trackers
- package registries
- public object storage listings
- docs pages and samples

#### Validation questions

- Is the token live?
- Does it have read-only scope?
- Is it revoked?
- Is it a sample value?
- Does the surrounding context expose enough to reconstruct a secret?

### Recommended Output Schema

```json
{
  "asset": "api-staging.example.com",
  "source": "subfinder + nmap",
  "type": "staging-api",
  "confidence": "medium",
  "evidence": [
    "TLS certificate SAN",
    "HTTP title",
    "Nmap version banner"
  ],
  "risk_hint": "possible exposed test interface"
}
```

---

## Phase 4 — CVE and Weakness Mapping

This phase translates exposure into likely weakness classes and known CVEs.

### CVE Mapping Workflow

1. Identify product and version.
2. Confirm the version from at least two sources when possible.
3. Look for vendor advisories and changelogs.
4. Compare against current CVE databases and trusted advisories.
5. Note whether the version is really vulnerable or merely near the vulnerable range.

### Sources to Cross-Check

- vendor security advisories
- NVD entries
- GitHub security advisories
- project changelogs
- package manager metadata
- public issue trackers
- distribution security notices

### Common Weakness Patterns

- outdated web server or framework
- exposed debug endpoints
- default credentials
- insecure headers or cookie settings
- weak access control
- sensitive files and backups
- exposed dashboards and metrics
- misconfigured object storage

### CVE Note Template

```text
Product: nginx
Observed version: 1.24.x
Evidence: server header, package metadata, deploy note
CVE candidates: verify with vendor advisory and patch history
Risk: medium
Status: unconfirmed until version is validated on-target
```

---

## Phase 5 — Reporting Inputs

Good recon notes make later reporting faster.

### What to preserve

- exact command used
- timestamp and timezone
- source of truth
- raw output excerpt
- screenshot if human review matters
- confidence level
- why the asset matters

### Minimal Evidence Bundle

```text
- one-line summary
- exact target
- observation
- proof
- impact hint
- validation note
```

### Example Finding Note

```markdown
### Exposed staging host

**Target:** `stage.example.com`  
**Observed:** Public login page with debug banner and version footer  
**Evidence:** Screenshot + HTTP headers + Nmap service banner  
**Impact:** Likely lower-hardening environment; could expose test data or weaker auth flows  
**Confidence:** Medium
```

---

## Tooling Reference

### Nmap

Useful for active confirmation of exposed services and version hints. Prefer restrained scans and only confirm what you already have reason to believe exists.

### Shodan

Useful for internet-wide metadata, certificates, banners, and service fingerprints.

### Subfinder

Passive subdomain enumeration with a clean workflow and fast output.

### Amass

Best used for wider asset graphing and attack-surface intelligence.

### Secret Scanners

Use to locate accidental exposures in public code, docs, or artifacts. Treat results as evidence candidates, not instant truths.

### CVE Databases

Cross-reference product and version with multiple sources before drawing a conclusion.

---

## Resource Pack

### Official / Primary

- Nmap reference guide and manual
- Nmap changelog and release archive
- OWASP Top Ten 2025
- OWASP Web Security Testing Guide
- OWASP Amass docs
- ProjectDiscovery Subfinder docs
- Shodan search filters and advanced search docs
- ZAP passive and active scan docs

### Recent Community Reading

- Medium posts on OSINT tooling and reconnaissance workflows
- Medium writeups on bug bounty recon pipelines
- Medium articles on reporting structure and PoC writing

### Suggested Reading Order

1. OWASP WSTG
2. OWASP Top Ten 2025
3. Amass docs
4. Subfinder docs
5. Shodan search examples
6. ZAP passive/active scan docs
7. Selected community writeups for workflow ideas

---
