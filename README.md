# 🛡️ SecureShield IDE

**Intelligent Secret Leakage Detection and Prevention for Software Development**

A production-grade VS Code extension that detects API keys, passwords, encryption keys,
JWT secrets, database credentials, and other sensitive credentials in your source code
**before they reach Git** — using an 8-gate detection pipeline with five independent
analysis layers.

---

## Why SecureShield?

Every year, millions of secrets are accidentally committed to public repositories.
A single leaked AWS key, OpenAI API key, or database password can result in:

- Financial loss (unauthorized cloud usage)
- Data breaches
- Compliance violations (GDPR, SOC2, PCI-DSS)
- Reputational damage

SecureShield stops leaks **at the source** — in the developer's IDE, before the
code ever touches Git.

---

## Features

### 🔍 Real-Time Detection
- Detects secrets **while you type** with <50ms latency
- Incremental scanning — only re-analyses changed lines
- Underlines detected secrets with severity-colored diagnostics

### 🎯 High Precision, Low Noise
- **8-gate pipeline** eliminates false positives at every stage
- Placeholder elimination (removes `your-api-key-here`, `<TOKEN>`, `example-*`)
- Format disambiguation (ignores UUIDs, Git SHAs, bcrypt hashes, CSS colors)
- Allowlist system with 3 levels: rule-level, global, developer-defined

### 🔧 One-Click Fix
- Moves hardcoded secrets to `.env` automatically
- Replaces source code with `process.env.KEY` (or language equivalent)
- Updates `.gitignore` with recommended entries
- Creates `.env.example` with safe placeholder values

### 🔒 Git Commit Protection
- Pre-commit hook blocks commits containing detected secrets
- Scans only staged files for speed
- Configurable blocking thresholds per severity level
- Integrates with Husky if present

### 📊 Security Dashboard
- Full statistics: detected, fixed, suppressed, commits blocked
- Severity distribution breakdown
- Detection history with fix status
- Database health monitor

---

## Installation

### Prerequisites
- VS Code 1.85.0 or later
- Node.js 18+

### From Source

```bash
# Clone the repository
git clone https://github.com/secureshield/secureshield-ide
cd secureshield-ide

# Install dependencies
npm install

# Build the extension
npm run build

# Run tests
npm test
```

Press **F5** in VS Code to launch the Extension Development Host.

---

## Configuration

Create `.secureshield.json` in your workspace root:

```json
{
  "version": 1,
  "detection": {
    "sensitivity": "balanced",
    "minimumConfidenceToWarn": 0.40
  },
  "git": {
    "blockCommitOnCritical": true,
    "blockCommitOnHigh": true,
    "blockCommitOnMedium": false
  },
  "ignore": {
    "paths": ["**/migrations/**", "**/seeds/**"],
    "stopwords": ["internal-placeholder"]
  },
  "customRules": [
    {
      "id": "company-internal-token",
      "description": "Company Internal API Token",
      "regex": "INT-[A-Z0-9]{32}",
      "severity": "critical"
    }
  ]
}
```

---

## Inline Suppression

To suppress a specific finding permanently:

```typescript
const apiKey = "sk-..."; // secureshield-ignore
```

To suppress an entire file, add to the first line:

```typescript
// secureshield-disable-file
```

---

## Commands

| Command | Description |
|---|---|
| `SecureShield: Scan Entire Workspace` | Manual full workspace scan |
| `SecureShield: Open Security Dashboard` | Open the statistics dashboard |
| `SecureShield: Install Git Pre-commit Hook` | Install commit protection |
| `SecureShield: Remove Git Pre-commit Hook` | Remove commit protection |
| `SecureShield: Export Security Report` | Export findings to JSON |
| `SecureShield: Clear Detection History` | Reset all statistics |

---

## Detection Architecture

```
Developer types code
       │
       ▼
Gate 0 — File Intelligence (exclude build output, lock files, binaries)
       │
       ▼
Gate 1 — Pre-Filter (O(1) keyword lookup — DB1 prefixes + DB2 identifiers)
       │
       ▼
Gate 2 — Placeholder Elimination (example, dummy, your-key-here)
       │
       ▼
Gate 3 — Format Disambiguation (UUIDs, Git SHAs, bcrypt outputs, CSS colors)
       │
       ▼
Gate 4 — Multi-Layer Detection
         ├── Layer 1: Regex Engine (222 Gitleaks rules)
         ├── Layer 2: Entropy Engine (Shannon entropy + charset analysis)
         ├── Layer 3: Context Engine (DB2 identifier index, ±5 line window)
         ├── Layer 4: StringGroup Engine (surrounding string literal analysis)
         └── Layer 5: File Context Scorer (file type + line type)
       │
       ▼
Gate 5 — Allowlist Engine (3-level: rule-level, global, developer-defined)
       │
       ▼
Gate 6 — Confidence Score Aggregation (weighted formula)
       │
       ▼
Gate 7 — Threshold Filter (minimum confidence to surface warning)
       │
       ▼
Gate 8 — Developer Memory (suppressed findings silently skipped)
       │
       ▼
Output — Diagnostic + Quick Fix + Dashboard + Git Protection
```

---

## Confidence Score Formula

```
BASE = (0.35 × regex) + (0.20 × entropy) + (0.20 × context)
     + (0.15 × stringGroup) + (0.10 × fileContext)

FINAL = BASE × fileRiskMultiplier × allowlistMultiplier
              × placeholderMultiplier × formatMultiplier

Hard overrides:
  Known provider match → floor at 0.90
  Inline ignore comment → 0.00
```

---

## Research Foundation

SecureShield implements ideas from:

> **"Checked-In Secret Detection: Strings Are All You Need"**
> Zhengdong Huang, Kevin Li, Jinqiu Yang, Yepang Liu, Lili Wei (2026)
> https://arxiv.org/abs/2608.04523

The paper proposes **StringGroup** — using surrounding string literals
rather than full code context for secret detection. SecureShield implements
this as **Layer 4 (StringGroupEngine)**, extended with a full IDE integration
layer, Git protection, and auto-remediation workflow not covered by the paper.

---

## Databases

| Database | Source | Contents |
|---|---|---|
| DB1 — Gitleaks Rules | `regex/assets/` | 222 regex rules, entropy thresholds, allowlists |
| DB2 — StringGroup Identifiers | `stringgroup/assets/` | 374 groups, ~94k identifier keywords |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [Gitleaks](https://github.com/gitleaks/gitleaks) — regex rules database (MIT)
- [detect-secrets](https://github.com/Yelp/detect-secrets) — detection concepts (Apache 2.0)
- Huang et al. — StringGroup research paper