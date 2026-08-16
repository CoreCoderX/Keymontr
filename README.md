# Keymontr

**Intelligent secret leakage detection and prevention for software development.**

Keymontr is a production-grade VS Code extension that detects API keys, passwords,
encryption keys, JWT secrets, database credentials, and 200+ other sensitive
credential types in your source code **before they reach Git** — using an
8-gate detection pipeline with five independent analysis layers.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![VS Code](https://img.shields.io/badge/VS%20Code-%5E1.131.0-007ACC.svg)](#prerequisites)
[![TypeScript](https://img.shields.io/badge/TypeScript-6.0-3178C6.svg)](tsconfig.json)
[![Version](https://img.shields.io/badge/version-0.1.0-important.svg)](package.json)
[![Gitleaks Rules](https://img.shields.io/badge/rules-222-4B8BBE.svg)](regex/assets/gitleaks-rules.json)
[![StringGroup DB](https://img.shields.io/badge/stringgroups-374-6BA81E.svg)](stringgroup/assets/stringgroups.json)

---

## Table of Contents

- [Why Keymontr?](#why-keymontr)
- [Features](#features)
- [How It Works](#how-it-works)
  - [The 8-Gate Detection Pipeline](#the-8-gate-detection-pipeline)
  - [The 5 Detection Layers](#the-5-detection-layers)
- [Confidence Score Formula](#confidence-score-formula)
- [What Keymontr Detects](#what-keymontr-detects)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Commands](#commands)
- [Inline Suppression](#inline-suppression)
- [Git Commit Protection](#git-commit-protection)
- [Security Dashboard](#security-dashboard)
- [Project Structure](#project-structure)
- [Development](#development)
- [Research Foundation](#research-foundation)
- [Databases](#databases)
- [Roadmap](#roadmap)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Why Keymontr?

Every year, millions of secrets are accidentally committed to public
repositories. A single leaked AWS key, OpenAI API key, or database password can
result in:

| Risk | Example Impact |
|---|---|
| Financial loss | Unauthorized cloud usage, cryptocurrency mining, premium API abuse |
| Data breach | Customer records, PII, and internal data exfiltration |
| Compliance violations | GDPR, SOC 2, PCI-DSS, HIPAA audit failures and fines |
| Reputational damage | Public disclosure, incident post-mortems, lost trust |

Traditional solutions catch these problems **after** the damage is done —
at CI time or via secret-scanning bots that alert you to secrets already
exposed in your history. Keymontr stops leaks **at the source**: in the
developer's IDE, while you type, before the code ever touches Git.

### Keymontr vs. CI-based scanning

| | Keymontr (IDE) | CI / Push scanning |
|---|---|---|
| Detection point | While typing, at commit | After push / at merge |
| Exposure window | None — secrets never enter history | Secret already in git history |
| Fix effort | One-click `.env` migration | History rewrite, key rotation |
| Feedback loop | Milliseconds | Minutes to hours |
| Coverage | Every developer, every keystroke | Only code that reaches the pipeline |

---

## Features

### Real-Time Detection

- Detects secrets **while you type** with sub-100ms latency (300 ms debounce)
- Incremental scanning — only re-analyzes changed lines (±2 line window)
- Underlines detected secrets with severity-colored diagnostics
- File decorations in the Explorer and a status bar indicator with finding
  count and highest severity
- Hover tooltips with a full confidence breakdown and the detection signals
  that fired

### High Precision, Low Noise

- **8-gate pipeline** eliminates false positives at every stage
- Placeholder elimination removes `your-api-key-here`, `<TOKEN>`,
  `example-*`, and other developer-written dummy values
- Format disambiguation ignores UUIDs, Git SHAs, bcrypt hashes, and CSS colors
- 3-level allowlist system: rule-level, global, and developer-defined
- Line-type awareness: comments, imports, and array elements are scored
  differently than assignments

### One-Click Fix

- Moves hardcoded secrets to `.env` automatically
- Replaces source code with `process.env.KEY` (or language equivalent)
- Updates `.gitignore` with recommended entries
- Creates `.env.example` with safe placeholder values
- Quick Fix actions: **Fix Now**, **Mark as Safe**, **Ignore Once**

### Git Commit Protection

- Pre-commit hook blocks commits containing detected secrets
- Scans only staged files for speed (`git show :file`)
- Configurable blocking thresholds per severity level
- Integrates with Husky when present
- Fail-open design — scanner errors never block your commits

### Security Dashboard

- Full statistics: detected, fixed, suppressed, commits blocked
- Severity distribution breakdown
- Detection history with fix status
- Database health monitor
- JSON export of security reports

---

## How It Works

```
Developer types code
       |
       v
Gate 0 - File Intelligence (exclude build output, lock files, binaries)
       |
       v
Gate 1 - Pre-Filter (O(1) keyword lookup - DB1 prefixes + DB2 identifiers)
       |
       v
Gate 2 - Placeholder Elimination (example, dummy, your-key-here)
       |
       v
Gate 3 - Format Disambiguation (UUIDs, Git SHAs, bcrypt outputs, CSS colors)
       |
       v
Gate 4 - Multi-Layer Detection
         |-- Layer 1: Regex Engine (222 Gitleaks rules)
         |-- Layer 2: Entropy Engine (Shannon entropy + charset analysis)
         |-- Layer 3: Context Engine (DB2 identifier index, +-5 line window)
         |-- Layer 4: StringGroup Engine (surrounding string literal analysis)
         `-- Layer 5: File Context Scorer (file type + line type)
       |
       v
Gate 5 - Allowlist Engine (3-level: rule-level, global, developer-defined)
       |
       v
Gate 6 - Confidence Score Aggregation (weighted formula)
       |
       v
Gate 7 - Threshold Filter (minimum confidence to surface warning)
       |
       v
Gate 8 - Developer Memory (suppressed findings silently skipped)
       |
       v
Output - Diagnostic + Quick Fix + Dashboard + Git Protection
```

### The 8-Gate Detection Pipeline

| Gate | Name | Purpose |
|---|---|---|
| 0 | File Intelligence | Excludes build output, lock files, `node_modules`, binaries |
| 1 | Pre-Filter | O(1) keyword lookup against DB1 prefixes and DB2 identifiers before any expensive analysis |
| 2 | Placeholder Elimination | Removes developer-written example values |
| 3 | Format Disambiguation | Eliminates UUIDs, Git SHAs, bcrypt hashes, CSS colors |
| 4 | Multi-Layer Detection | Runs 5 independent detection engines (see below) |
| 5 | Allowlist Engine | Applies rule-level, global, and developer-defined allowlists |
| 6 | Confidence Aggregator | Combines all layer scores via a weighted formula |
| 7 | Threshold Filter | Gates on minimum confidence to reduce noise |
| 8 | Developer Memory | Silently skips findings the developer acknowledged |

### The 5 Detection Layers

| Layer | Engine | Description |
|---|---|---|
| 1 | Regex Engine | 222 compiled Gitleaks rules with collision handling |
| 2 | Entropy Engine | Shannon entropy plus charset diversity analysis |
| 3 | Context Engine | DB2 identifier lookup with distance-weighted scoring (+-5 line window) |
| 4 | StringGroup Engine | Surrounding string literal analysis (research paper implementation) |
| 5 | File Context Scorer | File risk multipliers and line-type classification |

File risk levels modulate final scores: excluded (`0.0x`), reduced (`0.5x`),
normal (`1.0x`), elevated (`1.2x`), and high (`1.4x`). A hardcoded value in a
`.env` file is far more suspicious than the same string in a README comment.

---

## Confidence Score Formula

```
BASE = (0.35 x regex) + (0.20 x entropy) + (0.20 x context)
     + (0.15 x stringGroup) + (0.10 x fileContext)

FINAL = BASE x fileRiskMultiplier x allowlistMultiplier
              x placeholderMultiplier x formatMultiplier
```

Hard overrides:

- Known provider match -> floor at 0.90
- Inline ignore comment -> 0.00

Severity is derived from the final score:

| Confidence | Severity |
|---|---|
| 0.88 - 1.00 | Critical |
| 0.75 - 0.88 | High |
| 0.65 - 0.75 | Medium |
| 0.55 - 0.65 | Low |
| 0.40 - 0.55 | Informational |
| < 0.40 | Not surfaced |

---

## What Keymontr Detects

### Supported Secret Types

AWS, Azure, Google Cloud, OpenAI, Anthropic, Stripe, PayPal, GitHub, GitLab,
Slack, Discord, Twilio, SendGrid, Firebase, Supabase, JWT, RSA/EC private keys,
database connection strings, and 200+ more via the Gitleaks ruleset.

### Supported Languages

| Category | Languages |
|---|---|
| Programming | TypeScript, JavaScript, Python, Go, Rust, Java, C#, PHP, Ruby |
| Config / Markup | YAML, JSON, TOML, Shell scripts, `.env` files |

### AI Assistant Awareness

Keymontr detects when GitHub Copilot, Codeium, Tabnine, or other AI coding
assistants are active and adjusts its notification behavior accordingly —
informational only, never interfering with the assistant.

---

## Installation

### Prerequisites

| Requirement | Minimum |
|---|---|
| VS Code | 1.131.0 or later |
| Node.js | 18+ |
| Python (dev only) | 3.11+ (for regenerating the regex database) |

### From Source

```bash
# Clone the repository
git clone https://github.com/CoreCoderX/Keymontr.git
cd Keymontr

# Install dependencies
npm install

# Build the extension
npm run build

# Run tests
npm test
```

Press **F5** in VS Code to launch the Extension Development Host, or install
the generated `.vsix` package.

---

## Quick Start

1. Install the extension and reload VS Code.
2. Open a project. Keymontr starts scanning immediately.
3. Type or open a file — detected secrets are underlined with severity colors.
4. Hover over a finding to see the confidence breakdown and detection signals.
5. Click the lightbulb and choose **Fix Now** to migrate the secret to `.env`.
6. Run **Keymontr: Install Git Pre-commit Hook** to protect future commits.

---

## Configuration

Create `.keymontr.json` in your workspace root (JSON schema validation is
built in):

```json
{
  "$schema": "./schemas/keymontr-config.schema.json",
  "version": 1,

  "detection": {
    "sensitivity": "balanced",
    "minimumConfidenceToWarn": 0.40,
    "debounceMs": 300,
    "weights": {
      "regex": 0.35,
      "entropy": 0.20,
      "context": 0.20,
      "stringGroup": 0.15,
      "fileContext": 0.10
    }
  },

  "git": {
    "blockCommitOnCritical": true,
    "blockCommitOnHigh": true,
    "blockCommitOnMedium": false,
    "enablePreCommitHook": true
  },

  "ui": {
    "enableSounds": false,
    "showStatusBar": true,
    "showFileDecorations": true,
    "inlineSeverityIcons": true,
    "showConfidenceScore": true
  },

  "ignore": {
    "paths": ["**/migrations/**", "**/seeds/**"],
    "patterns": [],
    "stopwords": ["internal-placeholder"],
    "useDefaultIgnorePaths": true,
    "useDefaultStopwords": true
  },

  "customRules": [
    {
      "id": "company-internal-token",
      "description": "Company Internal API Token",
      "regex": "INT-[A-Z0-9]{32}",
      "severity": "critical"
    }
  ],

  "remediation": {
    "autoCreateEnvFile": true,
    "autoUpdateGitignore": true,
    "autoCreateEnvExample": true,
    "preferredEnvFileName": ".env"
  }
}
```

### VS Code Settings

| Setting | Default | Description |
|---|---|---|
| `keymontr.configFilePath` | `.keymontr.json` | Path to the Keymontr configuration file |
| `keymontr.enableRealTimeDetection` | `true` | Enable real-time secret detection |
| `keymontr.minimumConfidenceToWarn` | `0.4` | Minimum confidence to show a warning |

---

## Commands

| Command | Description |
|---|---|
| `Keymontr: Scan Workspace` | Manual full workspace scan |
| `Keymontr: Open Dashboard` | Open the statistics dashboard |
| `Keymontr: Fix Secret` | Migrate a secret to `.env` with code replacement |
| `Keymontr: Mark as Safe` | Add a finding to the developer allowlist |
| `Keymontr: Export Security Report` | Export findings to JSON |
| `Keymontr: Install Git Pre-commit Hook` | Install commit protection |
| `Keymontr: Remove Git Pre-commit Hook` | Remove commit protection |
| `Keymontr: Clear Detection History` | Reset all statistics |

---

## Inline Suppression

To suppress a specific finding permanently:

```typescript
const apiKey = "sk-..."; // keymontr-ignore
```

To suppress an entire file, add to the first line:

```typescript
// keymontr-disable-file
```

---

## Git Commit Protection

Keymontr installs a pre-commit hook that:

1. Scans only staged files (`git show :file`) for speed
2. Blocks the commit if a Critical or High secret is found (configurable)
3. Prints clear remediation instructions in the terminal
4. Fails open — scanner errors do not block commits

```bash
# Install the hook
git add . && git commit -m "fix: update config"   # after installing via command palette
```

Remove the hook at any time with **Keymontr: Remove Git Pre-commit Hook**.

---

## Security Dashboard

The dashboard webview gives you full visibility into your secret hygiene:

- Detected / fixed / suppressed / blocked counts
- Severity distribution chart
- Detection history with fix status
- Database health monitor (rule counts, index integrity)
- Export findings to JSON for audit trails

---

## Project Structure

```
Keymontr/
|-- src/
|   |-- core/
|   |   |-- pipeline/       # Gate 0-8 implementation
|   |   |-- layers/         # Layer 1-5 detection engines
|   |   |-- types/          # Finding, confidence, severity, rule types
|   |   `-- utils/          # Tokenizer, Shannon entropy, line classifier
|   |-- database/           # DB1 (Gitleaks) + DB2 (StringGroup) loaders
|   |-- config/             # .keymontr.json parsing and validation
|   |-- remediation/        # .env migration, code replacement, .gitignore
|   |-- git/                # Pre-commit hook, Husky integration, blocker
|   |-- vscode/             # Diagnostics, hovers, code actions, views, dashboard
|   |-- storage/            # History, developer memory, global state
|   |-- ai/                 # AI assistant detection
|   `-- extension.ts        # Activation entry point
|-- regex/                  # Gitleaks rule database (222 rules, generated)
|-- stringgroup/            # Curated identifier database (374 groups)
|-- schemas/                # JSON schema for .keymontr.json
|-- media/                  # Extension icon
|-- scripts/                # Database build and verification scripts
```

---

## Development

```bash
npm run build          # Build with esbuild
npm run watch          # Watch mode
npm run typecheck      # TypeScript type checking
npm run lint           # ESLint
npm test               # Jest test suite
npm run test:coverage  # Test suite with coverage
npm run check          # typecheck + lint + test
```

> New to the codebase? Start with `src/core/pipeline/` — the 8 gates flow
> in order, and each gate is a small, self-contained class.

---

## Research Foundation

Keymontr implements ideas from:

> **"Checked-In Secret Detection: Strings Are All You Need"**
> Zhengdong Huang, Kevin Li, Jinqiu Yang, Yepang Liu, Lili Wei (2026)
> https://arxiv.org/abs/2608.04523

The paper proposes **StringGroup** — using surrounding string literals
rather than full code context for secret detection. Keymontr implements
this as **Layer 4 (StringGroupEngine)**, extended with a full IDE
integration layer, Git protection, and an auto-remediation workflow not
covered by the paper.

---

## Databases

| Database | Source | Contents |
|---|---|---|
| DB1 - Gitleaks Rules | `regex/assets/` | 222 regex rules, entropy thresholds, allowlists |
| DB2 - StringGroup Identifiers | `stringgroup/assets/` | 374 groups, ~94k identifier keywords |

Both databases ship as JSON with a flat `keyword -> group` index, enabling
O(1) pre-filter lookups at runtime. See the [regex](regex/README.md) and
[stringgroup](stringgroup/README.md) documentation for regeneration details.

---

## Roadmap

- [ ] Marketplace publication
- [ ] Multi-root workspace support
- [ ] Team-shared allowlist sync (org rules)
- [ ] Additional remediation targets (Docker secrets, CI variables)
- [ ] Pre-push hook option in addition to pre-commit
- [ ] Git history scanning for existing exposures

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [Gitleaks](https://github.com/gitleaks/gitleaks) — regex rules database (MIT)
- [detect-secrets](https://github.com/Yelp/detect-secrets) — detection concepts (Apache 2.0)
- Huang et al. — StringGroup research paper
