# SecureShield IDE — Changelog

All notable changes to this project are documented in this file.

## [1.0.0] — Initial Release

### Added

#### Detection Engine
- 8-Gate detection pipeline with precision-first design
- Gate 0: File Intelligence — excludes build output, lock files, node_modules, binaries
- Gate 1: Pre-Filter — O(1) keyword lookup against DB1 and DB2 before expensive analysis
- Gate 2: Placeholder Elimination — removes developer-written example values
- Gate 3: Format Disambiguation — eliminates UUIDs, Git SHAs, bcrypt hashes, CSS colors
- Gate 4: Multi-Layer Detection with 5 independent engines
- Gate 5: Allowlist Engine — DB1 rule-level, global, and developer-defined allowlists
- Gate 6: Confidence Score Aggregator — weighted combination of all layer scores
- Gate 7: Threshold Filter — minimum confidence gating to reduce noise
- Gate 8: Developer Memory — permanent and session suppression of acknowledged findings

#### Detection Layers
- Layer 1: Regex Engine — 222 compiled Gitleaks rules with collision handling
- Layer 2: Entropy Engine — Shannon entropy with charset diversity analysis
- Layer 3: Context Engine — DB2 identifier lookup with distance-weighted scoring
- Layer 4: StringGroup Engine — paper implementation of surrounding string literal analysis
- Layer 5: File Context Scorer — file risk multipliers and line type classification

#### Databases
- DB1: Gitleaks TOML converted to JSON (222 rules, regex + entropy + allowlists)
- DB2: StringGroup identifier database (374 groups, ~94k identifier keywords)
- Keyword collision resolver for DB1's 37 shared keywords
- Lazy loader for per-group files

#### VS Code Integration
- Real-time detection while typing (debounced, 300ms default)
- Incremental scanning — only re-scans changed lines ±2 on typing trigger
- Diagnostic underlines with severity-mapped colors
- Quick Fix code actions: Fix Now, Mark as Safe, Ignore Once
- Hover tooltips with full confidence breakdown and detection signals
- File decorations (🔴🟠🟡🟢🔵) in Explorer sidebar
- Status bar indicator with finding count and highest severity
- Sidebar tree view grouped by severity
- Security dashboard webview with statistics, history, and database health
- Export security report to JSON

#### Remediation
- One-click .env migration with auto-generated env variable names
- Language-aware code replacement (TypeScript, Python, Go, Ruby, PHP, Java, C#, Rust)
- Automatic .gitignore update with recommended entries
- .env.example generation with placeholder values
- Inline suppression comment support (// secureshield-ignore)

#### Git Protection
- Pre-commit hook installer (direct Git hooks and Husky integration)
- Staged-file-only scanning via `git show :file`
- Configurable blocking thresholds per severity
- CLI output with clear remediation instructions
- Fail-open design (scanner errors do not block commits)

#### Configuration
- .secureshield.json with JSON schema validation
- Configurable detection weights, thresholds, and sensitivity
- Custom rule definitions for organization-specific secrets
- Path/pattern/stopword ignore lists
- Remediation preferences

#### AI Assistant Detection
- Informational notice when GitHub Copilot, Codeium, Tabnine, or other AI
  assistants are detected (informational only, no interference)

### Supported Languages
TypeScript, JavaScript, Python, Go, Rust, Java, C#, PHP, Ruby,
YAML, JSON, TOML, Shell scripts, .env files

### Supported Secret Types
AWS, Azure, Google Cloud, OpenAI, Anthropic, Stripe, PayPal,
GitHub, GitLab, Slack, Discord, Twilio, SendGrid, Firebase,
Supabase, JWT, RSA/EC private keys, database connection strings,
and 200+ more via Gitleaks ruleset