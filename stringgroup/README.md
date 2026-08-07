# Secret Identifier StringGroups Database

A comprehensive, machine-readable database of identifier names that are commonly used to hold secrets — API keys, tokens, passwords, private keys, credentials, webhook secrets, and similar — across clouds, AI providers, SaaS platforms, frameworks, CI/CD systems, databases, and configuration formats.

The database is built for **secret scanners**: given a variable name, constant name, config key, env var, or object property name, it tells you which secret category (if any) it matches — with enough coverage to power features like rich diagnostics ("matched an AWS credential" vs. "matched an OpenAI API key").

---

## Layout

```
.
├── README.md                          # this file
│
├── assets/                            # generated runtime layout (374 groups, ~94k keywords)
│   ├── stringgroups.json              #   Group -> Keywords   (object keyed by group name)
│   ├── keyword-index.json             #   Keyword -> Group    (flat O(1) lookup map)
│   └── groups/                        #   one file per group
│       ├── aws.json
│       ├── azure.json
│       ├── openai.json
│       └── ... (374 files)
│
└── scripts/stringgroups/              # build pipeline — source of truth lives here
    ├── 01-generic.json                #   curated fragment: generic secrets & aliases
    ├── 02-cloud.json                  #   curated fragment: AWS, Azure, GCP, ...
    ├── 03-ai.json                     #   curated fragment: OpenAI, Anthropic, ...
    ├── ...                            #   (16 fragments total)
    ├── 16-certificates.json
    ├── emit-assets.mjs                #   fragments -> assets/ (build)
    └── validate-assets.mjs            #   validates the assets/ layout
```

Everything under `assets/` is **generated** from the curated fragments — edit the fragments, never the assets.

---

## File formats

### 1. Group → Keywords object — `assets/stringgroups.json`

```json
{
  "Generic Secrets": ["API_KEY", "api_key", "apiKey", "ApiKey", "api-key", "apikey", "APIKEY", "..."],
  "AWS":             ["AWS_ACCESS_KEY_ID", "aws_access_key_id", "awsAccessKeyId", "..."],
  "OpenAI":          ["OPENAI_API_KEY", "..."]
}
```

O(1) access to a group by name; no repeated `"name"` keys; smaller and simpler to (de)serialize. This is the recommended **maintenance** format.

### 2. Keyword → Group index — `assets/keyword-index.json`

```json
{
  "API_KEY": "Generic Secrets",
  "apiKey": "Generic Secrets",
  "AWS_ACCESS_KEY_ID": "AWS",
  "OPENAI_API_KEY": "OpenAI",
  "STRIPE_SECRET_KEY": "Stripe"
}
```

The **runtime** format. Detection is a single hash lookup:

```js
// JavaScript
const index = require('./assets/keyword-index.json');
const group = index[identifier];           // "AWS", "OpenAI", ... or undefined
if (group) { /* identifier looks like a secret from group `group` */ }
```

```python
# Python
import json
index = json.load(open("assets/keyword-index.json", encoding="utf-8"))
group = index.get(identifier)              # None if not a known secret identifier
```

Every keyword maps to exactly one group, and every keyword in `stringgroups.json` is present in the index (verified by `validate-assets.mjs`).

### 3. Per-group files — `assets/groups/<slug>.json`

```json
{ "name": "AWS", "keywords": ["AWS_ACCESS_KEY_ID", "awsAccessKeyId", "..."] }
```

One file per group (slugified name, e.g. `google-cloud-platform.json`, `code-quality-security.json`). Load only the categories you care about, or toggle categories by including/excluding files.

### 4. Source fragments — `scripts/stringgroups/0*.json`

The curated source of truth. Each is an array of `{ "name": ..., "keywords": [...] }` groups, organised by ecosystem:

| Fragment | Covers |
|---|---|
| `01-generic.json` | generic secrets, auth, crypto, aliases, credentials |
| `02-cloud.json` | AWS, Azure, GCP, DigitalOcean, Cloudflare, OCI, IBM, Alibaba, Tencent, Hetzner, Linode, Vultr, Scaleway, … |
| `03-ai.json` | OpenAI, Anthropic, Gemini, Cohere, Groq, Mistral, Hugging Face, Together, DeepSeek, OpenRouter, Replicate, xAI, … |
| `04-scm-cicd.json` | GitHub, GitLab, Bitbucket, Azure DevOps + Jenkins, CircleCI, Travis, Azure Pipelines, Buildkite, … |
| `05-container-k8s.json` | Docker, Kubernetes, Helm, registries, service mesh, GitOps |
| `06-databases.json` | ~30 engines + ORMs + connection-string names |
| `07-messaging.json` | Kafka, RabbitMQ, SQS/SNS, Pub/Sub, Pulsar, Celery, BullMQ, … |
| `08-payments-crypto.json` | Stripe, PayPal, Square, Adyen, Razorpay, … + Web3/blockchain |
| `09-oauth-social.json` | Google, Facebook, Slack, Discord, Telegram, Okta, Auth0, Keycloak, Cognito, … |
| `10-email-sms-push.json` | SendGrid, Mailgun, SES, SMTP, Twilio, Vonage, FCM, APNs, OneSignal, … |
| `11-saas-devops.json` | Vercel, Netlify, Railway, Render, Fly, Heroku, HashiCorp, Vault, Terraform, Ansible, … |
| `12-monitoring-analytics.json` | Sentry, Datadog, Grafana, analytics, CRM, search, CDN, storage, maps, video, DNS, code quality |
| `13-frameworks.json` | Node, Express, Nest, Next, React, Vue, Angular, Django, Flask, FastAPI, Laravel, Spring, ASP.NET, Rails, Go, Rust, Flutter, Unity, … |
| `14-config-keys.json` | `.env`, YAML, JSON, TOML, XML, properties, K8s manifests, Docker Compose, Terraform, Helm values, CI/CD env |
| `15-abbreviations.json` | `pwd`, `pass`, `pw`, `cred`, `tok`, `sig`, `enc`, `priv`, `pub`, `cert`, `csr`, `pem`, `pfx`, `p12`, `ssh`, `rsa` + composites |
| `16-certificates.json` | TLS/SSL, certs, signing/JWT, encryption/ciphers, password hashing, PGP/GPG |

---

## Build & regenerate

Requires **Node.js ≥ 18** (no dependencies). Run from the project root.

```bash
# Regenerate the whole assets/ layout from the curated fragments
node scripts/stringgroups/emit-assets.mjs
```

## Validation

```bash
# Validate the assets layout (index <-> groups consistency, per-group files)
node scripts/stringgroups/validate-assets.mjs
```

The validator exits non-zero on failure and checks:

- valid JSON structure
- unique group names, no empty groups
- globally unique keywords (case-sensitive — distinct casing variants are preserved)
- the keyword index maps **every** keyword to exactly the group that contains it
- each `assets/groups/*.json` file matches `assets/stringgroups.json` 1:1
- spot-checks that key vendor keywords are present

---

## Adding or updating a provider

1. Edit the relevant fragment under `scripts/stringgroups/` (or add a new one, named `NN-<topic>.json`).
2. Re-run `node scripts/stringgroups/emit-assets.mjs`.
3. Re-run `node scripts/stringgroups/validate-assets.mjs`.

Because every canonical name is expanded into all common casings (`api_key` → `API_KEY`, `ApiKey`, `apiKey`, `api-key`, `API-KEY`, `api.key`, `apikey`, `APIKEY`), you usually only need to add the official, documented env var names once — the variants are generated automatically. Exact duplicates are removed across the whole database.

---

## Design notes

- **No one giant blob** — keywords are organised into named groups so the scanner can report *which* category matched ("AWS credential", "OpenAI API key").
- **Two runtime shapes** — `stringgroups.json` (Group → Keywords) for maintenance and diagnostics; `keyword-index.json` (Keyword → Group) for O(1) detection.
- **Generated, not hand-edited** — `assets/` is a pure build artifact of the fragments under `scripts/stringgroups/`; the build is deterministic (same fragments → identical output).
- **Normalized, but variants preserved** — equivalent identifiers are kept as distinct variants, and only exact-string duplicates are removed.
