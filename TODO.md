# TODO

## Feature Enhancements

### AI-Powered Secret Remediation

Implement an intelligent remediation system where the AI agent will automatically:

1. **Detect hardcoded secrets** — Scan the codebase for API keys, tokens, passwords, and other sensitive credentials committed directly in source files.
2. **Move secrets to `.env`** — Automatically extract hardcoded secrets and relocate them to a `.env` file (or environment-specific variant).
3. **Update source code references** — Replace hardcoded values with the appropriate environment variable references (e.g., `process.env.API_KEY`).
4. **Provide proper configuration** — Generate or update `.env.example` and `.gitignore` to ensure the `.env` file is tracked in templates but excluded from version control.
5. **Validate the remediation** — Run a follow-up scan to confirm the secret has been fully removed from source and is now accessed securely via environment variables.

#### Goals

- Zero-hardcoded-secrets codebase after remediation
- Minimal manual developer intervention
- Safe, auditable changes that can be reviewed before applying
- Support for multiple languages and frameworks (Node.js, Python, Go, etc.)

#### Status

- [ ] Design architecture
- [ ] Implement secret detection pipeline
- [ ] Implement automatic `.env` extraction
- [ ] Implement source code rewriting
- [ ] Add multi-programming-language support
- [ ] Add rollback / undo capability
- [ ] Write tests
