# PSTS Phase 1 — Enhancement Ideas (Codex)

Scope: Make Phase 1 (GitHub Workflow Integration) robust, auditable, and developer‑friendly while staying within MVP boundaries.

— Strategy and Planning

- Clarify Phase 1 “done”: SARIF uploaded to Security tab, JUnit summary artifact, PRs with proposed remediations gated by policy.
- Add acceptance criteria per component in buildplans/TechnicalPlan.md: inputs/outputs, metrics (e.g., fail on ≥1 High/Critical unless allowlisted).
- Define rule taxonomy and stability levels (experimental vs stable), plus expected false‑positive guidance for CI gates.

— GitHub Workflow Integration

- Policy config: introduce `.psts.yml` supporting `failOn: [Critical, High]`, `maxWarnings`, `excludedPaths`, env overrides.
- SARIF upload: ensure powershell-security workflow uploads SARIF to code scanning and stores raw JSON/JUnit as artifacts.
- PR automation: scope changes to files with violations, add labels (e.g., `security:autofix`, `psts`) and minimal permissions.
- Baselines: support generating/committing a baseline SARIF and fail only on new/changed findings.

— Analyzer Engine (src/PowerShellSecurityAnalyzer.psm1)

- Parameter parsing helper: centralize safe extraction of `CommandParameterAst` values for reuse across rules.
- Rule coverage expansion (low‑risk additions):
  - Web requests and certs: detect `-SkipCertificateCheck`, insecure `ServerCertificateValidationCallback`, weak `SecurityProtocol`.
  - Process/args hygiene: unvalidated concatenation in `Start-Process -ArgumentList`, unquoted paths.
  - Download + execute: file downloads followed by `&` or `Invoke-Expression`.
  - Insecure randomness: usage of `Get-Random` for security tokens (suggest RNGCryptoServiceProvider/RandomNumberGenerator).
- Rule metadata: add `PSTS###` RuleIds, `Description`, remediation text, CWE, tags. Populate `Metadata` for SARIF.
- Performance: honor `MaxFileSize` before AST parse, track skipped files; optional parallel analysis with per‑file timeout.
- Exclusions/suppressions: wire `ExcludedPaths` to config; support inline `# PSTS: ignore-next-line <RuleId>` suppressions.

— Output and Reporting (scripts/)

- SARIF completeness: include `helpUri`, `shortDescription`, `fullDescription`, `properties.tags`, severity mapping (Low=note, Medium=warning, High/Critical=error), deterministic fingerprints.
- JUnit summary: emit counts by severity and top N issues per file for quick CI log scanning.

— Developer Experience

- CLI wrapper `psts.ps1`: commands for `analyze`, `format sarif`, `format junit`, `baseline create/compare`, `config validate` to mirror CI locally.
- README updates: quickstart, `.psts.yml` schema, CI gating behavior, baseline workflow, and suppression examples.
- Contributing guide: rule template (evaluator skeleton, tests, metadata checklist) to standardize contributions.

— Testing

- Pester unit tests per rule: positive/negative cases, parameter variations (variables, splatting, pipeline).
- Golden file tests: expected JSON output for `tests/TestScripts/**/*` and comparison test to guard regressions.
- Schema regression: ensure required SARIF fields present across changes.

— Security Posture

- Analyzer safety: document that execution never occurs (AST‑only). Reject/skip unsupported encodings safely.
- Workflow hardening: pin actions by commit SHA, set minimal permissions (`contents: read`, `pull-requests: write`, `security-events: write`).
- Supply chain: pin `actions/copilot-autofix` dependencies; document build producing `dist` and consider integrity checks.

— Copilot Autofix Flow

- Guardrails: only modify files with violations; rerun analyzer on patch; skip PR if violations not reduced.
- PR quality: template includes rule IDs, before/after snippets, remediation links; auto‑labels and CODEOWNERS routing.

— Phase 2/3 Readiness (light‑touch)

- Emit simple diagnostics JSON alongside SARIF for LSP use.
- Keep evaluators pure/side‑effect free for reuse in VS Code and sandbox app.
- Include “preferred fix” snippets in rule metadata for future CodeAction support.

Proposed next steps (Phase 1):

1) Add `.psts.yml` schema + config loader; wire to analyzer and workflow gates.
2) Extend SARIF generation with full rule metadata + upload step in workflow.
3) Implement inline suppression + baseline creation/compare with gating on new findings.
4) Add one new high‑value rule (unsafe web requests) with Pester tests and golden outputs.
5) Provide CLI wrapper and README quickstart to align local and CI runs.
