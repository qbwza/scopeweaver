---
name: solana-zombie-audit
description: Use for authorized security research on legacy, deprecated, low-maintenance, migrated, or "zombie" Solana programs. Inventory on-chain deployment state, map deployed program to source, triage Solana/Anchor trust boundaries, review legacy and migration assumptions, design local invariant/fuzz campaigns, and produce evidence-graded findings. Defaults to read-only mainnet analysis and local simulation; never sends or signs mainnet transactions.
---

# Solana Zombie Audit

Use this skill when the target is an old, deprecated, migrated, abandoned, weakly maintained, or otherwise legacy Solana protocol/program, especially when assets or callable state may still remain on-chain.

This skill is intentionally different from a generic Solana code audit. It focuses on **time-dependent security assumptions**:

- source code vs deployed bytecode drift,
- upgrade authority and ProgramData state,
- old instructions or PDAs that remain callable,
- V1/V2/V3 migration boundaries,
- stale oracle/program/token dependencies,
- legacy SPL Token assumptions in a Token-2022 world,
- abandoned vaults/reserves/escrows with residual value,
- state-machine and accounting invariants that survive years of protocol evolution.

It is an orchestration skill. Prefer established tools for the engines:
- **Crucible** for coverage-guided, stateful invariant fuzzing of compiled Solana programs.
- **Trident** for manually guided, stateful Solana fuzzing and regression campaigns.
- **LiteSVM / Mollusk** for deterministic local PoCs and instruction-level simulation.
- **solsec + cargo-audit/clippy/deny/geiger** for static/dependency triage.

Read [reference.md](reference.md) for commands, scoring, review patterns, tool selection, and report structure.

---

## Mandatory boundaries

### Mainnet default: read-only

Allowed by default:
- RPC reads.
- Explorer/source/documentation reads.
- `solana program show`.
- `solana program dump`.
- Fetching account data, balances, transaction history, IDLs and ProgramData.
- Offline source review.
- Local/test-validator/LiteSVM/Mollusk/Trident/Crucible execution.
- Mainnet transaction simulation that does not sign or submit state-changing transactions.

Do not:
- sign or submit a mainnet transaction,
- use a private key or wallet secret,
- intentionally mutate production state,
- brute force or spam RPC/services,
- bypass access controls,
- test a suspected exploit against third-party funds.

A deprecated or abandoned protocol is **not** automatically authorized for active production testing.

### Evidence discipline

Never label a pattern match as a vulnerability by itself.

Classify every result as one of:
- **Confirmed** — reproducible in a local/forked environment with a concrete trace or invariant violation.
- **Probable** — source/deployment evidence is strong but reproduction is incomplete.
- **Review signal** — suspicious pattern or stale assumption that needs manual validation.
- **Out of scope / unknown** — deployment/source/auth scope cannot be established.

Never claim the target is "safe" or "secure".

---

## Workflow

```
Phase 0  Authorization + target identity
   ↓
Phase 1  Zombie triage + residual-state mapping
   ↓
Phase 2  On-chain deployment inventory
   ↓
Phase 3  Source ↔ deployed mapping
   ↓
Phase 4  Static trust-boundary triage
   ↓
Phase 5  Legacy / migration / dependency review
   ↓
Phase 6  Invariant model + local fuzz / PoC
   ↓
Phase 7  Evidence-graded report
```

Do not skip Phase 2–3 for legacy targets. Auditing the wrong GitHub revision is a common failure mode.

---

## Phase 0 — authorization and identity

Record:

- protocol/project name,
- program ID(s),
- network/cluster,
- candidate GitHub repository,
- whether the project is active, deprecated, migrated, or unknown,
- current bug bounty / safe-harbor status if any,
- whether the task is source-only, local PoC, or broader authorized testing.

If the user only provides a project name, first find and verify the program ID before deep audit work.

---

## Phase 1 — Zombie triage

Build a compact target card:

```text
Project:
Program ID:
Protocol state: active | deprecated | migrated | unknown
Residual TVL / vault value:
Active loans / positions:
Last core commit:
Last release:
Last known audit:
Bounty / safe harbor:
Upgradeability:
Source mapping confidence:
Zombie Score:
```

Use the Zombie Score only as a **research prioritization heuristic**, never as a probability of exploitability.

Prefer targets with several of:
- explicit deprecation/shutdown,
- core development inactive for years,
- residual assets or liabilities,
- still-callable withdrawal/redeem/claim paths,
- V1→V2/V3 migrations,
- old oracle/DEX/bridge/reward integrations,
- source code available but deployment provenance unclear,
- immutable deployment with no practical patch path,
- upgrade authority still present despite weak operations.

See [reference.md](reference.md) for the scoring rubric.

---

## Phase 2 — on-chain deployment inventory

For every program ID, collect:

- executable account,
- ProgramData account,
- upgrade authority,
- last deployed slot when available,
- loader type,
- related program IDs from Anchor.toml / IDL / docs,
- high-value vault/reserve/escrow/token accounts,
- critical authorities,
- dependent oracle/program/token IDs.

Prefer read-only CLI/RPC commands from [reference.md](reference.md).

If an upgrade authority is taken from old documentation rather than current chain state, mark it **historical**, not current.

---

## Phase 3 — source ↔ deployed mapping

Establish confidence before treating GitHub as production source.

Check:

1. `declare_id!` values.
2. `Anchor.toml` mainnet entries.
3. IDL program address and account schemas.
4. Rust/Solana/Anchor versions and `Cargo.lock`.
5. repository tags/releases and commit dates.
6. deployed ELF dump.
7. reproducible/verifiable build when practical.

Classify mapping:

- **High** — verified build or strong bytecode equivalence plus matching IDs/version provenance.
- **Medium** — IDs, release history and deployment metadata align, but no reproducible build.
- **Low** — only historical docs/forks/client SDKs match.
- **Unknown** — production source cannot be established.

Do not spend a long audit on Low/Unknown mapping without explicitly recording that limitation.

---

## Phase 4 — static trust-boundary triage

Run:

```bash
python3 skills/solana-zombie-audit/scripts/solana_source_triage.py <repo-or-program-path>
```

The script produces **review signals**, not findings.

Manual review priority:

### Accounts
- raw `AccountInfo`,
- `UncheckedAccount`,
- `remaining_accounts`,
- missing owner/signer/writable checks,
- missing mint/authority/program binding,
- type confusion and reused account roles.

### PDA
- manual `create_program_address`,
- user-controlled bumps,
- non-canonical bumps,
- seeds that omit user/mint/pool/market/domain identity,
- variable-length seed ambiguity,
- shared PDA authorities with excess privilege.

### CPI
- user-influenced program account,
- unchecked remaining accounts forwarded into CPI,
- `invoke_signed` with broad PDA authority,
- caller assuming CPI success means a trusted semantic result,
- stale state assumptions across CPI boundaries.

### Token semantics
- code written for classic SPL Token only,
- requested amount used as accounting truth instead of actual balance delta,
- Token-2022 Transfer Fee / Hook / Permanent Delegate assumptions,
- permissionless mint support with old token semantics.

### Oracle / accounting
- stale/confidence checks,
- decimal normalization,
- rounding direction,
- interest/index accumulation,
- reserve freshness,
- liquidation and withdrawal conservation.

---

## Phase 5 — legacy, migration and temporal review

This is the defining phase of this skill.

Construct a timeline:

```text
V1 deployed
  ↓
new oracle / new pool / new token
  ↓
V2 migration
  ↓
old UI removed
  ↓
old instructions still callable?
  ↓
today's chain state
```

Review:

- V1 signatures/messages/authorities accepted by V2,
- old token mint/freeze/minter privileges,
- duplicate logical accounts across old/new PDA schemes,
- nonces or counters reset across migrations,
- legacy withdraw/redeem/claim/emergency paths,
- stale oracle IDs or abandoned liquidity pools,
- dependency behavior that changed after deployment,
- old SPL Token assumptions versus Token-2022 assets,
- dead frontends hiding live programs,
- SDK/client deprecation while the underlying program remains active,
- old admin/upgrade keys that still control live value.

Ask: **Which assumptions were true when the code was written, but are no longer necessarily true now?**

---

## Phase 6 — invariant model and local dynamic testing

Write invariants before writing fuzz actions.

Examples for lending/vault systems:

```text
actual assets >= accounted liabilities
released value <= valid debited value
borrowed value <= collateral policy after valid oracle normalization
liquidation cannot create net value
withdrawal cannot bypass debt/accounting state
one logical position cannot be represented by multiple exploitable PDA identities
```

Examples for reward/mining systems:

```text
claimed rewards <= accrued rewards
stake/unstake/claim ordering cannot create extra reward debt
mint authority cannot exceed configured emission constraints
migration cannot duplicate entitlement
```

Examples for generic programs:

```text
untrusted accounts cannot substitute trusted dependencies
CPI cannot broaden authority beyond the intended action
invalid/stale oracle data cannot become accepted value
same semantic action cannot be executed twice through legacy/new paths
```

Tool choice:

- **Crucible**: prefer for compiled-binary coverage-guided state-machine fuzzing, especially when sequences matter.
- **Trident**: prefer when source/Anchor context is available and a guided flow model is easy to encode.
- **LiteSVM / Mollusk**: prefer for small deterministic PoCs and regression tests.
- Do not require one tool exclusively; use the smallest harness that proves the property.

Keep all exploit reproduction local unless the user has explicit authorization for another environment.

---

## Phase 7 — deliverable

Produce:

### Target summary
- program IDs,
- deployment/upgrade state,
- source mapping confidence,
- legacy/migration timeline,
- residual-state summary,
- authorization/scope.

### Review signals
Table with:
- signal,
- code location,
- why it matters,
- confidence,
- next local test.

### Findings
For each confirmed/probable issue:
- title,
- severity,
- status,
- exact code/deployment evidence,
- violated invariant,
- local reproduction,
- impact,
- prerequisites,
- remediation direction,
- scope limitations.

### Research backlog
List the next 3–10 highest-value local experiments.

---

## Completion checklist

Do not call the review complete unless the applicable items are recorded:

- [ ] Current program ID verified.
- [ ] ProgramData / upgrade authority checked from chain state.
- [ ] Source mapping confidence assigned.
- [ ] Last core commit/release recorded.
- [ ] Deprecated/migrated status verified rather than inferred from an old UI.
- [ ] Residual assets/liabilities mapped at least at a high level.
- [ ] Static triage run.
- [ ] Account / PDA / CPI / token / oracle trust boundaries reviewed.
- [ ] Legacy/migration timeline built.
- [ ] At least 3 protocol-specific invariants written.
- [ ] Suspicious behavior reproduced locally before being called confirmed.
- [ ] Current bounty/safe-harbor scope checked before any non-read-only testing.
- [ ] Report distinguishes confirmed findings from review signals.
