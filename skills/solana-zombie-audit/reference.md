# Solana Zombie Audit Reference

This reference supports `SKILL.md`. It is a research playbook, not a claim that any target is vulnerable.

## 1. Zombie Score

Use only for prioritization.

| Signal | Score |
|---|---:|
| Explicitly deprecated / shutdown | +3 |
| Last core commit older than 2 years | +2 |
| Residual value > $100k | +2 |
| Residual value > $1m | +4 instead of +2 |
| V1→V2/V3 migration history | +3 |
| Legacy withdraw/redeem/claim still callable | +3 |
| Old oracle / bridge / DEX / farm dependency | +2 |
| No recent audit evidence | +2 |
| Immutable deployment | +1 |
| Upgrade authority still present under weak maintenance | +2 |
| Source↔deployment mapping unclear | +2 research-cost signal |

Interpretation:
- 0–5: low priority unless the code is unusually interesting.
- 6–10: medium.
- 11–15: high.
- 16+: very high research priority.

This score measures **research attractiveness**, not exploit probability.

---

## 2. Read-only deployment inventory

Typical commands:

```bash
solana program show <PROGRAM_ID> -u mainnet-beta
solana program dump <PROGRAM_ID> deployed.so -u mainnet-beta
solana account <ACCOUNT> -u mainnet-beta
solana program show --programs -u mainnet-beta
```

Record at minimum:
- Program ID.
- ProgramData address.
- Upgrade authority.
- Last deployed slot if available.
- Program binary size/hash.
- Loader.
- Relevant program-owned/token accounts.

Do not infer current upgrade authority from old documentation.

---

## 3. Source mapping

### IDs

Search:

```bash
rg -n 'declare_id!|\[programs\.(mainnet|mainnet-beta)\]|program_id|Program ID' .
```

Check:
- `declare_id!` in each program.
- `Anchor.toml`.
- IDL metadata.
- SDK constants.
- historical release notes.

### Toolchain provenance

Capture:

```bash
rustc --version
cargo --version
solana --version
anchor --version
git rev-parse HEAD
git log -1 --format='%cI %H %s'
```

Inspect:
- `Cargo.toml`
- `Cargo.lock`
- `Anchor.toml`
- build scripts / Dockerfiles / CI.

### Binary confidence

Strongest to weakest:
1. verified/reproducible build.
2. identical or strongly matched ELF/build provenance.
3. program IDs + release/deployment timing + matching IDL/state layout.
4. old docs/SDK/fork only.

Never call level 4 production source.

---

## 4. Static tooling stack

Use tool output as triage, not proof.

### Baseline Rust

```bash
cargo audit
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
cargo geiger
```

### Solana-oriented

```bash
solsec scan <PROGRAM_PATH> --format json,markdown
```

Then run this skill's lightweight source triage:

```bash
python3 skills/solana-zombie-audit/scripts/solana_source_triage.py <PROGRAM_PATH>
python3 skills/solana-zombie-audit/scripts/solana_source_triage.py <PROGRAM_PATH> --json triage.json
```

Treat regex/static warnings as review leads only.

---

## 5. Dynamic tool selection

### Crucible

Best fit:
- compiled Solana program available,
- IDL available or raw instruction format understood,
- sequence bugs are likely,
- stateful invariant fuzzing,
- coverage guidance matters.

Useful properties:
- operates on compiled programs,
- LiteSVM-based,
- stateful and stateless fuzzing,
- sequence mutation,
- crash minimization,
- coverage reports.

### Trident

Best fit:
- Anchor/source workspace is available,
- custom flows are easy to encode,
- account-state-aware fuzzing,
- regression across versions.

### LiteSVM

Best fit:
- deterministic local PoC,
- fast local transaction execution,
- small test harnesses.

### Mollusk

Best fit:
- instruction-level program testing,
- precise account/CPI setup,
- lightweight SVM tests.

### Sonar

Useful as an auxiliary read/simulation utility:
- local transaction simulation,
- transaction decode/replay,
- account inspection,
- PDA derivation,
- program ELF retrieval,
- Anchor IDL lookup.

If a tool supports sending transactions, keep send functionality disabled for this workflow unless explicit authorized scope requires it.

---

## 6. Solana trust-boundary checklist

### Account identity

For every instruction ask:
- Who chooses this account?
- Who owns it?
- Does it need to sign?
- Must it be writable?
- Which mint/market/pool/user must it belong to?
- Is its program owner canonical?
- Can two logical roles point to the same account?

High-review patterns:
- `AccountInfo<'info>`
- `UncheckedAccount<'info>`
- `ctx.remaining_accounts`
- hand-written deserialization
- unchecked sysvar/program accounts

### PDA

Review:
- canonical bump,
- user-supplied bump,
- manual `create_program_address`,
- variable-length seed boundaries,
- omitted identity fields,
- same authority PDA reused across unrelated assets/pools,
- legacy and new PDA schemes representing the same logical object.

### CPI

Review:
- caller-selected program IDs,
- caller-selected remaining accounts,
- signer seeds and scope of PDA authority,
- state read before CPI but trusted after CPI,
- downstream return/state semantics,
- whether a trusted CPI target can itself be upgraded.

### Tokens

Review:
- classic SPL Token-only assumptions,
- Token-2022 interfaces,
- actual balance delta vs requested amount,
- Transfer Fee,
- Transfer Hook,
- Permanent Delegate,
- frozen/default account state,
- non-transferable tokens,
- decimals changes/normalization,
- arbitrary/permissionless mint support.

### Oracle

Review:
- oracle program/account identity,
- staleness,
- confidence,
- status,
- exponent/decimal scaling,
- fallback oracle behavior,
- migration from one oracle provider to another,
- dead/stale markets that remain accepted.

---

## 7. Legacy / migration checklist

Build a table:

| Era | Program ID | Authority | PDA scheme | Oracle | Token program | Key migration |
|---|---|---|---|---|---|---|

Then ask:

- Can V1 state be consumed by V2?
- Can the same entitlement be claimed through old and new paths?
- Did nonce/counter/state namespaces reset?
- Were old minter/freeze authorities revoked?
- Can old vault authority still move value?
- Are legacy instructions still reachable?
- Can a deprecated SDK construct transactions the current program still accepts?
- Did the frontend disappear while the program remained live?
- Did a dependency migrate addresses or semantics?
- Was an old emergency/admin path intentionally left open for withdrawals?

---

## 8. Protocol-specific invariant ideas

### Lending

```text
assets >= liabilities
borrowed_value <= allowed_collateral_value
repay cannot reduce debt less than value credited
withdraw cannot leave an unhealthy position unless explicitly allowed
liquidation cannot create net value
interest/index updates are monotonic and conservation-preserving
```

Sequence seeds:
```text
deposit → borrow → refresh → repay → withdraw
deposit → borrow → oracle-change → liquidate
deposit → borrow → partial-repay → partial-withdraw
deposit → borrow → stale-refresh → liquidate
```

### Vault / yield

```text
shares minted <= value actually received
value released <= shares/debt burned
total share claims <= realizable assets under defined accounting
strategy migration cannot duplicate claim
```

### Rewards / mining

```text
claim <= accrued
stake/unstake ordering cannot duplicate reward debt
pause/unpause cannot reset accrual unfairly
migration cannot claim old and new rewards twice
emission minting cannot exceed configured authority/rate
```

### Swap / AMM

```text
pool invariant moves only within fee/rounding rules
LP mint/burn cannot extract value via rounding loops
token account substitution cannot redirect reserves
legacy pool routes cannot bypass current token validation
```

---

## 9. Suggested research order for a legacy target

1. Verify program ID and chain state.
2. Identify ProgramData and upgrade authority.
3. Dump deployed ELF.
4. Match repository/release.
5. Run source triage and baseline static tools.
6. Draw instruction/account/PDA/CPI graph.
7. Draw legacy timeline.
8. Write 3–10 protocol-specific invariants.
9. Build smallest deterministic LiteSVM/Mollusk PoC for suspicious paths.
10. Move to Crucible/Trident only when sequence search adds value.
11. Minimize failing sequence.
12. Re-check bounty/safe-harbor before any testing outside local environments.

---

## 10. Report template

```markdown
# Target

Program:
Network:
Source:
Source mapping confidence:
Upgrade authority:
Legacy status:
Authorization:

# Deployment evidence

# Legacy timeline

# Residual state

# Static review signals

| Signal | Location | Confidence | Next test |

# Invariants

1.
2.
3.

# Findings

## [Severity] Title

Status: Confirmed / Probable
Location:
Invariant violated:
Prerequisites:
Local reproduction:
Impact:
Evidence:
Remediation direction:
Scope limitations:

# Open questions

# Next experiments
```

---

## 11. External tools to evaluate

The skill should orchestrate rather than duplicate these projects:

- Ackee Blockchain **Trident** — stateful/manual-guided Solana fuzzing.
- Asymmetric Research **Crucible** — coverage-guided stateful invariant fuzzing.
- **LiteSVM** — fast local Solana VM testing.
- Anza **Mollusk** — lightweight program testing.
- **solsec** — Solana-oriented static analysis/fuzz triage.
- OKX Labs **Sonar** — local transaction simulation / account / ELF / IDL utilities.
- `solana-auditor-skill` — useful generic audit workflow reference.

For legacy/Zombie research, this ScopeWeaver skill remains the orchestration layer because those tools generally do not prioritize residual-state discovery, source/deployment provenance, deprecation/migration history, or Zombie scoring.
