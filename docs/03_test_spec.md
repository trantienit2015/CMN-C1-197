# CMN-C1-197 — Test Specification

> Maps to the framework rules (mandatory TC + PB items). Tests are deterministic —
> no real network call anywhere in the suite. The Step 2 classifier has an OPTIONAL
> LLM enhancement (docs/02_design.md §3); §7 below covers it with a fake test-double
> LLM only, never a real Azure OpenAI call.
> `framework.*` / `shared.*` resolve via the CI include (locally, put the
> framework package on `PYTHONPATH`).

## 1. Test layout

```
tests/
├── _fixtures.py                       deterministic event/config builders + compile+invoke helper
├── unit/
│   ├── test_initialize_node.py        InitializeNode S-1 declaration + S-2 validation
│   ├── test_uc.py                     UC-01 … UC-12 (use-case + slot/service level)
│   ├── test_sec.py                    S-1 … S-5 + S-3 masking (TC-02/03/04/05/07/08/13)
│   └── test_llm_classify_service.py   TC-LLM-01 … 09 (optional LLM enhancement, fake test-double only)
├── integration/
│   └── test_graph.py                  full Graph().compile() + .invoke() (backbone order, status)
├── proof_of_boundary/
│   ├── test_import_isolation.py       PB-4 (AST scan: no Level 0 import in src/)
│   ├── test_state_safety.py           PB-2 / PB-5 (state credential/type AST scan)
│   └── test_runtime_boundary.py       PB-1 / PB-3 / PB-6 + S-3-at-output (compile + invoke)
└── test_scaffold.py                   the review criteria self-check (#1/#10/#11/#13/#14/#2)
```

## 2. Use-case tests (`tests/unit/test_uc.py`)

| UC | Scenario | Expected |
|----|----------|----------|
| UC-01 | initialize normalizes raw_events (S-2) | `status=AgentStatus.SUCCESS`, raw_events JSON-normalized |
| UC-02 | Azure-format event normalization (pre_process) | canonical fields extracted via Azure adapter |
| UC-03 | Prompt-injection event (main chain) | classified `prompt_injection`, alert with remediation |
| UC-04 | Privilege-escalation event (main chain) | severity `critical`, `requires_48h_notification: true` |
| UC-05 | Config-driven alert format | alert `format` honored (`eu_ai_act`) |
| UC-06 | Policy category allowlist | out-of-scope category suppressed → clean |
| UC-07 | Empty batch (full invoke) | valid, `status: clean` |
| UC-08 | Classifier-service determinism | identical output on repeat; confidence ∈ [0,1] |
| UC-09 | Full slot chain (initialize→post_process) | masked_alert + audit_log_entry + formatted_output |
| UC-10 | Excessive agency by tool volume | `excessive_agency` flagged above `max_tool_calls` |
| UC-11 | `policy_min_confidence` gate | violation presence toggles with threshold |
| UC-12 | Severity weight × confidence banding | privilege_escalation@1.0 → critical + 48h |

## 3. Security tests (`tests/unit/test_sec.py` + `test_initialize_node.py`) — TC mapping

| TC | Test | Layer |
|----|------|-------|
| TC-08 | ANONYMOUS refused (status error, no output) / INTERNAL allowed | S-1 (framework `__call__` gate) |
| TC-13 | `InitializeNode.required_trust_level.name` ∈ {ANONYMOUS, VERIFIED_EXTERNAL, INTERNAL}; = INTERNAL; ≠ VERIFIED_INTERNAL | S-1 |
| TC-02 | missing `session_id` → `status=ERROR` + error_log | S-2 |
| —     | oversized batch rejected (`max_events`) | S-2 |
| TC-07 | deterministic masking is idempotent; post_process masks embedded secret | S-3 |
| TC-05 | audit entry present on success path; on halt | S-4 / S-5 |
| TC-04 | post-invoke output holds only primitives; JSON round-trippable; no InvocationContext leaked | state safety |
| TC-03 | JWT/secret in caller-facing field redacted by the S-3 mask | S-3 / state safety |

## 4. Proof-of-Boundary tests (`tests/proof_of_boundary/`)

| PB | Boundary | Test |
|----|----------|------|
| PB-1 | S-1 trust gate | ANONYMOUS refused before the pipeline runs (no alert) |
| PB-2 / PB-5 | State serialization / checkpoint safety | post-invoke output is primitives only; JSON round-trippable; state-file AST scan (no credential field / BaseModel / InvocationContext) |
| PB-3 | L1 → pipeline | real classification end-to-end (Azure adapter, via compile + invoke) |
| PB-4 | Import isolation | AST scan: no `agenticstar` / Level-0 import in `src/` |
| PB-6 | Backbone execution order | `InitializeNode → PreProcessNode → MainNode → PostProcessNode → FinalizeNode`, status success |
| —  | S-3-at-output | secret reaching the alert is redacted at the post_process gate, NOT at S-1 |

## 5. Coverage summary

Cat 1 minimums (the developer guide): ≥ 1 success + ≥ 1 error/edge per node, ≥ 1
full-graph compile+invoke integration test, PB tests. This template ships 12 UC
tests, 4 InitializeNode unit tests, full S-1…S-5 security coverage, 4 integration
compile+invoke tests, and 3 PB files — exceeding the minimum.

## 6. Deployment path tests

### TC-DEP-01 Marketplace entry point identity — `tests/unit/test_cli_entry_point.py`

| Case | Expected |
|---|---|
| Identity is concrete | `agent_name` / `namespace` are non-empty and not the runner default |
| Identity matches the HTTP entry point | the values equal what `src/api/server.py` passes to `secrets_factory`; where that entry point provisions no secrets, they equal the manifest `namespace` and the lower-cased template id |
| The runner call uses the constants | `run_agent_marketplace` is called with the module constants, not inline literals |

### TC-DEP-02 Standalone entry point boundary — `tests/proof_of_boundary/test_server_llm_injection.py`

| Case | Expected |
|---|---|
| Boots with no credential provisioned | the module imports and the app/agent objects are constructed |
| External bearer never reaches the internal level | resolves to the verified-external level |
| Staging runner credential reaches the internal level | resolves to the internal level |
| Wrong or missing bearer while auth is enabled | rejected with 401 |

## 7. Optional LLM enhancement tests (`tests/unit/test_llm_classify_service.py`)

Covers the optional enhancement described in docs/02_design.md §3. All cases use a fake
`FakeLLM.complete(messages) -> {"content": ...}` test-double — no real Azure
OpenAI call anywhere in this suite, per the `no unapproved package` default the
rest of this template still holds to for its deterministic path.

| TC | Scenario | Expected |
|----|----------|----------|
| TC-LLM-01 | Well-formed JSON reply with a new finding | row added, `source: "llm"`, confidence clamped to [0,1] |
| TC-LLM-02 | Reply wrapped in prose + a markdown fence | still parses via `extract_json_object` |
| TC-LLM-03 | Malformed (non-JSON) reply | `enhance()` returns `None` — rule table stands alone |
| TC-LLM-04 | Well-formed JSON but wrong shape (`findings` not a list) | `None` |
| TC-LLM-05 | Reply names an unknown category or an unknown `event_id` | that row silently dropped; `None` if nothing valid remains |
| TC-LLM-06 | Reply only repeats an already-flagged `(event_id, category)` pair | `None` — no duplicate row |
| TC-LLM-07 | LLM client raises (simulated API error) | `None`, no exception propagates |
| TC-LLM-08 | No events at all | `None`; `client.complete` is never invoked |
| TC-LLM-09 | `llm=None` and no secret bound (bare `InvocationContext.from_state` failure) | `None` — the production default-construction path |
| — | `MainNode(llm=FakeLLM(...))` merges LLM rows into `owasp_classifications` | pipeline `status=SUCCESS`, merged row present |
| — | `MainNode(llm=FakeLLM(raises=True))` | pipeline still `status=SUCCESS` on the rule-table rows alone |
| — | `MainNode()` (no `llm=`, the real production wiring) | two invocations of the same state produce identical `owasp_classifications` (deterministic; LLM path never reached) |
