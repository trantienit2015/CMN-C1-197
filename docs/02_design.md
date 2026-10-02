# CMN-C1-197 — Design Specification

> Template: **CMN-C1-197** — Enterprise AI Agent Runtime Policy Violation & OWASP Agentic Top 10 Anomaly Alert Agent
> Category: **Cat 1** (single technical capability, industry-agnostic)
> Issue: #1 (`[impl] Design docs/02_design.md`)

## 1. Architecture & Inheritance

- **L1 Base**: `AgentBaseGraph` (L1 direct inheritance, 2026-05-18 policy). No
  Level 2 base agent and no Level 0 (`agenticstar`) import. L1 Base type: **L1
  direct** — `DocGenerationAgent` is a pattern reference only, NOT an inheritance
  target (proposal F-03).
- **Graph IS the agent**: `OWASPAnomalyAlertAgent` (`src/graph/graph.py`) inherits
  `AgentBaseGraph` directly. There is no separate agent class and no second graph
  (no double-graph). It is the public, independently-deployable endpoint.
- **Public entry point**: `Graph().compile()` then `.invoke(user_input, ctx=...)`
  — **never `.run()`** and **never** a developer `_invoke_impl()` walk. The
  framework owns the backbone traversal, the S-1 trust gate (in
  `BaseNode.__call__`), routing, retry, timing, and `node_history` (the independent review
  criterion #11).
- **Trust level**: `InitializeNode.required_trust_level = TrustLevel.INTERNAL` —
  a valid production enum value (criterion #13). Agent execution logs are
  internal operational telemetry, so INTERNAL is the appropriate floor.

### Three-layer separation

| Layer | This template |
|-------|---------------|
| State | `OWASPAlertState(AgentState)` — flat, primitives + JSON strings only (`src/schemas/state.py`). |
| Node | 4 slot nodes (`initialize` / `pre_process` / `main` / `post_process`), each overriding `execute(self, state) -> dict` (initialize overrides `on_initialize`). No `config` param, no `_invoke_impl`, never overrides `__call__`; status is an `AgentStatus.*` enum (node contract / criterion #1, #11). |
| Graph | `OWASPAnomalyAlertAgent.register_nodes()` calls `super().register_nodes()` then fills the three domain slots. `add_edges()` / `route()` are NOT overridden. No business logic in the graph. |

## 2. Pipeline (Cat 1 backbone + slot/service mapping)

The agent uses the fixed Cat 1 backbone (framework-owned topology):

```
initialize → pre_process → main → {route} → post_process → finalize
```

The architect-spec **6-step OWASP pipeline** (issues #3–#8) is mapped onto the
slots **without dropping any step** — each step's logic is extracted verbatim
into a dedicated deterministic service in `src/services/`, and the slot node
orchestrates the steps in order. The `main` slot runs the four core detection
steps sequentially (each delegating to its own service), so behavior is preserved
1:1; nothing is collapsed away.

| Step | Slot | Input field(s) | Output field | Service | Key logic |
|------|------|----------------|--------------|---------|-----------|
| (S-1/S-2) | `initialize` | `input_context` | `raw_events`, `log_source` | (node) | INTERNAL trust gate + input validation (session_id, max_events) + raw_events JSON normalization. |
| 1 EventStreamParse | `pre_process` | `raw_events`, `log_source` | `parsed_events` | `event_stream_parse_service` | Per-provider (Azure/AWS/GCP/generic) log normalization + S-1 sanitization (HTML strip + truncate). |
| 2 OWASPTaxonomyClassify | `main` | `parsed_events` | `owasp_classifications` | `owasp_classify_service` (+ optional `llm_classify_service`) | Deterministic rule-based signal matcher over OWASP Agentic Top 10 + structural heuristics (tool-call volume). The rule table is the floor: always computed first, and an optional model enhancement (§3) may only **add** rows it missed — never remove or downgrade one. |
| 3 PolicyViolationDetect | `main` | `owasp_classifications`, policy knobs | `policy_violations` | `policy_violation_service` | Config-driven policy-rule evaluation (min-confidence, category allowlist, per-category overrides). |
| 4 SeverityScore | `main` | `policy_violations` | `severity_assessment` | `severity_score_service` | Deterministic severity banding (CRITICAL/HIGH/MEDIUM/LOW) + FSA AI MRM 48h flag. |
| 5 IncidentAlert | `main` | `severity_assessment`, `alert_format` | `alert_payload` | `incident_alert_service` | Config-format structured alert (iso_42001 / nist_ai_rmf / eu_ai_act / fsa_ai_mrm / generic) + per-finding remediation. No hardcoded format. |
| 6 AuditLogWrite | `post_process` | `alert_payload` | `masked_alert`, `audit_log_entry`, `formatted_output` | `audit_log_service` | **S-3** deterministic masking (regex, not LLM) + **S-5** immutable audit entry (EU AI Act Art. 72). |

Domain knobs (policy rules, severity weights, alert format, remediation map,
`alert_id`, `generated_at`) flow from the caller's `input_context`. Upstream
validation failure sets `status=AgentStatus.ERROR`; downstream slots short-circuit
and `route()` sends the pipeline to `finalize`.

## 3. Classification — deterministic floor + optional LLM enhancement

The OWASP classifier (`OWASPTaxonomyClassify`, `src/services/owasp_classify_service.py`)
is a **transparent rule table**: regex signal patterns per OWASP Agentic category
plus structural heuristics. It performs no LLM inference and pulls no external
package, is unaffected by the optional path described below, and remains the **floor**: it is
always computed first and its rows are never removed, downgraded, or bypassed.

**Optional LLM assistance on top of the rule table.** The rule table alone is an unconditional
floor; an optional model call is layered on top of it for the classification step, never in place
of it. The classification step is exactly where natural-language reasoning over free-text log
content can catch novel attack phrasing that a fixed regex / structural signal table cannot, so the
model is additive there. Every row the rule table produces is still computed first and is never
removed, downgraded, or bypassed by the model's output.

**How the optional path works:** `src/services/llm_classify_service.py` optionally
calls Azure OpenAI (`shared.services.llm.azure_openai_client.AzureOpenAIClient`)
to propose *additional* classification rows beyond what the rule table found,
each tagged `"source": "llm"` and validated (event_id must match an input
event, `owasp_category` must be one of the 10 canonical OWASP Agentic keys,
`confidence` must be numeric and is clamped to `[0, 1]`) before being appended
to the deterministic rows. `config/agent.yaml` now declares
`requires.secrets: ["AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT",
"AZURE_OPENAI_DEPLOYMENT"]` and `requires.extras: ["openai"]`, and
`generation_mode` is now `"llm"`.

**What did not change:** any failure of the LLM path — no secret bound, an API
error, a malformed/wrong-shape response, or simply `llm_classify_service.enhance()`
being called with no LLM configured — is caught internally and returns `None`;
`MainNode.execute()` then proceeds with the rule-table rows exactly as before.
No exception ever reaches `FunctionNode.__call__`, and `status` is unaffected by
whether the enhancement fired. Event content sent to the LLM is passed through
the same deterministic `mask_sensitive()` (S-3) masking used elsewhere in this
template before it leaves the process, since the log content being classified
may itself carry the secrets/PII this agent exists to detect.

**Known residual risk (not closed by the optional path's own degrade):** `requires.secrets`
in `config/agent.yaml` is a compile-time declaration; whether the real
`AgentRegistry` compile path (Marketplace/STG) enforces those three secrets
unconditionally, independent of this node's own graceful degrade, could not be
verified locally (`AgentRegistry` is platform code, not part of the installed
`agenticstar-agentcore` wheel). See `docs/07_operation_guide.md` §5 for the
operational caveat this implies — provision the three secrets before deploying
this template to an environment that compiles through that path, rather than
relying on the degrade-to-heuristic behaviour to cover a compile-time gap.

## 4. State schema (`src/schemas/state.py`)

`OWASPAlertState(AgentState)` — extends the framework `AgentState`; flat,
msgpack-safe. Structured collections are stored as **JSON-serialized strings**
(helpers in `src/services/_support.py`). No Pydantic/dataclass, no credentials,
no `InvocationContext` in state. The caller's raw event batch +
log source + config knobs arrive via the framework-seeded `input_context` dict;
`InvocationContext` is reconstructed in a node via `InvocationContext.from_state`
when needed, never stored.

## 5. Configuration (`config/agent.yaml` + `config/config.yaml`)

The discovery manifest (`config/agent.yaml`) carries identity and contract keys at
root level (`id`, `name`, `namespace`, `version`, `enabled`, `category`, `industry`,
`generation_mode`, `base_type`, a single dotted `class` path, `required_trust_level`,
`requires.{secrets, extras}`). The runtime file (`config/config.yaml`) carries
`max_retry`, `timeout_seconds`, `security.s3_gate_enabled: true` (**mandatory**) and the
documented domain knob defaults (`log_source_default`, `max_field_chars`, `max_events`,
`max_tool_calls`, `policy_min_confidence`, `policy_enabled_categories`, `policy_rules`,
`severity_48h_bands`, `alert_format`). Per-request overrides flow through the
caller's `input_context`. All regulatory / policy mapping lives in config (Cat 1
industry-agnostic; no domain logic in code).

## 6. Five-layer security model

| Layer | Implementation | Location |
|-------|----------------|----------|
| S-1 | Framework trust gate in `BaseNode.__call__` using `InitializeNode.required_trust_level = INTERNAL`; under-trusted caller → `status=error` before `execute()` | `src/nodes/initialize_node.py` |
| S-2 | `InitializeNode.on_initialize()` — session/event validation, size limits, raw_events normalization | `src/nodes/initialize_node.py` |
| S-3 | deterministic masking (`mask_sensitive`, regex) on the serialized alert, applied in the terminal `post_process` (AuditLogWrite) before the alert leaves the agent | `src/nodes/post_process_node.py` + `src/services/audit_log_service.py` + `src/services/_support.py` |
| S-4 | `emit_trace_event(event_type, payload, state)` on the scan + write side-effect paths | `src/nodes/main_node.py`, `src/nodes/post_process_node.py` (`shared.utils.audit_logger`) |
| S-5 | Immutable audit-log entry (`audit_log_entry`) — EU AI Act Art. 72 evidence | `src/services/audit_log_service.py` |

The framework owns the execution order (`initialize → pre_process → main →
post_process → finalize`). The S-1 gate fires inside `InitializeNode.__call__`
before any `execute()`. Injection/secret blocking is at S-3 (output masking in
post_process), NOT S-1 (input normalization only).

## 7. Error handling

Validation/security failures set `status=AgentStatus.ERROR` (+ `error_log`) in
`initialize`; downstream slots short-circuit (no-op preserving ERROR) and
`route()` sends the pipeline straight to `finalize`. The S-3 masking primitive is
idempotent. A direct call to `post_process` on a halted state still emits an S-5
audit entry (status `halted`), so no outcome is un-audited.

## 8. Deployment entry points

The agent is reachable through two entry points, and both resolve their runtime inputs the same way.

| Entry point | File | Used by |
|---|---|---|
| Standalone HTTP | `src/api/server.py` | staging rehearsal, direct invocation |
| Marketplace one-shot Pod | `cli.py` | the platform runner (container `CMD`) |

Both read runtime parameters from `config/config.yaml` — the manifest carries discovery metadata
only — and both scope secrets to the same location (`namespace=cmn-c1-197`, `agent_name=OWASPAnomalyAlertAgent`), so a
secret provisioned for one path resolves identically on the other.

**No LLM client is constructed at either entry point, and the graph injects none.** Steps 1 and
3–6 are deterministic and never call a model. The only model touchpoint is Step 2's optional
enhancement (§3). When it runs it builds an `AzureOpenAIClient` **per invocation, inside the
service**, from the invocation-scoped secret provider — `ctx.secrets.require()` for
`AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_DEPLOYMENT` — never from the
process environment, and never cached on the node, so one caller's credential can never be reused
for another. `MainNode(llm=...)` exists as a test-double seam only; production wiring
(`register_nodes()`) passes none, so the per-invocation build is the path every real call takes.

**Degrade conditions.** The enhancement returns "no change" — leaving the rule-table result
untouched — when there is no event payload to send, when any of the three secrets is unavailable,
on an API error, on a malformed or unparsable response, and when it proposes no new row. It never
raises and never affects `status`, so a deployment that provisions none of the three secrets runs
the deterministic pipeline exactly as if the enhancement did not exist.

**Progress events.** Each pipeline stage emits a non-terminal progress event at its start, so a
caller sees the run advancing. Outside the Marketplace runtime the emitter resolves to a no-op, so
the same code is safe on every path. Terminal events belong to the platform runner and are never
emitted by this agent.

**Caller authentication at the standalone entry point.** A caller that no upstream middleware
vouched for stays anonymous unless it presents a deployment-level credential: the external bearer
token grants the verified-external level, and a separate staging-only runner credential is the only
way to reach the internal level. Trust established upstream is never changed.

**Marketplace one-shot Pod is not a viable deployment target for this manifest, as of AgentCore
1.0.3.** `required_trust_level: "INTERNAL"` above is a deliberate S-1 gate choice, not an oversight
(§8's own caller-authentication design leans on it). The current Marketplace runner stamps every
invocation's caller trust as `VERIFIED_EXTERNAL` unconditionally, with no elevation path, so the
S-1 gate rejects every single Marketplace invocation. This is a known platform-runner limitation
under active discussion; per current guidance, lowering a template's own required trust level to
work around it is not an acceptable fix — it widens a security boundary and needs a platform-level
decision. Until the runner supports an elevated caller trust path, the Marketplace Pod entry point
(`cli.py`) stays out of scope for this template; the standalone HTTP entry point
(`src/api/server.py`) is the supported deployment path.
