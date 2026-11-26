# Changelog

## Unreleased

- Update checks can follow a downstream feed: `PASSBOLT_UPDATE_REPOSITORY` selects whose releases
  or tags are compared (default `zai-one/passbolt-mcp`) and is validated before it reaches any URL,
  result or model-facing text — a malformed value makes no request and reports `status: "unknown"`
  instead of "up to date". `PASSBOLT_UPDATE_COMMAND` names the operator's own update command: it
  becomes `install_method: "operator_script"` and the suggested `update_command`, so callers are
  never told to install an artifact that lacks the operator's changes. The cache is now bound to the
  checked repository, results carry a `repository` field, and `passbolt_status` exposes it.
- Search and selection: `passbolt_search` filters by `query` (name/URI/username, matched per field),
  `target_url` (origin) and `username`; filters combine with AND and `target_url` alone lists every
  account on a site. `passbolt_select` accepts `resource_id`/`username`, returns the bound record's
  decrypted note (`note`, `note_available`) and never binds silently: several matches return
  `ambiguous: true` with `candidates`.
- Browser sinks: `passbolt_use_secret(page=<marker>)` selects the tab whose URL carries
  `?pb=<marker>`; the marker never changes the target, is bound into the approval digest, and uses a
  per-marker lock. Ambiguity is a structured `no_target` error instead of a guess, and web profiles
  may declare `verify.session_storage` to return the logged-in `account` (or `account_mismatch`).
- `passbolt_use_secret` returns the sink outcome (`status`, `url`, `account`, `page`, `error`,
  `detail`) instead of only a boolean; sinks print one JSON line with the outcome.
- `passbolt_status` exposes registered `sinks` (ref/kind/approval) plus the allowed `sink_refs` and
  `domain_hosts`, so callers never inspect the operator's `secrets/` directory.
- `PASSBOLT_RATE_LIMIT=0` disables the local sliding 60-second request window entirely. The window is
  an MCP-side guard (10 requests/min per vault by default), not a Passbolt server limit; the cooldown
  after a real 429/timeout/transport failure and the single in-flight lease still apply.
- `PASSBOLT_RATE_LIMIT_EXEMPT_READ_ONLY` (default `false`): operator opt-in that frees metadata-only
  vault reads (`passbolt_search`, `passbolt_directory`, `passbolt_list_folders`, `passbolt_status`) from
  the sliding 60-second request quota. The provider-failure cooldown (HTTP 429, timeout, transport
  error) and the single in-flight lease still apply, and every write or secret-use path keeps counting.

## 0.7.0

- Sinks: the delivery target (host, port, path/database) is derived from the Passbolt resource URI;
  callers cannot override it. Removed the domain allowlist check and mismatch approvals from the
  use path; `passbolt_select` no longer requires `target_url` (kept as an optional ranking hint).
  `passbolt_use_secret` accepts `job_ref` instead of a caller-supplied target.
- One-time jobs: `job_dir`/`max_job_bytes` in the sink registry, `job_sha256` bound into the
  approval digest, TOCTOU re-check before delivery, archived after use. New `scripts/passbolt_job.py`.
- Per-sink `require_approval` (`never` default, `always` for `ssh_adhoc`); audit records
  `job_sha256`, `target_host`, `target_port`.
- New example sinks: `login_fill` (single-tab CDP autofill, focus check, MFA/login-error codes),
  `pg_query` (read-only transaction plus conservative SQL allowlist), `ssh_ops` (known_hosts,
  profiles, argv-only commands, staged SFTP uploads).
- `scripts/install_sinks.py` deploys the examples, rewrites shebangs, pins SHA-256 and updates the
  registry atomically. `doctor` checks sink paths (job dir, known_hosts, profiles, CA).
- Sinks are split into a layered package (`passbolt_sinkkit`): envelope, guards, executors, a
  shared CLI and result writer. Entrypoints are thin; site-specific login flows are data in
  `web-profiles.json`, pinned together with the package by `bundle_sha256`.
- Docs: `docs/SINKS.md`; router/skill text now describes the record-URI model.

## 0.6.0

- Optional lazy tool loading (`PASSBOLT_TOOL_LOADING=eager|lazy`, default `eager` = unchanged): lazy lists a small core plus `passbolt_enable_toolsets` (toolsets with one-line description and token cost); enabling registers the tools at runtime and sends `notifications/tools/list_changed`. Allowlists, read-only mode and approval gates still apply. Setup wizard asks eager vs lazy. Startup tokens (tools/list + instructions, ≈chars/4): eager ≈2448, lazy ≈1048. Scope: enablement is per MCP session (FastMCP session visibility), so one client's enabled toolsets never appear for another. The HTTP transport here is stateless (every request is its own session), so enabled toolsets do not persist there: for shared HTTP use `eager` or `PASSBOLT_TOOLSETS`. README lazy section lists verified `tools/list_changed` client support with sources.
- `passbolt_move_folder` (PUT /move/folder) and `passbolt_unshare` (share `{id, delete:true}`, owner permissions kept, resources simulated first) in the opt-in `organize` toolset, both approval-gated.
- Shares now ask the user through MCP elicitation right before an approved share executes
  (`passbolt_share_resource`, create resource/folder with `share_with_*`); decline/cancel aborts and is
  audited. `PASSBOLT_SHARE_ELICITATION=auto|required|off` (default `auto`: prompt only when the client supports elicitation). Operator approval still required.
- Elicitation is shown only for a valid accepted approval that matches the exact request (operation +
  arguments digest); otherwise no prompt and the write is refused as before.
- Opt-in `organize` toolset: `passbolt_move_resource` (approval-gated move to a folder or root).
- Opt-in `directory` toolset: `passbolt_directory` (group/user UUIDs the binding policy allows as share targets; per-resource permissions).
- `PASSBOLT_TOOLSETS` unset or `default` keeps the 0.5.0 surface; `all` now also adds the opt-in `directory` and `organize` toolsets (write tools there still need `PASSBOLT_WRITE_ENABLED` and operator approval).
- Router generated from `ROUTES` with tool/skill/guide per line and playbook + `guide/tool-map` fallback.
- Router eval: 23 RU/EN requests (paraphrases, negative cases); fails on any unreachable tool, skill or guide.
- Security: resuming a create-with-share (resource or folder) whose share is still pending now asks the
  share elicitation again under the current `PASSBOLT_SHARE_ELICITATION` mode, with or without `approval_id`
  (the first attempt consumed the approval); before, the resume executed the share without a prompt. Completed
  results still replay without a prompt.
- Security: `passbolt_unshare` re-reads permissions right before the PUT and refuses (`provider_precondition_failed`,
  nothing sent, key settled as failed) if a selected permission is gone, reassigned or became owner. Passbolt has
  no conditional permission update, so a promotion in the short window after that re-read is still not caught.
- Fix: the share elicitation form is a required boolean confirmation field instead of an empty form (deprecated
  in FastMCP; hangs or renders blank in some clients, e.g. VS Code); consent needs accept with the box ticked.

## 0.5.0

- License: LicenseRef-ZAI-ONE 2.0 (source-available). Free install and use for yourself and your organisation, including commercial work; issues and pull requests welcome; copying code into other projects, redistribution, embedding and competing hosted services need written permission. Earlier releases keep their LicenseRef-ZAI-ONE 1.0 terms (see NOTICE). README first screen: one-line scope, why this MCP, maintenance and update check.
- Agent layer: router `instructions` (≤1200 chars: secrets never in chat, sink flow, operator approvals), compact template descriptions and titles; all descriptions ASCII.
- Toolsets `meta`, `read`, `use`, `write` (`PASSBOLT_TOOLSETS`, `PASSBOLT_TOOLS`, `PASSBOLT_DISABLED_TOOLS`, `PASSBOLT_READ_ONLY=1` = metadata reads only); `passbolt://toolsets`.
- New read-only `passbolt_list_folders` (`GET /folders.json`; id, name, parent, personal; v5 names decrypted in custody; folder policy enforced).
- Resources `passbolt://playbook`, `passbolt://guide/{security,sinks,errors}`; prompts `secret_handoff`, `access_review`.
- Self-contained skills `passbolt-secret-handoff`, `passbolt-access-review`, `passbolt-onboard-client`; Claude Code plugin manifest, Cursor rule, `.agents/skills`.
- `scripts/token_budget.py` + tests gate instruction, description and SKILL.md sizes.
- Model-facing text (router instructions, `passbolt://playbook`, the `passbolt-onboard-client` skill) no longer names
  the operator approval command: it says the operator accepts outside MCP and the agent never accepts it itself. The
  command stays in `docs/RUNTIME.md` for operators.
- Install snippets and the plugin manifest pin `zai-passbolt-mcp[standalone] @ git+https://github.com/zai-one/passbolt-mcp@v0.5.0`.

## 0.4.0

- Safe readiness diagnostics: request-local, closed-vocabulary stage/reason logs without exception text or secret
  material; metadata key trust, metadata decryption, secret fetch and secret decryption are reported separately without
  relaxing any trust predicate. The three-boolean `passbolt_status` contract is unchanged.
- Passbolt 5.12 PIN code resources (`v5-pin-code`) are listed by name and description instead of failing the whole
  search. The PIN is never returned, and `passbolt_use_secret` refuses to deliver it.
- Type-preserving `passbolt_update_resource`: the type comes from `resource_type_id` and is never converted.
  `v5-pin-code` entries accept only `name` and `description` and the PIN secret is not read, re-encrypted or sent;
  other or unknown types (TOTP, custom fields, notes, v4) are refused before any write.
- `v5-default` updates keep every uri, the icon and custom fields; `uri` replaces only the primary uri, and a password
  rotation keeps the secret's description and custom fields inside server custody. Data outside the v5 schema is
  refused before any encryption or write instead of being dropped.
- A new `uri` on update follows the same domain policy as create and is checked before any approval, secret read,
  decryption or write; new uris are limited to 1024 characters. Read mode accepts up to 32 uris per v5 resource.
- Search and select results carry `resource_type` (Passbolt slug or `unknown`).
- MCP tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) on every tool;
  `passbolt_select` is `readOnlyHint: false` because it authorises a later `passbolt_use_secret`.
- Suggest-only update checker `passbolt_check_update`: anonymous GitHub API, 3 s timeout, 24 h cache, plain `vX.Y.Z`
  tags only, 30-minute back-off after a failure, never auto-updates or touches the vault. A cached hint appears in
  server instructions and `passbolt_status`; opt out with `PASSBOLT_DISABLE_UPDATE_CHECK=1`.
- Tests: passwords, PINs, secure notes and encrypted payloads never appear in search, select or use results;
  concurrent/cancelled probes, malformed key envelopes, real-GPG diagnostic refusal and approved encrypted password
  updates with disposable keys.
- Docs: embedded composition, registered authentication handlers, and updating a vault record versus rotating a
  website password.

## 0.3.0

- Installable setup wizard and JSON/TOML client snippets that work outside the checkout.
- English and Russian agency information, integration contact and package installation guide.
- Local key/policy diagnostics via `passbolt_local_diagnostics` and `passbolt-mcp-doctor`; signs a synthetic marker and checks the configured server public key without vault requests.
- Built-in `https_probe` secret handler: one fixed HTTPS GET with bearer or basic authentication, verified TLS, no redirects/proxy environment/retries, and no response data returned to MCP.
- Real disposable-key selection/decryption/probe tests, target/scope/owner/replay checks and installed-wheel diagnostics.

## 0.2.0

- Explicit config-file startup and offline configuration doctor.
- Install/client guide, local setup wizard and clean-wheel validation.
- Isolate active GPG keyrings without copying agent sockets; stop the private runtime agent on close. Support MSYS GnuPG paths on Windows.
- Passwords remain in server custody. GnuPG must be installed separately. Real disposable-key crypto tests run in the Linux gate. Secret producer and automatic unknown-write reconciliation are future work.
- LicenseRef-ZAI-ONE and Issues-based feedback policy.
