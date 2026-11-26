# Changelog

## 0.10.0

- New `android_fill` sink: signs in to an Android app through uiautomator2. Records use
  `android://<package>[/<Activity>]`; the app must be in the foreground (the sink refuses to steal
  focus from another package), selectors come from `android-profiles.json` (text/resource-id/class/
  description/absolute xpath, fill/click/press/wait, `verify` present|absent), and the generic
  heuristic covers a two-field login form. Outcomes reuse the web sink vocabulary — `logged_in`,
  `rejected` with the app's own wording, `unconfirmed`, `mfa_required`. The password is typed via
  the accessibility `set_text` call, never `adb shell input text`, so it cannot leak through a
  process list on the host.
- `install_sinks.py --android-adb PATH` pins the adb binary for that sink; the sink also honours
  `ANDROID_SERIAL` and falls back to the single connected device.

## 0.9.8

- `passbolt_create_resource` can now create legacy **v4** records
  (`PASSBOLT_CREATE_LAYOUT=v4`, or `resource_type="v4-default"` for one call): plaintext
  `name`/`username`/`uri`/`description` plus a secret encrypted for the service user, with no
  metadata envelope — the same shape this vault's own UI produces, so it needs no metadata keys
  and stays editable by the server afterwards. Sharing at create time is refused (each recipient
  needs its own ciphertext): create the record, then grant access in the vault UI.
- `resource_type` defaults to `auto` and follows the layout setting; unknown values are rejected.
- The change log marks writes that grant nothing (a share-less create) as `approval:
  not_required` instead of implying a human approval that never happened.

## 0.9.7

- A configuration failure during a write (missing metadata private keys, an unusable record) now
  settles the attempt as `failed` instead of `pending`, and the custody error is raised as
  `ProviderConfigurationError` with an actionable hint. Previously such a call left a pending
  digest that blocked every retry with the same request as "pending reconciliation" — the trap we
  hit twice while migrating the demo record. Post-dispatch unknowns still stay pending.

## 0.9.6

- Fix the import that 0.9.5 missed: `runtime.py` referenced `ProviderError` without importing it,
  so any failing call would have raised `NameError` while writing the log entry.

## 0.9.5

- The local error log keeps the message of every failure this project authors (`ValueError`,
  `ProviderError`, `ProviderResponseError`), not only validation ones. Those strings are static
  and secret-free — provider payloads never become messages — and without them a failed write read
  as "provider_response_invalid" with no clue which check refused it.

## 0.9.4

- Two local shape checks during a v5 update (missing metadata, metadata type mismatch) raised a
  provider-response error, which the write gate settled as an unknown outcome: the request digest
  then blocked every retry as "pending reconciliation". They are validation errors about the
  record, so they now raise `ValueError` and settle the attempt as failed.

## 0.9.3

- The write path picks the envelope by **layout**, not by type id: a record with no v5 `metadata`
  is rewritten through the plaintext path even when Passbolt has renamed its type to a v5 one.
  That hybrid is exactly what Passbolt leaves behind when it converts a v4 record, and it made the
  follow-up note update fail with "resource metadata is invalid".

## 0.9.2

- `password-string` is updatable. Passbolt converts a v4 record to that v5 type when its metadata is
  first written, and the update path then refused it ("supports only v5-default and v5-pin-code"),
  which stranded the very record the migration had just touched. It shares the v5 metadata
  envelope (name, username, uris, description, icon, custom fields), so it goes through the same
  lossless rewrite with its own `resource_type_id` preserved. The v4 URI limit now follows the
  published type definition (1024), not a guessed column width.

## 0.9.1

- The v4 update sends no `secrets` field at all. Passbolt validates the secret list strictly on
  that endpoint (the first attempt answered HTTP 400 "Could not validate resource data" with
  `secrets` flagged), and it replaces the list when present — so a metadata-only PUT is the safe
  shape: the ciphertext stays untouched, verified by reading the record back after a live update.

## 0.9.0

- `passbolt_update_resource` now updates legacy **v4** resources (`password and description`),
  which is what a vault that was never migrated stores: `name`, `username`, `uri` and
  `description` change, untouched fields are re-sent from the stored resource so a partial PUT
  cannot blank them, and `uri` is capped at the v4 limit of 255 characters. Secrets are neither
  decrypted nor re-encrypted — the ciphertext read from the vault is sent back verbatim, so a
  metadata edit can never lose somebody's password. Password rotation on v4 is refused
  (`secret_source`): that stays a vault UI action. This is what unblocks writing a proper scheme
  into an old bare-host URI.

## 0.8.6

- The local error log records `detail` for validation failures — the message this project authored
  ("must be an http(s) site without credentials", "v5-default metadata has fields outside its
  schema"), bounded to 300 characters. Provider payloads and secrets still never reach it, but an
  operator can now see why a call was refused instead of only the exception class.

## 0.8.5

- A local validation error during a write (an unsupported field, a rejected URI) settled the
  attempt as `pending`, and the same request digest then blocked every later attempt with
  "pending reconciliation" even though nothing had been sent. Such errors now settle the write as
  `failed`, so a corrected retry with a new idempotency key works immediately.

## 0.8.4

- Updating a record's URI used its own HTTPS-only validator, so a `postgresql://` or `ssh://`
  address could be created but never written to an existing record. The update path now accepts
  the same scheme set as create (`http`, `https`, `postgresql`, `postgres`, `ssh`) and still
  refuses credentials, a query, a fragment or a bare host.

## 0.8.3

- Every applied write now leaves a local record in `state/data-changes.jsonl` (0600, rotated):
  operation, approval mode, actor, ids, the requested fields (URIs and names as-is, the note as a
  length only, `secret_source` as its kind) and the result.
  `scripts/tool_log_report.py --changes` prints the summary.
- `PASSBOLT_WRITE_APPROVAL=auto` lets the operator pre-authorise writes: the server records the same
  digest-bound approval as a standing one (`acceptance_type=standing`,
  `acceptance_origin=operator_config`), consumes it once and applies the write in a single call,
  audited and logged as `approval: "auto"`. The default stays `operator`, and no tool argument can
  switch the mode.

## 0.8.2

- `custom://<label>` records keep their connection fields in the note: `scheme`, `host`, `port`,
  `database`, `path` as `key = value` lines, comments allowed, 8 KB bound, one value per key. The
  server reads and validates the note when the secret is delivered and hands the sink an ordinary
  target (`"source": "note"`, audited as `custom_note`); the note itself never reaches the sink,
  and a note that tries to carry a password or token is refused.

## 0.8.1

- The pg sinks unwrap Debian's `/usr/bin/psql` (pg_wrapper). On a client-only host that wrapper
  refuses to start with "You must install at least one postgresql-client-<version> package" even
  though the versioned binary is present; the newest `/usr/lib/postgresql/*/bin/psql` is used
  instead. A wrapper that really has no client is reported as `remote_error` with that reason
  instead of a bare "psql invocation failed".

## 0.8.0

- PostgreSQL sinks speak through **psql** instead of psycopg: the ~13 MB `.venv-pg` and the
  Python driver dependency are gone. The password travels in a temporary `PGPASSFILE` (0600,
  private directory, deleted after the call) and never in argv or the child environment;
  `PGOPTIONS` keeps the session `default_transaction_read_only`; rows come back as one JSON
  object per line (`row_to_json`), so PostgreSQL types survive, bounded by `max_rows` and 1 MiB.
  `sslmode` defaults to `require` (encrypt, do not verify) and `psql_version` is reported.
  `pg_exec` becomes the bundled `pg_check.py` diagnostic.
- Record URIs name their protocol: `postgresql://`/`postgres://` for databases, `ssh://` for
  shells, `http(s)://` for web, with each sink declaring `uri_schemes`. A scheme the sink does
  not accept answers `provider_configuration_invalid` with the allowed list; `allow_bare_host`
  keeps accepting `host[:port][/db]` where records are already written that way, and a standard
  scheme picks its standard port.
- The domain allowlist no longer blocks. `domain_policy` defaults to `any`: creating or updating
  a record for a new site needs no settings edit, because the vault is the allowlist. The
  plain-HTTP delivery gate went with it. An existing `domain_hosts` stays advisory
  (`unlisted_host` in the audit) and `"domain_policy": "allowlist"` restores the old boundary.
  Migration note: an installation that relied on the old default now has write scope for any
  vault host it can already read — set `allowlist` if that was intentional.
- `validate_v5_metadata` (write) accepts the standard schemes (`http`, `https`, `postgresql`,
  `postgres`, `ssh`) and still refuses credentials, query, fragment or a bare host.

## 0.7.5

- The tool-error log keeps the scheme of a `target_url` hint (`http://demo.example`) instead of
  collapsing it to a bare host. Credentials, path, query and fragment are still dropped, but
  `http` vs `https` is exactly the mistake the guides have to explain, so it has to be readable
  in the log.

## 0.7.4

- Every failed tool call leaves a local, private line in
  `~/.config/passbolt-mcp/state/tool-errors.jsonl` (0600, rotated at 2 MB, two rotations):
  tool, `outcome`, safe `code`, exception class, our own `hint`, `actor`, `execution_id`,
  `duration_ms` and a whitelisted argument shape. Never a password, `secret_source`, note, full
  URI or provider message, and a broken log never fails a call. `PASSBOLT_TOOL_LOG=0` disables
  it; `PASSBOLT_TOOL_LOG_PATH` relocates it inside `$HOME`. `scripts/tool_log_report.py` groups
  the log by tool/code/hint and prints the argument shapes worth fixing in the guides — the
  point of the file is better instructions, not another dashboard.

## 0.7.3

- The refusal check reads every visible dialog, not just the first. On a real stand the login
  window itself is a dialog and appears earlier in the DOM than the message box above it, so
  0.7.2 reported a refused credential as `unconfirmed` even though the site had said
  "Неверный логин или пароль" out loud. `passbolt_use_secret` now returns `rejected` with the
  site's own sentence in `detail`.

## 0.7.2

- Browser sinks confirm a login instead of declaring one. After the steps the sink looks for
  the site's own refusal — an ARIA alert or a visible toolkit dialog reading like "Неверный
  логин или пароль" / "invalid credentials" / "account is locked" — and returns
  `status: "rejected"` with that sentence in `detail`; when the login form is simply still on
  screen it returns `unconfirmed`. Both are non-zero outcomes, so a refused credential can no
  longer come back as `logged_in`: ExtJS-style message boxes carry no `role=alert` and were
  missed, and the absence of an alert was read as success. A profile can widen the
  confirmation window with `settle_ms` (1000–30000 ms, default 6000).

## 0.7.1

- Domain matching follows the host, not the URL spelling. `passbolt_search` and
  `passbolt_select` take `target_url` as the address-bar form: `https://host/path?x=1`,
  `http://host` and a bare `host` are the same site, path/query/fragment are dropped
  instead of refused, and a hint may name a parent domain (`it-serv.ru` also lists
  `demo.it-serv.ru`). Ranking reports it as `domain_match` or `domain_suffix_match`, and
  several matches still come back as `candidates` for the caller to choose from — the
  hint only filters metadata, the delivery target stays the record URI. Credentials and
  non-HTTP schemes in a hint remain invalid.
- A record URI may be plain HTTP when the operator says so: `"allow_insecure_uri": true`
  on one sink, or `PASSBOLT_ALLOW_INSECURE_HTTP=1` for all of them. `http://` derives
  port 80 (an explicit port still wins, other schemes keep `default_port`), and a browser
  sink follows the tab the browser upgraded — 80 and 443 on the same host are one site,
  any other port is not. Plain-HTTP delivery also requires the host in `domain_hosts`
  (`plain_http_denied` in the audit); HTTPS records and the write-side origin policy are
  unchanged. The delivery envelope gains a `scheme` field.
- Configuration problems this project authors now answer `provider_configuration_invalid`
  with a short `hint` (for example which switch to set for a plain-HTTP lab site), so a
  caller can act instead of retrying. Provider and sink messages stay opaque.

## 0.7.0

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
