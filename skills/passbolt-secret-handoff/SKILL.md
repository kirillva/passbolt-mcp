---
name: passbolt-secret-handoff
description: Use a Passbolt credential without exposing it - search metadata, select for the exact URL, deliver to a registered sink, confirm, clean up. Use for "войди с паролем из Passbolt", "use vault credential", "передай доступ скрипту".
license: LicenseRef-ZAI-ONE
compatibility: Requires passbolt-mcp with passbolt:use scope and at least one sink registered by the operator.
metadata:
  service: passbolt
---
# Secret handoff (never in chat)

Read [references/security.md](references/security.md) and [references/sinks.md](references/sinks.md).

## Steps
1. Confirm which sink fits (`login_fill`, `pg_ro`, `ssh_ops`, `ssh_adhoc`); ask the user if several
   `sink_ref`s exist. The target host/port/path comes from the Passbolt record URI.
2. `passbolt_search(query)` → pick the resource by name/username (metadata only).
3. `passbolt_select(query)` → `selection_id`. `target_url` is only an optional ranking hint.
4. For `pg_ro`/`ssh_ops`/`ssh_adhoc`: create a one-time job with
   `scripts/passbolt_job.py` and pass its reference as `job_ref`.
5. `passbolt_use_secret(selection_id, sink_ref, job_ref?)` → report only the delivery status.
6. Let the consumer do its job and read only its result file (0600); never the secret.
7. Summarise: which resource (name), which sink, success/failure. No secret material.

## Guardrails
- Never pass a caller-chosen target: delivery always uses the record URI.
- If no sink fits: stop and ask the operator to register one; never offer to show the password.
- Errors: [references/errors.md](references/errors.md).
