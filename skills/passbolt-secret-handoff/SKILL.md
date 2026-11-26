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
1. Take the sink list from `passbolt_status` (`sinks`, `sink_refs`) instead of guessing or reading
   `secrets/`. The target host/port/path comes from the Passbolt record URI.
2. `passbolt_search(target_url=..., query=..., username=...)` → narrow by site, name, and login.
   Filters combine with AND; `target_url` alone lists every account on that site.
3. `passbolt_select(resource_id=...)` (or the same filters) → `selection_id` plus the record's
   decrypted `note`. If the answer is `ambiguous: true`, nothing is bound: choose one candidate and
   call `passbolt_select(resource_id=...)` again.
4. For `pg_ro`/`ssh_ops`/`ssh_adhoc`: create a one-time job with
   `scripts/passbolt_job.py` and pass its reference as `job_ref`.
5. `passbolt_use_secret(selection_id, sink_ref, job_ref?, page?)` → read `status`, `url` and
   `account`, not just `delivered_to_sink`. For browser sinks with several tabs per site, pass the
   `page` marker matching the tab URL `?pb=<marker>`.
6. Let the consumer do its job and read only its result file (0600); never the secret.
7. Summarise: which resource (name), which sink, which account, success/failure. No secret material.

## Guardrails
- Never pass a caller-chosen target: delivery always uses the record URI.
- Never close a browser tab that holds another user's session; close only the tab you opened.
- If no sink fits: stop and ask the operator to register one; never offer to show the password.
- Errors: [references/errors.md](references/errors.md).
