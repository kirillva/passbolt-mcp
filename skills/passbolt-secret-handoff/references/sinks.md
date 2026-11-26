# Sinks (where secrets go instead of the chat)

Sinks are registered by the operator in the sink policy file (`PASSBOLT_SINK_CONFIG_FILE`); the agent
can only pick a `sink_ref` allowed for its binding. The delivery target (host, port, path/database)
is taken from the Passbolt resource URI, so the agent cannot redirect a credential.

| Kind | What happens | Typical use |
|---|---|---|
| `secure_fill` | runs an operator-configured local command and passes the credential on stdin | browser login, ssh, pg |
| `out_file` | writes a short-lived envelope file into a private spool directory | handing off to a local script that reads and deletes it |
| `https_probe` | sends the secret to the configured HTTPS check and returns only pass/fail | verifying a credential still works |

## Which sinks exist

Do not guess a `sink_ref` and do not read the operator's `secrets/` directory: `passbolt_status`
returns `sinks` (ref, kind, requires_job, approval mode, `uri_schemes`), `sink_refs` (the ones your
binding may use), `domain_policy` and `domain_hosts` (advisory unless the policy is `allowlist`).

`passbolt_use_secret` returns the sink outcome, not just a boolean:
`{"delivered_to_sink": true, "status": "logged_in", "url": "...", "account": "..."}`.
A structured failure (`status: "no_target"`, `"rejected"`, `"unconfirmed"`, `"account_mismatch"`,
`"timeout"`) comes back the same way, so read `status`/`detail` instead of assuming success from
`delivered_to_sink`. `rejected` carries the site's own refusal ("Неверный логин или пароль"),
`unconfirmed` means the login form is still on screen and nothing confirmed the session — neither
is a success, and a wrong password must not be retried blindly.

## Scheme, port and protocol

The record URI names the protocol: `https`/`http` for web, `postgresql` (or `postgres`) for
databases, `ssh` for shells, and `host[:port][/db]` where the sink allows a bare host. An
explicit port wins, otherwise the scheme's standard port (443/80/5432/22). A scheme the sink
does not accept, or credentials/query in the URI, answers `provider_configuration_invalid`
with a `hint` listing what is allowed — relay it instead of retrying. There is no separate
domain allowlist to satisfy: the vault is the list. A browser upgrades HTTP on its own, so an
open tab may sit on 443 while the record says 80 — same site, the sink follows it. One trap: a
site that calls its own API over plain HTTP must keep its tab on HTTP too.

A `custom://<label>` record names its address in the note instead (`scheme`, `host`, `port`,
`database`, `path` as `key = value` lines): the server resolves and validates it, and the sink
receives an ordinary target without ever seeing the note.

## Several accounts on one site (browser sinks)

When several tabs are open on the same origin, an unqualified delivery is refused. Open or navigate
one tab per account with a non-secret marker in the query string, for example
`https://host/app/?pb=u-disp#/auth`, and pass `page="u-disp"` to `passbolt_use_secret`. The marker:

- selects the tab only; host, port and path still come from the record URI;
- is matched on the `pb` query parameter of the tab URL (`[a-z0-9._-]`, up to 32 chars);
- is bound into the approval digest, so it cannot be swapped after approval;
- can be read back from `browser_tabs list`, which keeps the tab identity visible to the agent.

Wait for `status: "logged_in"` and check `account` against the record's username. Never close a tab
that holds someone else's session; close only the tab you opened.

Jobs for `pg_ro`/`ssh_ops`/`ssh_adhoc` are one-time files created with
`scripts/passbolt_job.py`; `passbolt_use_secret` takes only `job_ref`. The job hash is bound into the
approval digest and the sink archives the file after execution. Read the sink result file (0600) for
output, never the secret.

Rules: the agent never reads `out_file` spools back into the chat, never `cat`s or echoes them, and
asks the operator to configure a sink when none fits. After use, the consumer must delete the spool
file (the example consumer in `examples/sinks/` does).
