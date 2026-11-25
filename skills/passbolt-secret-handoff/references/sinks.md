# Sinks (where secrets go instead of the chat)

Sinks are registered by the operator in the sink policy file (`PASSBOLT_SINK_CONFIG_FILE`); the agent
can only pick a `sink_ref` allowed for its binding. The delivery target (host, port, path/database)
is taken from the Passbolt resource URI, so the agent cannot redirect a credential.

| Kind | What happens | Typical use |
|---|---|---|
| `secure_fill` | runs an operator-configured local command and passes the credential on stdin | browser login, ssh, pg |
| `out_file` | writes a short-lived envelope file into a private spool directory | handing off to a local script that reads and deletes it |
| `https_probe` | sends the secret to the configured HTTPS check and returns only pass/fail | verifying a credential still works |

Jobs for `pg_ro`/`ssh_ops`/`ssh_adhoc` are one-time files created with
`scripts/passbolt_job.py`; `passbolt_use_secret` takes only `job_ref`. The job hash is bound into the
approval digest and the sink archives the file after execution. Read the sink result file (0600) for
output, never the secret.

Rules: the agent never reads `out_file` spools back into the chat, never `cat`s or echoes them, and
asks the operator to configure a sink when none fits. After use, the consumer must delete the spool
file (the example consumer in `examples/sinks/` does).
