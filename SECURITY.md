# Public Runner Security Boundary

## Trust model

`forge-runner` is hostile/untrusted execution infrastructure. Forge Studio is the sole authority for tenant/project state, durable jobs, approvals, provenance and artifact acceptance. The public repository never receives private source, database credentials, provider credentials, or long-lived cloud credentials.

## Threat model

| Threat | Control | Fail-closed signal |
|---|---|---|
| Manifest tampering | canonical SHA-256 + short-lived signed manifest endpoint | `MANIFEST_INTEGRITY` |
| Replay/stale execution | attempt ID + coordinator-side replay key + cancellation fencing | `STALE_EXECUTION` |
| Arbitrary repo/ref execution | coordinator dispatches only immutable public-runner commit | `RUNNER_REF_INVALID` |
| Action compromise | no third-party actions except `actions/checkout` pinned to full SHA | security audit fails |
| Secret exfiltration | only scoped callback credential; child process receives allowlisted env | `POLICY_VIOLATION` |
| SSRF/egress abuse | HTTPS + hostname allowlists + no process network URLs | `NETWORK_POLICY` |
| Path traversal | ephemeral workspace + path containment | `PATH_TRAVERSAL` |
| Resource exhaustion | input/output/count/runtime bounds and GitHub job timeout | `*_LIMIT` |
| Artifact substitution | SHA-256 before use and after production | `ARTIFACT_INTEGRITY` |
| Callback spoofing | short-lived per-execution callback credential + coordinator HMAC/static auth | HTTP 401 |
| Log leakage | structured redaction and bounded callback/log payloads | redacted logs |
| Public workflow compromise | immutable dispatch ref + pinned dependencies + minimal permissions | preflight/audit failure |

## Allowed workloads

Only `sha256`, `package`, `ffprobe`, `ffmpeg`, and `whisper` are accepted. Whisper must be preinstalled on the runner image; the workflow never downloads executable/model dependencies at runtime. Missing tools fail closed.

No private checkout, arbitrary shell, arbitrary repository/ref, package installation, dynamic action selection, remote FFmpeg protocol, or secret forwarding is supported.

## Recovery/fencing

Forge records `(job, attempt, correlation, manifest hash, runner commit/ref, capacity class)` and rejects callbacks from non-current attempts. Cancellation, timeout, recovery and release epoch changes must terminally fence the execution before any downstream success transition. A public run can therefore finish physically after cancellation, but its result cannot mutate the private durable job.

## Incident diagnostics

Inspect the execution row, manifest hash/signature, callback replay key, GitHub run ID/attempt, terminal reason, artifact hashes and security metrics. Treat `MANIFEST_*`, `ARTIFACT_INTEGRITY`, `NETWORK_POLICY`, `STALE_EXECUTION`, `CALLBACK_*`, `OUTPUT_LIMIT` and `POLICY_VIOLATION` as security events rather than transient provider errors.
