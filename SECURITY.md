# Public Runner Security Boundary

`forge-runner` is hostile/untrusted execution infrastructure. Forge Studio is the trusted coordinator and source of truth. The public repository never receives private source, database credentials, provider credentials, or long-lived cloud credentials.

## Threat model

- Manifest tampering: canonical SHA-256, HMAC signature and short TTL; fail `MANIFEST_INTEGRITY`.
- Manifest URL abuse: explicit HTTPS manifest-host allowlist; fail `NETWORK_POLICY`.
- Replay/stale execution: attempt identity, callback replay key, cancellation fencing and release epochs; fail `STALE_EXECUTION`.
- Arbitrary repository/ref execution: coordinator dispatches only a full 40-character runner commit SHA.
- Action compromise: only `actions/checkout`, pinned to a full SHA; security audit rejects mutable actions.
- Secret exfiltration: scoped callback credential only; child processes receive an allowlisted environment.
- SSRF/egress abuse: manifest, input-artifact and upload hostnames are explicit allowlists; process arguments reject network protocols.
- Path traversal: ephemeral 0700 workspace and path containment.
- Resource exhaustion: bounded manifest/input/output sizes, argument counts and 25-minute process timeout plus 30-minute workflow timeout.
- Artifact substitution: SHA-256 verified before use and returned after production.
- Callback spoofing: per-execution manifest credential; legacy static callback authentication is disabled by default.
- Log leakage: bounded, redacted process logs and callback payloads.
- Workflow compromise: production dispatch uses an immutable runner commit and minimal workflow permissions.

## Allowed workloads

Only `sha256`, `package`, `ffprobe`, `ffmpeg` and `whisper` are accepted. Whisper must already exist on the runner image; no runtime package/model download is permitted. No private checkout, arbitrary shell, arbitrary repository/ref, package installation, dynamic action selection, remote FFmpeg protocol or secret forwarding is supported.

## Required configuration

Repository variables: `FORGE_MANIFEST_HOSTS`, `FORGE_ARTIFACT_HOSTS`, `FORGE_UPLOAD_HOSTS`. Repository secrets: `FORGE_RUNNER_CALLBACK_URL` and the migration-only `FORGE_RUNNER_CALLBACK_TOKEN`. Empty allowlists fail closed.

## Fencing and recovery

Forge binds each run to `(job, attempt, correlation, manifest hash, runner commit, release epoch, capacity class)`. Cancellation, timeout, recovery or release-epoch changes fence the public execution before any success transition. A physically late public run may finish, but its callback cannot mutate the private durable job.

## Diagnostics

Inspect `forge_execution_runs`, `forge_runner_security_events`, `forge_runner_security_counters`, `webhook_replay_keys`, GitHub run IDs/attempts and artifact checksums. Treat manifest, artifact-integrity, egress, stale-run, callback-auth, output-limit and policy violations as security events rather than transient provider errors.
