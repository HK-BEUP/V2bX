# HK-BEUP Xray observation candidate

This is a local, unreleased candidate based on HK-BEUP/V2bX commit
`2a8384e4c6158c4ddf4e91786c34dceb65528bb4`.
Build with `GOEXPERIMENT=jsonv2 go build -tags xray`. This candidate's binaries
contain Xray only, not sing-box or Hysteria2. Do not use them for nodes configured
with another core. Existing protocol configuration and dependencies are unchanged.
The target site profile is VLESS + TCP + REALITY + xtls-rprx-vision, confirmed
by the operator and a read-only aggregate node-table audit on 2026-09-12.
The Xray distribution's existing DNS/routing/outbound features are retained;
this is not unsafe removal of every unused protocol registration.
The existing release workflow is NOT switched to this candidate by this document.

## Opt-in, observation only

Without `BEUP_OBSERVATION_CONFIG` there is no observer and no telemetry.
The path must point to an administrator-provisioned private settings file
(directory 0700, regular file 0600, owned by the process user). Invalid settings
disable telemetry without stopping proxy traffic. No settings, account bindings,
reporting keys, service-unit changes or registration documents are bundled.
Non-Unix platforms reject observer settings because their ownership policy has
not been audited; normal proxy startup with observation unset is unaffected.

The signed registration mode uses an Ed25519 public key, pinned node/receiver,
minimum sequence and a private signed lease (at most 15 minutes), reloaded every
5 seconds. Expiry suspends observation only. Sequence high-water protection is
in-process, not persistent across restart. Automatic roster renewal and private
delivery must be deployed and verified separately.

Only authenticated Xray logical dispatch requests are counted in 60-second
windows. VLESS is the locally exercised protocol. These are not successful
connections, HTTP requests, downloaded bytes or proof of an attack. Failure,
packet and byte metrics remain null, and complete remains false. Reports contain
random registered subjects and aggregates, never subscription credentials,
raw target addresses or payloads. Bounded nonblocking queues limit overhead.

This code does not ban accounts, change speed limits, close connections or
enable attack-protection enforcement. The backend observation receiver is
separate and not automatically enabled by installing this program.

## Before any production use

Verify each target uses Xray; back up the binary, configuration, certificates
and service definition; validate the release hash and configuration offline;
request a single-node maintenance window with an explicit rollback.
Keep telemetry off until the authenticated backend and lease delivery are ready.
Do not use the legacy installer as proof of safe rollback: it removes the
program directory before downloading and lacks artifact hash enforcement.

The source retains the upstream MPL-2.0 license. Tests use synthetic data only.
