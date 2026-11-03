# Status

Where Nyx Biometrics stands, November 2026. [ROADMAP.md](ROADMAP.md) has every item;
[HARDWARE.md](HARDWARE.md) what was verified on which hardware.

## In use on the G16 (infrared camera, Irlume, no fingerprint reader)

- **Face everywhere, infrared only**: the lock screen (starts on wake and when the lid
  opens), sudo (hands-free, with a scan overlay), administrator prompts (see-through face
  card), the login screen after logging out (empty password and Enter). The password
  always works. Every PAM change went in with a snapshot and a two-minute automatic
  rollback, then a face-only test.
- **Nyx Passwords**: unlock with the face (TPM-sealed key released by `nyx-auth-keyd`
  after polkit), face first with no password box until it's needed; from Glimpse's locked
  row too. Protected items in Glimpse (opt-in) and passkeys whose sites require user
  verification confirm through the broker.
- **Nyx Assistant**: Secrets requests need the person to sign in on top of the key press.
- **`nyx-authd`**, the sign-in broker: verified callers, polkit prompt, grants that end on
  lock and sleep, rate limits, an audit log without purposes.
- **Nyx Settings › Sign-in & Security**: methods, where they're used, look, login screen,
  SSH keys, undo.

## Built, not tried on hardware

- **Fingerprint** (fprintd): probes, enrollment, PAM stacks; the container suite covers
  it. The G16 has no reader.
- **Security keys** (pam_u2f): registration, primary and backup, PIN, PAM stacks; the
  container suite covers them. No key was at hand for a live sign-in.
- **SSH keys on a security key** (`nyx-authctl ssh-key`): argument building and listing are
  unit-tested; making and loading a key need one.
- **Colour cameras** (Gaze, lower trust): probed and chosen per camera; not this laptop's
  path.

## Tests

- Unit tests in every crate; `cargo test --workspace`, clippy `-D warnings` and fmt in CI.
- Real PAM in a container (`crates/nyx-auth-pam/tests/container.rs`): every method passing,
  failing and timing out, remote and lid-closed skips, password plus key, the lock
  services, the sudo overlay cues, and restore. A deliberately broken gate makes it fail.
- Nyx Passwords' daemon tests against a throwaway Vaultwarden, including protected items,
  face unlock scopes and passkey user verification, with a debug-only stand-in for the
  person.
- By hand on the G16: each surface's face sign-in, the automatic rollback, the broker end
  to end, and a stand-in broker being refused.

## Deferred

- **Security-key vault unlock** (FIDO2 `hmac-secret`) and **Vaultwarden two-step sign-in
  with a security key**: need a key to build against.
- **Design 2.0 tokens for QML**: belongs in nyx-design; the overlays take their colours
  from the shell theme meanwhile.
- **Nyx Setup**: no repository yet. [SETUP.md](SETUP.md) is the contract its sign-in step
  can use as is.

## Known limits

In [THREAT_MODEL.md](THREAT_MODEL.md): the system prompt shows polkit's fixed message,
not the asking app; programs in `~/.local/bin` are trusted as the suite's; hands-free
sudo and polkit are an owner's choice (anyone typing sudo while the owner is in view
gets root).
