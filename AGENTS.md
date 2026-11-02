# Biometrics

Unified local authentication for Nyx and Omarchy: face (Irlume for IR cameras, Gaze for
RGB), fingerprint (fprintd), FIDO2 security keys (pam_u2f, libfido2) and password,
behind one policy engine and one broker. docs/ARCHITECTURE.md is the map;
docs/THREAT_MODEL.md is binding for every change.

Commands: `cargo check --locked --workspace --all-features`; `cargo test --locked --workspace --all-features`;
`cargo clippy --locked --workspace --all-features --all-targets -- -D warnings`

Security rules:
- Never edit the host's /etc/pam.d, polkit rules, SDDM or lock plugins from a test or
  a build step. PAM stacks are tested in a container only (docs/ARCHITECTURE.md, PAM).
  Live changes go through nyx-auth-helper after Ken approves the diff.
- Password authentication must stay a working path on every system surface.
- Never weaken an authenticator's user-presence or user-verification requirement, and
  never let a weaker method satisfy a stronger policy. The policy engine refuses it.
- Never log passwords, PINs, biometric templates, embeddings, frames or key material.
- No custom cryptographic primitives or hardware drivers; use established libraries.
- Keep privileged code minimal: root helpers parse every argument again and accept a
  fixed verb list.

Use the public, pinned shared crates; never import another application's internals.
Keep application names, IDs, paths, D-Bus interfaces, and data formats stable.
Use canonical STYLE.md from the pinned nyx-design dependency. Reuse existing
widgets, theme tokens, icons, and shortcuts.
Run essential targeted checks only. Do not download models or run inference for
routine verification. Install app updates without opening/restarting them.
Common guidance: https://github.com/design-nexus/nyx/blob/main/docs/AGENTS_COMMON.md
Never force-push, delete history, or merge security-critical work without review.
