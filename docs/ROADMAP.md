# Roadmap

Status: **done** (merged and tested), **done (review)** (tested, in an open pull request), **in progress**, **planned**, **blocked** (waiting on
something outside this repository), **pending hardware** (code done, not yet run on the
device).

Work stops for Ken's approval at each gate. Nothing is merged automatically.

## Phase 1: audit and architecture

| Item | Status |
|---|---|
| Audit of existing repositories and the G16 ([AUDIT.md](AUDIT.md)) | done |
| Architecture ([ARCHITECTURE.md](ARCHITECTURE.md)) | done |
| Threat model ([THREAT_MODEL.md](THREAT_MODEL.md)) | done |
| `nyx-auth-core`: methods, assurance, surfaces, policy engine | done (review) |
| `nyx-auth-proto`: `Auth1` interface types and client | done (review) |

## Phase 2: hardware and enrollment

| Item | Status |
|---|---|
| Discovery: cameras (IR/RGB), fprintd readers, FIDO2 keys, TPM | done (review) |
| Adapters with mocks: fprintd, FIDO2, Irlume (IR), Gaze (RGB), password | done (review) |
| One face backend per camera | done (review) |
| `nyx-authctl doctor` | done (review); verified on the G16 |
| `nyx-auth-helper` with argv-matched polkit actions | done (review); not installed |
| Enrollment and management: fingers, faces, named primary and backup keys | done (review), [ENROLLMENT.md](ENROLLMENT.md) |
| **Gate**: install packages | done (Ken, 2026-11-01) |
| **Gate**: IR emitter setup, real enrollment | pending (Ken) |
| G16 IR camera with Irlume | pending hardware |
| G16 RGB camera with Gaze | pending hardware |
| TE-FPA-CA1 with libfprint | pending hardware |
| YubiKey (touch, PIN) | pending hardware |

## Phase 3: system authentication

| Item | Status |
|---|---|
| `nyx-auth-pam`: generator, parser, managed blocks, remote and lid gate | done (review) |
| Snapshots, atomic writes, 120-second auto-rollback | done (review) |
| Migration of Omarchy's `pam_u2f` and `pam_fprintd` lines | done (review) |
| Container suite (Docker, Arch, real PAM, mock modules): 22 cases | done (review) |
| **Gate**: sudo (face, hands-free) | done, verified on the G16 |
| **Gate**: polkit-1 (face, hands-free) | done, verified on the G16 |
| **Gate**: lock screen face service (`omarchy-lock-face`) | done, verified on the G16 |
| **Gate**: SDDM | live on the G16: face at the login screen after logging out (empty password, Enter); autologin at boot unchanged |

## Phase 4: native interface

| Item | Status |
|---|---|
| Design 2.0 tokens export for QML (nyx-design) | planned |
| `AuthOverlay.qml`: four styles, every method and state, with a preview | done |
| `design-nexus.auth-lock` from `ken.lock` (face on wake) | done, in use on the G16 |
| `design-nexus.auth-polkit` with the scan overlay | done, in use on the G16 |
| `design-nexus.auth-prompt`: the sudo scan overlay | done, in use on the G16 (app requests use the administrator prompt's face card) |
| SDDM theme | done: `nyx-biometrics`, Omarchy's screen with Halo; `nyx-authctl login-theme on\|off` |
| `nyx-authd` broker | done: session bus, verified callers, polkit prompt, grants, audit; in use |
| Nyx Settings: Sign-in & Security page, login screen switch, SSH keys | done, merged, installed |
| Reusable setup flow | contract written ([SETUP.md](SETUP.md)); the commands exist |
| Nyx Setup integration | blocked: no Nyx Setup repository |
| **Gate**: switch lock plugin | done (`ken.lock` kept as rollback) |

## Phase 5: Nyx Passwords

| Item | Status |
|---|---|
| `nyx-auth-keyd`: TPM-sealed key, polkit-confirmed release | done, in use |
| Face and fingerprint quick unlock | done, in use: face first, from Passwords and Glimpse |
| Security-key unlock with `hmac-secret` | planned |
| Re-prompt through the broker | done for Glimpse copies of protected items (opt-in) |
| Passkey user verification through the broker | done: when a site requires it |
| FIDO2/WebAuthn two-step sign-in | planned |

## Phase 6: extended integrations

| Item | Status |
|---|---|
| SSH agent for Bitwarden SSH key items, per-use approval | done in Nyx Passwords (its own agent) |
| OpenSSH `sk` keys | done: `nyx-authctl ssh-key`, Settings, [SSH.md](SSH.md); untested without a key |
| Assistant: `Secrets` approvals also need the person to sign in | done, through the broker; `Privileged` already needs `auth_admin` |
| Glimpse: protected items through the broker; face unlock from the locked row | done, in use |

## Phase 7: hardening

| Item | Status |
|---|---|
| Security review of every privileged component | done: one fix (stand-in broker), limits in [THREAT_MODEL.md](THREAT_MODEL.md) |
| Recovery drills | done in the container suite and live auto-rollback; TTY steps in RECOVERY.md |
| `ENROLLMENT.md`, `RECOVERY.md`, `HARDWARE.md` | first versions done |
| Final summary: completed, blocked, deferred | done: [STATUS.md](STATUS.md) |

## Not planned

- A Nyx password database or sync service: Vaultwarden stays the backend.
- Custom face recognition models, fingerprint drivers or cryptographic primitives.
- Passwordless decryption of the Vault from a face or fingerprint match alone: the match
  releases a root-held key; it is never the key.
- hyprlock integration: Omarchy's lock screen is the Quickshell plugin. hyprlock users can
  use the generated `nyx-lock-*` PAM services, but it isn't tested.
