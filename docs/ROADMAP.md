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
| **Gate**: live sudo, polkit-1, SDDM and lock services, one at a time | planned |

## Phase 4: native interface

| Item | Status |
|---|---|
| Design 2.0 tokens export for QML (nyx-design) | planned |
| QML `NyxAuth`: four styles, every method and state | planned |
| `design-nexus.auth-lock` from `ken.lock` (face and key contexts) | planned |
| `design-nexus.auth-polkit`, `design-nexus.auth-prompt` (with preview mode) | planned |
| SDDM theme | planned |
| `nyx-authd` broker | planned |
| Nyx Settings: Sign-in & Security section, Users-page summary card | planned |
| Reusable setup flow | planned |
| Nyx Setup integration | blocked: no Nyx Setup repository |
| **Gate**: switch lock and polkit plugins | planned |

## Phase 5: Nyx Passwords

| Item | Status |
|---|---|
| `nyx-auth-keyd`: TPM-sealed wrapping key, PAM-gated release | planned |
| Face and fingerprint quick unlock | planned |
| Security-key unlock with `hmac-secret` | planned |
| Re-prompt through the broker | planned |
| Passkey user verification through the broker | planned |
| FIDO2/WebAuthn two-step sign-in | planned |

## Phase 6: extended integrations

| Item | Status |
|---|---|
| SSH agent for Bitwarden SSH key items, per-use approval | planned |
| OpenSSH `sk` keys: guidance and detection | planned |
| Assistant: broker authentication for `Privileged` and `Secrets` approvals | planned |
| Glimpse: protected items through the broker | planned |

## Phase 7: hardening

| Item | Status |
|---|---|
| Security review of every privileged component | planned |
| Recovery drills from a TTY | planned |
| `ENROLLMENT.md`, `RECOVERY.md`, `HARDWARE.md` | first versions done |
| Final summary: completed, blocked, deferred | planned |

## Not planned

- A Nyx password database or sync service: Vaultwarden stays the backend.
- Custom face recognition models, fingerprint drivers or cryptographic primitives.
- Passwordless decryption of the Vault from a face or fingerprint match alone: the match
  releases a root-held key; it is never the key.
- hyprlock integration: Omarchy's lock screen is the Quickshell plugin. hyprlock users can
  use the generated `nyx-lock-*` PAM services, but it isn't tested.
