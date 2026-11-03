# Audit: authentication across Nyx and Omarchy

Taken on 2026-11-01 from the local checkouts of every `design-nexus` repository and from
the Omarchy installation on Ken's ROG Zephyrus G16 (GU605CW). Paths are relative to each
repository. "Implemented" means code that runs today; "documented" means a plan or doc only.

## Summary

| Area | State |
|---|---|
| Face recognition | Not implemented anywhere |
| Fingerprint | Omarchy scripts only; Settings launches them |
| FIDO2 security keys | Omarchy script only (touch-only `pam_u2f` for sudo and polkit) |
| Shared authentication service | None. "Nyx Biometrics" is a planned dependency in Nyx Passwords' docs |
| Nyx Setup | No repository |
| Nyx System Manager | No repository or code |
| Vault quick unlock | Keyring unlock only (raw user key in Secret Service) |
| Vault re-authentication | Master password, 5-minute grace |
| Privileged helpers | Three separate pkexec helpers (Settings, Store, Assistant) |

## Omarchy (system)

**Lock screen.** A Quickshell session lock in the Omarchy shell, not hyprlock (hyprlock
isn't installed). Ken runs `ken.lock`, a clone of `omarchy.lock` with visual changes;
`omarchy.lock` is in `disabledPlugins` in `~/.config/omarchy/shell.json`.
- It runs **two PAM contexts at once**: `omarchy-lock-password` (faillock + pam_unix) and
  `omarchy-lock-fingerprint` (pam_fprintd), written by `omarchy-apply-lock`. Separate
  contexts are why fingerprint and password can be offered together safely. Nyx extends
  this model rather than putting several modules in one stack.
- Fingerprint handling is careful: reachability probes, backoff, pause on sleep, a resume
  hook for fprintd (`/usr/lib/systemd/system-sleep/fprintd-resume`).

**Polkit agent.** The `omarchy.polkit` Quickshell plugin (`Quickshell.Services.Polkit`).
It reads `/etc/pam.d/polkit-1` to decide whether to show a fingerprint hint. Polkit's
helper runs **one sequential PAM stack**, so concurrency isn't available there.

**Login.** SDDM. `/etc/pam.d/sddm` includes `system-login`, which includes `system-auth`
(faillock, `pam_systemd_home`, `pam_unix`).

**sudo.** `/etc/pam.d/sudo` includes `system-auth`. Remote sudo over SSH uses the same file.

**Omarchy's own security scripts** (`/usr/bin/omarchy-setup-security-*`):
- `fido2`: installs `pam-u2f`, writes a global authfile `/etc/fido2/fido2`, and inserts
  `auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2` at the top of `sudo` and
  `polkit-1` with `sed`. Touch only; no PIN; no remote-session gate.
- `fingerprint`: installs `libfprint-git` and `fprintd`, enrolls one finger, verifies it,
  then inserts `pam_fprintd` into `sudo` and `polkit-1` behind a clamshell gate
  (`pam_exec omarchy-hw-laptop-closed`), and runs `omarchy-apply-lock`.
- Neither adds a gate for SSH sessions. A remote `sudo` would try the fingerprint reader
  or wait for a key touch on the laptop.

Nyx must **coexist with and migrate** these edits: detect Omarchy's lines, offer to move
them into Nyx's managed block, and never leave both active.

## nyx-settings

- Users page (`apps/settings/src/sections/accounts.rs`): "Sign-in security" collapsible
  (`728-786`) with FIDO2 and Fingerprint rows whose buttons open the Omarchy scripts in a
  floating terminal. **No status detection**: both Set up and Remove always show, and the
  page doesn't refresh afterwards.
- Online Accounts page (`native_accounts.rs`): account cards, Add account, storage-only
  accounts. Talks to `nyx-accountsd` over D-Bus.
- Privileged changes: `pkexec /usr/local/lib/nyx-settings/nyx-settings-helper` with action
  `io.github.design_nexus.nyx.settings.admin` (`auth_admin_keep`). The helper isn't
  installed by `install.sh`; Settings offers a "Set up…" banner.
- Navigation: sections in a `gtk::Stack`; in-page subscreens use a thread-local screen
  enum plus `window::rebuild` (the Online Accounts "Add" screen).

**Reuse:** the section and widget API, the helper-state check (byte-compare the installed
policy, check `--version`), and the in-page subscreen pattern.

## nyx-passwords (Nyx Vault)

Implemented:
- `nyx-passwordsd` alone holds keys (`bitwarden-crypto` 4.0, zeroizing allocator). Peers
  use peer-to-peer zbus on `$XDG_RUNTIME_DIR/nyx-passwords/bus`; identity is SO_PEERCRED
  plus SO_PEERPIDFD plus an executable allowlist (`daemon/peer.rs`). Scopes: App, Glimpse,
  Settings, Browser, Assistant. This is the strongest caller check in the suite.
- Locks on idle, Hyprland session lock, logind Lock and sleep.
- Keyring unlock: the raw user key in Secret Service, opt-in, requires a recent password.
- Item re-prompt: password within 5 minutes for every field but the username; export and
  enabling keyring unlock need the same.
- Two-step sign-in: authenticator, email, YubiKey OTP, recovery code.
- Software passkeys in the Bitwarden `fido2Credentials` format through the browser
  extension. **User verification is always reported** (`daemon/extension.rs:353`).
- SSH key items (generate, import, reveal). No agent.

Documented only: fingerprint unlock "via fprintd through polkit" (`PLAN.md:90`), FIDO2
two-step (`TASKS.md:70`), and waiting for "a shared Nyx Biometrics service"
(`docs/AUDIT.md`).

**Gaps Nyx Biometrics closes:** biometric and security-key quick unlock with real key
protection; re-prompt by biometrics or key; honest passkey user verification; FIDO2
two-step; an SSH agent with per-use approval.

## nyx-assistant

- Admin tools run `pkexec nyx-assistant-helper VERB` with one polkit action per verb
  (`auth_admin`, argv-matched) and a parent-process check. The strictest helper in the
  suite; the model for `nyx-auth-helper`.
- Capabilities with floors (`Privileged` and `Secrets` can't be set to Allow), one-use
  60-second grants bound to a hash of the arguments.
- **Gap:** approvals arrive as `Control::Approve` on a socket any same-user process can
  reach (`crates/assistant-ipc/src/server.rs:29-41`; accepted in `docs/AUDIT.md:434`).
  Polkit's password prompt is the only independent gate for admin actions, and there is
  none for `Secrets`.

## nyx-glimpse

The `pw` provider uses the `nyx-passwords-proto` client: search and daemon-side copy; the
secret never reaches Glimpse. Re-prompt items are refused for non-App scopes. No other
authentication.

## nyx-store

`pkexec nyx-store-helper` with one action and a plan-echo handshake; root-owned history.
No parent-process check.

## nyx-accounts and nyx-core

- nyx-accounts' "shared authentication interfaces" are **online accounts** (OAuth, app
  passwords), not local authentication. Caller checks use `GetConnectionCredentials` and
  an executable allowlist.
- nyx-core's `Control` interface ignores the sender. Nothing for local authentication.

## nyx-design

Design 2.0 (`nyx_theme::use_design_2()`, `STYLE.md`): solid surfaces by default, frosted
only as a theme option, radii 7/11/15, per-section accents, theme follows Omarchy by
polling `colors.toml`. No layer-shell or QML component. The lock and polkit overlays must
be QML (only the session-lock client can draw over a locked session), so Nyx Biometrics
needs the tokens in a form QML can read.

## Hardware: ROG Zephyrus G16 (GU605CW)

| Device | Finding |
|---|---|
| Camera | Shinetech 3277:0060 "USB2.0 FHD UVC WebCam" |
| RGB node | `/dev/video0`, MJPG up to 1920x1080 at 30 fps |
| IR node | `/dev/video2`, `GREY` 640x400 at 15 fps (a Windows Hello sensor) |
| IR emitter | Unverified. Many UVC IR modules start dark until enabled; Irlume probes and enables it during enrollment |
| TPM | `/dev/tpm0`, `/dev/tpmrm0` present; `tpm2-tss` installed |
| Fingerprint | No built-in reader detected on USB |
| TE-FPA-CA1 | Not connected at audit time; compatibility unknown until its USB ID is checked against libfprint |
| Security keys | None connected; `libfido2` 1.17 installed |
| Packages missing | `fprintd`, `libfprint`, `pam-u2f`, Irlume, Gaze, `usbutils`, `pamtester` |

Nothing above is a compatibility claim. See [HARDWARE.md](HARDWARE.md) once Phase 2 has
run on the device.

## Decisions taken from this audit

1. A new repository, `nyx-biometrics`, holds the framework. Nothing is renamed.
2. Face: Irlume for infrared cameras (primary), Gaze for RGB cameras (fallback), one
   backend per camera, behind one adapter trait. Fingerprint: fprintd. Keys: pam_u2f and
   libfido2.
3. Lock and polkit overlays are new Quickshell plugins (`design-nexus.auth-lock`, built
   from `ken.lock`; `design-nexus.auth-polkit`). `ken.lock` stays as the rollback.
4. PAM is changed only through managed, include-based blocks with snapshots, container
   tests and an auto-rollback timer, after Ken approves each diff.
5. Nyx Setup and the System Manager don't exist; the setup flow ships as a reusable piece
   that Settings uses now, and `nyx-auth-helper` follows the Assistant helper's pattern so
   it can later move into a shared System Manager.
