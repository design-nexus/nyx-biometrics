# Threat model

Binding for every change in this repository. When a change affects a row below, update
the row in the same commit.

## What we protect

- **Access to the session**: login, the lock screen.
- **Administrator rights**: sudo, polkit.
- **Vault contents**: the Bitwarden user key and the decrypted items in `nyx-passwordsd`.
- **Sensitive app actions**: anything a Nyx app asks the broker to protect.
- **Enrollment data**: face embeddings (held by Irlume or Gaze), fingerprint templates
  (fprintd), security-key registrations (pam_u2f authfiles), the policy file, PAM files.
- **Recovery**: the person's ability to get back in when a method fails or a key is lost.

## Who we defend against

| Adversary | Can | Out of scope |
|---|---|---|
| Someone with the unlocked laptop for a moment | Use the open session | Nothing more is asked of us; lock on idle |
| Someone with the locked laptop | Show photos, video, prints, a stolen key; try passwords | Taking the disk to another machine: use full-disk encryption |
| A remote user with SSH access and the password | Run `sudo` over SSH | |
| A malicious process running as the user | Everything the user can do without a prompt; call D-Bus; spawn allowed binaries; draw windows | Defeating root or the kernel |
| An AI agent acting for the user (Assistant, MCP tools) | Ask for actions and credentials through its tools | |
| A bug in our own PAM generation | Lock the person out, or let anyone in | |

A process running as the user is the hardest case. Same-user processes share a security
boundary on Linux; we raise the cost where it matters (Vault keys, admin rights, agent
approvals) by putting the decision behind root, PAM or real hardware, and say plainly
where we can't.

## Threats and mitigations

### Facial spoofing

- *Threat*: a photo, screen or video of the person passes a face check.
- *Mitigations*: only an infrared camera with a liveness check counts as a factor
  (`Method::assurance`). RGB matches, including Gaze's RGB liveness, are presence only and
  by default unlock only the lock screen. One face backend per camera. Irlume's and
  Gaze's thresholds stay on their secure defaults; Nyx never lowers them.
- *Residual*: IR liveness resists prints and screens but isn't certified presentation
  attack detection. Crafted IR imagery or a determined attacker may pass. Documented in
  Settings next to the face option.

### Unintended face authentication

- *Threat*: the screen unlocks because the person (or someone resembling them) happens to
  be in front of it; a face check runs without the person meaning to authenticate.
- *Mitigations*: face runs only after an explicit request (a wake, a key press, a prompt
  that names its purpose), with a short timeout.
- *Owner choice, hands-free sudo and polkit*: Irlume normally asks for a typed `yes` before
  scanning at sudo and polkit. An owner can waive that (`irlume auth consent hands-free`,
  chosen on Ken's G16). Then any program running as the user can get root by running
  `sudo` while the user is in view; remote sessions and a closed lid stay excluded. The
  Phase 4 overlay must show visibly whenever a scan runs, so it can't happen unnoticed. The camera is closed between attempts.
  Hands-free unlock is off by default and separate. A visible overlay shows whenever a
  face check runs.

### Fingerprint spoofing

- *Threat*: a lifted or moulded print passes.
- *Mitigations*: the reader's own match-on-chip where it exists; fprintd's retry limits;
  faillock still counts failures. Fingerprints are one factor, never two.
- *Residual*: reader-dependent. `HARDWARE.md` records which readers match on chip.

### Stolen or lost security key

- *Threat*: someone with the key gets in with a touch.
- *Mitigations*: a touch-only key is one factor and doesn't identify, so Vault and
  sensitive actions refuse it by default. Surfaces can require `verified` (PIN or on-key
  sensor) or password plus key. Removing a key is one action in Settings and rewrites the
  authfile. A password-plus-key rule on a system surface needs a registered backup key.
- *Residual*: on a surface that accepts a touch-only key, a stolen key is enough there.
  Settings says so when that's chosen.

### Remote sessions

- *Threat*: `sudo` over SSH waits for a fingerprint or key touch at the laptop (or worse,
  succeeds because someone at the laptop touched it).
- *Mitigations*: every non-password module is behind `nyx-auth-gate`, which skips them for
  remote sessions, sessions it can't identify and a closed lid. `Method::local_only` marks
  this in code; the checker refuses a non-password module without the gate, and the helper
  refuses to apply while the gate isn't installed. Irlume also stands down for remote
  transactions on its own. Required methods (password plus key) have no gate: remote use
  fails closed.
- *Residual*: a `sudo` in a terminal multiplexer started locally and later attached over
  SSH looks local. The socket-activated polkit helper has no session of its own, so for
  administrator prompts only the user's display session is checked.

### Malicious local process

- *Spoofed prompt*: a process draws a fake "Nyx" prompt to collect a password. We can't
  prevent drawing. Mitigations: the real prompts never ask for the password when a
  biometric or key is offered first; the lock screen is drawn by the session-lock client
  only.
- *Request confusion*: a process asks the broker to authenticate with a misleading purpose
  or someone else's action. Mitigations: actions are scoped to the caller's verified
  prefix, so a program can only ask for its own; the purpose is short plain text with no
  control characters and goes only to the caller, not the audit log. *Limit*: the prompt
  itself shows polkit's fixed message ("Confirm it's you to allow this"), not the caller
  or purpose: polkit lets only root pass a message of its own, and the broker runs as the
  user. The asking app says what it's for in its own window (the Assistant's approval,
  Passwords' page).
- *A stand-in broker*: any program running as the user can claim a session-bus name and
  answer "granted". Clients connect with `nyx_auth_proto::connect`, which checks the
  name's owner is this user's `nyx-authd` from where the suite installs it and then talks
  to that connection only; anything else falls back to polkit directly, a system service.
  Checked by hand with a program holding the name: refused, nothing asked.
- *Caller identity*: the broker knows a caller by the process behind its bus connection
  (uid, executable, start time). A process that connects and then replaces itself with an
  allowed program keeps the connection; the worst it gets is a prompt in that program's
  name, which the person still has to answer. Programs in `~/.local/bin` are trusted as
  the suite's, as Nyx Passwords' daemon already trusts its peers: a process running as the
  user that can replace them can also replace the apps themselves.
- *Self-approval*: there is no approve method on the broker. A grant needs a successful
  authentication at the prompt.
- *Grant theft*: grants are bound to the caller's identity and action, last at most five
  minutes, and end on any session lock and before sleep; they live only in the broker's
  memory, so logout ends them too. They aren't bearer tokens. The apps ask with no grant
  (once) today.
- *Prompt flooding*: one prompt at a time and six requests a minute per caller.
- *Launching an allowed binary*: a process can start `nyx-passwords` or another allowed
  client. That client still has to pass the broker prompt for protected actions.

### Replay

- PAM modules talk to their own daemons (fprintd, irlumed, gazed) and devices per attempt;
  pam_u2f uses a fresh FIDO2 challenge per attempt. Nyx never caches a match result and
  never accepts a result from the caller.
- Grants are per action and per caller and expire; a recorded D-Bus reply grants nothing.
- keyd releases the wrapping key only to a connection it verified, after a PAM check it
  ran itself.

### PAM misconfiguration

- *Threat*: a generated stack locks the person out, or lets anyone in (a stray
  `sufficient pam_permit`, a wrong jump count).
- *Mitigations*: the generator emits from a small fixed template set; it never emits
  `pam_permit` in `auth`. The parser re-reads the generated file and the container suite
  runs every case (each method passing, failing, timing out, absent; password fallback;
  remote gate; empty password) before apply. Apply snapshots first, writes atomically and
  rolls back after 120 seconds unless confirmed. Live changes need Ken's approval with the
  diff and test evidence. A root shell stays open during first activation.
- *Faillock*: a biometric or key success before `system-auth` doesn't reset faillock's
  counter, and a locked-out account can still use biometrics. This matches Omarchy's
  current fingerprint wiring and is documented; it doesn't let anyone in who couldn't
  otherwise.

### Privilege escalation through our helpers

- `nyx-auth-helper`: fixed verbs, argv-matched polkit actions with `auth_admin`, every
  argument re-parsed, absolute paths, cleared environment, refuses symlinks and non-regular
  files in `/etc/pam.d` and `/etc/nyx-biometrics`, writes only its own files plus the one
  marked line in each target.
- `nyx-auth-keyd`: socket-activated, hardened unit (`NoNewPrivileges`,
  `ProtectSystem=strict`, `PrivateNetwork`, `MemoryDenyWriteExecute`, no capabilities
  beyond what PAM and the TPM need). One request type. Peer checked by pidfd and executable.

### Vault key exposure

- The key is never in the user's session at rest. Face and fingerprint unlock depend on
  root-held, TPM-sealed material released only after polkit confirms the asking process
  (an `auth_self` action, answered through the `polkit-1` stack).
- With hands-free face at administrator prompts, a program running as the user that can
  start `nyx-passwordsd` gets the vault opened if the user is in view when it asks. The
  polkit prompt is shown on screen each time.
- Security-key unlock derives the wrapping key from the key with `hmac-secret`; nothing
  that unlocks is stored.
- The existing keyring unlock (raw user key in Secret Service) stays opt-in and is labelled
  weaker than these.
- Everything is dropped when the password or account keys change, on sign-out, and when
  the option is turned off.
- *Residual*: once unlocked, the vault is in `nyx-passwordsd`'s memory; a same-user process
  that can read that memory (ptrace is blocked by `PR_SET_DUMPABLE 0`) is out of scope.

### Agent-initiated credential access

- Assistant and Glimpse never receive secrets: copies go through the daemon's clipboard.
- Protected items copied from Glimpse need a broker authentication (when "Protected items
  in Glimpse" is on in Passwords; off, they stay in Passwords). The agent can't answer the
  prompt.
- Assistant approvals for `Secrets` need a broker authentication on top of the key press;
  `Privileged` already needs polkit's `auth_admin`.
- Passkeys: a site that requires user verification gets a broker authentication before
  anything is signed.

### Lost devices and recovery

- The password always remains a path on every system surface (`NoPasswordPath`).
- Backup keys are first-class; Settings warns when only one key is registered.
- `nyx-authctl pam restore` and `nyx-auth-helper restore` restore the last snapshot from a
  TTY or root shell; `RECOVERY.md` covers a boot without a graphical session.
- Losing a laptop: biometric templates are TPM-sealed by Irlume/Gaze where supported; Vault
  wrapping keys are TPM-sealed by keyd; neither leaves the machine.

## Data we never record

Passwords, PINs, biometric images, embeddings or templates, key handles, FIDO2 secrets,
wrapping keys, Vault data, and the text of purposes that include user data. Logs carry
caller, action, surface, outcome, methods and timestamps only.

## Changes that require re-authentication

Enrolling or removing a face, fingerprint or key; changing any policy; turning Vault quick
unlock on; restoring PAM from a snapshot. Each needs authentication that the current policy
for the affected surface accepts (`PolicySet::approval`).
