# Nyx Setup: the sign-in step

There's no Nyx Setup repository yet. When there is, its sign-in step needs nothing new
from Nyx Biometrics: Nyx Settings already drives the same commands. This is the contract.

## Read

| Command | Gives |
|---------|-------|
| `nyx-authctl status --json` | Everything Settings shows: helper, face, fingerprint, keys, SSH keys, each surface's policy and whether it's applied, autologin |
| `nyx-authctl doctor --json` | Hardware findings, each `ok`, `warn`, `missing` or `error` with a message |
| `nyx-authctl policy recommend` | The policy for this hardware, as TOML |

No root, no camera, no prompts. Safe to run on every page load.

## Act

In this order, each in a terminal the person can see (touch, PIN, face and diffs need
them):

1. `sudo nyx-authctl helper install` when `status.helper` isn't `ready`.
2. `nyx-authctl face enroll` (the backend chosen for the camera: Irlume for infrared,
   Gaze for colour).
3. `nyx-authctl finger enroll` when a reader is ready.
4. `nyx-authctl keys add NAME --pin`, then a second key with `--backup`.
5. `nyx-authctl policy set SURFACE METHOD on` for each choice, then
   `nyx-authctl pam apply SURFACE` for lock screen, sudo, polkit and login. Each shows the
   diff, tests one sign-in and keeps the change only if that works.
6. Optional: `nyx-authctl login-theme on`.

Setup should never apply a surface the person hasn't seen tested, never make a method
other than the password the only way in, and always end by naming `nyx-authctl pam
restore` and the TTY steps in [RECOVERY.md](RECOVERY.md).
