# SSH with a security key

Nyx Biometrics doesn't run an SSH agent of its own. Two kinds of SSH key work side by side,
each kept once, where it belongs:

| Key | Where the private key lives | What signs | Managed with |
|-----|----------------------------|------------|--------------|
| On a FIDO2 security key (`ed25519-sk`) | On the security key; `~/.ssh` holds only a handle | The security key, after a touch (and its PIN with `--pin`) | `nyx-authctl ssh-key` |
| In the vault (Bitwarden SSH key items) | Encrypted in Nyx Passwords | Nyx Passwords' agent, per key and per program you approve | Nyx Passwords |

Neither copies keys into the other. A security-key handle in the vault would add nothing:
it signs nothing without the hardware.

## Security-key keys

```sh
nyx-authctl ssh-key create github          # touch the key when it blinks
nyx-authctl ssh-key create work --pin      # every use asks for the key's PIN too
nyx-authctl ssh-key list
nyx-authctl ssh-key load                   # on a new computer: fetch the keys kept on it
```

- `create` runs OpenSSH's `ssh-keygen -t ed25519-sk` with `application=ssh:nyx-NAME`. The
  key is *resident* (kept on the security key) unless `--no-resident`, so `load`
  (`ssh-keygen -K`) can bring it to another computer. `--pin` adds `verify-required`: the
  security key checks its PIN or its own sensor before every signature.
- The file `~/.ssh/id_ed25519_sk_NAME` is a handle. It has no passphrase because it can't
  sign without the security key in hand.
- Add `~/.ssh/id_ed25519_sk_NAME.pub` to the server (`~/.ssh/authorized_keys`, GitHub,
  GitLab). OpenSSH uses the key straight from `~/.ssh` (`IdentityFile`), or through
  `ssh-agent`, which hands the signature to `ssh-sk-helper` and the security key.
- A security key without a fingerprint sensor proves possession (a touch), not who touched
  it. `--pin` makes it identity-checking.

## Vault keys through Nyx Passwords

Nyx Passwords keeps SSH key items from the Bitwarden vault and serves the ones you turn on
from `$XDG_RUNTIME_DIR/nyx-passwords/ssh-agent.sock`: list and sign only, each program
approved once or until the vault locks. Point `SSH_AUTH_SOCK` there, or per host with
`IdentityAgent` in `~/.ssh/config`:

```
Host vault-host
  IdentityAgent ${XDG_RUNTIME_DIR}/nyx-passwords/ssh-agent.sock

Host hardware-host
  IdentityFile ~/.ssh/id_ed25519_sk_work
  IdentitiesOnly yes
```

## Not yet

- Unlocking the vault's SSH agent approvals with the face goes through the same vault
  unlock as everything else; there's no separate face prompt per signature.
- Tested on this G16 without a security key at hand: argument building, listing and the
  status report are unit-tested; `create` and `load` need a key to try.
