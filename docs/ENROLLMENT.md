# Enrollment

Enrolling a face, fingerprint or key doesn't change how you sign in. That only changes
when you turn a method on for a surface (login, lock screen, sudo, administrator prompts),
which you review and approve separately.

Settings will have buttons for all of this. Until then, use `nyx-authctl`.

## Check first

```sh
nyx-authctl doctor
```

It lists your cameras, readers and keys, says which face backend owns which camera, and
what is missing.

## Security keys

You need `pam-u2f` installed, and the root helper (once):

```sh
sudo nyx-authctl helper install
```

Register your main key, then a backup:

```sh
nyx-authctl keys add "Primary YubiKey" --pin
nyx-authctl keys add "Backup YubiKey" --backup --pin
```

Touch each key when it blinks. `--pin` makes the key ask for its PIN every time it's used,
which lets it count as a verified key. Leave it out for touch only. A touch shows someone
is holding the key, not who.

The administrator prompt that follows is the helper writing the key into
`/etc/nyx-biometrics/u2f_keys`. That file is root-owned, so other programs can't add their
own keys.

```sh
nyx-authctl keys list                         # ID, name, role, PIN
nyx-authctl keys rename ID "Keychain key" --backup
nyx-authctl keys remove ID
```

**Omarchy keys.** If you used Omarchy's FIDO2 setup, `nyx-authctl keys import-omarchy`
copies your registrations. Omarchy's own file and PAM lines stay as they are until you
approve moving them (Phase 3).

**Host name.** pam_u2f ties registrations to `pam://<host name>`. If you rename the
computer, register your keys again.

## Fingerprints

You need `fprintd` and `libfprint`, and a reader libfprint supports (`nyx-authctl doctor`
says).

```sh
nyx-authctl finger enroll                     # right index finger
nyx-authctl finger enroll left-index-finger
nyx-authctl finger list
nyx-authctl finger remove left-index-finger
```

fprintd asks for administrator approval before enrolling.

## Face

```sh
nyx-authctl face enroll
nyx-authctl face manage
```

These run the backend that owns your camera:

- **Irlume**, for an infrared camera. Its enrollment checks the IR emitter and offers to
  turn it on.
- **Gaze**, when there's only a colour camera. A colour match only shows someone is
  there, so by default it can unlock the lock screen and nothing else.

Neither keeps photos. Both store face embeddings in root-only files, encrypted with the TPM
when there is one.
