# Recovery

Your password always stays a way in on the login screen, the lock screen, sudo and
administrator prompts. Nyx Biometrics refuses any policy that would remove it. This page
covers what to do if something still goes wrong.

## Every change can be undone

Before changing any sign-in file, Nyx copies everything it will touch to
`/var/lib/nyx-biometrics/pam-backups/<ID>/`. It only ever:

- adds a marked block to `/etc/pam.d/sudo`, `/etc/pam.d/sddm` or `/etc/pam.d/polkit-1`:

  ```text
  # BEGIN nyx-biometrics
  auth  include  nyx-auth-sudo
  # END nyx-biometrics
  ```

- writes its own files: `/etc/pam.d/nyx-auth-*` and `/etc/pam.d/nyx-lock-*`;
- for security keys at administrator prompts, adds
  `/etc/systemd/system/polkit-agent-helper@.service.d/50-nyx-security-keys.conf`;
- creates `/etc/pam.d/polkit-1` from `/usr/lib/pam.d/polkit-1` if it didn't exist.

## If a change doesn't work

`nyx-authctl pam apply` tests the change with one sign-in right away. If you don't
confirm within **2 minutes**, or the test fails, a systemd timer puts every file back by
itself. You don't need to do anything.

To undo a change you already kept:

```sh
nyx-authctl pam restore          # the newest change
nyx-authctl pam restore ID       # a specific one
```

## If sudo and administrator prompts both fail

Use the root shell you kept open while applying (`sudo -s` in another terminal), or
switch to a text console with Ctrl+Alt+F3 and sign in with your password. Then:

```sh
/usr/local/lib/nyx-biometrics/nyx-auth-helper pam-rollback ID
```

`ID` is the folder name under `/var/lib/nyx-biometrics/pam-backups/`. The newest one is
last in `ls /var/lib/nyx-biometrics/pam-backups`.

## By hand

Every snapshot holds plain copies of the files (`0`, `1`, …) and a `manifest.json`
saying which file each copy came from, and which files didn't exist before (delete
those). To remove Nyx Biometrics entirely:

1. Delete the lines from `# BEGIN nyx-biometrics` to `# END nyx-biometrics` in
   `/etc/pam.d/sudo`, `/etc/pam.d/sddm` and `/etc/pam.d/polkit-1`.
2. If `/etc/pam.d/polkit-1` starts with `# Created by Nyx Biometrics`, delete it.
3. Delete `/etc/pam.d/nyx-auth-*` and `/etc/pam.d/nyx-lock-*`.
4. Delete the polkit drop-in above and run `systemctl daemon-reload`.
5. Delete `/etc/sddm.conf.d/zz-nyx-biometrics.conf` to put Omarchy's login screen back
   (`nyx-authctl login-theme off` does the same). The theme in
   `/usr/share/sddm/themes/nyx-biometrics` is then unused.

From a live USB, mount your root partition and do the same under its mount point.

## Lost security key

Sign in with your password and remove it:

```sh
nyx-authctl keys list
nyx-authctl keys remove ID
```

If a surface needs a password **and** a key, you can't change it without a key. Use your
backup key: Nyx won't apply that rule until a backup is registered. Without one, use a
text console or root shell as above and restore the last snapshot.

## Face or fingerprint stops working

Nothing to recover: the password prompt follows. Check what changed:

```sh
nyx-authctl doctor
```
