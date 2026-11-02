# Nyx Biometrics

Local sign-in with your face, fingerprint or security key for Omarchy and the Nyx apps,
with your password always available as a fallback.

- **Face**: Irlume on infrared (Windows Hello) cameras, Gaze on ordinary webcams.
  A webcam-only face match only unlocks the lock screen by default.
- **Fingerprint**: fprintd and libfprint, for built-in and USB readers.
- **Security keys**: YubiKeys and other FIDO2 keys through pam_u2f, with or without a
  PIN. Keys with fingerprint sensors work, but aren't required.
- **Where it works**: the login screen, the lock screen, `sudo` in a local terminal,
  administrator prompts (polkit), Nyx Passwords, and sensitive actions in other Nyx apps.

Everything runs on this computer. Nothing is sent to a cloud service, and no face images
are kept.

> **Status: in development.** See [docs/ROADMAP.md](docs/ROADMAP.md) for what works today.
> Nothing here changes your sign-in setup until you review and approve it.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Audit of the existing Nyx apps](docs/AUDIT.md)
- [Roadmap](docs/ROADMAP.md)

## License

MIT. Irlume, Gaze, fprintd and pam_u2f are separate projects under their own licenses;
Nyx Biometrics talks to them through their command-line tools, D-Bus services and PAM
modules and doesn't link them.
