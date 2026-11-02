# Hardware

What has been checked on real devices, and what hasn't. A line says **verified** only
after it has run on the device; everything else is **pending**. Nothing here is a
compatibility promise.

Run `nyx-authctl doctor` to see what Nyx Biometrics finds on your own computer.

## ASUS ROG Zephyrus G16 (GU605CW)

### Camera

| Fact | Source |
|---|---|
| One USB module, Shinetech `3277:0060` "USB2.0 FHD UVC WebCam" | sysfs, 2026-11-01 |
| `/dev/video0`: colour, MJPG up to 1920x1080 at 30 fps | `VIDIOC_ENUM_FMT`, `v4l2-ctl` |
| `/dev/video2`: infrared, `GREY` 640x400 at 15 fps | `VIDIOC_ENUM_FMT`, `v4l2-ctl` |
| `/dev/video1`, `/dev/video3`: metadata nodes (no capture formats) | `VIDIOC_ENUM_FMT` |
| `nyx-authctl doctor` classifies both correctly | run 2026-11-01 |

The IR stream exceeds Windows Hello's published IR minimum (340x340 at 15 fps).

**Irlume mode.** Irlume's default dual mode also runs an anti-spoofing check on the colour
camera, which needs room light. This machine runs Irlume in IR-only mode
(`irlume auth sensor ir-only`, cameras pinned with `irlume set-cameras /dev/video0 /dev/video2`),
like Windows Hello: the IR emitter lights the face and Irlume's IR anti-spoofing model still
runs. Irlume labels IR-only experimental. Privileged prompts are hands-free
(`irlume auth consent hands-free`): sudo and polkit scan as soon as they prompt, with no `yes`.

**Not yet known:**
- whether the IR emitter lights without help. Many UVC IR modules start dark. Irlume probes
  this during enrollment and offers `irlume ir-setup`; if that fails, `linux-enable-ir-emitter`
  is the usual fallback. Nyx doesn't change camera controls itself.
- whether Irlume's anti-spoofing checks qualify on this sensor (`irlume doctor`).

**Required packages:** `irlume` (AUR) and an `onnxruntime` provider (`onnxruntime-cpu` is
enough). Gaze is only needed to test the colour camera on its own.

### Other

| Device | State |
|---|---|
| TPM 2.0 (`/dev/tpmrm0`) | present; `tpm2-tss` installed |
| Fingerprint reader | none built in (nothing on USB) |

### Checklist

| Check | Status |
|---|---|
| Irlume 0.15.0 installs from the AUR; `irlumed` runs | verified 2026-11-01 |
| `irlume doctor`: TPM, camera nodes, IR and RGB stream minimums, every model and ONNX Runtime pass | verified 2026-11-01 |
| `ir-calibration` passes after enrollment | verified 2026-11-01 |
| IR emitter lights during capture (2 of 3 frames lit, strobing) | verified 2026-11-02 |
| Enrollment (10 scans) | verified 2026-11-01 |
| Match in a dark room: refused in Irlume's default dual mode (its colour check needs light); works in IR-only mode | verified 2026-11-02 |
| Printed photo refused | pending |
| Phone-screen photo refused | pending |
| `nyx-authctl doctor` reports face as one factor (IR with liveness) | pending |
| Gaze on `/dev/video0` reports presence only | pending |
| Lock screen face unlock on wake (`design-nexus.auth-lock`, `omarchy-lock-face`) | verified 2026-11-02 |
| sudo face in a local terminal, IR-only, dark room, about 2 s | verified 2026-11-02 |
| sudo face hands-free (no `yes`), about 1.5 s | verified 2026-11-02 |
| sudo face skipped over SSH | pending |
| Administrator prompts (polkit) approved by face, hands-free | verified 2026-11-02 |

## TEC ESS TE-FPA-CA1 fingerprint reader

Not connected yet, so nothing is known about it: not its USB ID, its driver, or whether
libfprint supports it.

To check it:

1. Plug it in and run `nyx-authctl doctor`. With libfprint installed, doctor looks its USB
   ID up in libfprint's own device list (`60-autosuspend-fingerprint-reader.hwdb`) and says
   **supported**, **known unsupported**, or nothing. Without libfprint it can only guess
   from the vendor.
2. If it's supported: `nyx-authctl finger enroll`, then `nyx-authctl finger list`.
3. If it isn't: Nyx Biometrics won't install an experimental or out-of-tree driver by
   default. Report the USB ID upstream to libfprint.

| Check | Status |
|---|---|
| USB ID recorded | pending |
| libfprint support | pending |
| Enroll two fingers | pending |
| Wrong finger refused | pending |
| Unplug during verification is reported, password still works | pending |
| Replug is picked up without restarting fprintd | pending |

## Security keys

Any FIDO2 or U2F key that libfido2 supports works with `pam_u2f`. Nyx reads what each key
reports about itself (`fido2-token -I`), so it doesn't assume capabilities:

| Reported | Used for |
|---|---|
| `clientPin` set | PIN plus touch (verified security key) |
| `uv` | an on-key sensor; optional, never required |
| `hmac-secret` | Nyx Passwords unlock with the key (Phase 5) |
| transport `nfc` | NFC, where the computer has a reader libfido2 supports |

A key with only U2F (no FIDO2) works for touch, not PIN.

| Check | Status |
|---|---|
| YubiKey 5 (USB-A or USB-C): register, touch sign-in | pending |
| PIN plus touch | pending |
| Wrong PIN refused, retries counted by the key | pending |
| Two keys registered, either works | pending |
| Key removed mid-prompt: fall back to password | pending |
| NFC | pending (needs an NFC reader) |
