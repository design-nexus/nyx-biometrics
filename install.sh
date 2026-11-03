#!/bin/bash
# Build Nyx Biometrics and install nyx-authctl for this user. The root helper and the PAM
# gate are installed separately, deliberately: sudo nyx-authctl helper install
set -euo pipefail

cd "$(dirname "$0")"
cargo build --release --locked --quiet -p nyx-authctl -p nyx-auth-helper -p nyx-auth-pam -p nyx-auth-keyd -p nyx-authd

bin="$HOME/.local/bin"
mkdir -p "$bin"
for name in nyx-authctl nyx-auth-helper nyx-auth-gate nyx-auth-notify nyx-auth-keyd nyx-authd; do
  install -m 755 "target/release/$name" "$bin/$name"
done
# The sign-in broker starts when a Nyx app first asks.
services="${XDG_DATA_HOME:-$HOME/.local/share}/dbus-1/services"
mkdir -p "$services"
printf '[D-BUS Service]\nName=io.github.design_nexus.nyx.Auth\nExec=%s/nyx-authd\n' "$bin" > "$services/io.github.design_nexus.nyx.Auth.service"
busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig >/dev/null 2>&1 || true
# A running broker keeps the old build until it exits on its own; stop it now.
pkill -x -u "$(id -u)" nyx-authd 2>/dev/null || true
echo "Installed nyx-authctl and the sign-in broker to $bin."

if ! "$bin/nyx-authctl" helper status >/dev/null 2>&1; then
  echo "The root helper is missing or out of date. Install it with:"
  echo "  sudo $bin/nyx-authctl helper install"
fi
