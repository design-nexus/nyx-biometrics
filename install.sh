#!/bin/bash
# Build Nyx Biometrics and install nyx-authctl for this user. The root helper and the PAM
# gate are installed separately, deliberately: sudo nyx-authctl helper install
set -euo pipefail

cd "$(dirname "$0")"
cargo build --release --locked --quiet -p nyx-authctl -p nyx-auth-helper -p nyx-auth-pam -p nyx-auth-keyd

bin="$HOME/.local/bin"
mkdir -p "$bin"
for name in nyx-authctl nyx-auth-helper nyx-auth-gate nyx-auth-notify nyx-auth-keyd; do
  install -m 755 "target/release/$name" "$bin/$name"
done
echo "Installed nyx-authctl to $bin."

if ! "$bin/nyx-authctl" helper status >/dev/null 2>&1; then
  echo "The root helper is missing or out of date. Install it with:"
  echo "  sudo $bin/nyx-authctl helper install"
fi
