#!/bin/bash
# Turn on face, fingerprint and security-key sign-in for sudo in local terminals.
# Needs you at the keyboard: it asks for your password, enrolls your face if needed, and
# keeps the change only after one real sudo works. Undo: nyx-authctl pam restore
set -euo pipefail

cd "$(dirname "$0")/.."
bin=./target/release
authctl="$bin/nyx-authctl"

step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

step "Building"
cargo build --release --quiet -p nyx-authctl -p nyx-auth-helper -p nyx-auth-pam

if ! "$authctl" helper status >/dev/null 2>&1; then
  step "Installing the root helper (asks for your password)"
  sudo "$authctl" helper install
fi

doctor=$("$authctl" doctor)
if grep -q "no face is enrolled" <<<"$doctor"; then
  step "Enrolling your face: look at the camera when it turns on"
  "$authctl" face enroll
fi

step "What this computer can use now"
"$authctl" doctor

policy="${XDG_CONFIG_HOME:-$HOME/.config}/nyx/auth/policy.toml"
if [[ ! -f $policy ]]; then
  step "Writing the suggested policy to $policy"
  mkdir -p "$(dirname "$policy")"
  "$authctl" policy recommend >"$policy"
fi
"$authctl" policy check

step "Safety net"
echo "Open a second terminal, run: sudo -s   and leave it open until this finishes."
read -rp "Press Enter when it's open (or Ctrl+C to stop here)... "

step "Applying to sudo"
"$authctl" pam apply sudo
