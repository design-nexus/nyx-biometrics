#!/bin/bash
# Install the Nyx lock screen and administrator prompt plugins for the Omarchy shell, with
# the shared overlay. The shell reloads changed local plugins by itself. Switching to them
# from ken.lock, omarchy.lock or omarchy.polkit is a separate, deliberate step in
# ~/.config/omarchy/shell.json.
set -euo pipefail

cd "$(dirname "$0")/../shell"
plugins="${XDG_CONFIG_HOME:-$HOME/.config}/omarchy/plugins"
# Staged beside, not inside, the plugins folder: the shell loads whatever appears there.
stage="$(dirname "$plugins")/.nyx-plugin-stage"
mkdir -p "$plugins"

for plugin in design-nexus.auth-lock design-nexus.auth-polkit; do
  cp common/AuthOverlay.qml "$plugin/AuthOverlay.qml"
  rm -rf "$stage"
  cp -r "$plugin" "$stage"
  rm -rf "$plugins/$plugin"
  mv "$stage" "$plugins/$plugin"
  echo "Installed $plugin to $plugins."
done
