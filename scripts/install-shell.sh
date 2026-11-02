#!/bin/bash
# Install the Nyx lock screen plugin for the Omarchy shell, with the shared overlay.
# The shell reloads a changed local plugin by itself. Switching to it from ken.lock or
# omarchy.lock is a separate, deliberate step in ~/.config/omarchy/shell.json.
set -euo pipefail

cd "$(dirname "$0")/../shell"
plugins="${XDG_CONFIG_HOME:-$HOME/.config}/omarchy/plugins"

cp common/AuthOverlay.qml design-nexus.auth-lock/AuthOverlay.qml
# Staged beside, not inside, the plugins folder: the shell loads whatever appears there.
stage="$(dirname "$plugins")/.nyx-plugin-stage"
mkdir -p "$plugins"
rm -rf "$stage"
cp -r design-nexus.auth-lock "$stage"
rm -rf "$plugins/design-nexus.auth-lock"
mv "$stage" "$plugins/design-nexus.auth-lock"
echo "Installed design-nexus.auth-lock to $plugins."
