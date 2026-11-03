import QtQuick
import Quickshell
import Quickshell.Hyprland
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Commons as Commons
import qs.Ui

// The scan overlay for terminal sign-ins. sudo's PAM stack runs nyx-auth-notify around a
// face, fingerprint or key check, which calls `notify` here. It only shows what's
// happening: it takes no keyboard focus and lets every click through, so typing stays in
// the terminal, and it never decides anything.
Item {
  id: root

  property var shell: null
  property string omarchyPath: ""

  property string phase: "idle"
  property string method: "face"
  property string service: ""
  property var targetScreen: null

  property string overlayStyle: "halo"
  property real overlayIntensity: 0.7
  property bool overlayAnimate: true

  readonly property bool shown: phase !== "idle"

  function focusedScreen() {
    var monitor = Hyprland.focusedMonitor
    var name = monitor ? String(monitor.name || "") : ""
    for (var i = 0; i < Quickshell.screens.length; i++) {
      if (Quickshell.screens[i].name === name) return Quickshell.screens[i]
    }
    return Quickshell.screens.length > 0 ? Quickshell.screens[0] : null
  }

  function settle(next, holdMs) {
    phase = next
    safetyTimer.stop()
    hideTimer.interval = holdMs
    hideTimer.restart()
  }

  Timer {
    id: hideTimer
    repeat: false
    onTriggered: root.phase = "idle"
  }

  // A scan that never reports back (the terminal was closed mid-way) still goes away.
  Timer {
    id: safetyTimer
    interval: 20000
    repeat: false
    onTriggered: root.phase = "idle"
  }

  ShellIpc {
    target: "nyx-auth"

    function notify(event: string, service: string, method: string): string {
      if (event === "start") {
        root.method = ["face", "fingerprint", "key"].indexOf(method) >= 0 ? method : "face"
        root.service = service
        root.targetScreen = root.focusedScreen()
        hideTimer.stop()
        root.phase = "scanning"
        safetyTimer.restart()
      } else if (event === "failed" && root.phase === "scanning") {
        root.settle("failure", 1400)
      } else if (event === "done" && root.phase === "scanning") {
        root.settle("success", 800)
      }
      return "ok"
    }
  }

  FileView {
    path: Quickshell.env("HOME") + "/.config/nyx/auth/overlay.json"
    watchChanges: true
    printErrors: false
    onFileChanged: reload()
    onLoaded: {
      try {
        var p = JSON.parse(text())["sudo"] || {}
        if (["halo", "circular", "cyberpunk", "minimal", "edge"].indexOf(p.style) >= 0) root.overlayStyle = p.style
        if (typeof p.intensity === "number") root.overlayIntensity = Math.max(0, Math.min(1, p.intensity))
        if (typeof p.animate === "boolean") root.overlayAnimate = p.animate
      } catch (e) {
        console.warn("nyx sign-in overlay: overlay.json: " + e)
      }
    }
  }

  PanelWindow {
    id: panel
    screen: root.targetScreen
    visible: root.shown && root.targetScreen !== null
    color: "transparent"
    anchors { top: true; bottom: true; left: true; right: true }
    exclusionMode: ExclusionMode.Ignore
    WlrLayershell.namespace: "nyx-auth-prompt"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.None
    // Nothing here is clickable: every click goes to what's underneath.
    mask: Region {}

    AuthOverlay {
      readonly property bool edge: root.overlayStyle === "edge"
      style: root.overlayStyle
      // Over a busy desktop a scan needs its own surface.
      card: true
      method: root.method
      phase: root.phase
      detail: root.method === "face" ? "Terminal sign-in · face" : root.method === "fingerprint" ? "Terminal sign-in · fingerprint" : "Terminal sign-in · security key"
      intensity: root.overlayIntensity
      animate: root.overlayAnimate
      accent: Commons.Color.lock.borderActive
      surface: Commons.Color.lock.background
      text: Commons.Color.lock.text
      dim: Commons.Color.lock.placeholder
      bad: Commons.Color.lock.textError
      width: edge ? parent.width : (root.overlayStyle === "minimal" ? implicitWidth : root.overlayStyle === "halo" ? 248 : 240)
      height: edge ? parent.height : (root.overlayStyle === "minimal" ? 44 : root.overlayStyle === "halo" ? 268 : 240)
      x: edge ? 0 : (parent.width - width) / 2
      y: edge ? 0 : Math.round(parent.height * 0.18)
      opacity: root.shown ? 1 : 0
      Behavior on opacity { NumberAnimation { duration: 180 } }
    }
  }
}
