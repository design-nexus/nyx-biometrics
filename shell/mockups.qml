import QtQuick
import Quickshell
import "common"
import "mockups"

// Overlay mockups on a lock-screen backdrop, one style per page:
//   NYX_MOCK_PAGE=3 quickshell -p shell/mockups.qml
ShellRoot {
  id: shell
  readonly property int page: Math.max(0, Math.min(pages.length - 1, parseInt(Quickshell.env("NYX_MOCK_PAGE") || "0")))
  readonly property var pages: [
    ["circular", "Circular face scan", "Current"],
    ["cyberpunk", "Cyberpunk scanner", "Current"],
    ["minimal", "Minimal floating", "Current"],
    ["edge", "Edge glow", "Current"],
    ["Halo", "Halo", "Nyx Design 2.0"],
    ["Nocturne", "Nocturne", "Nyx, goddess of night"],
    ["Eclipse", "Eclipse", "Nyx, goddess of night"],
    ["NeonGrid", "Neon Grid", "Cyberpunk"],
    ["Terminal", "Terminal", "Hacker"],
    ["HoloHud", "Holo HUD", "Modern sci-fi"]
  ]
  readonly property var current: pages[page]

  Component { id: halo; Halo {} }
  Component { id: nocturne; Nocturne {} }
  Component { id: eclipse; Eclipse {} }
  Component { id: neon; NeonGrid {} }
  Component { id: terminal; Terminal {} }
  Component { id: holo; HoloHud {} }
  Component { id: overlay; AuthOverlay {} }

  function component(kind) {
    return { Halo: halo, Nocturne: nocturne, Eclipse: eclipse, NeonGrid: neon, Terminal: terminal, HoloHud: holo }[kind] || overlay
  }

  FloatingWindow {
    title: "nyx-auth-mockup"
    implicitWidth: 1280
    implicitHeight: 800
    color: "#06060a"

    // A night backdrop standing in for the blurred wallpaper.
    Rectangle {
      anchors.fill: parent
      gradient: Gradient {
        GradientStop { position: 0; color: "#0d1022" }
        GradientStop { position: 0.6; color: "#08080f" }
        GradientStop { position: 1; color: "#050507" }
      }
    }

    Text {
      x: 28; y: 22
      text: (shell.page + 1) + " · " + shell.current[1]
      color: "#e8e8ec"; font.pixelSize: 22; font.weight: Font.DemiBold
    }
    Text {
      x: 28; y: 54
      text: shell.current[2]
      color: shell.current[2] === "Current" ? "#8a8a94" : "#5b9cff"; font.pixelSize: 13; font.letterSpacing: 1
    }

    Text {
      anchors.horizontalCenter: parent.horizontalCenter
      y: 40
      text: "1:13"
      color: "#e8e8ec"; font.pixelSize: 64; font.weight: Font.Light
    }
    Text {
      anchors.horizontalCenter: parent.horizontalCenter
      y: 120
      text: "Monday, November 2"
      color: "#8a8a94"; font.pixelSize: 15
    }

    // The overlay, scanning, where the lock screen puts it.
    Loader {
      id: hero
      anchors.horizontalCenter: parent.horizontalCenter
      y: shell.current[0] === "edge" ? 0 : 168
      width: shell.current[0] === "edge" ? parent.width : 300
      height: shell.current[0] === "edge" ? parent.height : (shell.current[0] === "minimal" ? 60 : 300)
      sourceComponent: shell.component(shell.current[0])
      onLoaded: {
        item.phase = "scanning"
        if (item.style !== undefined) item.style = shell.current[0]
      }
    }

    // The password field, as on the lock screen.
    Rectangle {
      id: field
      anchors.horizontalCenter: parent.horizontalCenter
      y: shell.current[0] === "minimal" ? 260 : 486
      width: 381; height: 67; radius: 11
      color: "#111114"
      border.width: 2
      border.color: "#2a2f45"
      Text {
        anchors.centerIn: parent
        text: "Enter password"
        color: "#6b6b75"; font.pixelSize: 20
      }
      Text {
        anchors.left: parent.left; anchors.leftMargin: 20
        anchors.verticalCenter: parent.verticalCenter
        text: String.fromCodePoint(0xF0C7B)
        color: "#5b9cff"; font.pixelSize: 22
      }
    }

    // Success and failure, small, down the right.
    Column {
      anchors.right: parent.right
      anchors.rightMargin: 40
      anchors.verticalCenter: parent.verticalCenter
      anchors.verticalCenterOffset: 20
      spacing: 18
      Repeater {
        model: ["success", "failure"]
        Rectangle {
          required property string modelData
          width: 210; height: 210
          radius: 11
          color: "#0a0a0f"
          border.width: 1
          border.color: "#1c1c24"
          clip: true
          Loader {
            anchors.centerIn: parent
            width: 300; height: 300
            scale: 0.68
            sourceComponent: shell.component(shell.current[0])
            onLoaded: {
              item.phase = modelData
              if (item.style !== undefined) item.style = shell.current[0]
            }
          }
          Text {
            anchors.bottom: parent.bottom; anchors.bottomMargin: 6
            anchors.horizontalCenter: parent.horizontalCenter
            text: modelData
            color: "#6b6b75"; font.pixelSize: 10; font.letterSpacing: 2
          }
        }
      }
    }
  }
}
