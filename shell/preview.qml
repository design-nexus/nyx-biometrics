import QtQuick
import QtQuick.Layouts
import Quickshell
import "common"

// Every overlay style in every state, for checking how they look. Run:
//   quickshell -p shell/preview.qml
ShellRoot {
  FloatingWindow {
    title: "nyx-auth-preview"
    color: "#09090a"
    implicitWidth: 1280
    implicitHeight: 900

    GridLayout {
      anchors.fill: parent
      anchors.margins: 18
      columns: 5
      rowSpacing: 6
      columnSpacing: 6

      Repeater {
        model: [
          ["halo", "face", "scanning"], ["halo", "fingerprint", "scanning"], ["halo", "key", "pin"], ["halo", "face", "success"], ["halo", "face", "failure"],
          ["circular", "face", "scanning"], ["circular", "fingerprint", "scanning"], ["circular", "key", "pin"], ["circular", "face", "success"], ["circular", "face", "failure"],
          ["cyberpunk", "face", "scanning"], ["cyberpunk", "fingerprint", "scanning"], ["cyberpunk", "key", "scanning"], ["cyberpunk", "face", "success"], ["cyberpunk", "face", "timeout"],
          ["minimal", "face", "scanning"], ["minimal", "fingerprint", "failure"], ["minimal", "key", "pin"], ["minimal", "password", "scanning"], ["minimal", "face", "success"],
          ["edge", "face", "scanning"], ["edge", "key", "scanning"], ["edge", "face", "success"], ["edge", "face", "failure"], ["edge", "face", "timeout"]
        ]

        Rectangle {
          required property var modelData
          Layout.fillWidth: true
          Layout.fillHeight: true
          color: "#111114"
          radius: 11

          AuthOverlay {
            anchors.fill: parent
            anchors.margins: modelData[0] === "edge" ? 4 : 0
            style: modelData[0]
            method: modelData[1]
            phase: modelData[2]
          }
        }
      }
    }
  }
}
