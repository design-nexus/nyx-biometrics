import QtQuick

// Nyx, goddess of night: a crescent that waxes as she looks, among slow stars.
Item {
  id: root
  property string phase: "scanning"
  property string method: "face"
  readonly property color silver: "#dcd8ff"
  readonly property color violet: "#8b7cff"
  readonly property color tone: phase === "success" ? "#f3e7b3" : phase === "failure" ? "#ff8a9a" : silver
  implicitWidth: 300
  implicitHeight: 300

  Rectangle {
    anchors.fill: parent
    radius: 15
    color: "#0b0a1a"
    border.width: 1
    border.color: "#1d1a3a"
    clip: true

    Repeater {
      model: 34
      Rectangle {
        required property int index
        readonly property real seed: Math.sin(index * 91.7) * 0.5 + 0.5
        x: (Math.sin(index * 12.9898) * 0.5 + 0.5) * root.width
        y: (Math.sin(index * 78.233) * 0.5 + 0.5) * root.height * 0.9
        width: seed > 0.8 ? 2.5 : 1.5; height: width; radius: width
        color: root.silver
        opacity: 0.25 + 0.5 * seed
        SequentialAnimation on opacity {
          running: root.phase === "scanning"
          loops: Animation.Infinite
          PauseAnimation { duration: 400 + seed * 2400 }
          NumberAnimation { to: 0.1; duration: 900 }
          NumberAnimation { to: 0.8; duration: 900 }
        }
      }
    }

    // The moon: a lit disc with a dark disc sliding off it, so the crescent waxes.
    Item {
      id: moon
      width: 120; height: 120
      anchors.horizontalCenter: parent.horizontalCenter
      y: 46
      property real wax: root.phase === "success" ? 1 : root.phase === "failure" ? 0.15 : 0.15
      SequentialAnimation on wax {
        running: root.phase === "scanning"
        loops: Animation.Infinite
        NumberAnimation { from: 0.12; to: 0.75; duration: 2200; easing.type: Easing.InOutSine }
        NumberAnimation { to: 0.12; duration: 2200; easing.type: Easing.InOutSine }
      }
      Rectangle {
        anchors.centerIn: parent
        width: 150; height: 150; radius: 75
        color: "transparent"
        border.width: 1
        border.color: Qt.rgba(root.violet.r, root.violet.g, root.violet.b, 0.35)
      }
      Rectangle { anchors.fill: parent; radius: width / 2; color: root.tone; opacity: 0.95 }
      Rectangle {
        width: parent.width; height: parent.height; radius: width / 2
        color: "#0b0a1a"
        x: -moon.wax * (parent.width + 4) + 26
        y: -6
        visible: root.phase !== "success"
      }
    }

    Text {
      anchors.horizontalCenter: parent.horizontalCenter
      y: 196
      text: root.phase === "success" ? "The night knows you" : root.phase === "failure" ? "A stranger in the dark" : "Nyx is looking for you"
      color: root.tone
      font.family: "serif"; font.italic: true; font.pixelSize: 18
    }
    Text {
      anchors.horizontalCenter: parent.horizontalCenter
      y: 228
      text: root.phase === "failure" ? "TYPE YOUR PASSWORD" : "FACE · INFRARED"
      color: root.violet; font.pixelSize: 10; font.letterSpacing: 3
    }
  }
}
