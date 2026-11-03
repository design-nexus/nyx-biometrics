import QtQuick

// Nyx Design 2.0: one solid card, quiet rings, the accent used once.
Item {
  id: root
  property string phase: "scanning"
  property string method: "face"
  property color accent: "#5b9cff"
  readonly property color tone: phase === "success" ? "#4fd18b" : phase === "failure" ? "#ff6b6b" : accent
  implicitWidth: 300
  implicitHeight: 300

  Rectangle {
    anchors.centerIn: parent
    width: 248; height: 268
    radius: 15
    color: "#111114"
    border.width: 1
    border.color: "#1f1f25"

    Canvas {
      id: c
      width: 150; height: 150
      anchors.horizontalCenter: parent.horizontalCenter
      y: 30
      property real spin: 0
      NumberAnimation on spin { running: root.phase === "scanning"; from: 0; to: 360; duration: 2400; loops: Animation.Infinite }
      onSpinChanged: requestPaint()
      Component.onCompleted: requestPaint()
      onPaint: {
        var g = getContext("2d"); g.reset()
        var cx = width / 2, cy = height / 2
        g.lineCap = "round"
        g.strokeStyle = "#24242c"; g.lineWidth = 2
        g.beginPath(); g.arc(cx, cy, 66, 0, Math.PI * 2); g.stroke()
        g.beginPath(); g.arc(cx, cy, 56, 0, Math.PI * 2); g.stroke()
        g.strokeStyle = root.tone; g.lineWidth = 3
        if (root.phase === "scanning") {
          var a = spin * Math.PI / 180
          g.beginPath(); g.arc(cx, cy, 66, a, a + Math.PI * 0.5); g.stroke()
          g.globalAlpha = 0.5
          g.beginPath(); g.arc(cx, cy, 56, -a * 1.4, -a * 1.4 + Math.PI * 0.3); g.stroke()
        } else {
          g.beginPath(); g.arc(cx, cy, 66, 0, Math.PI * 2); g.stroke()
        }
      }
    }
    Text {
      anchors.centerIn: c
      text: root.phase === "success" ? String.fromCodePoint(0xF012C) : root.phase === "failure" ? String.fromCodePoint(0xF0156) : String.fromCodePoint(0xF0C7B)
      color: root.tone
      font.pixelSize: 46
    }
    Text {
      anchors.horizontalCenter: parent.horizontalCenter
      y: 200
      text: root.phase === "success" ? "Welcome back, Ken" : root.phase === "failure" ? "That wasn't a match" : "Looking for you"
      color: "#e8e8ec"; font.pixelSize: 16; font.weight: Font.Medium
    }
    Text {
      anchors.horizontalCenter: parent.horizontalCenter
      y: 226
      text: root.phase === "failure" ? "Try again or type your password" : "Face · infrared"
      color: "#8a8a94"; font.pixelSize: 12
    }
  }
}
