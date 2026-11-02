import QtQuick

// Cyberpunk: magenta and cyan, a slanted frame, a receding grid, and text that glitches.
Item {
  id: root
  property string phase: "scanning"
  property string method: "face"
  readonly property color magenta: "#ff2bd6"
  readonly property color cyan: "#20f0ff"
  readonly property color tone: phase === "success" ? "#39ff88" : phase === "failure" ? "#ff3b5c" : cyan
  implicitWidth: 300
  implicitHeight: 300
  property real glitch: 0
  SequentialAnimation on glitch {
    running: root.phase !== "success"
    loops: Animation.Infinite
    PauseAnimation { duration: 1400 }
    NumberAnimation { to: 1; duration: 60 }
    NumberAnimation { to: -1; duration: 60 }
    NumberAnimation { to: 0; duration: 80 }
  }

  Rectangle { anchors.fill: parent; color: "#0a0612"; radius: 7 }

  Canvas {
    anchors.fill: parent
    Component.onCompleted: requestPaint()
    onPaint: {
      var g = getContext("2d"); g.reset()
      var h = height, w = width, top = h * 0.62
      g.strokeStyle = Qt.rgba(1, 0.17, 0.84, 0.35); g.lineWidth = 1
      for (var i = 0; i < 8; i++) {
        var y = top + Math.pow(i / 7, 1.8) * (h - top)
        g.beginPath(); g.moveTo(0, y); g.lineTo(w, y); g.stroke()
      }
      for (var j = -8; j <= 8; j++) {
        g.beginPath(); g.moveTo(w / 2 + j * 14, top); g.lineTo(w / 2 + j * 70, h); g.stroke()
      }
    }
  }

  // Slanted frame.
  Item {
    id: frame
    width: 150; height: 150
    anchors.horizontalCenter: parent.horizontalCenter
    y: 34
    transform: Matrix4x4 { matrix: Qt.matrix4x4(1, -0.12, 0, 9, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1) }
    Rectangle { anchors.fill: parent; color: "transparent"; border.width: 2; border.color: root.magenta; opacity: 0.8 }
    Rectangle { anchors.fill: parent; anchors.margins: 8; color: "transparent"; border.width: 1; border.color: root.tone }
    Rectangle {
      visible: root.phase === "scanning"
      x: 8; width: parent.width - 16; height: 3; color: root.tone
      NumberAnimation on y { running: root.phase === "scanning"; from: 10; to: 136; duration: 900; loops: Animation.Infinite; easing.type: Easing.InOutQuad }
    }
  }
  Text { anchors.centerIn: frame; anchors.horizontalCenterOffset: 3 + root.glitch * 4; text: root.phase === "success" ? String.fromCodePoint(0xF012C) : root.phase === "failure" ? String.fromCodePoint(0xF0156) : String.fromCodePoint(0xF0C7B); color: root.magenta; opacity: 0.7; font.pixelSize: 64 }
  Text { anchors.centerIn: frame; anchors.horizontalCenterOffset: -2 - root.glitch * 3; text: root.phase === "success" ? String.fromCodePoint(0xF012C) : root.phase === "failure" ? String.fromCodePoint(0xF0156) : String.fromCodePoint(0xF0C7B); color: root.tone; font.pixelSize: 64 }

  Text {
    anchors.horizontalCenter: parent.horizontalCenter
    anchors.horizontalCenterOffset: root.glitch * 6
    y: 204
    text: root.phase === "success" ? "ACCESS GRANTED" : root.phase === "failure" ? "IDENTITY REJECTED" : "SCANNING BIOMETRICS"
    color: root.tone; font.family: "monospace"; font.bold: true; font.pixelSize: 15; font.letterSpacing: 3
  }
  Text {
    anchors.horizontalCenter: parent.horizontalCenter
    y: 228
    text: "// NYX.SEC ▸ FACE ▸ IR-940"
    color: root.magenta; font.family: "monospace"; font.pixelSize: 10; font.letterSpacing: 2
  }
}
