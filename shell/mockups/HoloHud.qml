import QtQuick

// Modern sci-fi: counter-rotating segmented rings, a reticle, plain-language readouts.
// The readouts state what is happening, never invented scores.
Item {
  id: root
  property string phase: "scanning"
  property string method: "face"
  readonly property color cyan: "#7fe7ff"
  readonly property color tone: phase === "success" ? "#7dffb3" : phase === "failure" ? "#ff7d7d" : cyan
  implicitWidth: 300
  implicitHeight: 300

  Canvas {
    id: c
    anchors.centerIn: parent
    anchors.verticalCenterOffset: -14
    width: 210; height: 210
    property real t: 0
    NumberAnimation on t { running: root.phase === "scanning"; from: 0; to: Math.PI * 2; duration: 5000; loops: Animation.Infinite }
    onTChanged: requestPaint()
    Component.onCompleted: requestPaint()
    onPaint: {
      var g = getContext("2d"); g.reset()
      var cx = width / 2, cy = height / 2, col = root.tone
      function ring(r, n, gap, rot, alpha, w) {
        g.strokeStyle = Qt.rgba(col.r, col.g, col.b, alpha); g.lineWidth = w
        var seg = Math.PI * 2 / n
        for (var i = 0; i < n; i++) { g.beginPath(); g.arc(cx, cy, r, rot + i * seg, rot + (i + 1) * seg - gap); g.stroke() }
      }
      ring(98, 3, 0.5, t, 0.9, 2)
      ring(88, 36, 0.09, -t * 0.6, 0.35, 5)
      ring(72, 6, 0.35, t * 1.5, 0.7, 1.5)
      g.strokeStyle = Qt.rgba(col.r, col.g, col.b, 0.5); g.lineWidth = 1
      for (var k = 0; k < 4; k++) {
        var a = k * Math.PI / 2
        g.beginPath(); g.moveTo(cx + Math.cos(a) * 30, cy + Math.sin(a) * 30); g.lineTo(cx + Math.cos(a) * 60, cy + Math.sin(a) * 60); g.stroke()
      }
    }
  }
  Text {
    anchors.centerIn: c
    text: root.phase === "success" ? String.fromCodePoint(0xF012C) : root.phase === "failure" ? String.fromCodePoint(0xF0156) : String.fromCodePoint(0xF0C7B)
    color: root.tone; font.pixelSize: 40
  }
  Column {
    anchors.left: parent.left; anchors.leftMargin: 6
    anchors.top: c.top; anchors.topMargin: 4
    spacing: 3
    Repeater {
      model: ["IR", "ACTIVE", "", "DEPTH", "LIVE"]
      Text { required property string modelData; text: modelData; color: root.tone; opacity: 0.7; font.family: "monospace"; font.pixelSize: 9; font.letterSpacing: 2 }
    }
  }
  Column {
    anchors.right: parent.right; anchors.rightMargin: 6
    anchors.top: c.top; anchors.topMargin: 4
    spacing: 3
    Repeater {
      model: root.phase === "success" ? ["ID", "KEN", "", "STATE", "OPEN"] : root.phase === "failure" ? ["ID", "NONE", "", "STATE", "LOCKED"] : ["ID", "—", "", "STATE", "SCAN"]
      Text { required property string modelData; text: modelData; color: root.tone; opacity: 0.7; font.family: "monospace"; font.pixelSize: 9; font.letterSpacing: 2; anchors.right: parent.right }
    }
  }
  Text {
    anchors.horizontalCenter: parent.horizontalCenter
    anchors.bottom: parent.bottom; anchors.bottomMargin: 18
    text: root.phase === "success" ? "IDENTITY CONFIRMED" : root.phase === "failure" ? "NO MATCH — USE PASSWORD" : "ACQUIRING"
    color: root.tone; font.pixelSize: 13; font.letterSpacing: 4
  }
}
