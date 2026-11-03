import QtQuick

// A total eclipse: a dark disc whose corona turns while it looks, and flares gold on a match.
Item {
  id: root
  property string phase: "scanning"
  property string method: "face"
  readonly property color corona: phase === "success" ? "#ffd58a" : phase === "failure" ? "#ff6b6b" : "#9fb8ff"
  implicitWidth: 300
  implicitHeight: 300

  Canvas {
    id: c
    anchors.centerIn: parent
    width: 230; height: 230
    property real spin: 0
    NumberAnimation on spin { running: root.phase === "scanning"; from: 0; to: Math.PI * 2; duration: 6000; loops: Animation.Infinite }
    onSpinChanged: requestPaint()
    Component.onCompleted: requestPaint()
    onPaint: {
      var g = getContext("2d"); g.reset()
      var cx = width / 2, cy = height / 2, r = 62
      var col = root.corona
      for (var i = 0; i < 48; i++) {
        var a = spin + i * Math.PI * 2 / 48
        var len = 18 + 26 * Math.abs(Math.sin(i * 2.3 + spin * 2))
        g.strokeStyle = Qt.rgba(col.r, col.g, col.b, 0.10 + 0.25 * Math.abs(Math.sin(i * 1.7)))
        g.lineWidth = 2
        g.beginPath()
        g.moveTo(cx + Math.cos(a) * (r + 2), cy + Math.sin(a) * (r + 2))
        g.lineTo(cx + Math.cos(a) * (r + len), cy + Math.sin(a) * (r + len))
        g.stroke()
      }
      var grad = g.createRadialGradient(cx, cy, r - 2, cx, cy, r + 30)
      grad.addColorStop(0, Qt.rgba(col.r, col.g, col.b, 0.85))
      grad.addColorStop(1, Qt.rgba(col.r, col.g, col.b, 0))
      g.fillStyle = grad
      g.beginPath(); g.arc(cx, cy, r + 30, 0, Math.PI * 2); g.fill()
      g.fillStyle = "#050507"
      g.beginPath(); g.arc(cx, cy, r, 0, Math.PI * 2); g.fill()
    }
  }
  Text {
    anchors.centerIn: c
    text: root.phase === "success" ? String.fromCodePoint(0xF012C) : root.phase === "failure" ? String.fromCodePoint(0xF0156) : String.fromCodePoint(0xF0C7B)
    color: root.corona; opacity: 0.85; font.pixelSize: 40
  }
  Text {
    anchors.horizontalCenter: parent.horizontalCenter
    anchors.top: c.bottom; anchors.topMargin: -6
    text: root.phase === "success" ? "Totality. Welcome back." : root.phase === "failure" ? "Not recognised" : "Hold still"
    color: "#e8e8ec"; font.pixelSize: 15; font.letterSpacing: 1
  }
}
