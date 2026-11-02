import QtQuick

// One authentication indicator in four styles. It only draws: callers set the method and
// state from their PAM flow, so a preview can show it without authenticating anything.
//
//   style:  "circular" | "cyberpunk" | "minimal" | "edge"
//   method: "face" | "fingerprint" | "key" | "password"
//   phase:  "idle" | "scanning" | "success" | "failure" | "timeout" | "pin"
//
// Surfaces are solid (Nyx Design 2.0): no blur or glass. Colours come from the caller so
// the indicator follows the theme it sits in.
Item {
  id: root

  property string style: "circular"
  property string method: "face"
  property string phase: "idle"
  property string message: ""
  property color accent: "#5b9cff"
  property color surface: "#141418"
  property color text: "#e8e8ec"
  property color dim: "#8a8a94"
  property color good: "#4fd18b"
  property color bad: "#ff6b6b"
  // 0..1: how strong glows and sweeps are.
  property real intensity: 0.7
  property bool animate: true

  readonly property bool active: phase === "scanning" || phase === "pin"
  readonly property color tone: phase === "success" ? good : (phase === "failure" ? bad : (phase === "timeout" ? dim : accent))
  readonly property string glyph: {
    if (phase === "success") return String.fromCodePoint(0xF012C) // md-check
    if (phase === "failure") return String.fromCodePoint(0xF0156) // md-close
    if (phase === "timeout") return String.fromCodePoint(0xF051F) // md-timer_sand
    if (method === "fingerprint") return String.fromCodePoint(0xF0237)
    if (method === "key") return String.fromCodePoint(0xF030B)
    if (method === "password") return String.fromCodePoint(0xF033E) // md-lock
    return String.fromCodePoint(0xF0C7B) // md-face_recognition
  }
  readonly property string label: {
    if (message.length > 0) return message
    if (phase === "success") return "Welcome back"
    if (phase === "failure") return method === "face" ? "Face not recognised" : "Not recognised"
    if (phase === "timeout") return "Timed out. Use your password"
    if (phase === "pin") return "Enter the security key's PIN"
    if (phase === "scanning") {
      if (method === "fingerprint") return "Touch the fingerprint reader"
      if (method === "key") return "Touch your security key"
      if (method === "password") return "Enter your password"
      return "Looking for you…"
    }
    return ""
  }

  implicitWidth: style === "edge" ? 640 : (style === "minimal" ? pill.implicitWidth : 220)
  implicitHeight: style === "edge" ? 400 : (style === "minimal" ? 44 : 220)

  // A failure shakes once, in every style.
  SequentialAnimation {
    id: shake
    running: false
    NumberAnimation { target: root; property: "shift"; to: -8; duration: 50 }
    NumberAnimation { target: root; property: "shift"; to: 8; duration: 80 }
    NumberAnimation { target: root; property: "shift"; to: -4; duration: 70 }
    NumberAnimation { target: root; property: "shift"; to: 0; duration: 60 }
  }
  property real shift: 0
  onPhaseChanged: if (phase === "failure" && animate) shake.restart()

  // ---------- Circular face scan ----------
  Item {
    id: circular
    visible: root.style === "circular"
    anchors.centerIn: parent
    anchors.horizontalCenterOffset: root.shift
    width: 132
    height: width

    Rectangle {
      anchors.fill: parent
      radius: width / 2
      color: root.surface
      border.width: 2
      border.color: Qt.rgba(root.tone.r, root.tone.g, root.tone.b, 0.25)
    }

    Canvas {
      id: ring
      anchors.fill: parent
      property real sweep: root.phase === "success" ? 1 : (root.active ? 0.28 : 0)
      property real spin: 0
      Behavior on sweep { NumberAnimation { duration: 280; easing.type: Easing.OutCubic } }
      onSweepChanged: requestPaint()
      onSpinChanged: requestPaint()
      Connections { target: root; function onToneChanged() { ring.requestPaint() } }
      NumberAnimation on spin {
        running: root.animate && root.active
        from: 0; to: Math.PI * 2; duration: 1300; loops: Animation.Infinite
      }
      onPaint: {
        var ctx = getContext("2d")
        ctx.reset()
        if (sweep <= 0) return
        ctx.lineWidth = 5
        ctx.lineCap = "round"
        ctx.strokeStyle = root.tone
        ctx.globalAlpha = 0.45 + 0.55 * root.intensity
        ctx.beginPath()
        var start = -Math.PI / 2 + (root.phase === "success" ? 0 : spin)
        ctx.arc(width / 2, height / 2, width / 2 - 6, start, start + sweep * Math.PI * 2)
        ctx.stroke()
      }
    }

    Text {
      anchors.centerIn: parent
      text: root.glyph
      color: root.tone
      font.pixelSize: 52
      SequentialAnimation on opacity {
        running: root.animate && root.active
        loops: Animation.Infinite
        alwaysRunToEnd: true
        NumberAnimation { to: 0.45; duration: 650; easing.type: Easing.InOutSine }
        NumberAnimation { to: 1.0; duration: 650; easing.type: Easing.InOutSine }
      }
    }
  }
  Text {
    visible: root.style === "circular"
    anchors.top: circular.bottom
    anchors.topMargin: 14
    anchors.horizontalCenter: circular.horizontalCenter
    text: root.label
    color: root.phase === "failure" ? root.bad : root.text
    font.pixelSize: 15
  }

  // ---------- Cyberpunk scanner ----------
  Item {
    id: cyber
    visible: root.style === "cyberpunk"
    anchors.centerIn: parent
    anchors.horizontalCenterOffset: root.shift
    width: 150
    height: 150

    Rectangle { anchors.fill: parent; color: root.surface; opacity: 0.92 }

    Repeater {
      model: 4
      Item {
        required property int index
        width: 26; height: 26
        x: index % 2 === 0 ? 0 : cyber.width - width
        y: index < 2 ? 0 : cyber.height - height
        Rectangle { width: parent.width; height: 3; color: root.tone; y: index < 2 ? 0 : parent.height - 3 }
        Rectangle { width: 3; height: parent.height; color: root.tone; x: index % 2 === 0 ? 0 : parent.width - 3 }
      }
    }

    Text {
      anchors.centerIn: parent
      text: root.glyph
      color: root.tone
      font.pixelSize: 56
    }

    Rectangle {
      id: scanLine
      visible: root.active
      x: 10
      width: cyber.width - 20
      height: 2
      color: root.tone
      opacity: 0.35 + 0.6 * root.intensity
      NumberAnimation on y {
        running: root.animate && root.active
        from: 12; to: cyber.height - 14; duration: 1100; loops: Animation.Infinite
        easing.type: Easing.InOutSine
      }
    }
  }
  Text {
    visible: root.style === "cyberpunk"
    anchors.top: cyber.bottom
    anchors.topMargin: 12
    anchors.horizontalCenter: cyber.horizontalCenter
    text: {
      var m = root.method === "key" ? "KEY" : root.method.toUpperCase()
      if (root.phase === "success") return "MATCH // ACCESS GRANTED"
      if (root.phase === "failure") return "NO MATCH // " + m
      if (root.phase === "timeout") return "TIMEOUT // USE PASSWORD"
      if (root.phase === "pin") return "PIN // " + m
      if (root.phase === "scanning") return "SCAN // " + m
      return "READY // " + m
    }
    color: root.tone
    font.family: "monospace"
    font.pixelSize: 13
    font.letterSpacing: 2
  }

  // ---------- Minimal floating ----------
  Rectangle {
    id: pill
    visible: root.style === "minimal"
    anchors.centerIn: parent
    anchors.horizontalCenterOffset: root.shift
    implicitWidth: row.implicitWidth + 28
    width: implicitWidth
    height: 44
    radius: 11
    color: root.surface
    border.width: 1
    border.color: Qt.rgba(root.tone.r, root.tone.g, root.tone.b, 0.5)

    Row {
      id: row
      anchors.centerIn: parent
      spacing: 10
      Text {
        text: root.glyph
        color: root.tone
        font.pixelSize: 20
        anchors.verticalCenter: parent.verticalCenter
        SequentialAnimation on opacity {
          running: root.animate && root.active
          loops: Animation.Infinite
          alwaysRunToEnd: true
          NumberAnimation { to: 0.5; duration: 700 }
          NumberAnimation { to: 1.0; duration: 700 }
        }
      }
      Text {
        text: root.label
        color: root.phase === "failure" ? root.bad : root.text
        font.pixelSize: 14
        anchors.verticalCenter: parent.verticalCenter
      }
    }
  }

  // ---------- Edge glow ----------
  Item {
    visible: root.style === "edge"
    anchors.fill: parent

    // Stacked hairlines fading inwards read as a soft glow without blur.
    Repeater {
      model: 16
      Rectangle {
        required property int index
        anchors.fill: parent
        anchors.margins: index * 1.5
        color: "transparent"
        radius: 15
        border.width: 2
        border.color: root.tone
        opacity: (root.phase === "idle" ? 0 : Math.pow(1 - index / 16, 2.2) * 0.6) * (0.4 + 0.6 * root.intensity) * edgePulse.level
      }
    }

    QtObject {
      id: edgePulse
      property real level: 1
      SequentialAnimation on level {
        running: root.animate && root.active
        loops: Animation.Infinite
        alwaysRunToEnd: true
        NumberAnimation { to: 0.45; duration: 900; easing.type: Easing.InOutSine }
        NumberAnimation { to: 1.0; duration: 900; easing.type: Easing.InOutSine }
      }
    }

    Rectangle {
      visible: root.label.length > 0
      anchors.horizontalCenter: parent.horizontalCenter
      anchors.bottom: parent.bottom
      anchors.bottomMargin: 26
      width: edgeText.implicitWidth + 24
      height: 30
      radius: 7
      color: root.surface
      Text {
        id: edgeText
        anchors.centerIn: parent
        text: root.glyph + "  " + root.label
        color: root.tone
        font.pixelSize: 13
      }
    }
  }
}
