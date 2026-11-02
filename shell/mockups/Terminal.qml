import QtQuick

// Hacker: a console that types its own scan log.
Item {
  id: root
  property string phase: "scanning"
  property string method: "face"
  readonly property color green: "#3dff7a"
  readonly property color tone: phase === "failure" ? "#ff5f56" : green
  implicitWidth: 300
  implicitHeight: 300
  property int shown: 1
  readonly property var log: phase === "success"
    ? ["$ nyx-auth --face", "[ok] ir emitter online", "[ok] face detected", "[ok] liveness passed", "[ok] identity: ken", "", "  ACCESS GRANTED  "]
    : phase === "failure"
    ? ["$ nyx-auth --face", "[ok] ir emitter online", "[ok] face detected", "[!!] no match", "[..] falling back to password", "", "  ACCESS DENIED  "]
    : ["$ nyx-auth --face", "[ok] ir emitter online", "[..] looking for a face", "[..] liveness check", "", "", ""]
  Timer {
    interval: 380; repeat: true
    running: root.phase === "scanning"
    onTriggered: root.shown = root.shown >= 5 ? 1 : root.shown + 1
  }

  Rectangle {
    anchors.fill: parent
    radius: 7
    color: "#030806"
    border.width: 1
    border.color: "#0f3a1e"

    Column {
      x: 18; y: 18
      spacing: 4
      Repeater {
        model: root.log
        Text {
          required property string modelData
          required property int index
          visible: root.phase !== "scanning" || index < root.shown
          text: modelData
          color: modelData.indexOf("ACCESS") >= 0 ? "#030806" : (modelData.indexOf("[!!]") === 0 ? "#ff5f56" : root.green)
          font.family: "monospace"; font.pixelSize: 13
          Rectangle {
            z: -1; anchors.fill: parent; anchors.margins: -2
            visible: parent.text.indexOf("ACCESS") >= 0
            color: root.tone
          }
        }
      }
    }

    Text {
      x: 18
      anchors.bottom: parent.bottom; anchors.bottomMargin: 54
      text: "[" + "#".repeat(root.phase === "scanning" ? root.shown * 4 : 20) + "-".repeat(root.phase === "scanning" ? 20 - root.shown * 4 : 0) + "]"
      color: root.tone; font.family: "monospace"; font.pixelSize: 13
    }
    Text {
      x: 18
      anchors.bottom: parent.bottom; anchors.bottomMargin: 22
      text: "> _"
      color: root.green; font.family: "monospace"; font.pixelSize: 13
      SequentialAnimation on opacity { loops: Animation.Infinite; NumberAnimation { to: 0; duration: 500 } NumberAnimation { to: 1; duration: 500 } }
    }
  }
}
