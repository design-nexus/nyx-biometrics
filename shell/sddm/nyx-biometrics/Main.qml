import QtQuick 2.0
import SddmComponents 2.0

// Omarchy's login screen (omarchy-settings, MIT) with Nyx Biometrics' Halo. An empty
// password and Enter asks Irlume for the face (its on-demand trigger); typing a password
// works as before. The images stay Omarchy's own, so they follow its updates.
Rectangle {
  id: root
  width: 640
  height: 480
  color: "#1a1b26"

  readonly property string omarchy: "file:///usr/share/sddm/themes/omarchy/"
  property string currentUser: userModel.lastUser
  property bool loginFailed: false
  // "idle" | "scanning" | "success" | "failure", for the face only.
  property string face: "idle"
  property bool faceTry: false
  property int sessionIndex: {
    for (var i = 0; i < sessionModel.rowCount(); i++) {
      var name = (sessionModel.data(sessionModel.index(i, 0), Qt.DisplayRole) || "").toString()
      if (name.indexOf("uwsm") !== -1)
        return i
    }
    return sessionModel.lastIndex
  }

  function submit() {
    root.faceTry = password.text.length === 0
    if (root.faceTry)
      root.face = "scanning"
    sddm.login(root.currentUser, password.text, root.sessionIndex)
  }

  Connections {
    target: sddm
    function onLoginFailed() {
      if (root.faceTry) {
        root.face = "failure"
        settle.restart()
      } else {
        root.loginFailed = true
      }
      root.faceTry = false
      password.text = ""
      password.focus = true
    }
    function onLoginSucceeded() {
      root.loginFailed = false
      if (root.faceTry)
        root.face = "success"
    }
  }

  Timer {
    id: settle
    interval: 2500
    onTriggered: if (root.face === "failure") root.face = "idle"
  }

  Column {
    anchors.centerIn: parent
    spacing: 40

    Image {
      id: logo
      source: root.omarchy + "logo.png"
      width: Math.min(sourceSize.width, root.width * 0.8)
      height: sourceSize.width > 0 ? Math.round(width * sourceSize.height / sourceSize.width) : 0
      fillMode: Image.PreserveAspectFit
      anchors.horizontalCenter: parent.horizontalCenter
    }

    AuthOverlay {
      anchors.horizontalCenter: parent.horizontalCenter
      width: 248
      height: 268
      style: "halo"
      method: "face"
      phase: root.face === "idle" ? "idle" : root.face
      message: root.face === "idle" ? "Press Enter to use your face" : ""
      detail: root.face === "idle" ? "Or type your password" : "Face · infrared"
      accent: "#7aa2f7"
      surface: "#1a1b26"
      text: "#c0caf5"
      dim: "#565f89"
      good: "#9ece6a"
      bad: "#f7768e"
    }

    Row {
      anchors.horizontalCenter: parent.horizontalCenter
      spacing: 15

      Image {
        source: root.omarchy + (root.loginFailed ? "lock-failed.png" : "lock.png")
        width: 34
        height: 38
        fillMode: Image.PreserveAspectFit
        anchors.verticalCenter: parent.verticalCenter
      }

      Item {
        width: entry.width
        height: entry.height

        Image {
          id: entry
          source: root.omarchy + (root.loginFailed ? "entry-failed.png" : "entry.png")
          anchors.centerIn: parent
        }

        Row {
          anchors.left: parent.left
          anchors.leftMargin: 20
          anchors.verticalCenter: parent.verticalCenter
          spacing: 5

          Repeater {
            model: Math.min(password.text.length, 21)

            Image {
              source: root.omarchy + "bullet.png"
              width: 7
              height: 7
            }
          }
        }

        TextInput {
          id: password
          anchors.fill: parent
          anchors.leftMargin: 20
          anchors.rightMargin: 20
          verticalAlignment: TextInput.AlignVCenter
          echoMode: TextInput.Password
          font.family: "JetBrainsMono Nerd Font"
          font.pixelSize: 24
          font.letterSpacing: 5
          passwordCharacter: "\u2022"
          color: "transparent"
          selectionColor: "transparent"
          selectedTextColor: "transparent"
          cursorDelegate: Item {}
          focus: true

          onTextChanged: {
            root.loginFailed = false
            if (text.length > 0 && root.face === "failure")
              root.face = "idle"
          }

          Keys.onPressed: {
            if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
              root.submit()
              event.accepted = true
            }
          }
        }
      }
    }
  }

  Component.onCompleted: password.forceActiveFocus()
}
