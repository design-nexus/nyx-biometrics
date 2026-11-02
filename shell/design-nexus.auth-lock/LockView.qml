import QtQuick
import QtQuick.Effects
import qs.Commons
import qs.Commons as Commons
import qs.Ui

Item {
  id: root

  property string backgroundPath: ""
  property string videoPosterPath: ""
  property int backgroundVersion: 0
  property bool fingerprintConfigured: false
  property bool fingerprintUnavailable: false
  property bool faceConfigured: false
  property bool faceAuthenticating: false
  property string faceMessage: ""
  property string facePhase: "idle"
  property string overlayStyle: "halo"
  property real overlayIntensity: 0.7
  property bool overlayAnimate: true
  readonly property bool overlayShown: faceConfigured && facePhase !== "idle"
  property bool authenticatingPassword: false
  property string failureMessage: ""
  property int failedAttempts: 0
  property bool inputEnabled: true
  property bool loadBackground: true
  property string passwordText: ""
  property bool syncingPasswordText: false

  readonly property string placeholderText: Commons.I18n.t("lock.enterPassword")
  readonly property int fieldWidth: 381
  readonly property int fieldHeight: 67
  readonly property int outlineThickness: 3
  readonly property int fieldFontSize: Math.round(Style.font.heading * 1.125)
  readonly property int passwordDotFontSize: Math.round(Style.font.heading * 1.33)
  readonly property int passwordDotLetterSpacing: Math.round(Style.font.heading * 0.19)
  // Space to keep clear on each side of the field for the fingerprint icon
  // (icon width plus a gap) so the centered dots never run under it.
  readonly property real fingerprintReserve: (fingerprintConfigured || faceConfigured) ? Math.round(Math.max(fingerprintIcon.implicitWidth, faceIcon.implicitWidth) + 12) : 0
  // Shrink the dots to fit once the password outgrows the field, so every
  // keystroke stays visible — otherwise long passwords clip with no feedback.
  readonly property real passwordDotScale: dotMetrics.advanceWidth > 0
    ? Math.min(1, (passwordInput.width - 4) / dotMetrics.advanceWidth)
    : 1
  readonly property bool showPasswordCursor: inputEnabled && !authenticatingPassword && failureMessage.length === 0
  readonly property bool errorState: failureMessage.length > 0
  readonly property var inputBorderSpec: errorState
    ? Border.surfaceSpec("lock", "border-error", Commons.Color.lock.borderError, root.outlineThickness, "border-alpha")
    : Border.surfaceSpec("lock", "border-active", Commons.Color.lock.borderActive, root.outlineThickness, "border-alpha")

  // A video wallpaper shows its still poster: nothing plays behind the lock.
  readonly property bool video: Util.isVideoPath(root.backgroundPath)

  signal submitPassword(string password)
  signal passwordTextEdited(string password)
  signal clearFailureRequested()
  signal wakeRequested()

  function forcePasswordFocus() {
    passwordInput.forceActiveFocus()
  }

  // The field loses focus as the machine suspends and nothing restores it on
  // resume. Dropping and retaking focus also hands the input method (fcitx5)
  // a fresh focus-in.
  function refocusPassword() {
    if (!inputEnabled || !passwordInput.enabled) return
    passwordInput.focus = false
    Qt.inputMethod.reset()
    forcePasswordFocus()
    Qt.inputMethod.update(Qt.ImQueryAll)
  }

  function clearPassword() {
    passwordTextEdited("")
  }

  // Waking a DPMS-blanked display can stall the compositor for seconds while
  // the monitor modesets, so the wake key's release arrives late and client-side
  // key repeat floods the field with that character. A held key has no business
  // typing a password; only holding Backspace/Delete to clear stays useful.
  function dropsAutoRepeat(key) {
    return key !== Qt.Key_Backspace && key !== Qt.Key_Delete
  }

  function syncPasswordText() {
    if (passwordInput.text === passwordText) return
    syncingPasswordText = true
    passwordInput.text = passwordText
    syncingPasswordText = false
  }

  onPasswordTextChanged: syncPasswordText()
  onInputEnabledChanged: {
    if (inputEnabled) Qt.callLater(forcePasswordFocus)
  }
  // The lock surface can gain keyboard focus while the field lacks it.
  Window.onActiveChanged: {
    if (Window.active && inputEnabled) Qt.callLater(refocusPassword)
  }

  // Timers stand still through a suspend, so a tick that finds the wall clock
  // jumped is the first moment after resume.
  Timer {
    interval: 1000
    repeat: true
    running: root.inputEnabled
    property double lastTickMs: Date.now()
    onRunningChanged: lastTickMs = Date.now()
    onTriggered: {
      var now = Date.now()
      var slept = now - lastTickMs > 3000
      lastTickMs = now
      if (slept) root.refocusPassword()
    }
  }

  // Keys that reach the view while the field is unfocused move focus to the
  // field and keep the keystroke, so the first character isn't lost.
  focus: true
  Keys.onPressed: function(event) {
    if (!inputEnabled || !passwordInput.enabled || passwordInput.activeFocus) return
    forcePasswordFocus()
    wakeRequested()
    var printable = event.text.length > 0 && event.text.charCodeAt(0) >= 32 && event.text.charCodeAt(0) !== 127
    if (printable && !event.isAutoRepeat && !(event.modifiers & (Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier))) {
      passwordInput.insert(passwordInput.cursorPosition, event.text)
      event.accepted = true
    }
  }
  Component.onCompleted: {
    syncPasswordText()
    if (inputEnabled) Qt.callLater(forcePasswordFocus)
  }

  // Measures the masked password at full size; passwordDotScale compares this
  // against the field width to decide how far the dots must shrink to fit.
  TextMetrics {
    id: dotMetrics
    font.family: Style.font.family
    font.pixelSize: root.passwordDotFontSize
    font.letterSpacing: root.passwordDotLetterSpacing
    text: "●".repeat(passwordInput.text.length)
  }

  Rectangle {
    anchors.fill: parent
    color: Commons.Color.background

    BackgroundMedia {
      id: wallpaper
      objectName: "lockWallpaper"
      anchors.fill: parent
      path: root.loadBackground ? (root.video ? root.videoPosterPath : root.backgroundPath) : ""
      version: root.backgroundVersion
      // Decode only once sized, at the lock's own size: an unsized first
      // request decoded the file at its native resolution, then again once
      // sized. That size is what the lock service keeps decoded ahead of the
      // lock, so the first frame has the wallpaper.
      cached: true
      constrainDecode: true
      decodeSize: Qt.size(width, height)
    }

    MultiEffect {
      anchors.fill: wallpaper
      source: wallpaper
      autoPaddingEnabled: false
      blurEnabled: root.loadBackground && wallpaper.ready
      blur: 1.0
      blurMax: 128
      blurMultiplier: 1.25
      contrast: -0.08
    }

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      onClicked: { root.wakeRequested(); root.forcePasswordFocus() }
      onPositionChanged: {
        root.wakeRequested()
        if (root.inputEnabled && !passwordInput.activeFocus) root.forcePasswordFocus()
      }
    }

    BorderSurface {
      id: inputField
      width: root.fieldWidth
      height: root.fieldHeight
      anchors.centerIn: parent
      color: Commons.Color.lock.background
      borderSpec: root.inputBorderSpec
      radius: Style.cornerRadius
      clip: true

      TextInput {
        id: passwordInput
        anchors.fill: parent
        anchors.topMargin: inputField.borderTop
        // Reserve the fingerprint icon's width on both sides so the centered
        // dots stay symmetric and never slide under the icon as they grow.
        anchors.rightMargin: inputField.borderRight + 18 + root.fingerprintReserve
        anchors.bottomMargin: inputField.borderBottom
        anchors.leftMargin: inputField.borderLeft + 18 + root.fingerprintReserve
        verticalAlignment: TextInput.AlignVCenter
        horizontalAlignment: TextInput.AlignHCenter
        activeFocusOnPress: true
        clip: true
        enabled: root.inputEnabled && !root.authenticatingPassword
        readOnly: root.authenticatingPassword
        echoMode: TextInput.Password
        passwordCharacter: "\u25CF"
        passwordMaskDelay: 0
        color: Commons.Color.lock.text
        selectionColor: Commons.Color.lock.selection
        selectedTextColor: Commons.Color.lock.text
        font.family: Style.font.family
        font.pixelSize: text.length > 0 ? Math.max(1, Math.floor(root.passwordDotFontSize * root.passwordDotScale)) : root.fieldFontSize
        font.letterSpacing: text.length > 0 ? root.passwordDotLetterSpacing * root.passwordDotScale : 0
        cursorVisible: activeFocus && root.showPasswordCursor && text.length > 0
        cursorDelegate: Rectangle {
          width: 2
          color: Commons.Color.lock.text
          visible: passwordInput.cursorVisible
        }

        onTextChanged: {
          if (!root.syncingPasswordText) root.passwordTextEdited(text)
          if (text.length > 0) {
            root.wakeRequested()
          }
          if (text.length > 0 && root.failureMessage.length > 0) root.clearFailureRequested()
        }

        onAccepted: {
          var submitted = root.passwordText
          root.passwordTextEdited("")
          if (submitted.length > 0) root.submitPassword(submitted)
        }

        Keys.onPressed: function(event) {
          root.wakeRequested()
          if (event.isAutoRepeat && root.dropsAutoRepeat(event.key)) {
            event.accepted = true
            return
          }
          if (event.key === Qt.Key_Escape || (event.modifiers & Qt.ControlModifier && event.key === Qt.Key_U)) {
            root.passwordTextEdited("")
            event.accepted = true
          }
        }
      }

      Text {
        textFormat: Text.PlainText
        anchors.fill: passwordInput
        text: root.authenticatingPassword ? Commons.I18n.t("lock.checking") : (root.failureMessage.length > 0 ? root.failureMessage : root.placeholderText)
        visible: passwordInput.text.length === 0
        color: root.authenticatingPassword ? Commons.Color.lock.text : (root.failureMessage.length > 0 ? Commons.Color.lock.textError : Commons.Color.lock.placeholder)
        font.family: Style.font.family
        font.pixelSize: root.fieldFontSize
        font.italic: !root.authenticatingPassword && root.failureMessage.length > 0
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
      }

      // Fingerprint hint pinned inside the field's right edge when a sensor is
      // enrolled, so the user knows they can touch to unlock instead of typing.
      // Matches hyprlock, which draws its fingerprint icon in the same spot.
      // A reader the shell cannot reach crosses out rather than disappears, so
      // it stops inviting touches that can never unlock.
      Text {
        id: fingerprintIcon
        objectName: "fingerprintIndicator"
        textFormat: Text.PlainText
        anchors.right: parent.right
        anchors.rightMargin: inputField.borderRight + 18
        anchors.verticalCenter: parent.verticalCenter
        visible: root.fingerprintConfigured
        text: root.fingerprintUnavailable ? "󰺱" : "󰈷"
        color: root.fingerprintUnavailable ? Commons.Color.lock.textError : Commons.Color.lock.placeholder
        font.family: Style.font.family
        font.pixelSize: Math.round(root.fieldFontSize * 1.1)
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
      }
    }

    // Face hint pinned inside the field's left edge, mirroring the fingerprint icon. It
    // pulses while a scan runs, so a scan never happens unnoticed.
    Text {
      id: faceIcon
      objectName: "faceIndicator"
      parent: inputField
      textFormat: Text.PlainText
      anchors.left: parent.left
      anchors.leftMargin: inputField.borderLeft + 18
      anchors.verticalCenter: parent.verticalCenter
      visible: root.faceConfigured
      text: String.fromCodePoint(0xF0C7B)
      color: root.faceAuthenticating ? Commons.Color.lock.borderActive : Commons.Color.lock.placeholder
      font.family: Style.font.family
      font.pixelSize: Math.round(root.fieldFontSize * 1.1)
      horizontalAlignment: Text.AlignHCenter
      verticalAlignment: Text.AlignVCenter

      SequentialAnimation on opacity {
        running: root.faceAuthenticating
        loops: Animation.Infinite
        alwaysRunToEnd: true
        NumberAnimation { to: 0.35; duration: 450; easing.type: Easing.InOutSine }
        NumberAnimation { to: 1.0; duration: 450; easing.type: Easing.InOutSine }
      }
    }

    // The scan indicator, in the style chosen in Settings. Only while something is
    // happening: a locked screen at rest shows just the face icon in the field.
    AuthOverlay {
      objectName: "faceOverlay"
      visible: root.overlayShown
      style: root.overlayStyle
      method: "face"
      phase: root.facePhase
      message: root.faceMessage
      intensity: root.overlayIntensity
      animate: root.overlayAnimate
      accent: Commons.Color.lock.borderActive
      surface: Commons.Color.lock.background
      text: Commons.Color.lock.text
      dim: Commons.Color.lock.placeholder
      bad: Commons.Color.lock.textError
      width: style === "edge" ? parent.width : (style === "minimal" ? implicitWidth : style === "halo" ? 260 : 240)
      height: style === "edge" ? parent.height : (style === "minimal" ? 44 : style === "halo" ? 280 : 240)
      detail: "Face · infrared"
      x: style === "edge" ? 0 : inputField.x + (inputField.width - width) / 2
      y: style === "edge" ? 0 : (style === "minimal" ? inputField.y + inputField.height + 18 : inputField.y - height - 28)
    }

    Text {
      objectName: "faceStatus"
      textFormat: Text.PlainText
      anchors.top: inputField.bottom
      anchors.topMargin: 18
      anchors.horizontalCenter: inputField.horizontalCenter
      visible: root.faceConfigured && !root.overlayShown && root.faceMessage.length > 0 && !(root.fingerprintConfigured && root.fingerprintUnavailable)
      text: root.faceMessage
      color: Commons.Color.lock.placeholder
      font.family: Style.font.family
      font.pixelSize: Style.font.heading
      horizontalAlignment: Text.AlignHCenter
    }

    // The crossed-out icon has no meaning to a user who has never seen it — it
    // is not intuitive that it signals a broken reader — so the words carry the
    // explanation and the icon only reinforces it.
    Text {
      objectName: "fingerprintUnavailableNotice"
      textFormat: Text.PlainText
      anchors.top: inputField.bottom
      anchors.topMargin: 18
      anchors.horizontalCenter: inputField.horizontalCenter
      visible: root.fingerprintConfigured && root.fingerprintUnavailable
      text: Commons.I18n.t("lock.fingerprintUnavailable")
      color: Commons.Color.lock.textError
      font.family: Style.font.family
      font.pixelSize: Style.font.heading
      font.italic: true
      horizontalAlignment: Text.AlignHCenter
    }
  }
}
