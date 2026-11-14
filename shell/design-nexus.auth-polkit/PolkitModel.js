function promptLooksFingerprint(text) {
  var s = String(text || "").toLowerCase()
  return s.indexOf("finger") !== -1 || s.indexOf("fprint") !== -1 || s.indexOf("swipe") !== -1
}

// pam_u2f asks "Please enter the PIN:" through the same conversation as the password.
function promptLooksPin(text) {
  return /\bPIN\b/i.test(String(text || ""))
}

// pam_u2f's cue while it waits for a touch: "Please touch the FIDO authenticator." (older
// releases: "Please touch the device.")
function messageLooksKeyTouch(text) {
  return /touch the (FIDO authenticator|device)/i.test(String(text || ""))
}

function fingerprintConfiguredFromPamConfig(raw) {
  // Fingerprint is available whenever pam_fprintd appears anywhere in the auth
  // stack — it need not be the first module. A clamshell gate (pam_exec) may
  // legitimately precede it to skip fingerprint while the lid is closed.
  var lines = String(raw || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].replace(/^\s+|\s+$/g, "")
    if (!line || line.charAt(0) === "#") continue
    if (!line.match(/^auth\s+/)) continue
    if (line.indexOf("pam_fprintd.so") !== -1) return true
  }
  return false
}

function authorizationLabel(message, tr) {
  var t = typeof tr === "function" ? tr : function(key, english) { return english }
  var text = String(message || "")
  var match = text.match(/^Authentication is (?:needed|required) to run [`']([^`']+)[`'] as /i)
  return match ? t("polkit.authorizeRunning", "Authorize running '%1'").replace("%1", match[1]) : text
}

if (typeof module !== "undefined") {
  module.exports = {
    promptLooksFingerprint: promptLooksFingerprint,
    promptLooksPin: promptLooksPin,
    messageLooksKeyTouch: messageLooksKeyTouch,
    fingerprintConfiguredFromPamConfig: fingerprintConfiguredFromPamConfig,
    authorizationLabel: authorizationLabel
  }
}
