//! Security keys that are plugged in, through libfido2's `fido2-token`.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;

use crate::cmd::Runner;

pub const FIDO2_TOKEN: &str = "/usr/bin/fido2-token";
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Token {
    /// `/dev/hidrawN`.
    pub device: String,
    pub usb_id: String,
    pub label: String,
}

/// What a key reports about itself. Reading it needs no touch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TokenInfo {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub transports: Vec<String>,
    /// CTAP options: `true` when set, `false` when reported as `no<name>`.
    pub options: BTreeMap<String, bool>,
    pub pin_retries: Option<u32>,
}

impl TokenInfo {
    pub fn fido2(&self) -> bool {
        self.versions.iter().any(|v| v.starts_with("FIDO_2"))
    }

    /// The key has a PIN set.
    pub fn pin_set(&self) -> bool {
        self.options.get("clientPin") == Some(&true)
    }

    /// The key can verify its owner on its own (a PIN can be set, or it has a sensor).
    pub fn can_verify(&self) -> bool {
        self.options.contains_key("clientPin") || self.options.contains_key("uv")
    }

    /// A sensor on the key, such as a YubiKey Bio. Not required for anything.
    pub fn has_sensor(&self) -> bool {
        self.options.contains_key("uv")
    }

    /// Needed for security-key Vault unlock.
    pub fn hmac_secret(&self) -> bool {
        self.extensions.iter().any(|e| e == "hmac-secret")
    }

    pub fn nfc(&self) -> bool {
        self.transports.iter().any(|t| t == "nfc")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum Keys {
    /// libfido2's tools aren't installed.
    NotInstalled,
    Present {
        keys: Vec<(Token, Option<TokenInfo>)>,
    },
    Error {
        message: String,
    },
}

pub fn probe(runner: &dyn Runner) -> Keys {
    let out = match runner.run(FIDO2_TOKEN, &["-L"], TIMEOUT) {
        Ok(o) => o,
        Err(crate::cmd::RunError::Missing(_)) => return Keys::NotInstalled,
        Err(e) => return Keys::Error { message: e.to_string() },
    };
    if !out.success() {
        return Keys::Error { message: out.stderr.trim().to_string() };
    }
    let keys = parse_list(&out.stdout)
        .into_iter()
        .map(|t| {
            let info =
                runner.run(FIDO2_TOKEN, &["-I", &t.device], TIMEOUT).ok().filter(|o| o.success()).map(|o| parse_info(&o.stdout));
            (t, info)
        })
        .collect();
    Keys::Present { keys }
}

/// `/dev/hidraw5: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)`
pub fn parse_list(text: &str) -> Vec<Token> {
    text.lines()
        .filter_map(|line| {
            let (device, rest) = line.split_once(": ")?;
            let hex = |key: &str| {
                let start = rest.find(key)? + key.len();
                let digits: String = rest[start..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
                u16::from_str_radix(&digits, 16).ok()
            };
            let vendor = hex("vendor=0x")?;
            let product = hex("product=0x")?;
            let label = rest.split_once('(').map(|(_, l)| l.trim_end_matches(')').trim().to_string()).unwrap_or_default();
            Some(Token { device: device.trim().into(), usb_id: format!("{vendor:04x}:{product:04x}"), label })
        })
        .collect()
}

pub fn parse_info(text: &str) -> TokenInfo {
    let mut info = TokenInfo::default();
    let list = |v: &str| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match key.trim() {
            "version strings" => info.versions = list(value),
            "extension strings" => info.extensions = list(value),
            "transport strings" => info.transports = list(value),
            "pin retries" => info.pin_retries = value.parse().ok(),
            "options" => {
                for opt in list(value) {
                    match opt.strip_prefix("no") {
                        // `noplat` and `nouv` are negations; option names never start with "no".
                        Some(name) if !name.is_empty() => info.options.insert(name.to_string(), false),
                        _ => info.options.insert(opt, true),
                    };
                }
            }
            _ => {}
        }
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::{FakeRunner, Output};

    const YUBIKEY_5: &str = "proto: 0x02
major: 0x05
minor: 0x07
build: 0x01
caps: 0x05 (wink, cbor, msg)
version strings: U2F_V2, FIDO_2_0, FIDO_2_1_PRE, FIDO_2_1
extension strings: credProtect, hmac-secret, largeBlobKey, credBlob, minPinLength
transport strings: nfc, usb
algorithms: es256 (public-key), eddsa (public-key), es384 (public-key)
aaguid: a25342c0-3cdc-4414-8e46-f4807fca511c
options: rk, up, noplat, alwaysUv, credMgmt, authnrCfg, clientPin, largeBlobs, pinUvAuthToken, setMinPINLength, makeCredUvNotRqd, credentialMgmtPreview
fwversion: 0x50701
maxmsgsiz: 1280
pin protocols: 2, 1
pin retries: 8
pin change required: false
uv retries: undefined
";

    #[test]
    fn lists_keys() {
        let list = "/dev/hidraw5: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)\n/dev/hidraw9: vendor=0x1ea8, product=0xfc25 (Nitrokey 3)\n";
        let keys = parse_list(list);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].device, "/dev/hidraw5");
        assert_eq!(keys[0].usb_id, "1050:0407");
        assert_eq!(keys[0].label, "Yubico YubiKey OTP+FIDO+CCID");
        assert_eq!(keys[1].usb_id, "1ea8:fc25");
    }

    #[test]
    fn reads_capabilities() {
        let info = parse_info(YUBIKEY_5);
        assert!(info.fido2());
        assert!(info.pin_set());
        assert!(info.can_verify());
        assert!(!info.has_sensor());
        assert!(info.hmac_secret());
        assert!(info.nfc());
        assert_eq!(info.options.get("plat"), Some(&false));
        assert_eq!(info.pin_retries, Some(8));

        let no_pin = parse_info("version strings: U2F_V2, FIDO_2_0\noptions: rk, up, noplat, noclientPin\n");
        assert!(!no_pin.pin_set());
        assert!(no_pin.can_verify());
        let u2f_only = parse_info("version strings: U2F_V2\n");
        assert!(!u2f_only.fido2());
        assert!(!u2f_only.can_verify());
    }

    #[test]
    fn probe_without_tools_or_keys() {
        assert_eq!(probe(&FakeRunner::new()), Keys::NotInstalled);
        let none = FakeRunner::new().reply("/usr/bin/fido2-token -L", Output::ok(""));
        assert_eq!(probe(&none), Keys::Present { keys: vec![] });
    }

    #[test]
    fn a_key_removed_between_list_and_info_has_no_info() {
        let r = FakeRunner::new()
            .reply("/usr/bin/fido2-token -L", Output::ok("/dev/hidraw5: vendor=0x1050, product=0x0407 (YubiKey)\n"))
            .reply("/usr/bin/fido2-token -I /dev/hidraw5", Output::failed(1, "fido_dev_open /dev/hidraw5: FIDO_ERR_RX"));
        let Keys::Present { keys } = probe(&r) else { panic!() };
        assert_eq!(keys.len(), 1);
        assert!(keys[0].1.is_none());
    }
}
