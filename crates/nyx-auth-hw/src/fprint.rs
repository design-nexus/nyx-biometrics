//! Fingerprint readers, through fprintd on the system bus and libfprint's device list.

use std::fs;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::cmd::Runner;

pub const BUSCTL: &str = "/usr/bin/busctl";
const SERVICE: &str = "net.reactivated.Fprint";
const MANAGER: &str = "/net/reactivated/Fprint/Manager";
const TIMEOUT: Duration = Duration::from_secs(5);

/// libfprint's list of the USB readers it drives, and of known readers it doesn't.
pub const LIBFPRINT_HWDB: &str = "/usr/lib/udev/hwdb.d/60-autosuspend-fingerprint-reader.hwdb";

/// Vendors that only make fingerprint readers, for when libfprint isn't installed yet.
const READER_VENDORS: &[&str] = &["27c6", "138a", "06cb", "08ff", "1c7a", "147e", "10a5", "2808", "298d", "04f3"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reader {
    pub path: String,
    pub name: String,
    /// `press` or `swipe`.
    pub scan_type: String,
    /// fprintd's finger names, such as `right-index-finger`.
    pub enrolled: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum Fprint {
    /// fprintd isn't installed or can't be started.
    NotInstalled,
    /// fprintd runs but sees no reader.
    NoReader,
    Ready {
        readers: Vec<Reader>,
    },
    Error {
        message: String,
    },
}

impl Fprint {
    pub fn enrolled(&self) -> bool {
        matches!(self, Fprint::Ready { readers } if readers.iter().any(|r| !r.enrolled.is_empty()))
    }
}

/// What libfprint says about a USB device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Support {
    Supported,
    KnownUnsupported,
    /// libfprint isn't installed, so this is a guess from the vendor.
    Unconfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsbReader {
    pub usb_id: String,
    pub product: String,
    pub support: Support,
}

pub fn probe(runner: &dyn Runner, user: &str) -> Fprint {
    let devices = match call(runner, &["call", SERVICE, MANAGER, "net.reactivated.Fprint.Manager", "GetDevices"]) {
        Ok(v) => v,
        Err(e) if not_installed(&e) => return Fprint::NotInstalled,
        Err(e) => return Fprint::Error { message: e },
    };
    let paths: Vec<String> = devices
        .pointer("/data/0")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|p| p.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if paths.is_empty() {
        return Fprint::NoReader;
    }
    let readers = paths
        .into_iter()
        .map(|path| {
            let prop = |name: &str| {
                call(runner, &["get-property", SERVICE, &path, "net.reactivated.Fprint.Device", name])
                    .ok()
                    .and_then(|v| v.get("data").and_then(Value::as_str).map(String::from))
                    .unwrap_or_default()
            };
            let enrolled = match call(
                runner,
                &["call", SERVICE, &path, "net.reactivated.Fprint.Device", "ListEnrolledFingers", "s", user],
            ) {
                Ok(v) => v
                    .pointer("/data/0")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|f| f.as_str().map(String::from)).collect())
                    .unwrap_or_default(),
                Err(_) => Vec::new(),
            };
            Reader { name: prop("name"), scan_type: prop("scan-type"), path, enrolled }
        })
        .collect();
    Fprint::Ready { readers }
}

fn call(runner: &dyn Runner, args: &[&str]) -> Result<Value, String> {
    let mut full = vec!["--system", "--json=short"];
    full.extend_from_slice(args);
    let out = runner.run(BUSCTL, &full, TIMEOUT).map_err(|e| e.to_string())?;
    if !out.success() {
        return Err(out.stderr.trim().to_string());
    }
    serde_json::from_str(out.stdout.trim()).map_err(|e| e.to_string())
}

fn not_installed(err: &str) -> bool {
    ["ServiceUnknown", "not activatable", "was not provided by any .service files", "not found"].iter().any(|s| err.contains(s))
}

/// USB readers that are plugged in, judged against libfprint's list when it's installed.
pub fn usb_readers(sysfs: &Path, hwdb: Option<&str>) -> Vec<UsbReader> {
    let table = hwdb.map(parse_hwdb);
    let Ok(entries) = fs::read_dir(sysfs.join("bus/usb/devices")) else { return Vec::new() };
    let mut out: Vec<UsbReader> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let dir = e.path();
            let vendor = fs::read_to_string(dir.join("idVendor")).ok()?.trim().to_lowercase();
            let product_id = fs::read_to_string(dir.join("idProduct")).ok()?.trim().to_lowercase();
            let product = fs::read_to_string(dir.join("product")).unwrap_or_default().trim().to_string();
            let usb_id = format!("{vendor}:{product_id}");
            let support = match &table {
                Some((supported, unsupported)) if supported.contains(&usb_id) => Support::Supported,
                Some((_, unsupported)) if unsupported.contains(&usb_id) => Support::KnownUnsupported,
                Some(_) => return None,
                None if READER_VENDORS.contains(&vendor.as_str()) || product.to_lowercase().contains("fingerprint") => {
                    Support::Unconfirmed
                }
                None => return None,
            };
            Some(UsbReader { usb_id, product, support })
        })
        .collect();
    out.sort_by(|a, b| a.usb_id.cmp(&b.usb_id));
    out.dedup_by(|a, b| a.usb_id == b.usb_id);
    out
}

/// `usb:v27C6p5110*` lines, split at libfprint's "Known unsupported devices" comment.
fn parse_hwdb(text: &str) -> (Vec<String>, Vec<String>) {
    let mut supported = Vec::new();
    let mut unsupported = Vec::new();
    let mut in_unsupported = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') && line.to_lowercase().contains("unsupported") {
            in_unsupported = true;
            continue;
        }
        let Some(rest) = line.strip_prefix("usb:v") else { continue };
        let Some((v, p)) = rest.split_once('p') else { continue };
        let id = format!("{}:{}", v.to_lowercase(), p.trim_end_matches('*').to_lowercase());
        if in_unsupported { unsupported.push(id) } else { supported.push(id) }
    }
    (supported, unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::{FakeRunner, Output};

    const GET_DEVICES: &str = "/usr/bin/busctl --system --json=short call net.reactivated.Fprint /net/reactivated/Fprint/Manager net.reactivated.Fprint.Manager GetDevices";
    const DEV: &str = "/net/reactivated/Fprint/Device/0";

    fn dev_cmd(rest: &str) -> String {
        format!("/usr/bin/busctl --system --json=short {rest}")
    }

    #[test]
    fn not_installed_when_the_service_is_unknown() {
        let r = FakeRunner::new().reply(
            GET_DEVICES,
            Output::failed(1, "Call failed: The name net.reactivated.Fprint was not provided by any .service files"),
        );
        assert_eq!(probe(&r, "ken"), Fprint::NotInstalled);
        assert_eq!(probe(&FakeRunner::new(), "ken"), Fprint::Error { message: "/usr/bin/busctl isn't installed".into() });
    }

    #[test]
    fn no_reader() {
        let r = FakeRunner::new().reply(GET_DEVICES, Output::ok(r#"{"type":"ao","data":[[]]}"#));
        assert_eq!(probe(&r, "ken"), Fprint::NoReader);
    }

    #[test]
    fn reader_with_and_without_fingers() {
        let base = FakeRunner::new()
            .reply(GET_DEVICES, Output::ok(&format!(r#"{{"type":"ao","data":[["{DEV}"]]}}"#)))
            .reply(
                &dev_cmd(&format!("get-property net.reactivated.Fprint {DEV} net.reactivated.Fprint.Device name")),
                Output::ok(r#"{"type":"s","data":"Goodix MOC Fingerprint Sensor"}"#),
            )
            .reply(
                &dev_cmd(&format!("get-property net.reactivated.Fprint {DEV} net.reactivated.Fprint.Device scan-type")),
                Output::ok(r#"{"type":"s","data":"press"}"#),
            );
        let list = dev_cmd(&format!("call net.reactivated.Fprint {DEV} net.reactivated.Fprint.Device ListEnrolledFingers s ken"));

        let none = base.reply(&list, Output::failed(1, "Call failed: net.reactivated.Fprint.Error.NoEnrolledPrints"));
        let state = probe(&none, "ken");
        assert!(!state.enrolled());
        let Fprint::Ready { readers } = state else { panic!() };
        assert_eq!(readers[0].name, "Goodix MOC Fingerprint Sensor");
        assert_eq!(readers[0].scan_type, "press");

        let some = FakeRunner::new()
            .reply(GET_DEVICES, Output::ok(&format!(r#"{{"type":"ao","data":[["{DEV}"]]}}"#)))
            .reply(&list, Output::ok(r#"{"type":"as","data":[["right-index-finger","left-index-finger"]]}"#));
        let state = probe(&some, "ken");
        assert!(state.enrolled());
        let Fprint::Ready { readers } = state else { panic!() };
        assert_eq!(readers[0].enrolled, vec!["right-index-finger", "left-index-finger"]);
    }

    #[test]
    fn usb_readers_against_libfprint() {
        let root = tempfile::tempdir().unwrap();
        let devs = root.path().join("bus/usb/devices");
        for (name, v, p, product) in [
            ("1-1", "27c6", "5110", "Goodix"),
            ("1-2", "0b05", "19b6", "ITE Device"),
            ("1-3", "06cb", "00bd", "Synaptics"),
            ("1-4", "1c7a", "0570", "EgisTec"),
        ] {
            let d = devs.join(name);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("idVendor"), v).unwrap();
            fs::write(d.join("idProduct"), p).unwrap();
            fs::write(d.join("product"), product).unwrap();
        }
        let hwdb = "# Supported by libfprint driver goodixmoc\nusb:v27C6p5110*\n ID_AUTOSUSPEND=1\n\n# Known unsupported devices\nusb:v06CBp00BD*\n";
        let found = usb_readers(root.path(), Some(hwdb));
        assert_eq!(
            found,
            vec![
                UsbReader { usb_id: "06cb:00bd".into(), product: "Synaptics".into(), support: Support::KnownUnsupported },
                UsbReader { usb_id: "27c6:5110".into(), product: "Goodix".into(), support: Support::Supported },
            ]
        );
        // Without libfprint, reader vendors are a guess and other devices are ignored.
        let guessed = usb_readers(root.path(), None);
        assert_eq!(guessed.len(), 3);
        assert!(guessed.iter().all(|r| r.support == Support::Unconfirmed));
    }
}
