//! Cameras, from sysfs and the formats each node offers.
//!
//! Listing formats opens the node but never starts a stream, so the camera light stays off.

use std::fs;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use nyx_auth_core::Camera;
use serde::Serialize;

/// One capture node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CameraNode {
    /// `/dev/videoN`.
    pub device: PathBuf,
    pub name: String,
    /// USB `vendor:product`, when the camera is on USB.
    pub usb_id: Option<String>,
    /// Four-character pixel formats, such as `MJPG` or `GREY`.
    pub formats: Vec<String>,
    pub kind: Camera,
}

/// Formats an infrared sensor delivers: single-channel greyscale.
const IR_FORMATS: &[&str] = &["GREY", "Y10 ", "Y12 ", "Y16 ", "Y8I ", "Y10B"];

/// Infrared when every format is greyscale; colour when any isn't. `None` for nodes with
/// no capture formats (UVC metadata nodes).
pub fn classify(formats: &[String]) -> Option<Camera> {
    if formats.is_empty() {
        return None;
    }
    if formats.iter().all(|f| IR_FORMATS.contains(&f.as_str())) { Some(Camera::Infrared) } else { Some(Camera::Rgb) }
}

/// Lists capture nodes under `sysfs` (normally `/sys`), reading formats with `formats`.
pub fn discover_with(sysfs: &Path, dev: &Path, formats: impl Fn(&Path) -> Vec<String>) -> Vec<CameraNode> {
    let Ok(entries) = fs::read_dir(sysfs.join("class/video4linux")) else { return Vec::new() };
    let mut nodes: Vec<CameraNode> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let id = e.file_name().to_string_lossy().into_owned();
            if !id.starts_with("video") {
                return None;
            }
            let base = e.path();
            let name = fs::read_to_string(base.join("name")).unwrap_or_default().trim().to_string();
            let device = dev.join(&id);
            let fmts = formats(&device);
            let kind = classify(&fmts)?;
            Some(CameraNode { device, name, usb_id: usb_id(&base), formats: fmts, kind })
        })
        .collect();
    nodes.sort_by_key(|n| index(&n.device));
    nodes
}

pub fn discover() -> Vec<CameraNode> {
    discover_with(Path::new("/sys"), Path::new("/dev"), formats)
}

fn index(device: &Path) -> u32 {
    device
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("video"))
        .and_then(|n| n.parse().ok())
        .unwrap_or(u32::MAX)
}

/// The USB interface's parent device holds `idVendor` and `idProduct`.
fn usb_id(node: &Path) -> Option<String> {
    let mut dir = fs::canonicalize(node.join("device")).ok()?;
    for _ in 0..4 {
        let vendor = fs::read_to_string(dir.join("idVendor"));
        let product = fs::read_to_string(dir.join("idProduct"));
        if let (Ok(v), Ok(p)) = (vendor, product) {
            return Some(format!("{}:{}", v.trim(), p.trim()));
        }
        dir = dir.parent()?.to_path_buf();
    }
    None
}

const V4L2_BUF_TYPE_VIDEO_CAPTURE: u32 = 1;

#[repr(C)]
struct FmtDesc {
    index: u32,
    kind: u32,
    flags: u32,
    description: [u8; 32],
    pixelformat: u32,
    mbus_code: u32,
    reserved: [u32; 3],
}

/// `_IOWR('V', 2, struct v4l2_fmtdesc)`.
const VIDIOC_ENUM_FMT: libc::c_ulong = 0xC040_5602;

/// The capture formats a node offers. Empty when it can't be opened or offers none.
pub fn formats(device: &Path) -> Vec<String> {
    let Ok(file) = fs::OpenOptions::new().read(true).custom_flags_nonblock().open(device) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for index in 0..32 {
        let mut desc = FmtDesc {
            index,
            kind: V4L2_BUF_TYPE_VIDEO_CAPTURE,
            flags: 0,
            description: [0; 32],
            pixelformat: 0,
            mbus_code: 0,
            reserved: [0; 3],
        };
        // SAFETY: VIDIOC_ENUM_FMT reads and writes exactly one v4l2_fmtdesc, which FmtDesc
        // mirrors (64 bytes, C layout), and the descriptor stays open for the call.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), VIDIOC_ENUM_FMT as _, &mut desc as *mut FmtDesc) };
        if rc != 0 {
            break;
        }
        out.push(fourcc(desc.pixelformat));
    }
    out
}

fn fourcc(v: u32) -> String {
    v.to_le_bytes().iter().map(|b| if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '?' }).collect()
}

trait NonBlock {
    fn custom_flags_nonblock(&mut self) -> &mut Self;
}

impl NonBlock for fs::OpenOptions {
    fn custom_flags_nonblock(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmts(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn fmtdesc_matches_the_kernel_layout() {
        assert_eq!(std::mem::size_of::<FmtDesc>(), 64);
        assert_eq!(fourcc(u32::from_le_bytes(*b"GREY")), "GREY");
    }

    #[test]
    fn classify_by_formats() {
        assert_eq!(classify(&fmts(&["GREY"])), Some(Camera::Infrared));
        assert_eq!(classify(&fmts(&["MJPG", "YUYV"])), Some(Camera::Rgb));
        assert_eq!(classify(&fmts(&["GREY", "YUYV"])), Some(Camera::Rgb));
        assert_eq!(classify(&[]), None);
    }

    /// The G16's camera: an RGB node and an IR node, each with a metadata node.
    #[test]
    fn discovers_the_g16_layout() {
        let root = tempfile::tempdir().unwrap();
        let sys = root.path().join("sys");
        let usb = sys.join("devices/usb3/3-7");
        for (i, name) in [
            (0, "USB2.0 FHD UVC WebCam: USB2.0 F"),
            (1, "USB2.0 FHD UVC WebCam: USB2.0 F"),
            (2, "USB2.0 FHD UVC WebCam: USB2.0 I"),
            (3, "USB2.0 FHD UVC WebCam: USB2.0 I"),
        ] {
            let intf = usb.join(format!("3-7:1.{i}"));
            fs::create_dir_all(&intf).unwrap();
            let node = sys.join(format!("class/video4linux/video{i}"));
            fs::create_dir_all(&node).unwrap();
            fs::write(node.join("name"), format!("{name}\n")).unwrap();
            std::os::unix::fs::symlink(&intf, node.join("device")).unwrap();
        }
        fs::write(usb.join("idVendor"), "3277\n").unwrap();
        fs::write(usb.join("idProduct"), "0060\n").unwrap();

        let nodes = discover_with(&sys, Path::new("/dev"), |d| match d.to_str().unwrap() {
            "/dev/video0" => fmts(&["MJPG", "YUYV"]),
            "/dev/video2" => fmts(&["GREY"]),
            _ => Vec::new(),
        });
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].device, Path::new("/dev/video0"));
        assert_eq!(nodes[0].kind, Camera::Rgb);
        assert_eq!(nodes[1].device, Path::new("/dev/video2"));
        assert_eq!(nodes[1].kind, Camera::Infrared);
        assert_eq!(nodes[1].usb_id.as_deref(), Some("3277:0060"));
    }

    #[test]
    fn no_video4linux_means_no_cameras() {
        let root = tempfile::tempdir().unwrap();
        assert!(discover_with(root.path(), Path::new("/dev"), |_| Vec::new()).is_empty());
    }
}
