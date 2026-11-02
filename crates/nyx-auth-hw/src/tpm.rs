use std::path::Path;

/// A TPM 2.0 behind the kernel's resource manager, which keyd and the face backends use.
pub fn present(dev: &Path) -> bool {
    dev.join("tpmrm0").exists()
}
