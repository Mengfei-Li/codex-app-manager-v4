use std::io;
use std::path::Path;

#[cfg(windows)]
use std::thread;
#[cfg(windows)]
use std::time::Duration;

#[cfg(not(windows))]
use std::fs;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

/// Replaces `target` with the already-flushed file at `source` without a
/// remove-then-rename gap. Both paths must be on the same volume.
pub(crate) fn replace_file(source: &Path, target: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };

        let source = source
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let target = target
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        const MAX_ATTEMPTS: u32 = 7;
        for attempt in 0..MAX_ATTEMPTS {
            let result = unsafe {
                MoveFileExW(
                    source.as_ptr(),
                    target.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            if result != 0 {
                return Ok(());
            }

            let error = io::Error::last_os_error();
            let transient = matches!(error.raw_os_error(), Some(5 | 32 | 33));
            if !transient || attempt + 1 == MAX_ATTEMPTS {
                return Err(error);
            }
            thread::sleep(Duration::from_millis(10_u64 << attempt));
        }
        unreachable!("bounded Windows replace loop always returns")
    }

    #[cfg(unix)]
    {
        fs::rename(source, target)
    }

    #[cfg(not(any(windows, unix)))]
    {
        if target.exists() {
            fs::remove_file(target)?;
        }
        fs::rename(source, target)
    }
}
