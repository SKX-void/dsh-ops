#![forbid(unsafe_code)]
mod batch;
pub mod contract;
mod file;
mod file_path;
mod paths;
mod results;
mod store;
use cap_std::{ambient_authority, fs::Dir};
use contract::*;
use serde_json::Value;

/// Persist a directory's entries after an atomic publish.
///
/// cap-std hands out `O_PATH` directory descriptors on Linux and `fsync` on an
/// `O_PATH` descriptor fails with `EBADF`. Reopening the same directory through
/// `/proc/self/fd` yields an ordinary descriptor, which is how cap-primitives
/// itself works around `O_PATH` handles elsewhere.
pub(crate) fn sync_directory(dir: &Dir) -> Result<()> {
    let handle = dir.try_clone()?.into_std_file();
    let first = match handle.sync_all() {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        if let Ok(reopened) = std::fs::File::open(format!("/proc/self/fd/{}", handle.as_raw_fd())) {
            return reopened.sync_all().map_err(Into::into);
        }
    }
    Err(first.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A crash-safe publish replays the barrier on the directory itself, so the
    /// barrier has to work on the handle cap-std hands out.
    #[test]
    fn directory_sync_succeeds_on_ambient_directories() {
        let root = std::env::temp_dir().join(format!("dsh-ops-sync-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).expect("create temporary directory");
        let dir = Dir::open_ambient_dir(&root, ambient_authority()).expect("open ambient directory");
        sync_directory(&dir).expect("directory sync");
        std::fs::remove_dir(&root).expect("remove temporary directory");
    }
}

pub fn dispatch(request: Request) -> Result<Value> {
    if request.scope.is_empty()
        || request.scope.len() > 256
        || !std::path::Path::new(&request.root).is_absolute()
    {
        return Err(Failure::new(
            "INVALID_ARGUMENT",
            "An absolute workspace root and a bounded scope identity are required",
        ));
    }
    let root = std::fs::canonicalize(&request.root)?;
    let mut request = Request {
        root: root
            .to_str()
            .ok_or_else(|| Failure::new("INVALID_ARGUMENT", "Non-UTF8 root"))?
            .into(),
        ..request
    };
    // File reads/searches do not create or consult the durable audit store.
    // This is important for read-only sessions and keeps observation separate
    // from mutation audit records.
    if matches!(request.tool.as_str(), "inspect_local_file" | "glob" | "grep" | "replace") {
        request.root_identity = String::new();
        return file::dispatch(&request);
    }
    let dir = Dir::open_ambient_dir(root, ambient_authority())?;
    use cap_fs_ext::MetadataExt;
    let metadata = dir.dir_metadata()?;
    request.root_identity = format!("{}:{}", metadata.dev(), metadata.ino());
    if request.read_only
        && !(request.tool == "result"
            && request.args.get("action").and_then(Value::as_str) == Some("page"))
    {
        return Err(Failure::new(
            "POLICY_DENIED",
            "Read-only requests cannot mutate audit or result storage",
        ));
    }
    let store = store::Store::open(&dir, request.read_only)?;
    match request.tool.as_str() {
        "batch" => batch::run(&dir, &store, &request),
        "result" => results::run(&store, &request),
        _ => Err(Failure::new("INVALID_ARGUMENT", "Unknown capability")),
    }
}
