use crate::{api, validation};
use std::{fs::File, io::Write as _, path::PathBuf};

#[cfg(target_os = "linux")]
use std::{ffi::OsString, os::fd::AsRawFd as _, path::Path};

pub const HELP: &str = "Usage: asterctl (--token TOKEN | --token-file PATH) [OPTIONS] blob-read
                --id ID --topic TOPIC --scope SCOPE --output PATH

Read an authenticated Blob to a new local file without overwriting an existing path.
Requires Linux and destination-filesystem support for anonymous temporary files and descriptor linking.

OPTIONS:
      --id ID          Blob ID as Base64-encoded 32 bytes (required)
      --topic TOPIC    Exact Blob topic (required)
      --scope SCOPE    Exact Blob scope (required)
      --output PATH    New destination path (required)
      --help           Show this help

See asterctl --help for global options.
Blob bytes are written only to --output; stdout contains metadata only.
";

/// Stable native gRPC Blob response-page size owned by the CLI protocol layer.
pub(crate) const RPC_PAGE_BYTES: usize = 64 * 1024;
const MAX_PAGE_BYTES: usize = RPC_PAGE_BYTES;
const MAX_MEDIA_TYPE_BYTES: usize = 255;
const MAX_SCHEMA_ID_BYTES: usize = 1024;

#[derive(Debug, PartialEq, Default)]
pub struct Read {
    id: Vec<u8>,
    topic: String,
    scope: String,
    output: Option<PathBuf>,
}

impl Read {
    pub fn set_output(&mut self, path: PathBuf) -> Result<(), &'static str> {
        if path.as_os_str().is_empty() {
            return Err("output path must not be empty");
        }
        self.output = Some(path);
        Ok(())
    }

    pub fn set_option(&mut self, name: &str, value: String) -> Result<(), &'static str> {
        match name {
            "--id" => {
                self.id = validation::identity(&value)
                    .ok_or("Blob ID must be a Base64-encoded 32-byte ID")?;
            }
            "--topic" => {
                validation::topic(&value)?;
                self.topic = value;
            }
            "--scope" => {
                validation::scope(&value)?;
                self.scope = value;
            }
            _ => unreachable!("Blob read option"),
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.is_empty() {
            return Err("--id is required; see blob-read --help");
        }
        if self.topic.is_empty() {
            return Err("--topic is required; see blob-read --help");
        }
        if self.scope.is_empty() {
            return Err("--scope is required; see blob-read --help");
        }
        if self.output.is_none() {
            return Err("--output is required; see blob-read --help");
        }
        Ok(())
    }

    pub fn into_parts(self) -> (api::ReadBlobRequest, PathBuf) {
        (
            api::ReadBlobRequest {
                id: self.id,
                topic: self.topic,
                scope: self.scope,
                ..Default::default()
            },
            self.output.expect("validated output path"),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub id: Vec<u8>,
    pub publisher: Vec<u8>,
    pub publisher_counter: u64,
    pub topic: String,
    pub scope: String,
    pub priority: buffa::EnumValue<api::Priority>,
    pub ttl_ms: Option<u64>,
    pub total_len: u64,
    pub media_type: Option<String>,
    pub schema_id: Vec<u8>,
    pub acceptance_marker: u64,
}

impl Metadata {
    fn from_page(page: &api::ReadBlobResponse) -> Self {
        Self {
            id: page.id.clone(),
            publisher: page.publisher.clone(),
            publisher_counter: page.publisher_counter,
            topic: page.topic.clone(),
            scope: page.scope.clone(),
            priority: page.priority,
            ttl_ms: page.ttl_ms,
            total_len: page.total_len,
            media_type: page.media_type.clone(),
            schema_id: page.schema_id.clone(),
            acceptance_marker: page.acceptance_marker,
        }
    }
}

pub(crate) struct Validator {
    request: api::ReadBlobRequest,
    metadata: Option<Metadata>,
    next_offset: u64,
    complete: bool,
}

impl Validator {
    pub fn new(request: api::ReadBlobRequest) -> Self {
        Self {
            request,
            metadata: None,
            next_offset: 0,
            complete: false,
        }
    }

    pub fn accept(&mut self, page: &api::ReadBlobResponse) -> Result<(), &'static str> {
        if self.complete {
            return Err("ReadBlob failed: page received after completion");
        }
        let observed = Metadata::from_page(page);
        if observed.id != self.request.id
            || observed.topic != self.request.topic
            || observed.scope != self.request.scope
            || observed.id.len() != 32
            || observed.publisher.len() != 32
            || observed.publisher_counter == 0
            || observed.ttl_ms == Some(0)
            || observed
                .priority
                .as_known()
                .is_none_or(|priority| priority == api::Priority::Unspecified)
            || observed.total_len == 0
            || observed
                .media_type
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_MEDIA_TYPE_BYTES)
            || observed.schema_id.len() > MAX_SCHEMA_ID_BYTES
            || observed.acceptance_marker == 0
        {
            return Err("ReadBlob failed: invalid or unexpected Blob metadata");
        }
        if self
            .metadata
            .as_ref()
            .is_some_and(|expected| expected != &observed)
        {
            return Err("ReadBlob failed: Blob metadata changed between pages");
        }
        if page.offset != self.next_offset {
            return Err("ReadBlob failed: noncontiguous page offset");
        }
        if page.chunk.is_empty() || page.chunk.len() > MAX_PAGE_BYTES {
            return Err("ReadBlob failed: invalid page length");
        }
        let page_len =
            u64::try_from(page.chunk.len()).map_err(|_| "ReadBlob failed: page length overflow")?;
        let next = page
            .offset
            .checked_add(page_len)
            .ok_or("ReadBlob failed: page offset overflow")?;
        if next > observed.total_len || page.complete != (next == observed.total_len) {
            return Err("ReadBlob failed: invalid completion or total length");
        }
        if self.metadata.is_none() {
            self.metadata = Some(observed);
        }
        self.next_offset = next;
        self.complete = page.complete;
        Ok(())
    }

    pub fn finish(self) -> Result<Metadata, &'static str> {
        let metadata = self
            .metadata
            .ok_or("ReadBlob failed: stream ended without a page")?;
        if !self.complete || self.next_offset != metadata.total_len {
            return Err("ReadBlob failed: stream ended before complete Blob length");
        }
        Ok(metadata)
    }
}

pub(crate) struct OutputFile {
    #[cfg(target_os = "linux")]
    directory: File,
    #[cfg(target_os = "linux")]
    destination_name: OsString,
    file: File,
}

impl OutputFile {
    #[cfg(target_os = "linux")]
    pub fn create(path: PathBuf) -> Result<Self, &'static str> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        let parent = parent.unwrap_or_else(|| Path::new("."));
        let destination_name = path
            .file_name()
            .ok_or("output path must name a file")?
            .to_owned();
        let directory = rustix::fs::openat(
            rustix::fs::CWD,
            parent,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| "cannot open output directory")?;
        match rustix::fs::statat(
            &directory,
            &destination_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => return Err("output path already exists"),
            Err(rustix::io::Errno::NOENT) => {}
            Err(_) => return Err("cannot inspect output path"),
        }
        let anonymous = rustix::fs::openat(
            &directory,
            ".",
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::TMPFILE,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(|_| "blob-read output is unsupported by the destination filesystem")?;
        Ok(Self {
            directory,
            destination_name,
            file: File::from(anonymous),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create(_path: PathBuf) -> Result<Self, &'static str> {
        Err("blob-read output is unsupported on this platform")
    }

    pub fn write_page(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        self.file
            .write_all(bytes)
            .map_err(|_| "cannot write output file")
    }

    pub fn finish(&mut self) -> Result<(), &'static str> {
        self.file
            .sync_all()
            .map_err(|_| "cannot finish output file")?;
        #[cfg(target_os = "linux")]
        return publish_open_file(&self.file, &self.directory, &self.destination_name);
        #[cfg(not(target_os = "linux"))]
        Err("blob-read output is unsupported on this platform")
    }
}

#[cfg(target_os = "linux")]
fn publish_open_file(
    file: &File,
    directory: &File,
    destination_name: &OsString,
) -> Result<(), &'static str> {
    let direct = rustix::fs::linkat(
        file,
        "",
        directory,
        destination_name,
        rustix::fs::AtFlags::EMPTY_PATH,
    );
    match direct {
        Ok(()) => return Ok(()),
        Err(rustix::io::Errno::EXIST) => return Err("output path already exists"),
        Err(_) => {}
    }

    let descriptor_path = format!("/proc/self/fd/{}", file.as_raw_fd());
    match rustix::fs::linkat(
        rustix::fs::CWD,
        descriptor_path,
        directory,
        destination_name,
        rustix::fs::AtFlags::SYMLINK_FOLLOW,
    ) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::EXIST) => Err("output path already exists"),
        Err(_) => Err("blob-read output publication is unsupported by the destination filesystem"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::fs::{self, OpenOptions};

    #[cfg(target_os = "linux")]
    fn output_around(file: File) -> OutputFile {
        OutputFile {
            directory: File::open(std::env::temp_dir()).unwrap(),
            destination_name: OsString::from("unused"),
            file,
        }
    }

    fn request() -> api::ReadBlobRequest {
        api::ReadBlobRequest {
            id: vec![1; 32],
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            ..Default::default()
        }
    }

    fn page(offset: u64, chunk: Vec<u8>, complete: bool) -> api::ReadBlobResponse {
        api::ReadBlobResponse {
            id: vec![1; 32],
            publisher: vec![2; 32],
            publisher_counter: 3,
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            priority: api::Priority::Immediate.into(),
            ttl_ms: Some(u64::MAX),
            total_len: 65_537,
            media_type: Some("application/octet-stream".into()),
            schema_id: b"schema".to_vec(),
            acceptance_marker: 4,
            offset,
            chunk,
            complete,
            ..Default::default()
        }
    }

    #[test]
    fn blob_read_requires_contiguous_bounded_pages_and_exact_completion() {
        let mut validator = Validator::new(request());
        validator
            .accept(&page(0, vec![7; MAX_PAGE_BYTES], false))
            .unwrap();
        assert!(validator.accept(&page(65_535, vec![8], true)).is_err());

        let mut validator = Validator::new(request());
        validator
            .accept(&page(0, vec![7; MAX_PAGE_BYTES], false))
            .unwrap();
        validator.accept(&page(65_536, vec![8], true)).unwrap();
        assert_eq!(validator.finish().unwrap().ttl_ms, Some(u64::MAX));
    }

    #[test]
    fn blob_read_rejects_metadata_or_ttl_changes_on_later_pages() {
        let mut validator = Validator::new(request());
        validator
            .accept(&page(0, vec![7; MAX_PAGE_BYTES], false))
            .unwrap();
        let mut changed = page(65_536, vec![8], true);
        changed.ttl_ms = None;
        assert!(validator.accept(&changed).is_err());

        let mut invalid = page(0, vec![7], false);
        invalid.publisher_counter = 0;
        assert!(Validator::new(request()).accept(&invalid).is_err());
        invalid.publisher_counter = 3;
        invalid.acceptance_marker = 0;
        assert!(Validator::new(request()).accept(&invalid).is_err());
        invalid.acceptance_marker = 4;
        invalid.ttl_ms = Some(0);
        assert!(Validator::new(request()).accept(&invalid).is_err());
    }

    #[test]
    fn blob_read_rejects_early_end_and_pages_after_completion() {
        let mut early = Validator::new(request());
        early
            .accept(&page(0, vec![7; MAX_PAGE_BYTES], false))
            .unwrap();
        assert!(early.finish().is_err());

        let mut complete = Validator::new(request());
        let mut one = page(0, vec![7], true);
        one.total_len = 1;
        complete.accept(&one).unwrap();
        assert!(complete.accept(&one).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn blob_read_removes_partial_output_unless_finish_succeeds() {
        let path =
            std::env::temp_dir().join(format!("asterctl-blob-partial-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        {
            let mut output = OutputFile::create(path.clone()).unwrap();
            output.write_page(b"partial plaintext").unwrap();
        }
        assert!(!path.exists());
        {
            let mut output = OutputFile::create(path.clone()).unwrap();
            output.write_page(b"complete plaintext").unwrap();
            output.finish().unwrap();
        }
        assert_eq!(fs::read(&path).unwrap(), b"complete plaintext");
        fs::remove_file(path).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn blob_read_finalization_never_replaces_a_destination_created_during_transfer() {
        let path = std::env::temp_dir().join(format!(
            "asterctl-blob-finalize-race-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        let mut output = OutputFile::create(path.clone()).unwrap();
        output.write_page(b"downloaded bytes").unwrap();
        fs::write(&path, b"unrelated replacement").unwrap();

        assert_eq!(output.finish(), Err("output path already exists"));
        drop(output);
        assert_eq!(fs::read(&path).unwrap(), b"unrelated replacement");

        fs::remove_file(path).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn blob_read_publishes_the_exact_open_inode_not_a_named_replacement() {
        let directory =
            std::env::temp_dir().join(format!("asterctl-blob-open-inode-{}", std::process::id()));
        let path = directory.join("destination");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();

        let mut output = OutputFile::create(path.clone()).unwrap();
        output.write_page(b"downloaded bytes").unwrap();
        use std::os::unix::fs::MetadataExt as _;
        let open_inode = (
            output.file.metadata().unwrap().dev(),
            output.file.metadata().unwrap().ino(),
        );

        assert_eq!(output.finish(), Ok(()));
        assert_eq!(fs::read(&path).unwrap(), b"downloaded bytes");
        let linked = fs::metadata(&path).unwrap();
        assert_eq!(open_inode, (linked.dev(), linked.ino()));

        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn blob_read_never_creates_a_named_partial_file() {
        let directory = std::env::temp_dir().join(format!(
            "asterctl-blob-anonymous-output-{}",
            std::process::id()
        ));
        let path = directory.join("destination");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();

        let mut output = OutputFile::create(path.clone()).unwrap();
        output.write_page(b"partial plaintext").unwrap();
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        drop(output);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);

        fs::remove_dir(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn blob_read_fails_closed_when_the_filesystem_lacks_anonymous_temporaries() {
        let path = PathBuf::from(format!(
            "/proc/asterctl-blob-unsupported-{}",
            std::process::id()
        ));
        assert_eq!(
            OutputFile::create(path).err(),
            Some("blob-read output is unsupported by the destination filesystem")
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn blob_read_fails_closed_on_unsupported_platforms() {
        let path = std::env::temp_dir().join("asterctl-blob-unsupported-platform");
        assert_eq!(
            OutputFile::create(path).err(),
            Some("blob-read output is unsupported on this platform")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn blob_read_reports_real_write_and_sync_failures() {
        let full = OpenOptions::new().write(true).open("/dev/full").unwrap();
        let mut output = output_around(full);
        assert_eq!(
            output.write_page(b"plaintext"),
            Err("cannot write output file")
        );

        let null = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let mut output = output_around(null);
        output.write_page(b"plaintext").unwrap();
        assert_eq!(output.finish(), Err("cannot finish output file"));
    }
}
