use std::{
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
    path::Path,
};

use nix::{
    errno::Errno,
    fcntl::{self, OFlag, OpenHow, ResolveFlag},
    sys::stat::{self, Mode},
};

/// A handle to an open directory.
///
/// Directory handles create or open files and directories. A directory handle
/// only has access to child files or directories - attempting to create or open
/// a file outside of this directory is an error.
///
/// While the this API resembles a capability based filesystem API, it's used
/// here for convenience and not security. Because a verytmp tmpfs exists
/// in its own detached filesystem, there is no way to specify a path into
/// the filesystem that isn't relative to the root file descriptor! Both [Dir]
/// and [std::fs::File] do both implment [IntoRawFd] as an escape hatch for
/// advanced use, which allows a caller to escape the capability-style API.
pub struct Dir {
    // NOTE: because of the way verytmp works, there's no cleanup necessary. if
    // there was a reason to close the root fd, this could be an OwnedFd but
    // we can go absolutely hog wild and trust the kernel gc to clean up after us
    // even if we get kill -9'd.
    root: OwnedFd,
}

impl From<OwnedFd> for Dir {
    fn from(fd: OwnedFd) -> Self {
        Self { root: fd }
    }
}

#[allow(unused)]
impl Dir {
    /// Return a builder for creating or opening a child directory. See
    /// [DirOptions] for example usage.
    pub fn dir<'a>(&'a self) -> DirOptions<'a> {
        DirOptions::new_default(self)
    }

    /// Create a child directory at a subpath.
    ///
    /// To customize the directory mode on creation, use the [`Dir::dir`] method.
    /// See [`DirOptions`] for details.
    pub fn create_dir<P: AsRef<Path>>(&self, p: P) -> io::Result<()> {
        self.dir().create(p)
    }

    /// Return a builder for creating or opening a file in this directory or
    /// in one of its children.
    ///
    /// See [OpenOptions] for an example.
    pub fn file<'a>(&'a self) -> OpenOptions<'a> {
        OpenOptions::new_default(self)
    }

    /// Open a new file for writing.
    ///
    /// The file will be created if it does not exist, and will be truncated
    /// if it does.
    ///
    /// To specify creation mode or open flags, use the [Dir::file] method.
    /// See [`OpenOptions`] for details.
    pub fn create<P: AsRef<Path>>(&self, p: P) -> io::Result<File> {
        self.file().write(true).create(true).truncate(true).open(p)
    }

    /// Open a new file in read-only mode.
    ///
    /// To specify creation mode or open flags, use the [Dir::file] method.
    /// See [`OpenOptions`] for details.
    pub fn open<P: AsRef<Path>>(&self, p: P) -> io::Result<File> {
        self.file().read(true).open(p)
    }
}

#[doc(hidden)]
impl AsRawFd for Dir {
    fn as_raw_fd(&self) -> RawFd {
        self.root.as_raw_fd()
    }
}

impl IntoRawFd for Dir {
    fn into_raw_fd(self) -> RawFd {
        self.root.into_raw_fd()
    }
}

/// Options and flags for opening directories.
///
/// This is the directory-level equivalent of [OpenOptions] and should have an
/// API similar to that of [std::fs::DirBuilder] and
/// [std::os::unix::fs::DirBuilderExt].
///
/// Like [OpenOptions], the only way to obtain a [DirOptions] is through an
/// existing directory.
///
/// # Note
///
/// This crate currently doesn't implement an equivalent of
/// [`std::fs::create_dir_all`]. Sorry about that!
///
/// # Examples
///
/// Create a directory with a custom mode:
///
/// ```no_run
/// use verytmp;
///
/// let dir = verytmp::verytmp()?;
///
/// let file = dir.dir()
///     .mode(0o765)
///     .create("foo");
///
/// # Ok::<(), std::io::Error>(())
/// ```
///
#[derive(Clone)]
pub struct DirOptions<'a> {
    fs: &'a Dir,
    mode: u32,
}

impl<'a> DirOptions<'a> {
    fn new_default(fs: &'a Dir) -> Self {
        Self { fs, mode: 0o744 }
    }
}

#[allow(unused)]
impl<'a> DirOptions<'a> {
    /// Set the unix mode of a newly create directory.
    pub fn mode(&mut self, mode: u32) -> &mut Self {
        self.mode = mode;
        self
    }

    /// Create a new directory as a child of an existing directory.
    ///
    pub fn create<P: AsRef<Path>>(&mut self, p: P) -> io::Result<()> {
        let mode = Mode::from_bits_truncate(self.mode);
        stat::mkdirat(Some(self.fs.root.as_raw_fd()), p.as_ref(), mode)?;
        Ok(())
    }
}

/// Options and flags that configure how a file is opened.
///
/// `OpenOptions` is intended to mirror [std::fs::OpenOptions] as closely as
/// possible and should be API compatible where possible.
///
/// Unlike the standard library, there is no way to create a stand-alone set of
/// `OpenOptions` options - every `OpenOptions` is tied to the directory tree
/// where it's allowed to create files, and has to be obtained from the [Dir::file]
/// method.
///
/// # Examples
///
/// ```no_run
/// use verytmp;
///
/// let dir = verytmp::verytmp()?;
///
/// let file = dir.file()
///     .create_new(true)
///     .read(true)
///     .write(true)
///     .open("foo.txt");
///
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// Opening a file read only:
///
/// ```no_run
/// use verytmp;
///
/// let dir = verytmp::verytmp()?;
///
/// let file = dir.file()
///     .read(true)
///     .open("foo.txt");
///
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Clone)]
pub struct OpenOptions<'a> {
    fs: &'a Dir,
    append: bool,
    create: bool,
    create_new: bool,
    read: bool,
    truncate: bool,
    write: bool,
    flags: i32,
    mode: u32,
}

// idea and impls here are borrowed from stdlib. this is potentially not the
// way you might choose to implement this on your own, but it's the one here
// because it's consistent with stdlib and easy to check for behavior
// differences.
//
// https://github.com/rust-lang/rust/blob/1.76.0/library/std/src/sys/unix/fs.rs#L1083-L1107
impl<'a> OpenOptions<'a> {
    fn new_default(fs: &'a Dir) -> Self {
        Self {
            fs,
            append: false,
            create: false,
            create_new: false,
            read: false,
            truncate: false,
            write: false,
            flags: 0,
            mode: 0o666,
        }
    }

    fn access_flags(&self) -> io::Result<OFlag> {
        match (self.read, self.write, self.append) {
            (true, false, false) => Ok(OFlag::O_RDONLY),
            (false, true, false) => Ok(OFlag::O_WRONLY),
            (true, true, false) => Ok(OFlag::O_RDWR),
            // append implies write
            (false, _, true) => Ok(OFlag::O_WRONLY | OFlag::O_APPEND),
            (true, _, true) => Ok(OFlag::O_RDWR | OFlag::O_APPEND),
            // invalid
            (false, false, false) => Err(Errno::EINVAL.into()),
        }
    }

    fn create_flags(&self) -> io::Result<OFlag> {
        if !(self.write || self.append) && (self.truncate || self.create || self.create_new) {
            return Err(Errno::EINVAL.into());
        }
        if self.append && self.truncate && !self.create_new {
            return Err(Errno::EINVAL.into());
        }

        let oflag = match (self.create, self.truncate, self.create_new) {
            (false, false, false) => OFlag::empty(),
            (true, false, false) => OFlag::O_CREAT,
            (false, true, false) => OFlag::O_TRUNC,
            (true, true, false) => OFlag::O_CREAT | OFlag::O_TRUNC,
            // create_new ignores create and truncate
            (_, _, true) => OFlag::O_CREAT | OFlag::O_EXCL,
        };
        Ok(oflag)
    }

    fn create_mode(&self) -> Mode {
        if self.create || self.create_new {
            Mode::from_bits_truncate(self.mode)
        } else {
            Mode::empty()
        }
    }
}

#[allow(unused)]
impl<'a> OpenOptions<'a> {
    /// Sets the option for append mode.
    ///
    /// When set, the opened file will be append too instead of overwritten.
    /// Note that settings `.write(true).append(true)` has the same effect
    /// as `.append(true)`.
    pub fn append(&mut self, append: bool) -> &mut Self {
        self.append = append;
        self
    }

    /// Sets the option to create a new file if the file does not already
    /// exist. For a file to be created, `.write(true)` or `.append(true)` must
    /// be set as well.
    ///
    /// See [OpenOptions::create_new] if you'd like to only create if it does
    /// not already exist.
    pub fn create(&mut self, create: bool) -> &mut Self {
        self.create = create;
        self
    }

    /// Set the option to create a new file if and only if it doesn't already
    /// exist. The file must also be opened with `.write(true)` or
    /// `.append(true)`.
    ///
    /// Setting this option to true ignores the `create` and `truncate` options.
    ///
    /// See [OpenOptions::create_new] to create or overwrite an existing file.
    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.create_new = create_new;
        self
    }

    /// Sets the option to open a file for reading.
    pub fn read(&mut self, read: bool) -> &mut Self {
        self.read = read;
        self
    }

    /// Sets the option to truncate a file on opening.
    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.truncate = truncate;
        self
    }

    /// Sets the option to open a file writing.
    ///
    /// To truncate a file when writing, use `.truncate(true)`.
    pub fn write(&mut self, write: bool) -> &mut Self {
        self.write = write;
        self
    }

    /// Set open flags that will be directly passed to `openat2` when this file
    /// is opened.
    ///
    /// These flags are merged with any flags set by setting other options on
    /// this `OpenOptions`.
    pub fn flags(&mut self, flags: i32) -> &mut Self {
        self.flags = flags;
        self
    }

    /// Set the mode a new file will be created with.
    ///
    /// It's an error to set mode to a non-zero value if a file is not opened
    /// with `.create(true)` set or the `O_CREAT` flag passed to `flags`.
    pub fn mode(&mut self, mode: u32) -> &mut Self {
        self.mode = mode;
        self
    }

    /// Open the file at `path` with all of the currently configured options on
    /// `self`.
    ///
    /// `path` must be a path relative to the directory associated with `self`.
    pub fn open<P: AsRef<Path>>(&mut self, path: P) -> io::Result<File> {
        let fd = self.fs.root.as_raw_fd();
        let path = path.as_ref();
        let how = OpenHow::new()
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_MAGICLINKS)
            .mode(self.create_mode())
            .flags(OFlag::O_CLOEXEC | self.access_flags()? | self.create_flags()?);

        dbg! { (fd, path, how) };

        let fd = fcntl::openat2(fd, path, how).map_err(openat_err)?;
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn openat_err(e: Errno) -> io::Error {
    match e {
        Errno::EXDEV => io::Error::new(
            io::ErrorKind::PermissionDenied,
            "can't open a file outside of the current root directory",
        ),
        e => e.into(),
    }
}

#[cfg(test)]
mod test {
    use std::{
        io::{Read, Seek, Write},
        os::unix::fs::OpenOptionsExt,
    };

    use super::*;

    #[test]
    fn test_dir_create() {
        let temp_root = tempfile::tempdir().expect("root tempfile");
        let dir = Dir::from(open_dir(temp_root.path()).expect("dir fd"));

        let mut f = dir.create("an_file.txt").expect("create failed");
        f.write_all(b"some data").unwrap();
        assert_eq!(
            std::fs::read(temp_root.path().join("an_file.txt")).unwrap(),
            b"some data",
        );
    }

    #[test]
    fn test_dir_create_dir() {
        let temp_root = tempfile::tempdir().expect("root tempfile");
        let dir = Dir::from(open_dir(temp_root.path()).expect("dir fd"));

        dir.create_dir("foo").expect("create dir failed");

        let foo_md = std::fs::symlink_metadata(temp_root.path().join("foo")).unwrap();
        assert!(foo_md.is_dir(), "should be a directory");
    }

    #[test]
    fn test_read_write_in_dir() {
        let temp_root = tempfile::tempdir().expect("root tempfile");
        let dir = Dir::from(open_dir(temp_root.path()).expect("dir fd"));

        dir.create_dir("foo").expect("create dir failed");
        let mut f = dir
            .create("foo/bar.txt")
            .expect("creating a file inside a dir");
        f.write_all(b"kilroy was here").unwrap();

        let mut content = String::with_capacity(32);
        dir.open("foo/bar.txt")
            .expect("opening a file inside a dir failed")
            .read_to_string(&mut content)
            .expect("failed to read kilroy");
        assert_eq!("kilroy was here", &content);
    }

    #[test]
    fn test_create_not_beneath() {
        let temp_root = tempfile::tempdir().expect("root tempfile");
        let dir = Dir::from(open_dir(temp_root.path()).expect("dir fd"));

        dir.create_dir("foo").expect("create dir failed");
        dir.create_dir("foo/bar").expect("create nested dir failed");

        let err = dir
            .open("foo/bar/../../../../etc/passwd")
            .expect_err("should have been an error");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_create_builder() {
        let temp_root = tempfile::tempdir().expect("root tempfile");
        let dir = Dir::from(open_dir(temp_root.path()).expect("dir fd"));

        dir.create_dir("foo").expect("create dir failed");
        let mut bar = dir
            .file()
            .read(true)
            .write(true)
            .create_new(true)
            .open("foo/bar.txt")
            .expect("create failed");

        bar.write_all(b"kilroy was here").expect("write failed");
        bar.seek(io::SeekFrom::Start(0)).expect("seek failed");

        let mut content = String::with_capacity(32);
        bar.read_to_string(&mut content).expect("read failed");
        assert_eq!("kilroy was here", &content);
    }

    fn open_dir<P: AsRef<Path>>(path: P) -> std::io::Result<OwnedFd> {
        std::fs::OpenOptions::new()
            .read(true)
            .mode(libc::O_DIRECTORY as u32)
            .open(path)
            .map(|f| f.into())
    }
}
