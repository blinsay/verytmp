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
    pub fn dir<'a>(&'a self) -> DirOptions<'a> {
        DirOptions::new_default(self)
    }

    pub fn create_dir<P: AsRef<Path>>(&self, p: P) -> io::Result<()> {
        self.dir().create(p)
    }

    pub fn file<'a>(&'a self) -> OpenOptions<'a> {
        OpenOptions::new_default(self)
    }

    pub fn create<P: AsRef<Path>>(&self, p: P) -> io::Result<File> {
        self.file().write(true).create(true).truncate(true).open(p)
    }

    pub fn open<P: AsRef<Path>>(&self, p: P) -> io::Result<File> {
        self.file().read(true).open(p)
    }
}

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
    pub fn mode(&mut self, mode: u32) -> &mut Self {
        self.mode = mode;
        self
    }

    pub fn create<P: AsRef<Path>>(&mut self, p: P) -> io::Result<()> {
        let mode = Mode::from_bits_truncate(self.mode);
        stat::mkdirat(Some(self.fs.root.as_raw_fd()), p.as_ref(), mode)?;
        Ok(())
    }
}

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
    pub fn append(&mut self, append: bool) -> &mut Self {
        self.append = append;
        self
    }

    pub fn create(&mut self, create: bool) -> &mut Self {
        self.create = create;
        self
    }

    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.create_new = create_new;
        self
    }

    pub fn read(&mut self, read: bool) -> &mut Self {
        self.read = read;
        self
    }

    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.truncate = truncate;
        self
    }

    pub fn write(&mut self, write: bool) -> &mut Self {
        self.write = write;
        self
    }

    pub fn flags(&mut self, flags: i32) -> &mut Self {
        self.flags = flags;
        self
    }

    pub fn mode(&mut self, mode: u32) -> &mut Self {
        self.mode = mode;
        self
    }

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
