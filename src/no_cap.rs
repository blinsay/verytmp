use std::{
    fs::File,
    io,
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
    path::Path,
    ptr::addr_of_mut,
};

use nix::{
    errno::Errno,
    fcntl::OFlag,
    sys::stat::{self, Mode},
    NixPath,
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

    pub fn open<P: AsRef<Path>>(&mut self, p: P) -> io::Result<File> {
        let oflags = OFlag::O_CLOEXEC | self.access_flags()? | self.create_flags()?;
        let mode = Mode::from_bits_truncate(self.mode);

        let fd = openat2(
            self.fs.root.as_raw_fd(),
            p.as_ref(),
            oflags,
            mode,
            ResovleFlags::RESOLVE_BENEATH | ResovleFlags::RESOLVE_NO_MAGICLINKS,
        )
        .map_err(openat_err)?;
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
}

/// A raw wrapper for openat2.
///
/// TODO: use the nix implementation once it's released
/// https://github.com/nix-rust/nix/pull/2339
fn openat2<P: ?Sized + NixPath>(
    dir: RawFd,
    path: &P,
    oflag: OFlag,
    mode: Mode,
    resolve: ResovleFlags,
) -> nix::Result<RawFd> {
    let mut how = unsafe {
        let mut how: MaybeUninit<libc::open_how> = MaybeUninit::uninit();
        let ptr = how.as_mut_ptr();
        addr_of_mut!((*ptr).flags).write(oflag.bits() as libc::c_ulonglong);
        addr_of_mut!((*ptr).mode).write(mode.bits() as libc::c_ulonglong);
        addr_of_mut!((*ptr).resolve).write(resolve.bits());
        how.assume_init()
    };

    let fd = path.with_nix_path(|cstr| unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir,
            cstr.as_ptr(),
            &mut how as *mut _,
            std::mem::size_of::<libc::open_how>(),
        )
    })?;
    Errno::result(fd as i32)
}

// This macro is copied directly from nix to support openat2. Merge that upstream
// and delete this ASAP.
//
// https://github.com/nix-rust/nix/blob/c6a7d402d9eabf21f2edea28aa4839617e9d5478/src/macros.rs#L55C1-L78C1
macro_rules! libc_bitflags {
    (
        $(#[$outer:meta])*
        pub struct $BitFlags:ident: $T:ty {
            $(
                $(#[$inner:ident $($args:tt)*])*
                $Flag:ident $(as $cast:ty)*;
            )+
        }
    ) => {
        ::bitflags::bitflags! {
            #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
            #[repr(transparent)]
            $(#[$outer])*
            pub struct $BitFlags: $T {
                $(
                    $(#[$inner $($args)*])*
                    const $Flag = libc::$Flag $(as $cast)*;
                )+
            }
        }
    };
}

// TODO: use the nix implementation once it's released
// https://github.com/nix-rust/nix/pull/2339
libc_bitflags! {
    pub struct ResovleFlags: libc::c_ulonglong {
        RESOLVE_BENEATH;
        RESOLVE_NO_MAGICLINKS;
    }
}

#[cfg(test)]
mod openat_test {
    use std::io::{Read, Seek, Write};

    use super::*;
    use nix::{fcntl::OFlag, sys::stat::Mode};

    #[test]
    fn test_openat2() {
        let tmpdir = tempfile::tempdir().unwrap();

        let dir_fd = nix::fcntl::open(
            tmpdir.path(),
            OFlag::O_DIRECTORY | OFlag::O_RDONLY,
            Mode::empty(),
        )
        .unwrap();

        let new_file = openat2(
            dir_fd,
            "potato.txt",
            OFlag::O_CREAT | OFlag::O_RDWR,
            Mode::S_IWUSR | Mode::S_IRUSR,
            ResovleFlags::RESOLVE_BENEATH | ResovleFlags::RESOLVE_NO_MAGICLINKS,
        )
        .expect("openat2");

        let mut file = unsafe { File::from_raw_fd(new_file) };
        file.write_all(b"hello from openat2").unwrap();
        file.seek(io::SeekFrom::Start(0)).unwrap();

        let mut content = String::with_capacity(32);
        file.read_to_string(&mut content).unwrap();

        assert_eq!("hello from openat2", &content[..]);
    }

    #[test]
    fn test_openat2_resolve_beneath() {
        let tmpdir = tempfile::tempdir().unwrap();

        let dir_fd = nix::fcntl::open(
            tmpdir.path(),
            OFlag::O_DIRECTORY | OFlag::O_RDONLY,
            Mode::empty(),
        )
        .unwrap();

        let res = openat2(
            dir_fd,
            "../../test_dir",
            OFlag::O_CREAT | OFlag::O_RDWR,
            Mode::S_IWUSR | Mode::S_IRUSR,
            ResovleFlags::RESOLVE_BENEATH,
        );

        // from man openat(2):
        //
        // RETURNS:
        //      EXDEV   how.resolve  contains either RESOLVE_IN_ROOT or
        //      RESOLVE_BENEATH, and an escape from the root during path
        //      resolution was detected.
        assert_eq!(Err(Errno::EXDEV), res);
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_dir_create() {
        unimplemented!("test me")
    }

    #[test]
    fn test_dir_create_dir() {
        unimplemented!("test me")
    }

    #[test]
    fn test_create_not_beneath() {
        unimplemented!("test me")
    }

    #[test]
    fn test_create_builder() {
        unimplemented!("test me")
    }
}
