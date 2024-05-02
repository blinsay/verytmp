//! `verytmp` is a linux-only crate for creating temporary in-memory filesystems.
//!
//! `verytmp` creates a a tmpfs disconnected from the filesystem and returns a
//! reference to the root of the new tempfs. Once all file descriptors that
//! refer to the tmpfs are cleaned up, the kernel cleans up the tmpfs and frees
//! all of the memory it used.
//!
//! This approach makes `verytmp` different from [`tempfile`] or just throwing
//! files in `$TMPDIR`. With `verytmp` there is no userspace cleanup required,
//! temporary files are cleaned up even on a `kill -9` and take no disk space.
//!
//! [`tempfile`]: https://crates.io/crates/tempfile
//!
//! # Using verytmp
//!
//! `verytmp` creates a tmpfs and returns the root as a directory struct. Because
//! the tmpfs is disconnected from the rest of the filesystem, there is no way to
//! specify a plain old path that points into the tmpfs. Instead, paths have to be
//! specified relative to the root of the tempfs or another directory inside of it.
//!
//! The [verytmp](verytmp) function returns a directory handle to the root
//! of the tmpfs that can be used to start creating files and directories.
//!
//! ```no_run
//! # use std::io::{Read, Seek, SeekFrom, Write};
//! // create a new tmpfs to read/write from. there's nothing in here
//! // to begin with.
//! let fs = verytmp::verytmp().expect("failed to set up tmpfs");
//!
//! fs.create_dir("hello").unwrap();
//! let mut my_cool_file = fs.create("hello/my_cool_file.txt").unwrap();
//! my_cool_file.write_all(b"potatoes").unwrap();
//!
//! // drop the verytmp root, which means there is now no way to open any more
//! // files or directories in the root of the tmpfs. my_cool_file is already
//! // open, so it can be used in all the normal ways you can use a file.
//! std::mem::drop(fs);
//!
//! my_cool_file.seek(SeekFrom::Start(0)).unwrap();
//! let mut content = String::new();
//! my_cool_file.read_to_string(&mut content).unwrap();
//! assert_eq!("potatoes", &content);
//!
//! // once all of the references to the tmpfs are gone, linux will free up the
//! // memory used for this tmpfs without the program having to do anything else.
//! std::mem::drop(my_cool_file);
//! ```
//!
//! Keep in mind that even though this handle owns the root of the filesystem, and will
//! close if you drop it, that dropping the root doesn't necessarily close the filesystem.
//! As long as another file or directory in your `verytmp` fs is open, the kernel will keep
//! the entire tempfs alive.
//!
//! # `cap-std`
//!
//! [`cap-std`] offers a capability based API for filesystems that is also built
//! around accessing files realtive to an existing directory. Enabling the `cap-std`
//! feature in `verytmp` replaces `verytmp::Dir` with `cap_std::fs::Dir`.
//!
//! ```no_run
//! # #[cfg(feature="cap-std")]
//! let fs: cap_std::fs::Dir = verytmp::verytmp().expect("failed to set up tmpfs");
//! // more cool code here...
//! ```
//!
//! This is highly recommended if you're already using `cap-std` in your
//! application, and provides a more fully-featured filesystem API than `verytmp`'s
//! built-in `Dir`.
//!
//! [`cap-std`]: https://crates.io/crates/cap-std
//!
//! # Platform support
//!
//! `verytmp` relies on unprivileged user namespaces. It works by creating a child
//! process in new user and mount namespaces, mounting a tmpfs in that process, and
//! passing the root directory back to the calling process as a file descriptor.
//!
//! This is a very linux-specific trick, which means that `verytmp` is currently only
//! available on linux.
//!
//! # Acknolwedgements
//!
//! This project is a Rust port of [verytmp.c], a delightful little library by
//! [Geoff Thomas](https://kerberos.club).
//!
//! [verytmp.c]: https://kerberos.club/tmp/verytmp.c

use std::{
    io::{self, IoSlice, IoSliceMut},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

use nix::{
    cmsg_space,
    fcntl::{self, OFlag},
    mount::{self, MsFlags},
    sched::{self, CloneFlags},
    sys::{
        socket::{
            self, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
        },
        stat::Mode,
    },
    unistd::{self, Gid, Uid},
};

cfg_if::cfg_if! {
    if #[cfg(not(feature = "cap-std"))] {
        mod no_cap; // fr fr
        pub use no_cap::*;
    } else {
        use cap_std::fs::Dir;
    }
}

/// Create a tmpfs and return a handle to the root of the filesystem.
///
/// See the module documentation for more information on verytmp, and see the
/// [`Dir`] documentation for examples of how to create files and directories
/// in your tmpfs.
pub fn verytmp() -> io::Result<Dir> {
    unsafe {
        let fd = verytmp_fd()?;
        Ok(fd.into())
    }
}

/// Write formatted data into a file at a static path, as utf8 text. No newline
/// is inserted at the end of input.
///
/// This macro is equivalent to calling `std::fs::write(fomrmat!(...))` with
/// it's args.
macro_rules! write_file {
    ($path:expr, $($args:tt)+) => {
        std::fs::write($path, format!($($args)+))
            .map_err(|e| nix::Error::try_from(e).unwrap_or(nix::Error::ERANGE))
    };
}

/// An fd-level version of [`verytmp`].
///
/// Creates a tmps by forking, unsharing to create new mount and user
/// namespaces, and then mounting a tmpfs somewhere only the child can
/// access it. The root of the tmpfs is opened and passed back to the
/// parent process as an open fd.
///
/// Prefer [`verytmp`] unless you have an extremely good reason to work
/// with a raw file descriptor.
pub unsafe fn verytmp_fd() -> io::Result<OwnedFd> {
    let (rx, tx) = socket::socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )?;

    let uid = unistd::geteuid();
    let gid = unistd::getegid();

    match unsafe { unistd::fork()? } {
        // the parent process recieves the verytmp fd poiting to the root of
        // the new verytmpfs from the recv socket.
        unistd::ForkResult::Parent { .. } => {
            // close the side we don't need. close by dropping the OwnedFd here
            // instead of messing with nix to do it ourselves.
            std::mem::drop(tx);

            // safety: we are willing to trust that the other side of the
            // socketpair gave us a real fd.
            let fd = recv_fd(rx.as_raw_fd())?;
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
        // in the child our job is to set up a new tmpfs mount in a new mount
        // namespace and pass the fd for the root dir back through the socket.
        unistd::ForkResult::Child => {
            // close the side we don't need. close by dropping the OwnedFd here
            // instead of messing with nix to do it ourselves.
            std::mem::drop(rx);

            // unshare and mount and then try to send the result. there's
            // nothing good  we can actually do here if sending the fd back
            // over the socket fails, so panic. if anyone somehow sees output
            // or exit status from this process, it should be clear something
            // bad happened.
            let root_fd = unshare_and_mount("/proc/self/task", uid, gid);
            send_fd(tx.as_raw_fd(), root_fd).expect("sendmsg failed");
            std::process::exit(0);
        }
    }
}

fn unshare_and_mount(mount_path: &'static str, uid: Uid, gid: Gid) -> nix::Result<RawFd> {
    sched::unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)?;
    write_file!("/proc/self/setgroups", "deny")?;
    write_file!("/proc/self/uid_map", "{uid} {uid} 1")?;
    write_file!("/proc/self/gid_map", "{gid} {gid} 1")?;

    // abuse /proc/self as a directory that can be mounted onto and is only
    // visible in the child. since this directory only exists in the child
    // and the child is going to exit asap, there's no real impact.
    //
    // TODO: doing this better requires some syscalls that don't have libc
    // or nix wrappers yet (fsopen, fsconfig, fsmount).
    mount::mount(
        Some(mount_path),
        "/proc/self/task",
        Some("tmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )?;

    let root_fd = fcntl::open(
        "/proc/self/task",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY,
        Mode::empty(),
    )?;

    Ok(root_fd)
}

fn send_fd(socket_fd: RawFd, send_fd: nix::Result<RawFd>) -> io::Result<()> {
    // fds is declared here because ControlMessage::ScmRights has to wrap
    // a slice ref and this is the path of least resistance to teaching
    // borrowck that the lifetime of cmsgs is tied to the lifetime of fds
    // without it complaining about temporaries.
    let mut fds = [RawFd::default(); 1];
    let (errno, cmsgs) = match send_fd {
        Ok(root_fd) => {
            fds[0] = root_fd;
            (0, Some(ControlMessage::ScmRights(&fds)))
        }
        Err(e) => (e as i32, None),
    };

    let buf = (errno as i32).to_be_bytes();
    socket::sendmsg::<()>(
        socket_fd,
        &[IoSlice::new(&buf)],
        cmsgs.as_slice(),
        MsgFlags::empty(),
        None,
    )?;

    Ok(())
}

fn recv_fd(socket_fd: RawFd) -> io::Result<RawFd> {
    // do the recvmsg dance
    let mut msg_buf = [0u8; 32];
    let mut iov = vec![IoSliceMut::new(&mut msg_buf)];
    let mut cmsg_buf = cmsg_space!(RawFd);
    let msg = socket::recvmsg::<()>(
        socket_fd,
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )?;

    // parse the actual message to see if it's an errno. if it is, return
    // it and bail out.
    let Some(iov) = msg.iovs().next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing errno from child",
        ));
    };

    let raw_errno = i32::from_be_bytes(
        iov.try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid errno"))?,
    );

    if raw_errno != 0 {
        return Err(nix::Error::from_raw(raw_errno).into());
    }

    // pull the actual fd out of the control messages
    let Some(ControlMessageOwned::ScmRights(fds)) = msg.cmsgs().next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected a single cmsg",
        ));
    };

    if fds.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected a single passed fd",
        ));
    }

    Ok(fds[0])
}

#[cfg(test)]
mod test {
    use super::*;
    use nix::errno::Errno;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::IntoRawFd;

    #[test]
    fn test_send_recv_fd() {
        let (tx, rx) = socket::socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();

        {
            let mut tmpfile = tempfile::tempfile().unwrap();
            write!(&mut tmpfile, "hello from a test").unwrap();

            send_fd(tx.as_raw_fd(), Ok(tmpfile.into_raw_fd())).expect("failed to send Ok(fd)");
        }

        {
            let fd = recv_fd(rx.as_raw_fd()).expect("didn't get a valid fd");
            let mut tmpfile = unsafe { File::from_raw_fd(fd) };
            tmpfile.seek(SeekFrom::Start(0)).unwrap();

            let mut content = String::with_capacity(32);
            tmpfile.read_to_string(&mut content).unwrap();

            assert_eq!(&content, "hello from a test");
        }
    }

    #[test]
    fn test_send_recv_errno() {
        let (tx, rx) = socket::socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();

        {
            send_fd(tx.as_raw_fd(), Err(Errno::EBADF)).expect("failed to send Err(EBADF)");
        }

        {
            let res = recv_fd(rx.as_raw_fd());
            let actual_errno = res
                .expect_err("expected an error code")
                .raw_os_error()
                .map(Errno::from_raw);
            assert_eq!(actual_errno, Some(Errno::EBADF));
        }
    }
}
