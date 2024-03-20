
`verytmp` is a crate for creating temporary in-memory filesystems.

`verytmp` creates a a tmpfs disconnected from the filesystem and returns a
reference to the root of the new tempfs. Once all file descriptors that
refer to the tmpfs are cleaned up, the kernel is free to clean up the tmpfs
and free all the memory it used.

This approach makes `verytmp` different from [`tempfile`] or just throwing
files in `$TMPDIR`. With `verytmp` there is no userspace cleanup required,
temporary files are cleaned up even on a `kill -9`, and no wondering when
was the last time someone cleaned out `/tmp`.

[`tempfile`]: https://crates.io/crates/tempfile

# Using verytmp

`verytmp` creates a tmpfs and returns the root as a directory struct. Because
the tmpfs is disconnected from the rest of the filesystem, there's no way to
specify a plain old path that points into the tmpfs. Instead, directories in
the tmpfs can create files or directories at subpaths underneath them.

The [verytmp](verytmp) function returns a directory handle to the root
of the tmpfs that can be used to start creating files and directories. Keep in
mind that this handle **owns** the root of the filesystem, and will close if you
drop it.

```no_run
# use std::io::{Read, Seek, SeekFrom, Write};
// create a new tmpfs to read/write from. there's nothing in here
// to begin with.
let fs = verytmp::verytmp().expect("failed to set up tmpfs");

fs.create_dir("hello").unwrap();
let mut my_cool_file = fs.create("hello/my_cool_file.txt").unwrap();
my_cool_file.write_all(b"potatoes").unwrap();

// drop the verytmp root, which means there is now no way to open any more
// files or directories in the root of the tmpfs. my_cool_file is already
// open, so it can be used in all the normal ways you can use a file.
std::mem::drop(fs);

my_cool_file.seek(SeekFrom::Start(0)).unwrap();
let mut content = String::new();
my_cool_file.read_to_string(&mut content).unwrap();
assert_eq!("potatoes", &content);

// once all of the references to the tmpfs are gone, linux will free up the
// memory used for this tmpfs without the program having to do anything else.
std::mem::drop(my_cool_file);
```

# `cap-std`

[`cap-std`] offers a capability based API for filesystems that is also built
around accessing files only under a root directory. If you're already using
`cap-std` in your application, enabling the `cap-std` feature in `verytmp`
replaces `verytmp::Dir` with `cap_std::fs::Dir`.

```no_run
# #[cfg(feature="cap-std")]
let fs: cap_std::fs::Dir = verytmp::verytmp().expect("failed to set up tmpfs");
// more cool code here...
```

# Platform support

`verytmp` relies on unprivileged user namespaces. It works by creating a child
process in new user and mount namespaces, mounting a tmpfs in that process, and
passing the root directory back to the calling process as a file descriptor.

This is a very linux-specific trick, which means that `verytmp` is currently only
available on linux.

[`cap-std`]: https://crates.io/crates/cap-std

# Acknolwedgements

This project is a Rust port of [verytmp.c], a delightful little library by
[Geoff Thomas](https://kerberos.club).

[verytmp.c]: https://kerberos.club/tmp/verytmp.c
