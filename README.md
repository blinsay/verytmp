`verytmp` is a linux-only crate for creating temporary in-memory filesystems.

`verytmp` creates a a tmpfs disconnected from the filesystem and returns a
reference to the root of the new tempfs. Once all file descriptors that
refer to the tmpfs are cleaned up, the kernel cleans up the tmpfs and frees
all of the memory it used.

```rust
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

See the Cargo documentation for more details.

# Source Only

This crate is currently not available on crates.io because it uses an implementation
of `openat2` from [nix](https://crates.io/crates/nix) that isn't yet available upstream.

# Acknolwedgements

This project is a Rust port of [verytmp.c], a delightful little library by
[Geoff Thomas](https://kerberos.club).

[verytmp.c]: https://kerberos.club/tmp/verytmp.c
