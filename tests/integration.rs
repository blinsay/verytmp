fn main() {
    println!("hello");
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::{self, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;

    #[test]
    fn test_verytmp_raw() {
        // just test that we can stat the raw fd
        let fd = unsafe { verytmp::verytmp_fd().unwrap() };
        nix::sys::stat::fstat(fd.as_raw_fd()).unwrap();
    }

    #[test]
    #[cfg(not(feature = "cap-std"))]
    fn test_verytmp() {
        let fs = verytmp::verytmp().expect("verytmp");
        fs.create_dir("foo").expect("mkdir: foo");
        fs.create_dir("foo/bar").expect("mkdir: foo/bar");

        let f = fs
            .file()
            .read(true)
            .write(true)
            .create_new(true)
            .open("foo/bar/baz.txt")
            .expect("create");
        assert_read_write(f);
    }

    #[test]
    #[cfg(feature = "cap-std")]
    fn test_verytmp_cap_std() {
        let fs = verytmp::verytmp().expect("verytmp");
        fs.create_dir("foo").expect("mkdir: foo");
        fs.create_dir("foo/bar").expect("mkdir: foo/bar");

        let mut open_options = cap_std::fs::OpenOptions::new();
        open_options.read(true).write(true).create_new(true);

        let f = fs
            .open_with("foo/bar/baz.txt", &open_options)
            .expect("open_with");
        assert_read_write(f.into_std());
    }

    fn assert_read_write(mut f: File) {
        f.write_all(b"hello verytmp").expect("write_all");
        f.seek(SeekFrom::Start(0)).expect("seek");

        let content = io::read_to_string(&mut f).expect("read to string");
        assert_eq!("hello verytmp", content.as_str());
    }
}
