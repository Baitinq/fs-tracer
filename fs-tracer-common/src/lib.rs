#![no_std]

use core::fmt::{Formatter, self};
use core::str;


#[derive(Clone, Copy)]
pub struct WriteSyscallBPF {
    pub pid: u32,
    pub fd: u64,
    pub buf: [u8; 128],
    pub count: u64,
}

unsafe impl Sync for WriteSyscallBPF {}

impl fmt::Debug for WriteSyscallBPF {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteSyscallArgs")
            .field("pid", &self.pid)
            .field("fd", &self.fd)
            .field("buf", &str::from_utf8(&self.buf).unwrap_or("") )
            .field("count", &self.count)
            .finish()
    }
}