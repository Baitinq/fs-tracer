#![no_std]
#![feature(c_size_t)]

use core::ffi::c_uint;
use core::fmt::{self, Formatter};
use core::str;
use aya_ebpf::cty::c_long;
use core::ffi::c_size_t;

pub enum SyscallInfo {
    Write(WriteSyscallBPF),
}

#[derive(Clone, Copy)]
pub struct WriteSyscallBPF {
    pub pid: u32,
    pub fd: c_uint,
    pub buf: [u8; 96], //TODO: might want to use c_char here
    pub count: c_size_t,

    pub ret: c_long,
}

unsafe impl Sync for WriteSyscallBPF {}

impl fmt::Debug for WriteSyscallBPF {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteSyscallBPF")
            .field("pid", &self.pid)
            .field("fd", &self.fd)
            .field("buf", &str::from_utf8(&self.buf).unwrap_or(""))
            .field("count", &self.count)
            .field("ret", &self.ret)
            .finish()
    }
}
