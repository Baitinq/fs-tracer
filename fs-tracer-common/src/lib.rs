#![no_std]
#![feature(c_size_t)]

use aya_ebpf::cty::c_long;
use core::ffi::c_int;
use core::ffi::c_size_t;
use core::ffi::c_uint;
use core::fmt::{self, Formatter};
use core::str;

mod vmlinux;

use crate::vmlinux::umode_t;

pub enum SyscallInfo {
    Write(WriteSyscallBPF),
    Open(OpenSyscallBPF),
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

#[derive(Clone, Copy)]
pub struct OpenSyscallBPF {
    pub pid: u32,
    pub dfd: c_int,
    pub filename: [u8; 96],
    pub flags: c_int,
    pub mode: umode_t,
    pub ret: c_long,
}

unsafe impl Sync for OpenSyscallBPF {}

impl fmt::Debug for OpenSyscallBPF {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenSyscallBPF")
            .field("pid", &self.pid)
            .field("dfd", &self.dfd)
            //       .field("filename", &str::from_utf8(&self.filename).unwrap_or(""))
            .field("flags", &self.flags)
            .field("ret", &self.ret)
            .finish()
    }
}
