#![no_std]
#![no_main]
#![feature(c_size_t)]

#![allow(warnings, unused)]
mod vmlinux;
mod syscalls;

use core::str;
use aya_bpf::cty::{c_int, c_long};
use aya_bpf::maps::HashMap;
use aya_bpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    BpfContext,
};
use aya_log_ebpf::info;
use fs_tracer_common::{SyscallInfo, WriteSyscallBPF};

#[map]
static EVENTS: PerfEventArray<SyscallInfo> = PerfEventArray::with_max_entries(24, 0);

// NOTE: We use this map for tracking syscalls. We have a tracepoint both at the entry
// and exit of a syscall. Since we need to get arguments from both places, we need to be
// able to correlate a syscall enter to an exit. We do this via the tgid. Since a thread
// can only execute 1 syscall at a time, we can have a map of tgid -> syscall of size =
// num_of_threads.
#[map]
static SYSCALL_ENTERS: HashMap<u32, SyscallInfo> = HashMap::with_max_entries(24, 0);

enum SyscallType {
    Enter,
    Exit,
}

#[tracepoint]
pub fn fs_tracer_enter(ctx: TracePointContext) -> c_long {
    match try_fs_tracer(ctx, SyscallType::Enter) {
        Ok(ret) => ret,
        Err(ret) => -ret,
    }
}

#[tracepoint]
pub fn fs_tracer_exit(ctx: TracePointContext) -> c_long {
    //info!(&ctx, "Hi");
    match try_fs_tracer(ctx, SyscallType::Exit) {
        Ok(ret) => ret,
        Err(ret) => -ret,
    }
}

fn try_fs_tracer(ctx: TracePointContext, syscall_type: SyscallType) -> Result<c_long, c_long> {
    let syscall_nr = unsafe { ctx.read_at::<c_int>(8)? } ;

    handle_syscall(ctx, syscall_nr, syscall_type)
}

fn handle_syscall(
    ctx: TracePointContext,
    syscall_nr: c_int,
    syscall_type: SyscallType,
) -> Result<c_long, c_long> {
    match syscall_nr {
        1 => syscalls::write::handle_sys_write(ctx, syscall_type),
        257 => syscalls::open::handle_sys_open(ctx, syscall_type),
        8 => {
            Ok(0)
            //handle_sys_lseek(ctx);
        }
        3 => {
            Ok(0)
            //handle_sys_close(ctx);
        }
        _ => {
            info!(&ctx, "unhandled syscall: {}", syscall_nr);
            Err(1)
        }
    }
}

// thread can only execute 1 syscall at a time <-

//TODO: How are we going to correlate. We have open of a filename, we need to insert that into (pid, fd) -> filename. on close we remove from map. we need some timeout to remove stale entries
//TODO: to get the fd from open, we need to know the return value of the syscall. for that we need a tracepoint on end and keep a map of (tgid, pid) -> WriteSyscallBPF). we need to differenciate the syscalls by id
//TODO: Maybe we can use git itself for the diffs etc.

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
