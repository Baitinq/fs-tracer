use aya_ebpf::{
    cty::{c_char, c_longlong, c_uint},
    helpers::{bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes},
};
use core::ffi::c_size_t;
use fs_tracer_common::FSeekSyscallBPF;

use crate::*;

pub fn handle_sys_fseek(
    ctx: TracePointContext,
    syscall_type: SyscallType,
) -> Result<c_long, c_long> {
    match syscall_type {
        SyscallType::Enter => unsafe { handle_sys_fseek_enter(ctx) },
        SyscallType::Exit => unsafe { handle_sys_fseek_exit(ctx) },
    }
}

unsafe fn handle_sys_fseek_enter(ctx: TracePointContext) -> Result<c_long, c_long> {
    // info!(&ctx, "handle_sys_fseek start");
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FSeekSyscallArgs {
        fd: c_int,
        offset: i64,
        whence: c_uint,
    }
    let args = ctx.read_at::<FSeekSyscallArgs>(16)?;

    // if fd is stdout, stderr or stdin, ignore
    if args.fd <= 2 {
        return Ok(0);
    }

    info!(
        &ctx,
        "handle_sys_fseek fd: {} pid: {} offset: {} whence: {}",
        args.fd,
        ctx.pid(),
        args.offset,
        args.whence
    );

    let tgid: u32 = ctx.tgid();
    let _ = SYSCALL_ENTERS.insert(
        &tgid,
        &SyscallInfo::FSeek(FSeekSyscallBPF {
            pid: ctx.pid(),
            fd: args.fd,
            offset: args.offset,
            whence: args.whence,
            ret: -9999,
        }),
        0,
    );

    Ok(0)
}

unsafe fn handle_sys_fseek_exit(ctx: TracePointContext) -> Result<c_long, c_long> {
    //info!(&ctx, "handle_sys_fseek_exit start");
    let ret = ctx.read_at::<c_long>(16)?; //TODO: We cant use unwrap, thats why we couldnt use the aya helper fns

    let tgid = ctx.tgid();
    if let Some(syscall) = SYSCALL_ENTERS.get(&tgid)
        && let SyscallInfo::FSeek(mut syscall_fseek) = syscall
    {
        syscall_fseek.ret = ret;
        EVENTS.output(&ctx, &SyscallInfo::FSeek(syscall_fseek), 0);
        let _ = SYSCALL_ENTERS.remove(&tgid);
        return Ok(0);
    }

    Err(0)
}
