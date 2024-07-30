use aya_ebpf::{
    cty::{c_char, c_uint},
    helpers::{bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes},
};
use core::ffi::c_size_t;
use fs_tracer_common::CloseSyscallBPF;

use crate::*;

pub fn handle_sys_close(
    ctx: TracePointContext,
    syscall_type: SyscallType,
) -> Result<c_long, c_long> {
    match syscall_type {
        SyscallType::Enter => unsafe { handle_sys_close_enter(ctx) },
        SyscallType::Exit => unsafe { handle_sys_close_exit(ctx) },
    }
}

unsafe fn handle_sys_close_enter(ctx: TracePointContext) -> Result<c_long, c_long> {
    // info!(&ctx, "handle_sys_close start");
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CloseSyscallArgs {
        fd: c_int,
    }
    let args = ctx.read_at::<CloseSyscallArgs>(16)?;
    let tgid: u32 = ctx.tgid();
    let _ = SYSCALL_ENTERS.insert(
        &tgid,
        &SyscallInfo::Close(CloseSyscallBPF {
            pid: ctx.pid(),
            fd: args.fd,
            ret: -9999,
        }),
        0,
    );

    Ok(0)
}

unsafe fn handle_sys_close_exit(ctx: TracePointContext) -> Result<c_long, c_long> {
    // info!(&ctx, "handle_sys_close_exit start");
    let ret = ctx.read_at::<c_long>(16)?; //TODO: We cant use unwrap, thats why we couldnt use the aya helper fns

    let tgid = ctx.tgid();
    if let Some(syscall) = SYSCALL_ENTERS.get(&tgid)
        && let SyscallInfo::Close(mut syscall_close) = syscall
    {
        syscall_close.ret = ret;
        EVENTS.output(&ctx, &SyscallInfo::Close(syscall_close), 0);
        let _ = SYSCALL_ENTERS.remove(&tgid);
        return Ok(0);
    }

    Err(0)
}
