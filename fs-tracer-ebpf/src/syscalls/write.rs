use aya_bpf::{
    cty::{c_char, c_uint},
    helpers::{bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes},
};
use core::ffi::c_size_t;

use crate::*;

pub fn handle_sys_write(
    ctx: TracePointContext,
    syscall_type: SyscallType,
) -> Result<c_long, c_long> {
    match syscall_type {
        SyscallType::Enter => unsafe { handle_sys_write_enter(ctx) },
        SyscallType::Exit => unsafe { handle_sys_write_exit(ctx) },
    }
}

unsafe fn handle_sys_write_enter(ctx: TracePointContext) -> Result<c_long, c_long> {
    // info!(&ctx, "handle_sys_write start");
    #[derive(Clone, Copy)]
    struct WriteSyscallArgs {
        fd: c_uint,
        buf: *const c_char,
        count: c_size_t,
    }
    let args = ctx.read_at::<WriteSyscallArgs>(16)?;

    // if fd is stdout, stderr or stdin, ignore
    if args.fd <= 2 {
        return Ok(0);
    }

    let mut buf = [0u8; 96]; //we need to make this muuuuuch bigger, we could use some sync with a bpf ds
    let _ = bpf_probe_read_user_str_bytes(args.buf as *const u8, &mut buf);
    let buf_ref = &buf;

    let mut anotherbuf = [0u8; 96];
    let _ = bpf_probe_read_kernel_str_bytes(buf_ref.as_ptr(), &mut anotherbuf);

    let tgid: u32 = ctx.tgid();
    let _ = SYSCALL_ENTERS.insert(
        &tgid,
        &SyscallInfo::Write(WriteSyscallBPF {
            pid: ctx.pid(),
            fd: args.fd,
            buf: anotherbuf,
            count: args.count,
            ret: -9999,
        }),
        0,
    );

    Ok(0)
}

unsafe fn handle_sys_write_exit(ctx: TracePointContext) -> Result<c_long, c_long> {
    //info!(&ctx, "handle_sys_write_exit start");
    let ret = ctx.read_at::<c_long>(16)?; //TODO: We cant use unwrap, thats why we couldnt use the aya helper fns

    let tgid = ctx.tgid();
    if let Some(syscall) = SYSCALL_ENTERS.get(&tgid) {
        let SyscallInfo::Write(mut syscall_write) = syscall;
        syscall_write.ret = ret;
        EVENTS.output(&ctx, &SyscallInfo::Write(syscall_write), 0);
        let _ = SYSCALL_ENTERS.remove(&tgid);
        return Ok(0);
    }

    Err(0)
}
