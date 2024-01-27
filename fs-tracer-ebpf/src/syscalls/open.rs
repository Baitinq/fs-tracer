#![feature(ptr_metadata)]

use aya_bpf::helpers::{bpf_d_path, bpf_probe_read};

use crate::*;

pub fn handle_sys_open(ctx: TracePointContext, syscall_type: SyscallType) -> Result<u32, u32> {
    //info!(&ctx, "called");
    match syscall_type {
        SyscallType::Enter => unsafe { handle_sys_open_enter(ctx) },
        SyscallType::Exit => unsafe { handle_sys_open_exit(ctx) },
    }
}

unsafe fn handle_sys_open_enter(ctx: TracePointContext) -> Result<u32, u32> {
    //info!(&ctx, "handle_sys_open_enter start");
    let x = bpf_get_current_task_btf() as *const task_struct;
    let pid = (*x).fs as *const fs_struct;
    let uwu = (*pid).pwd;
    let ra = uwu.dentry as *const dentry;
    let ma = str::from_utf8_unchecked(&(*ra).d_iname);
    let mut buf = [0u8; 120];
    #[derive(Clone, Copy)]
    struct OpenAtSyscallArgs {
        dfd: i64,
        filename: *const u8,
        flags: u64,
        mode: u64,
    }

    //TODO: Check if the flags is relative

    let args = *ptr_at::<OpenAtSyscallArgs>(&ctx, 16).unwrap_unchecked();

    if args.dfd == -100 {
        info!(&ctx, "wat")
    } else {
        info!(&ctx, "not relative {}", args.dfd);
        let files = (*x).files;
        let fdt = (*files).fdt;
        let fdd = (*fdt).fd;
        let file = (*fdd).add(args.dfd as usize * 8);
        let pat = (*file).f_path;
        let pathname = pat.dentry;
        let mut huh = [0u8; 64];
        let xxxx = (*pathname).d_name.name;
        let aa = core::slice::from_raw_parts(xxxx, 10);
        info!(&ctx, "dawdwa: {}", str::from_utf8_unchecked(aa))
        //let filename = bpf_probe_read_kernel_str_bytes(xxxx.name, &mut huh);
    }

    let _ = bpf_probe_read_user_str_bytes(args.filename, &mut buf);
    let xd = &buf;
    info!(
        &ctx,
        "Tf {} {} dfd: {}",
        ma,
        str::from_utf8_unchecked(xd),
        args.dfd
    );

    Ok(0)
}

unsafe fn handle_sys_open_exit(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "handle_sys_open_exit start");
    let ret = *ptr_at::<i64>(&ctx, 16).unwrap_unchecked(); //TODO: We cant use unwrap, thats why we couldnt use the aya helper fns

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
