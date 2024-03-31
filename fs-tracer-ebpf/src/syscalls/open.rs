use aya_ebpf::{
    cty::{c_char, c_int, c_long},
    helpers::{
        bpf_get_current_task_btf, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user_str_bytes, bpf_tail_call,
    },
    maps::PerCpuArray,
};
use fs_tracer_common::OpenSyscallBPF;

use crate::{
    vmlinux::{task_struct, umode_t},
    *,
};

const AT_FDCWD: c_int = -100;
const MAX_PATH: usize = 96; //TODO: 4096

#[repr(C)]
pub struct Buffer {
    pub buf: [u8; MAX_PATH],
}

#[map]
static mut PATH_BUF: PerCpuArray<Buffer> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut TMP_BUF: PerCpuArray<Buffer> = PerCpuArray::with_max_entries(1, 0);

pub fn handle_sys_open(
    ctx: TracePointContext,
    syscall_type: SyscallType,
) -> Result<c_long, c_long> {
    //info!(&ctx, "called");
    match syscall_type {
        SyscallType::Enter => unsafe { handle_sys_open_enter(ctx) },
        SyscallType::Exit => unsafe { handle_sys_open_exit(ctx) },
    }
}

unsafe fn handle_sys_open_enter(ctx: TracePointContext) -> Result<c_long, c_long> {
    //info!(&ctx, "handle_sys_open_enter start");

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct OpenAtSyscallArgs {
        dfd: c_int,
        filename: *const c_char,
        flags: c_int,
        mode: umode_t,
    }

    let args = ctx.read_at::<OpenAtSyscallArgs>(16)?;

    if args.dfd != AT_FDCWD {
        return Err(1);
    }

    // TODO: If the path isnt relative, we already know the full path

    let buf = get_buf(&PATH_BUF)?;
    let filename: &str = unsafe {
        core::str::from_utf8_unchecked(
            bpf_probe_read_user_str_bytes(args.filename as *const u8, &mut buf.buf)
                .unwrap_unchecked(),
        )
    };

    info!(&ctx, "filename: {} dfd: {}", filename, args.dfd);

    if filename.len() < 3 {
        return Ok(0);
    }

    //let kbuf = get_buf(&PATH_BUF)?;
    //info!(&ctx, "count: {}", kbuf.buf.len());
    let (s, s1) = filename.split_at(0); //tODO this doesnt work
    if s == "/" {
        info!(&ctx, "SHIITT AINT RELATIVE BOIIIIIIIIIIIIIIIIIIIIIIII");
        return Ok(0);
    } else {
        info!(&ctx, "relative call! {} {}", s, s1);
    }

    //TODO
    //    if filename.get(0).unwrap_unchecked() == '/' {
    //      return Ok(0);
    //}

    let mut task = bpf_get_current_task_btf() as *mut task_struct;
    let pwd = get_task_pwd(&ctx, task)?;

    info!(&ctx, "PWD: {}", pwd);

    let tgid: u32 = ctx.tgid();
    let _ = SYSCALL_ENTERS.insert(
        &tgid,
        &SyscallInfo::Open(OpenSyscallBPF {
            pid: ctx.pid(),
            dfd: args.dfd,
            filename: buf.buf,
            mode: args.mode,
            flags: args.flags,
            ret: -9999,
        }),
        0,
    );
    Ok(0)
}

unsafe fn handle_sys_open_exit(ctx: TracePointContext) -> Result<c_long, c_long> {
    //info!(&ctx, "handle_sys_open_exit start");
    let ret = ctx.read_at::<c_long>(16)?; //TODO: We cant use unwrap, thats why we couldnt use the aya helper fns

    let tgid = ctx.tgid();
    if let Some(syscall) = SYSCALL_ENTERS.get(&tgid)
        && let SyscallInfo::Open(mut syscall_open) = syscall
    {
        syscall_open.ret = ret;
        EVENTS.output(&ctx, &SyscallInfo::Open(syscall_open), 0);
        let _ = SYSCALL_ENTERS.remove(&tgid);
        return Ok(0);
    }

    //bpf_tail_call(ctx, prog_array_map, index) //what is this
    Err(0)
}

unsafe fn get_task_pwd<'a>(
    ctx: &TracePointContext,
    task: *const task_struct,
) -> Result<&'a str, c_long> {
    let result = get_buf(&PATH_BUF)?;
    let tmp_buf: &mut Buffer = get_buf(&TMP_BUF)?;
    let fs = bpf_probe_read_kernel(&(*task).fs)?;
    let pwd: vmlinux::path = bpf_probe_read_kernel(&(*fs).pwd)?;
    let mut prev_dentry = bpf_probe_read_kernel(&pwd.dentry)?;
    let mut dentry = prev_dentry;
    let mut iters: usize = 0;
    let mut num_chars: usize = 0;
    loop {
        info!(ctx, "num_chars: {}", num_chars);

        let iname =
            bpf_probe_read_kernel_str_bytes(&(*dentry).d_iname as *const u8, &mut tmp_buf.buf)?;
        if iname.len() > 40 {
            break;
        }

        *result.buf.as_mut_ptr().add(num_chars) = '/' as u8; //TODO: Look at this to get char
        num_chars += 1;
        for i in 0..iname.len() {
            *result.buf.as_mut_ptr().add(num_chars) = iname[i]; //we shouldnt append but prepend
            num_chars += 1;
        }

        iters += 1;
        prev_dentry = dentry;
        dentry = bpf_probe_read_kernel(&(*dentry).d_parent)?;
        if dentry == prev_dentry || iters >= 2 {
            //TODO: we are running out of instrs
            break;
        }
    }
    *result.buf.as_mut_ptr().add(num_chars) = 0; //idk why we have to index like this

    Ok(str_from_u8_nul_utf8_unchecked(&result.buf))
}

unsafe fn get_buf<'a>(buf: &PerCpuArray<Buffer>) -> Result<&'a mut Buffer, i64> {
    let ptr = buf.get_ptr_mut(0).ok_or(1)?;
    Ok(&mut *ptr)
}

unsafe fn str_from_u8_nul_utf8_unchecked(utf8_src: &[u8]) -> &str {
    let mut nul_range_end = utf8_src.len();
    for i in 0..utf8_src.len() {
        if i > 200 {
            //satisfy the verifier
            break;
        }
        if utf8_src[i] == b'\0' {
            nul_range_end = i;
            break;
        }
    }

    str::from_utf8_unchecked(&utf8_src[0..nul_range_end])
}
