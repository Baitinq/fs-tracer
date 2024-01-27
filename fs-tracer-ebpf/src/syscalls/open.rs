
use core::{mem::{self, size_of}, ptr};

use aya_bpf::{helpers::{bpf_d_path, bpf_probe_read, bpf_probe_read_kernel, gen}, cty::{c_void, c_long}, maps::PerCpuArray};

use crate::{*, vmlinux::files_struct};
use crate::vmlinux::file;

#[repr(C)]
pub struct Buffer {
    pub buf: [u8; 8192],
}

#[map]
static mut BUF: PerCpuArray<Buffer> = PerCpuArray::with_max_entries(1, 0);

pub fn handle_sys_open(ctx: TracePointContext, syscall_type: SyscallType) -> Result<c_long, c_long> {
    //info!(&ctx, "called");
    match syscall_type {
        SyscallType::Enter => unsafe { handle_sys_open_enter(ctx) },
        SyscallType::Exit => unsafe { handle_sys_open_exit(ctx) },
    }
}

unsafe fn handle_sys_open_enter(ctx: TracePointContext) -> Result<c_long, c_long> {
    //info!(&ctx, "handle_sys_open_enter start");
    let mut task = bpf_get_current_task_btf() as *mut task_struct;

    //info!(&ctx, "test: {}", (*files).next_fd);
    let pid = (*task).fs as *const fs_struct;
    let uwu = (*pid).pwd;
    let ra = uwu.dentry as *const dentry;
    let ma = str::from_utf8_unchecked(&(*ra).d_iname);
     let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(1)?;
        &mut *ptr
    };

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
        info!(&ctx, "relative call!");
    }
    else {
        info!(&ctx, "not relative call!");
          /*   let files = (*x).files;
        let fdt = (*files).fdt;
        let fdd = (*fdt).fd;*/
        info!(&ctx, "pid from ctx: {}", ctx.pid());
        info!(&ctx, "pid from task {}", (*task).pid);

        let files = bpf_probe_read_kernel(&(*task).files)?;
        let fdt = bpf_probe_read_kernel(&(*files).fdt)?;
        let fdarr = bpf_probe_read_kernel(&(*fdt).fd)?;
        info!(&ctx, "wuit: {}", args.dfd as isize);
        info!(&ctx, "test: {}", ctx.read_at::<u16>(16).unwrap_unchecked());
        let fd = bpf_probe_read_kernel(&(*fdarr.offset(3)))?; //todo: get good fd here. lets add a progrtam to test. shellcode.
        let mut deb = bpf_probe_read_kernel(&(*fd).f_path)?;
        let rwada = bpf_probe_read_kernel(&deb.dentry)?;
        let iname = bpf_probe_read_kernel_str_bytes(&(*rwada).d_iname as *const u8, &mut buf.buf)?;
        let xaxwaxa = str::from_utf8_unchecked(iname);
        
        info!(&ctx, "DEBUGGG: {}", xaxwaxa);
        info!(&ctx, "dawdwawd");
        /*let file = (*fdd).add(args.dfd as usize * 8);
        let mut pat = (*file).f_path;
        //info!(&ctx, "path: {}", &pat)
        let aya_bpf_path_ptr: *mut aya_bpf::bindings::path = unsafe {
            mem::transmute::<&mut vmlinux::path, *mut aya_bpf::bindings::path>(&mut pat)
        };

        let mut buff = [0i8; 120];
    bpf_d_path( aya_bpf_path_ptr , &mut buff as *mut i8, 120);*/

        /*let pathname = pat.dentry;
        let mut huh = [0u8; 64];
        let xxxx = (*pathname).d_name.name;
        let aa = core::slice::from_raw_parts(xxxx, 10);
        info!(&ctx, "dawdwa: {}", str::from_utf8_unchecked(aa))*/
        //let filename = bpf_probe_read_kernel_str_bytes(xxxx.name, &mut huh);
    }


    /*let filename = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(
            args.filename as *const u8,
            &mut buf.buf,
        ).unwrap_unchecked())
    };

    info!(
        &ctx,
        "Tf {} {} dfd: {}",
        2,//ma
        filename,
        args.dfd
    );
 */
    Ok(0)
}

unsafe fn handle_sys_open_exit(ctx: TracePointContext) -> Result<c_long, c_long> {
    //info!(&ctx, "handle_sys_open_exit start");
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
