#![no_std]
#![no_main]

use core::ffi::c_void;
use core::str;

use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext, BpfContext, helpers::gen
};
use aya_log_ebpf::info;

#[tracepoint]
pub fn fs_tracer(ctx: TracePointContext) -> u32 {
    match try_fs_tracer(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &TracePointContext, offset: usize) -> Option<*const T> {
    let start = ctx.as_ptr();

    Some(unsafe { start.add(offset) } as *const T)
}

fn try_fs_tracer(ctx: TracePointContext) -> Result<u32, u32> {
    let syscall_nr = unsafe { * ptr_at::<i32>(&ctx, 8).unwrap() };
    
    return handle_syscall(ctx, syscall_nr);
}

fn handle_syscall(ctx: TracePointContext, syscall_nr: i32) -> Result<u32, u32> {
    match syscall_nr {
        1 => {
            return handle_sys_write(ctx);
        },
        2 => {
            return Ok(0)
            //handle_sys_open(ctx);
        },
        8 => {
            return Ok(0)
            //handle_sys_lseek(ctx);
        },
        3 => {
            return Ok(0)
            //handle_sys_close(ctx);
        },
        _ => {
            info!(&ctx, "unhandled syscall: {}", syscall_nr);
            panic!("syscall: {}",syscall_nr);
        }
    }
}

#[derive(Clone, Copy)]
struct WriteArgs {
    fd: u64,
    buf: *const u8,
    count: u64,
}

fn handle_sys_write(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "handle_sys_write start");
    let args = unsafe { *ptr_at::<WriteArgs>(&ctx, 16).unwrap() };

    info!(&ctx, "argfs fd: {}", args.fd);
    let mut buf = [0u8; 256];
    get_string_from_userspace(args.buf, &mut buf);
    let buf_ref = &buf;
    info!(&ctx, "buf: {}", unsafe { str::from_utf8_unchecked(buf_ref) });
    info!(&ctx, "count: {}", args.count);

    info!(&ctx, "handle_sys_write end");
    return Ok(0)
} //TODO: Communicate with userspace (share a some data structure in memory?)

fn get_string_from_userspace(ptr: *const u8, buf: &mut [u8]) {
    unsafe { gen::bpf_probe_read_user_str( buf.as_mut_ptr() as *mut c_void, buf.len() as u32, ptr as *const c_void) };
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}