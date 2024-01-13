#![no_std]
#![no_main]

use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext, BpfContext, cty::{int32_t, uint32_t},
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
    let syscall_nr = unsafe { * ptr_at::<int32_t>(&ctx, 8).unwrap() };
    
    return handle_syscall(ctx, syscall_nr);
}

fn handle_syscall(ctx: TracePointContext, syscall_nr: i32) -> Result<u32, u32> {
    match syscall_nr {
        1 => { //i dont think the numbers are right
            return handle_sys_write(ctx);
        },
        3 => {
            return Ok(0)
            //handle_sys_open(ctx);
        },
        8 => {
            return Ok(0)
            //handle_sys_lseek(ctx);
        },
        57 => {
            return Ok(0)
            //handle_sys_close(ctx);
        },
        _ => {
            panic!("syscall: {}",syscall_nr);
        }
    }
}

#[derive(Clone, Copy)]
struct WriteArgs {
    fd: int32_t,
    buf: *const u8,
    count: uint32_t,
}

fn handle_sys_write(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "handle_sys_write");
    let args = unsafe { *ptr_at::<WriteArgs>(&ctx, 0).unwrap() };
    
    info!(&ctx, "fd: {}", args.fd);

    return Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
