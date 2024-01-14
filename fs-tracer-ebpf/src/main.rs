#![no_std]
#![no_main]

use core::ffi::c_void;
use core::str;

use aya_bpf::{
    macros::{tracepoint, map},
    programs::TracePointContext, BpfContext, helpers::{gen::{self, bpf_probe_read_kernel_str}, bpf_probe_read_kernel_str_bytes}, maps::{PerfEventArray, PerCpuArray},
};
use aya_log_ebpf::info;
use fs_tracer_common::WriteSyscallBPF;

#[derive(Clone, Copy)]
 struct WriteSyscallArgs {
     fd: u64,
     buf: *const u8,
     count: u64,
}

#[map]
static EVENTS: PerfEventArray<WriteSyscallBPF> = PerfEventArray::with_max_entries(1024, 0);

//#[map]
//static mut READ_FROM_USERSPACE_BUFFER: PerCpuArray<[u8;2048]> = PerCpuArray::with_max_entries(1, 0);

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

/*static mut read_from_userspace_buffer: [u8; 2048] = [0u8; 2048];
static mut write_to_userspace_buffer: [u8; 2048] = [0u8; 2048];
static mut write_syscall_bpf: WriteSyscallBPF = WriteSyscallBPF {
    fd: 0,
    buf: [0u8; 2048],
    count: 0,
};*/

fn handle_sys_write(ctx: TracePointContext) -> Result<u32, u32> {
    //info!(&ctx, "handle_sys_write start");
    let args = unsafe { *ptr_at::<WriteSyscallArgs>(&ctx, 16).unwrap() };

    // if fd is stdout, stderr or stdin, ignore
    if args.fd <= 2 {
        return Ok(0)
    }

   // info!(&ctx, "argfs fd: {}", args.fd);
    let mut buf = [0u8; 128];
    //get_string_from_userspace(args.buf, unsafe { &mut *READ_FROM_USERSPACE_BUFFER.get_ptr_mut(0).unwrap() });
    get_string_from_userspace(args.buf, &mut buf);
    let buf_ref = &buf;
   // info!(&ctx, "buf: {}", unsafe { str::from_utf8_unchecked(buf_ref) });
    //info!(&ctx, "count: {}", args.count);                                                                                                               ";

    let mut anotherbuf = [0u8; 128];
    unsafe { bpf_probe_read_kernel_str(anotherbuf.as_mut_ptr() as *mut c_void, 128, buf_ref.as_ptr() as *const c_void) };

    EVENTS.output(&ctx, &WriteSyscallBPF {
        pid: ctx.pid(),
        fd: args.fd,
        buf: anotherbuf,
        count: args.count,
    }, 0);

    //info!(&ctx, "handle_sys_write end");
    return Ok(0)
}

//TODO: How are we going to correlate. We have open of a filename, we need to insert that into (pid, fd) -> filename. on close we remove from map. we need some timeout to remove stale entries
//TODO: to get the fd from open, we need to know the return value of the syscall. for that we need a tracepoint on end and keep a map of (tgid, pid) -> WriteSyscallBPF)

fn get_string_from_userspace(ptr: *const u8, buf: &mut [u8]) {
    unsafe { gen::bpf_probe_read_user_str( buf.as_mut_ptr() as *mut c_void, buf.len() as u32, ptr as *const c_void) };
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}