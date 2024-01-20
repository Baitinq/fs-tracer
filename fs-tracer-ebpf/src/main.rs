#![no_std]
#![no_main]

use core::ffi::c_void;

use aya_bpf::helpers::{bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes};
use aya_bpf::maps::HashMap;
use aya_bpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    BpfContext,
};
use aya_log_ebpf::info;
use fs_tracer_common::WriteSyscallBPF;

#[map]
static EVENTS: PerfEventArray<WriteSyscallBPF> = PerfEventArray::with_max_entries(1024, 0);

#[map]
static SYSCALLENTERS: HashMap<u32, WriteSyscallBPF> = HashMap::with_max_entries(1024, 0);

//TODO: Clean up code. Generics. Arbitrary length buffer? https://github.com/elbaro/mybee/blob/fe037927b848cdbe399c0b0730ae79400cf95279/mybee-ebpf/src/main.rs#L29

enum SyscallType {
    Enter,
    Exit,
}

//#[map]
//static mut READ_FROM_USERSPACE_BUFFER: PerCpuArray<[u8;2048]> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn fs_tracer_enter(ctx: TracePointContext) -> u32 {
    match try_fs_tracer(ctx, SyscallType::Enter) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn fs_tracer_exit(ctx: TracePointContext) -> u32 {
    match try_fs_tracer(ctx, SyscallType::Exit) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &TracePointContext, offset: usize) -> Option<*const T> {
    let start = ctx.as_ptr(); //maybe try using the  bpf_probe_read here to see if we can use result of that to know the type of the syscall

    Some(unsafe { start.add(offset) } as *const T)
}

fn try_fs_tracer(ctx: TracePointContext, syscall_type: SyscallType) -> Result<u32, u32> {
    let syscall_nr = unsafe { *ptr_at::<i32>(&ctx, 8).unwrap() };
    //info!( &ctx, "syscall_nr: {}", syscall_nr);

    //let typee = unsafe { *(cmd.as_ptr().add(0)  as *const u16)};
    //let typee = ctx.read_at(0)

    /* let a: [u64; 1] = [0u64; 1];
       let ret = unsafe { bpf_probe_read(a.as_ptr() as *mut c_void, 8, ctx.as_ptr().add(0) as *const c_void)}; //TODO: Maybe we can try reading some high btis to get the type of the syscall exit or enter
       info!(&ctx, "ret: {}", ret);
    info!(&ctx, "x: {}", unsafe {a[0]});
       info!(&ctx, "syscall_nr: {}", syscall_nr);*/
    //info!(&ctx, "type: {}", typee);
    //return Ok(1);
    handle_syscall(ctx, syscall_nr, syscall_type)
}

fn handle_syscall(
    ctx: TracePointContext,
    syscall_nr: i32,
    syscall_type: SyscallType,
) -> Result<u32, u32> {
    match syscall_nr {
        1 => handle_sys_write(ctx, syscall_type),
        2 => {
            Ok(0)
            //handle_sys_open(ctx);
        }
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

fn handle_sys_write(ctx: TracePointContext, syscall_type: SyscallType) -> Result<u32, u32> {
    match syscall_type {
        SyscallType::Enter => handle_sys_write_enter(ctx),
        SyscallType::Exit => handle_sys_write_exit(ctx),
    }
}

fn handle_sys_write_enter(ctx: TracePointContext) -> Result<u32, u32> {
    // info!(&ctx, "handle_sys_write start");
    #[derive(Clone, Copy)]
    struct WriteSyscallArgs {
        fd: u64,
        buf: *const u8,
        count: u64,
    }
    let args = unsafe { *ptr_at::<WriteSyscallArgs>(&ctx, 16).unwrap() };

    // if fd is stdout, stderr or stdin, ignore
    if args.fd <= 2 {
        return Ok(0);
    }

    // info!(&ctx, "argfs fd: {}", args.fd);
    let mut buf = [0u8; 96]; //we need to make this muuuuuch bigger
                             //get_string_from_userspace(args.buf, unsafe { &mut *READ_FROM_USERSPACE_BUFFER.get_ptr_mut(0).unwrap() });
                             //get_string_from_userspace(args.buf, &mut buf);
    let _ = unsafe { bpf_probe_read_user_str_bytes(args.buf, &mut buf) };
    let buf_ref = &buf;
    // info!(&ctx, "buf: {}", unsafe { str::from_utf8_unchecked(buf_ref) });
    //info!(&ctx, "count: {}", args.count);                                                                                                               ";

    let mut anotherbuf = [0u8; 96];
    let _ = unsafe { bpf_probe_read_kernel_str_bytes(buf_ref.as_ptr(), &mut anotherbuf) };

    let tgid: u32 = ctx.tgid();
    let _ = SYSCALLENTERS.insert(
        &tgid,
        &WriteSyscallBPF {
            pid: ctx.pid(),
            fd: args.fd,
            buf: anotherbuf,
            count: args.count,
            ret: -9999,
        },
        0,
    );

    Ok(0)
}

fn handle_sys_write_exit(ctx: TracePointContext) -> Result<u32, u32> {
    //info!(&ctx, "handle_sys_write_exit start");
    let ret = unsafe { *ptr_at::<i64>(&ctx, 16).unwrap() }; //TODO: We cant use unwrap, thats why we couldnt use the aya helper fns

    let tgid = ctx.tgid();
    if let Some(&syscall) = unsafe { SYSCALLENTERS.get(&tgid) } {
        let mut newsyscall = syscall.clone();
        newsyscall.ret = ret;
        EVENTS.output(&ctx, &newsyscall, 0);
    }
    //syscall_enter.ret = ret;
    //EVENTS.output(&ctx, &syscall_enter, 0);

    Ok(0)
}

// thread can only execute 1 syscall at a time <-

//TODO: How are we going to correlate. We have open of a filename, we need to insert that into (pid, fd) -> filename. on close we remove from map. we need some timeout to remove stale entries
//TODO: to get the fd from open, we need to know the return value of the syscall. for that we need a tracepoint on end and keep a map of (tgid, pid) -> WriteSyscallBPF). we need to differenciate the syscalls by id
//TODO: Maybe we can use git itself for the diffs etc.

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
