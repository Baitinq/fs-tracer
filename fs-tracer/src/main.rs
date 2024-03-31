use aya::maps::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use fs_tracer_common::SyscallInfo;
use log::{debug, info, warn};
use tokio::{signal, task};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/fs-tracer"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/fs-tracer"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let trace_enters_program: &mut TracePoint =
        bpf.program_mut("fs_tracer_enter").unwrap().try_into()?;
    trace_enters_program.load()?;
    trace_enters_program.attach("syscalls", "sys_enter_openat")?; //TODO: For some reason enter not being called. Try c program or assembly
                                                                  //trace_enters_program.attach("syscalls", "sys_enter_write")?;
                                                                  // program.attach("syscalls", "sys_exit_write")?;
                                                                  //trace_enters_program.attach("syscalls", "sys_enter_lseek")?;
                                                                  //program.attach("syscalls", "sys_enter_close")?;

    let trace_exits_program: &mut TracePoint =
        bpf.program_mut("fs_tracer_exit").unwrap().try_into()?;
    trace_exits_program.load()?;
    trace_exits_program.attach("syscalls", "sys_exit_openat")?;
    //program2.attach("syscalls", "sys_exit_write")?;

    println!("Num of cpus: {}", online_cpus()?.len());

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const SyscallInfo;
                    let data = unsafe { ptr.read_unaligned() };
                    match data {
                        SyscallInfo::Write(x) => println!("WRITE KERNEL: DATA {:?}", x),
                        SyscallInfo::Open(x) => println!("OPEN KERNEL DATA: {:?}", x),
                    }
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

