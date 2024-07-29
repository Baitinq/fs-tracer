mod syscall_handler;

use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf};
use aya::{maps::AsyncPerfEventArray, programs::TracePoint};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use core::panic;
use fs_tracer_common::SyscallInfo;
use log::{debug, info, warn};
use serde::Serialize;
use std::env;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let fs_tracer_api_key = env::var("FS_TRACER_API_KEY").expect("FS_TRACER_API_KEY must be set");

    let url = format!("http://leunam.dev:9999/api/v1/file/");

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
    trace_enters_program.attach("syscalls", "sys_enter_openat")?;
    trace_enters_program.attach("syscalls", "sys_enter_write")?;
    trace_enters_program.attach("syscalls", "sys_enter_lseek")?;
    trace_enters_program.attach("syscalls", "sys_enter_close")?;

    let trace_exits_program: &mut TracePoint =
        bpf.program_mut("fs_tracer_exit").unwrap().try_into()?;
    trace_exits_program.load()?;
    trace_exits_program.attach("syscalls", "sys_exit_openat")?;
    trace_exits_program.attach("syscalls", "sys_exit_write")?;
    trace_exits_program.attach("syscalls", "sys_exit_lseek")?;
    trace_exits_program.attach("syscalls", "sys_exit_close")?;

    println!("Num of cpus: {}", online_cpus()?.len());

    let exit = Arc::new(AtomicBool::new(false));
    let ctrlc_exit = exit.clone();
    ctrlc::set_handler(move || {
        println!("received Ctrl+C!");
        ctrlc_exit.store(true, Ordering::Relaxed);
    })
    .expect("could not set Ctrl+C handler");

    let (resolved_files_send, resolved_files_recv) = crossbeam_channel::unbounded();

    let mut handles = vec![];
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        let thread_exit = exit.clone();
        let thread_sender = resolved_files_send.clone();
        handles.push(tokio::spawn(async move {
            let mut syscall_handler = syscall_handler::SyscallHandler::new(thread_sender);
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(4096))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    if thread_exit.load(Ordering::Relaxed) {
                        info!("STOPPED THREAD, RETURNING");
                        return;
                    }
                    let ptr = buf.as_ptr() as *const SyscallInfo;
                    let data = unsafe { ptr.read_unaligned() };
                    if let Err(_) = syscall_handler.handle_syscall(data) {
                        panic!("Error handling syscall!");
                    }
                }
            }
        }));
    }

    drop(resolved_files_send);

    let batch_timeout = Duration::from_secs(20);
    let mut last_sent_time = Instant::now();

    let mut resolved_files_for_request: Vec<FSTracerFile> = vec![];
    for elt in &resolved_files_recv {
        info!("HELLO123!");
        if elt.absolute_path.starts_with("/proc/") {
            continue;
        }
        resolved_files_for_request.push(elt);
        if last_sent_time.elapsed() < batch_timeout {
            continue;
        }

        info!("SENDING REQUEST!");
        send_request(&url, &fs_tracer_api_key, &resolved_files_for_request);
        resolved_files_for_request.clear();
        last_sent_time = Instant::now();
    }

    info!("All threads stopped, exiting now...");

    if !resolved_files_for_request.len() > 0 {
        send_request(&url, &fs_tracer_api_key, &resolved_files_for_request);
    }

    Ok(())
}

#[derive(Serialize, Debug)]
struct FSTracerFile {
    timestamp: String,
    absolute_path: String,
    contents: String,
    offset: i64,
}

fn send_request(url: &str, fs_tracer_api_key: &str, files: &Vec<FSTracerFile>) {
    //TODO: We need to handle when you reopen a file.
    let serialized_body = serde_json::to_string(files).expect("failed to serialize failes");
    for _ in 1..4 {
        match ureq::post(&url)
            .set("API_KEY", &fs_tracer_api_key)
            .send_string(&serialized_body)
        {
            Ok(resp) => {
                if resp.status() == 200 {
                    break;
                }
                info!("Failed to send request: {:?}", resp);
            }
            Err(err) => {
                info!("Failed to send request: {:?}", err);
            }
        }
    }

    info!("SENT REQUEST! {:?}", serialized_body);
}
