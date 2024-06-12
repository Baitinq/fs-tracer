use std::ffi::CStr;

use crossbeam_channel::Sender;
use delay_map::HashMapDelay;

use fs_tracer_common::{OpenSyscallBPF, SyscallInfo, WriteSyscallBPF};

pub struct SyscallHandler {
    resolved_files: Sender<String>,
    open_files: HashMapDelay<i32, String>,
}

impl SyscallHandler {
    pub fn new(resolved_files: Sender<String>) -> Self {
        Self {
            resolved_files,
            open_files: HashMapDelay::new(std::time::Duration::from_secs(400)),
        }
    }

    pub fn handle_syscall(&mut self, data: SyscallInfo) -> Result<(), ()> {
        match data {
            SyscallInfo::Write(write_syscall) => self.handle_write(write_syscall),
            SyscallInfo::Open(open_syscall) => self.handle_open(open_syscall),
            //TODO: SyscallInfo::Close
        }
    }

    fn handle_write(&self, write_syscall: WriteSyscallBPF) -> Result<(), ()> {
        let filename = match self.open_files.get(&write_syscall.fd) {
            None => {
                println!("DIDNT FIND AN OPEN FILE FOR THE WRITE SYSCALL");
                return Ok(());
            }
            Some(str) => str,
        };
        let contents = CStr::from_bytes_until_nul(&write_syscall.buf)
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();
        println!("WRITE KERNEL: DATA {:?}", write_syscall);
        let _ = self.resolved_files.send(format!(
            r#"
                {{
                    "timestamp": "{}",
                    "absolute_path": "{}",
                    "contents": "{}"
                }}
                "#,
            chrono::Utc::now().to_rfc3339(),
            filename,
            contents,
        ));
        Ok(())
    }

    fn handle_open(&mut self, open_syscall: OpenSyscallBPF) -> Result<(), ()> {
        let filename = CStr::from_bytes_until_nul(&open_syscall.filename)
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();
        println!("OPEN KERNEL DATA: {:?}", open_syscall);
        println!("OPEN FILENAME: {:?}", filename);
        let fd = open_syscall.ret;
        self.open_files.insert(fd, filename.to_string());
        Ok(())
    }
}
